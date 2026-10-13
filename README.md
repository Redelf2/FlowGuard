# FlowGuard

FlowGuard is a small static analyzer for Python. It reads source code and looks for a few kinds of risky data flow. It does not run the program it analyzes.

The parser and basic taint tracking work. Security findings do not work yet. The command line still prints a parse summary and does not list tainted names.

## What this version does

Given a Python file, FlowGuard:

1. Reads the file as text.
2. Parses it with Python's built-in `ast` module.
3. Lists simple variable assignments and function calls, with line numbers.
4. Prints that summary as text or JSON.
5. Can track tainted names inside one scope through `trace_assignments()`. A scope is the module, one function, or one class body.

An **abstract syntax tree (AST)** is a structured version of the source. `backup = secret` becomes an assignment whose target is `backup` and whose value is the name `secret`. FlowGuard walks that tree instead of executing the file.

**Taint** means a label on a value that came from a configured source such as `os.getenv()` or `input()`. `backup = secret` copies the label. `secret = "public"` removes it from `secret` for later lines in that same scope.

A successful parse is not a security result. The report says `Security findings: not checked yet.` JSON output has no `findings` field, because an empty list would look like "nothing risky was found."

## What this version does not do

- It does not report a vulnerability when a tainted name reaches `print()` or `subprocess.run()`.
- It does not decide that a file is safe or unsafe.
- It does not apply the rules below as findings yet. The taint engine only reads their source names.
- It does not follow a name across functions, parameters, closures, or `global`.
- It does not execute, exploit, or rewrite the target file.

## Planned rules

These names are the first configured set. A finding will later require a tracked path from a source to a sink. A match will be described as a **potential** risk.

| ID | Title | Severity | Sources | Destinations |
| --- | --- | --- | --- | --- |
| FG001 | Potential sensitive-data exposure | medium | `os.getenv`, `os.environ.get` | `print`, selected `logging.*` calls |
| FG002 | Potential command injection | high | `input` | `subprocess.run`, `subprocess.call`, `subprocess.check_output`, `subprocess.Popen`, `os.system` |

Severity is a project choice, not a measurement of exploitability. FG002 is `high` because untrusted input reaching a command is the more serious of the two checks. FG001 is `medium` because an environment variable is not automatically a secret.

`shell=True` is already captured by the parser when it appears as a keyword. The command rule does not use that fact until detection exists.

## Project layout

```text
FlowGuard/
├── flowguard.py                 # command-line entry point
├── flowguard/
│   ├── __init__.py              # package version
│   ├── parser.py                # AST extraction, including scope labels
│   ├── taint_engine.py          # assignment tracking inside one scope
│   ├── rules.py                 # rule definitions (not applied as findings yet)
│   └── reporter.py              # text and JSON for the parse summary
├── tests/
│   ├── __init__.py              # makes tests importable
│   ├── test_parser.py
│   ├── test_taint_engine.py
│   ├── test_rules.py
│   └── samples/
│       ├── vulnerable_secret.py
│       ├── vulnerable_command.py
│       └── safe_example.py
├── README.md
└── requirements.txt
```

`vulnerable_command.py` would run a shell command if you executed it yourself. The tests and the FlowGuard command only read it.

## Setup

Install Python 3.10 or newer. No third-party packages are required.

From this directory:

```bash
python -m unittest discover -s tests -t . -v
```

On Windows, if `python` is not available, use `py -3` instead.

## Usage

From the project root:

```bash
python flowguard.py tests/samples/vulnerable_secret.py
```

```bash
python flowguard.py tests/samples/vulnerable_command.py --format json
```

Exit codes:

| Code | Meaning |
| --- | --- |
| 0 | The file parsed. Findings were not checked. |
| 2 | The path is missing, is a directory, could not be read, or is not valid Python. |

Parser errors go to standard error. The summary goes to standard output.

Example text summary:

```text
FlowGuard
File: tests\samples\vulnerable_secret.py
Parsed assignments: 2
Parsed function calls: 2
Security findings: not checked yet.

Assignments:
  line 9: secret = os.getenv (call)
  line 10: backup = secret (name)

Function calls:
  line 9: os.getenv('API_KEY')
  line 11: print(backup)
```

The file path uses your operating system's separators. The example above is the Windows output.

The line numbers follow the sample file, including its docstring.

## Parser behavior

Recorded assignments:

- `secret = os.getenv("API_KEY")` is a `call` assignment, and `os.getenv` is also a call.
- `backup = secret` is a `name` assignment. That is an alias: a copy from one variable to another.
- `message = "hello"` is a `constant` assignment. Literal text is shown with `repr`, so the report contains `'hello'`.
- `secret: str = ...` is recorded. `secret: str` without a value is not.
- `secret += extra` is recorded as `augassign`.
- `a = b = value` records both `a` and `b`.
- Two assignments to the same name are both kept. Each one has a `scope` such as `<module>` or `load:4`. The parser does not decide which write is the current value. The taint engine does that inside one scope.

Recorded calls include positional arguments and keywords. `subprocess.run(user_input, shell=True)` keeps the argument `user_input` and the keyword `shell=True`. Calls nested inside other calls are listed outer call first.

## Known parser limits

These are recorded limits, not silent guesses:

- Tuple unpacking such as `first, second = pair` is not turned into simple assignments. Calls inside the statement are still listed.
- Assignments to attributes or subscripts, such as `self.secret = ...` or `data["k"] = ...`, are not treated as simple variables.
- A call written as something other than a plain dotted name is labeled `<complex>`.
- `import os` does not by itself create a call. `getenv()` and `os.getenv()` are different names. Import aliases are not resolved.
- `os.environ["API_KEY"]` is a subscript, not a call, so it is not a source in the current rule list.
- The file must be UTF-8. The extension does not have to be `.py`; the contents must be valid Python syntax.
- Every call in the file is listed, including calls inside functions and decorators. Listing a call does not mean it is reachable at runtime.

## Samples

| File | What it is for |
| --- | --- |
| `tests/samples/vulnerable_secret.py` | `os.getenv` is copied to `backup` and then printed. Later this should be a potential FG001 flow. |
| `tests/samples/vulnerable_command.py` | `input()` is passed to `subprocess.run(..., shell=True)`. Later this should be a potential FG002 flow. Do not run this file. |
| `tests/samples/safe_example.py` | `print` receives `message`, which is the literal `"hello"`. `secret` comes from `os.getenv` and does not reach `print` in this file. The parser only shows those facts. |

## Tests

```bash
python -m unittest discover -s tests -t . -v
```

`-t .` puts the project root on the import path so `import flowguard` loads the package.

The parser tests include a file that would create a marker file if it were executed. The test fails if that marker appears.

## Taint tracking

`trace_assignments(parse_result)` walks each scope from top to bottom. The configured sources come from the rule table: `os.getenv`, `os.environ.get`, and `input`.

```python
secret = os.getenv("API_KEY")  # secret is tainted
backup = secret                # backup is tainted; path is secret -> backup
secret = "public"              # secret is no longer tainted; backup still is
message = "hello"              # message is not tainted
```

A function named `load` on line 4 has scope `load:4`. A nested function is `outer:1.inner:3`. Names in those scopes are not the same variable.

These cases are reported as unsupported instead of being called safe or tainted:

- A call that is not a configured source, such as `wrapped = str(secret)`.
- A right-hand side that is not a simple name, constant, or direct call, such as `os.getenv("API_KEY") or "missing"`.
- A copy from a name that was never assigned in that same scope. Parameters, closure reads, and names from another function fall here.
- An assignment covered by `global` or `nonlocal`. The engine does not move that value into the other scope.

Unpacking, attribute assignment, and `getenv()` after `from os import getenv` keep the parser limits above. `getenv()` is not treated as `os.getenv`.

## Next milestone

Milestone 3 is to turn a tracked path into a finding when a tainted value reaches a configured destination such as `print()` or `subprocess.run()` in the same scope. A finding will stay a potential risk, with the rule id, severity, path, and a recommended fix.
