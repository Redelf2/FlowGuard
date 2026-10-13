# FlowGuard

FlowGuard is a small static analyzer for Python. It reads source code and looks for a few kinds of risky data flow. It does not run the program it analyzes.

The parser, taint tracking, and two security rules work. A finding is a potential risk on a tracked path. It is not proof that the file is exploitable. Exit code 0 means the file was analyzed, not that it is safe.

## What this version does

Given a Python file, FlowGuard:

1. Reads the file as text.
2. Parses it with Python's built-in `ast` module.
3. Lists simple variable assignments and function calls, with line numbers.
4. Prints that summary as text or JSON.
5. Tracks tainted names inside one scope. A scope is the module, one function, or one class body.
6. Reports a finding when a rule's source reaches that same rule's destination.

An **abstract syntax tree (AST)** is a structured version of the source. `backup = secret` becomes an assignment whose target is `backup` and whose value is the name `secret`. FlowGuard walks that tree instead of executing the file.

**Taint** means a label on a value that came from a configured source such as `os.getenv()` or `input()`. `backup = secret` copies the label. `secret = "public"` removes it from `secret` for later lines in that same scope.

A successful run is not a safety verdict. Zero findings means no tracked value reached a configured sink. Unsupported values are left out of that count.

## What this version does not do

- It does not prove that a finding can be exploited, or that zero findings means the file is safe.
- It does not follow a name across functions, parameters, closures, or `global`.
- It does not treat `print(str(secret))` or `logger.info(secret)` as a tracked sink. The call name must match the rule exactly, and the argument must be a plain name or a direct source call.
- It does not execute, exploit, or rewrite the target file.

## Rules

A finding requires a tracked path from one of that rule's sources to one of that rule's destinations in the same scope. The match is a **potential** risk.

| ID | Title | Severity | Sources | Destinations |
| --- | --- | --- | --- | --- |
| FG001 | Potential sensitive-data exposure | medium | `os.getenv`, `os.environ.get` | `print`, selected `logging.*` calls |
| FG002 | Potential command injection | high | `input` | `subprocess.run`, `subprocess.call`, `subprocess.check_output`, `subprocess.Popen`, `os.system` |

Severity is a project choice, not a measurement of exploitability. FG002 is `high` because untrusted input reaching a command is the more serious of the two checks. FG001 is `medium` because an environment variable is not automatically a secret.

`shell=True` raises the confidence of an FG002 finding to `increased`. Without it, a subprocess finding stays `limited`. `os.system` is `increased` because it always uses a shell. Confidence is not proof.

## Project layout

```text
FlowGuard/
├── flowguard.py                 # command-line entry point
├── flowguard/
│   ├── __init__.py              # package version
│   ├── parser.py                # AST extraction, including scope labels
│   ├── taint_engine.py          # assignment tracking inside one scope
│   ├── rules.py                 # FG001 and FG002 findings
│   ├── evaluate.py              # labeled detection and false-positive rates
│   └── reporter.py              # text and JSON, including findings
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

Score the labeled samples without running them:

```bash
python flowguard.py --evaluate
```

Exit codes:

| Code | Meaning |
| --- | --- |
| 0 | The file was analyzed. This does not mean it is safe. |
| 2 | The path is missing, is a directory, could not be read, or is not valid Python. |

Parser errors go to standard error. The summary goes to standard output.

Example text summary:

```text
FlowGuard
File: tests\samples\vulnerable_secret.py
Parsed assignments: 2
Parsed function calls: 2
Security findings: 1
A finding is a potential risk on a tracked path. Unsupported values are omitted. This is not proof that the file is safe or that a finding is exploitable.

Assignments:
  line 9: secret = os.getenv (call)
  line 10: backup = secret (name)

Function calls:
  line 9: os.getenv('API_KEY')
  line 11: print(backup)

Findings:

[MEDIUM] FG001 Potential sensitive-data exposure
File: tests\samples\vulnerable_secret.py
Source: os.getenv at line 9
Data flow: secret -> backup -> print
Destination: print at line 11
Confidence: limited

Reason:
A value read by a configured secret source may reach a print or logging call. This is a potential exposure: not every environment variable is a secret.

Recommendation:
Avoid sending secret values to logs or standard output. Redact them, or log only the fact that a value was loaded.

Limitation:
A match is a potential risk based on the configured names and a tracked path. FlowGuard does not execute the program and does not prove that the flow is exploitable.
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
- `import os` does not by itself create a call. The call list still shows the written name, so `getenv()` is not rewritten to `os.getenv()`. Alias resolution happens later, and only for a clear import of a known source.
- `os.environ["API_KEY"]` is a subscript, not a call, so it is not a source in the current rule list.
- The file must be UTF-8. The extension does not have to be `.py`; the contents must be valid Python syntax.
- Every call in the file is listed, including calls inside functions and decorators. Listing a call does not mean it is reachable at runtime.

## Samples

The first three files are the original demonstrations. The evaluation set adds more files under `tests/samples/eval/`. Do not run the samples. `vulnerable_command.py` and `input_os_system.py` would pass typed text to a shell if you executed them.

| File | What it is for |
| --- | --- |
| `tests/samples/vulnerable_secret.py` | FG001: `os.getenv` is copied to `backup` and then printed. |
| `tests/samples/vulnerable_command.py` | FG002: `input()` reaches `subprocess.run(..., shell=True)`. |
| `tests/samples/safe_example.py` | `print` receives the literal `"hello"`, not the getenv value. |

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

`from os import getenv` and `from os import getenv as read_env` are treated as `os.getenv`. `import os as os_module` then `os_module.getenv` is treated the same way. A function, parameter, or assignment named `getenv` hides that import. `from helpers import getenv` is not `os.getenv`. `from os import *` is not resolved. An import inside one function is not applied to a nested function. Sink aliases such as `os_module.system` are not resolved.

A rule fires only for its own sources and sinks. `print(input())` is not FG001, because `input` is not a secret source. `subprocess.run(os.getenv(...))` is not FG002, because `os.getenv` is not the untrusted-input source.

## Evaluation

`python flowguard.py --evaluate` parses the labeled files and compares findings with the labels. One measured run reported:

```text
Vulnerable files: 20
Detected: 20
Detection rate: 100.0%
Safe files: 18
False positives: 0
False-positive rate: 0.0%
Unsupported files, not scored: 11
Unexpected findings in unsupported files: 0
Elapsed: 0.050 seconds
```

The elapsed time is from that run. A later run on the same machine can differ by a few milliseconds.

The eight files named `author_written_chatgpt_` in `tests/samples/eval/eval_by_team/` are now labeled and scored. Their headers say they were written without opening the scorer. All three vulnerable files were detected. The three safe files produced no finding. The two unsupported files, a function parameter and `print(str(...))`, stayed out of both rates. The engine was not changed for this run.

Detection rate is the share of vulnerable files whose expected rule ids were reported. False-positive rate is the share of safe files that produced any finding. The eleven unsupported files are known limits, including `from os import *`, `print(str(secret))`, `print("key=" + secret)`, a nested function using an outer import, `logger.info` and `logger.warning`, an `or` expression, a function parameter, and `self.secret`. They are not counted as misses or as false positives.

Bandit and Semgrep were not installed in this environment, so they were not run and no comparison table was produced. Nothing was installed to add them.

This is FlowGuard's own labeled set. It is not a comparison with another analyzer.
