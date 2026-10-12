# FlowGuard

FlowGuard is a university project: a small static analyzer for Python. It reads source code and looks for selected risky data flows. It does not run the program it inspects.

Two kinds of flow are planned:

1. **Potential sensitive-data exposure.** A value from a source such as `os.getenv()` is copied through variables and reaches `print()` or a selected logging call.
2. **Potential command injection.** A value from `input()` reaches a command-execution call such as `subprocess.run()`, especially with `shell=True`.

A finding will mean "the source text matches a rule," not "this is proven to be exploitable."

## What works in this version (0.1)

The parser works. It uses Python's built-in `ast` module. AST means Abstract Syntax Tree: a structured tree of the code's syntax. From that tree, FlowGuard lists:

- assignments, such as `backup = secret`, with line numbers
- function and method calls, such as `os.getenv(...)` and `subprocess.run(..., shell=True)`, with line numbers and arguments

The command-line tool can read one Python file and print that list as text or JSON.

## What is not implemented yet

These parts exist only as placeholders, so the tool cannot pretend the scan is finished:

- taint tracking (following a value from variable to variable)
- security rules and vulnerability findings
- severity, remediation text, and confidence
- scanning a whole directory

`track_taint()` and `apply_rules()` raise `NotImplementedError` on purpose. An empty finding list would look like a clean result, which would be misleading.

Exit code 0 means the file was parsed. It does not mean the file is safe.

## Setup

Install Python 3.10 or newer. This project has no third-party dependencies. You do not need to install anything from `requirements.txt`.

Check the version:

```bash
python --version
```

## Usage

From the `FlowGuard` directory:

```bash
python flowguard.py tests/samples/vulnerable_secret.py
```

JSON parse report:

```bash
python flowguard.py tests/samples/vulnerable_secret.py --format json
```

Text output looks like this:

```text
FlowGuard 0.1.0 parse report
File: tests/samples/vulnerable_secret.py

Security analysis is not implemented yet. This report lists assignments and function calls only. It is not a vulnerability finding.

Assignments:
  line 5: secret = os.getenv('API_KEY')
  line 6: backup = secret

Function calls:
  line 5: os.getenv('API_KEY')
  line 7: print(backup)
```

The quotes in call text come from `ast.unparse`. They may differ from the quotes in the original file. The call name and line number still refer to that source line.

Missing files and invalid Python syntax are written to standard error, and the process exits with status 2.

## Samples

The files in `tests/samples/` are inputs for the analyzer. Do not run them.

| File | Role |
| --- | --- |
| `vulnerable_secret.py` | Example flow `os.getenv` → `secret` → `backup` → `print` |
| `vulnerable_command.py` | Example flow `input` → `user_input` → `subprocess.run(..., shell=True)` |
| `safe_example.py` | Ordinary string and a fixed argument list with `shell=False` |

`vulnerable_command.py` would pass typed text to a shell if you executed it. FlowGuard only reads it. The safe sample is labeled for later rule tests. Version 0.1 does not judge it safe or unsafe.

## Tests

From the `FlowGuard` directory:

```bash
python -m unittest discover -s tests -v
```

## Project layout

```text
FlowGuard/
├── flowguard.py              # command-line entry point
├── flowguard/
│   ├── parser.py             # ast parsing (implemented)
│   ├── taint_engine.py       # data-flow tracking (not implemented)
│   ├── rules.py              # FG001 and FG002 plan (not implemented)
│   └── reporter.py           # text and JSON parse reports
├── tests/
│   ├── test_parser.py
│   ├── test_taint_engine.py
│   ├── test_rules.py
│   └── samples/
├── README.md
└── requirements.txt
```

`flowguard.py` is the script you run. The `flowguard/` directory is the importable package. On Python 3.14, running the script can still `import flowguard` and receive the package.

## Parser behavior and limitations

Supported now:

- normal assignments, including `a = b = value`
- annotated assignments such as `secret: str = input()`
- unpacking on the left, such as `left, right = pair` (both names get the whole right-hand side)
- simple calls, dotted calls such as `os.getenv`, nested calls, and keyword arguments
- accurate starting line numbers, including for a call written across several lines

Not handled yet, and not reported as if they were handled:

- telling two uses of the same name apart by function or scope
- following a value through an alias (`backup = secret` is only listed, not linked)
- resolving imports (`from os import getenv` is recorded as a call named `getenv`, not `os.getenv`)
- augmented assignments such as `count += input()` (the `input()` call is listed; the assignment is not)
- assignment expressions such as `secret := os.getenv(...)` (the call is listed; the assignment is not)
- names bound by `for` or `with`
- splitting a tuple on the right-hand side into separate values
- directory scans, classes, cross-file flows, and dynamic calls such as `eval`

The parser never imports the target file and never calls `exec`.

## Planned rules

| ID | Title | Idea |
| --- | --- | --- |
| FG001 | Potential sensitive-data exposure | `os.getenv()` and other configured secret sources reaching `print()` or selected logging calls |
| FG002 | Potential command injection | `input()` and other configured untrusted sources reaching `subprocess.run()` and similar calls |

## Next milestone

Basic taint tracking inside one file: mark source calls, copy that mark through direct assignments and aliases, and drop it when a variable is assigned a new value. Rules and finding reports come after that tracking is tested.
