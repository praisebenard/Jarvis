# Repository Guidelines

## Project Structure & Module Organization

The application currently lives in the root-level `jarvis.py`. It provides an interactive security-review CLI, including web target checks and PHP source inspection. `scope.txt` lists authorized target hostnames, one per line; lines beginning with `#` are ignored. Generated text reports are stored in `reports/`. `jarvis.py.backup` is a historical copy, not the active entry point. Tests live in `tests/` and use Python's standard `unittest` framework; there is no separate source package or asset directory.

## Build, Test, and Development Commands

This repository has no build system or declared dependency manifest. Use the existing virtual environment when available:

- `source .venv/bin/activate` activates the local Python environment.
- `python jarvis.py` starts the interactive CLI; enter `help` to see commands and `exit` to quit.
- `python -m unittest discover -s tests` runs the automated test suite.
- `python -m py_compile jarvis.py` checks Python syntax without running the interactive program.

The application imports `requests`; install it in your environment if it is missing. Runtime files such as `scope.txt` and `reports/` are resolved relative to the current working directory.

## Coding Style & Naming Conventions

Use Python 3, four spaces per indentation level, `snake_case` for functions and variables, and uppercase `SNAKE_CASE` for module constants. Keep the single-file organization unless a change clearly benefits from extracting a module. Preserve the CLI's existing command names and provide concise usage messages for new commands. No formatter or linter configuration is present.

## Testing Guidelines

The suite uses `unittest`; no coverage target is configured. For behavior changes, run relevant tests and manually exercise the CLI with a local fixture where appropriate. Keep security checks inside the scope configured in `scope.txt`; do not use an unapproved external host as a test target.

## Commit & Pull Request Guidelines

Git metadata and commit history are unavailable in this checkout, so no repository-specific commit convention can be confirmed. Write short, imperative commit subjects (for example, `Clarify PHP report output`). Pull requests should describe the behavior change, list the commands or manual scenarios checked, and include a sample output or report excerpt when output changes.

## Security & Configuration

Only add targets to `scope.txt` when testing is authorized. Treat session cookies and generated evidence as sensitive: do not commit real credentials, tokens, or private target data in reports.
