# Contributing to Argus

Thanks for helping improve the project! This guide keeps contributions quick and consistent.

## Getting Set Up

- Install Python 3.11+ and [`uv`](https://docs.astral.sh/uv/).
- Install dependencies: `uv sync --group dev`.
- Run the CLI locally: `uv run argus --help`.

## Before You Open a PR

- Make changes on a branch; keep PRs focused and small.
- Add tests or fixtures when behavior changes.
- Run the checks:
  - `uv run ruff check .` — linting
  - `uv run ruff format --check .` — formatting
  - `uv run mypy argus` — type checking
  - `uv run pytest` — tests

## Opening a PR

- Describe the change, motivation, and testing done.
- Include any screenshots or logs if relevant.
- Make sure CI is green.

## Reporting Issues

- Share a concise description, steps to reproduce, expected vs. actual behavior, and your environment (OS, Python, package version).

## Security Vulnerabilities

- **Do NOT open public issues for security vulnerabilities.**
- See [`SECURITY.md`](SECURITY.md) for responsible disclosure instructions.
