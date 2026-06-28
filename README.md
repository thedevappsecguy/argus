# Argus - ADK Threat-Modeling Agent

[![CI](https://github.com/thedevappsecguy/argus/actions/workflows/ci.yml/badge.svg)](https://github.com/thedevappsecguy/argus/actions/workflows/ci.yml)
[![PyPI version](https://badge.fury.io/py/argus-agent.svg)](https://badge.fury.io/py/argus-agent)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Argus turns PRDs, design docs, feature docs, RFCs, ADRs, and architecture notes into
developer-facing threat model reports. It uses a Google ADK multi-agent workflow for
security reasoning, exact-reference skills for grounding, and deterministic tools for schema
validation, model element binding, OWASP severity calculation, and final Markdown rendering.

## Install

The package is named `argus-agent`; the command is `argus`.

```bash
uv tool install argus-agent
```

Or:

```bash
pip install argus-agent
```

For local development from this repository:

```bash
uv sync
uv tool install --reinstall .
```

## Quick Start

Argus accepts one readable UTF-8 text document. It does not ingest directories, GitHub URLs,
OpenAPI specs, Terraform, or binary files in this version.

Bash:

```bash
export GEMINI_API_KEY="your-api-key"
argus path/to/design.md
```

PowerShell:

```powershell
$env:GEMINI_API_KEY = "your-api-key"
argus path/to/design.md
```

cmd.exe:

```bat
set GEMINI_API_KEY=your-api-key
argus path\to\design.md
```

If `--out` is omitted, Argus writes the report to `<input>.threatmodel.md`.

```bash
argus path/to/design.md --out path/to/design.threatmodel.md
```

## Configuration

Config precedence is:

```text
CLI flags > exported environment > .env > built-in defaults
```

`GEMINI_API_KEY` is required and is intentionally environment-only. Do not pass API keys as
CLI arguments.

| Setting | Env var | CLI flag | Default |
|---|---|---|---|
| Gemini API key | `GEMINI_API_KEY` | none | required |
| Reasoning model | `ARGUS_PRO_MODEL` | `--pro-model` | `gemini-2.5-pro` |
| Lighter model | `ARGUS_FLASH_MODEL` | `--flash-model` | `gemini-2.5-flash` |
| One model for all stages | none | `--model` | none |
| Temperature | `ARGUS_TEMPERATURE` | `--temperature` | `0.1` |

Cheap smoke test:

```bash
argus path/to/design.md --model gemini-3.1-flash-lite
```

Use separate models for deeper and lighter stages:

```bash
argus path/to/design.md --pro-model gemini-2.5-pro --flash-model gemini-2.5-flash
```

Use a local `.env` file:

```dotenv
GEMINI_API_KEY=your-api-key
ARGUS_PRO_MODEL=gemini-2.5-pro
ARGUS_FLASH_MODEL=gemini-2.5-flash
ARGUS_TEMPERATURE=0.1
```

Use 1Password CLI:

```bash
op run --env-file=.env -- argus path/to/design.md --out path/to/design.threatmodel.md
```

## Progress Output

Interactive terminals show a progress bar with the current stage and elapsed time. Non-TTY
execution prints concise stage lines. Disable progress output with:

```bash
argus path/to/design.md --no-progress
```

Workflow stages:

```text
input document
  -> ingestion_agent
  -> architecture_zone_agent
  -> entry_point_agent
  -> scenario_enumeration_agent
  -> schema_validation_agent
  -> element_binding_agent
  -> false_positive_validation_agent
  -> control_challenge_agent
  -> risk_rating_agent
  -> report_agent
  -> Markdown report
```

## Output

The report includes:

- Architecture summary and data-flow view.
- Confirmed threats ranked by severity.
- STRIDE category, affected element, attack path, and mitigating controls.
- Ruled-out findings when the false-positive gate rejects a candidate.
- Assumptions, open questions, coverage notes, and limitations.

## Security Design

- Agents perform document understanding, zone mapping, entry-point discovery, scenario
  enumeration, false-positive validation, control challenge, and risk-factor assignment.
- `schema_validation_tool` enforces structured stage outputs.
- `element_validation_tool` filters threats that do not reference real model elements.
- `risk_rating_tool` converts agent-assigned OWASP factor scores into deterministic severity.
- `report_render_tool` renders the final Markdown report; the report agent does not freehand it.
- Exact-reference OWASP, ATLAS, AIUC-1, and risk-rating skill corpora are packaged under
  `argus.skill_corpus`.

## Troubleshooting

Missing API key:

```text
GEMINI_API_KEY is required. Set it in the environment or a .env file.
```

Fix it by exporting `GEMINI_API_KEY`, creating `.env`, or using `op run --env-file=.env`.

Wrong command shape:

```bash
argus path/to/design.md
```

Do not use `argus run`; the installed CLI is intentionally flat.

Model capacity or rate-limit errors:

```bash
argus path/to/design.md --model gemini-3.1-flash-lite
```

Unreadable input:

```text
Input must be a readable UTF-8 text document.
```

Convert the source document to text or Markdown before running Argus.

## Local Development

```bash
uv sync
uv run pytest
uv run ruff check .
```

The live Gemini test is opt-in so normal test runs remain deterministic:

```bash
ARGUS_RUN_LIVE=1 uv run pytest -m live
```

## Project Layout

```text
argus/
  agents/          - ADK workflow, stage schemas, runner, and tools
  models.py        - SystemModel, Actor, Component, DataFlow, Control
  threats.py       - ProposedThreats, VerifiedThreats, element binding
  rating.py        - RatedThreat, ThreatStatus, rate_threats
  risk.py          - OWASP Risk Rating factor-to-severity matrix
  context.py       - SystemModel to structured agent context
  security/        - untrusted input guard
  skill_corpus/    - packaged exact-reference skills
  skills.py        - skill loader
  skills_router.py - just-in-time skill selection from SystemModel tags
  report.py        - Markdown report renderer
  config.py        - runtime config resolver
  cli.py           - Typer CLI
tests/             - unit, integration, and opt-in live tests
```

## Contributing and Security

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup and PR guidance.

If you discover a vulnerability, follow [SECURITY.md](SECURITY.md). Do not open a public
issue for security reports.

## Releasing

```bash
uv version --bump patch
uv version 0.1.1
```

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE).
