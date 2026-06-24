# Argus - ADK Threat-Modeling Agent

[![CI](https://github.com/thedevappsecguy/argus/actions/workflows/ci.yml/badge.svg)](https://github.com/thedevappsecguy/argus/actions/workflows/ci.yml)
[![PyPI version](https://badge.fury.io/py/argus-agent.svg)](https://badge.fury.io/py/argus-agent)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## The Problem
In modern enterprise development, security engineers are often a bottleneck. They do not have the bandwidth to manually threat-model every single PRD, design doc, or RFC before a sprint begins. Discovering design flaws late in the SDLC leads to expensive architectural refactoring, delayed releases, or catastrophic security breaches. 

## The Solution
**Argus** solves this by acting as an autonomous Security Champion. It turns raw PRDs, design docs, feature docs, RFCs, and architecture notes into developer-facing, STRIDE-categorized, OWASP-risk-rated threat model reports using an ADK-only multi-agent workflow. This allows development teams to securely "shift left" without friction.

## Architecture

```text
Input document
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

Agents drive the threat-modeling decisions. Narrow tools remain authoritative for schema
validation, model element binding, deterministic OWASP severity calculation, and Markdown
rendering.

## Components

| Area | Description |
|------|-------------|
| `agents` | ADK `Workflow` (formerly `SequentialAgent`) and tool bridge |
| `threats` | Shared candidate and verified threat schemas |
| `rating` + `risk` | Deterministic OWASP factor-to-severity matrix |
| `skill_corpus` | Packaged exact-reference OWASP, ATLAS, AIUC-1, and risk-rating corpora |
| `cli` | `argus run` for document input with optional `--out` |

## Installation

Install the package from PyPI. Note that while the package is named `argus-agent`, the CLI command remains `argus`:

```bash
# Recommended: install globally with uv
uv tool install argus-agent

# Or with pip
pip install argus-agent
```

## Usage

You must provide a Gemini API key via the `GEMINI_API_KEY` environment variable:

```bash
export GEMINI_API_KEY="your-api-key"
argus run path/to/design.md

# Or securely using 1Password CLI (Recommended)
op run --env-file=.env -- argus run path/to/design.md
```

## Local Development

If you want to clone the repository to run it locally or contribute:

```bash
uv sync

# Run tests
uv run pytest
```

## Project Layout

```text
argus/
  .github/           - CI/CD workflows, issue templates, CODEOWNERS
  argus/
    agents/          - ADK workflow, stage schemas, runner, and tools
    models.py        - SystemModel, Actor, Component, DataFlow, Control
    threats.py       - ProposedThreats, VerifiedThreats, element binding
    rating.py        - RatedThreat, ThreatStatus, rate_threats
    risk.py          - OWASP Risk Rating factor-to-severity matrix
    context.py       - SystemModel -> structured agent context
    security/        - prompt input guard
    skill_corpus/    - packaged exact-reference skills
    skills.py        - skill loader (SKILL.md + resources/list.yaml)
    skills_router.py - just-in-time skill selection from SystemModel tags
    report.py        - Markdown report renderer
    config.py        - Gemini model IDs and API key lookup
    cli.py           - Typer CLI
  tests/             - unit and integration tests
  renovate.json      - Automated dependency updates
  SECURITY.md        - Vulnerability reporting policy
  CONTRIBUTING.md    - Contribution guidelines
```

## Security Design

- Agent-driven scenario flow: agents map zones, entry points, scenarios, attack paths, control
  challenges, and risk factors.
- Element binding gate: candidate threats not tied to real model elements are filtered before
  verification.
- Risk-rating gate: the risk agent assigns OWASP factor scores using the risk-rating skill, and
  the deterministic rating tool calculates severity.
- Report gate: the report agent calls the renderer tool; it does not freehand final Markdown.

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `GEMINI_API_KEY` | - | Gemini/AI Studio API key |
| `ARGUS_PRO_MODEL` | `gemini-2.5-pro` | Model for deeper reasoning stages |
| `ARGUS_FLASH_MODEL` | `gemini-2.5-flash` | Model for lighter stages |
| `ARGUS_TEMPERATURE` | `0.1` | LLM temperature |

## Contributing & Security

- We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details on setting up your development environment, testing, and submitting PRs.
- **Security:** If you discover a vulnerability, please see our [Security Policy](SECURITY.md) for instructions on responsible disclosure via GitHub Security Advisories. Do NOT open a public issue.

## Releasing a New Version

We use the built-in `uv version` tool so that versions stay command-driven and consistent.

1. **Bump the version**:
   ```bash
   # Option A: Bump by semantic component (patch, minor, major)
   uv version --bump patch
   
   # Option B: Set an explicit version
   uv version 0.1.1
   ```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
