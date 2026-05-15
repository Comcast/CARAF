# PQCheck

A Flask web app that analyzes GitHub repositories for:

- Post-Quantum Cryptography (PQC) signals
- crypto dependency exposure
- maintenance risk indicators
- AI-assisted migration guidance

This version is organized as blueprints and includes UI pages plus JSON/export endpoints.

## Features

- Analyze GitHub repository metadata and classify maintenance status
- Detect potential PQC indicators from README and repository code search
- Pull dependency graph from GitHub SBOM API
- Enrich dependencies from common ecosystems:
  - Python (`requirements`, `pyproject`, `setup.py`, `Pipfile`, conda)
  - Node (`package.json`)
  - Rust (`Cargo.toml`)
  - Java (`pom.xml`)
  - .NET (`*.csproj`, `packages.config`)
  - Ruby (`Gemfile`)
  - Nim (`*.nimble`)
  - GitHub Actions workflows
- Generate exportable CSV and HTML reports
- Optional AI integration for:
  - repo risk assessment
  - dependency migration advice
  - chat responses

## Prerequisites

- Python 3.10+
- Git
- `sbom-tool` installed and available on `PATH`

## Installation

1. Open a terminal in this directory:

```bash
cd PQCheck
```

2. Create and activate a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

3. Install required packages:

```bash
pip install flask requests openai
```

## Environment Variables

Set these before running the app:

- `GITHUB_TOKEN` (recommended): improves GitHub API quota and access
- `AI_API_KEY` (optional): enables AI assessment/chat

Example:

```bash
export GITHUB_TOKEN="<your_token>"
export AI_API_KEY="<your_key>"
```

## Run

```bash
python3 app.py
```

App URL: `http://127.0.0.1:5000`

## UI Routes

- `GET /` - home page
- `GET|POST /crypto` - crypto/PQC analysis page
- `GET /sbom_dependency` - dependency analysis page
- `GET /ai` - AI chat page

## Quick API Examples

Analyze repo crypto posture:

```bash
curl -X POST http://127.0.0.1:5000/repo_crypto \
  -H "Content-Type: application/json" \
  -d '{"repo":"open-quantum-safe/liboqs"}'
```

Analyze dependencies:

```bash
curl -X POST http://127.0.0.1:5000/dependency \
  -H "Content-Type: application/json" \
  -d '{"repo":"open-quantum-safe/liboqs"}'
```

Chat endpoint:

```bash
curl -X POST http://127.0.0.1:5000/chat \
  -H "Content-Type: application/json" \
  -d '{"repo":"open-quantum-safe/liboqs","message":"Is this production ready for PQC?"}'
```

## Notes

- If AI is not configured, AI endpoints return fallback text instead of model output.
- Some dependency collection paths rely on external services and may be affected by rate limits.
- `sbom-tool` must be installed separately on your machine.

## Metric Source Reliability

Each maintenance metric in the `/repo_crypto` response includes a `source` and `confidence` field inside `metric_sources`. These indicate where the value was obtained and how reliable it is.

### Confidence Levels

| Level | Meaning |
|-------|---------|
| `high` | Retrieved from a definitive, primary API endpoint |
| `medium` | Inferred from a secondary or fallback source |
| `low` | Weakly signalled (e.g. README text mention) |

### Per-Metric Fallback Chain

**Last Push**
| Priority | Source | Confidence |
|----------|--------|------------|
| 1 | `github.repo.pushed_at` — direct repo metadata | high |
| 2 | `github.repo.updated_at` — last update timestamp | medium |
| 3 | `github.commits.latest` — date of most recent commit | medium |
| — | `unavailable` — all sources failed | low |

**Latest Release**
| Priority | Source | Confidence |
|----------|--------|------------|
| 1 | `github.releases.latest` — GitHub Releases API | high |
| 2 | `pypi.latest_upload` — latest PyPI package upload date | medium |
| 3 | `github.tags.latest` — date of latest git tag commit | medium |
| — | `unavailable` | low |

**Contributors**
| Priority | Source | Confidence |
|----------|--------|------------|
| 1 | `github.contributors.link_header` — pagination header (most accurate) | high |
| 2 | `github.contributors.list` — list length from API response | medium |
| 3 | `github.stats.contributors` — stats endpoint fallback | medium |
| — | `unavailable` | low |

**CI**
| Priority | Source | Confidence |
|----------|--------|------------|
| 1 | `github_actions.workflows_dir` — `.github/workflows/` directory exists | high |
| 2 | `ci_config:<file>` — found Travis, CircleCI, Jenkins, etc. config file | medium |
| 3 | `readme_ci_badge_or_text` — CI keyword detected in README | low |
| — | `no_ci_signal_found` | medium |

**Security Policy**
| Priority | Source | Confidence |
|----------|--------|------------|
| 1 | `repo_file:<path>` — SECURITY.md found at known location | high |
| 2 | `github.community.profile.security` — community profile API | medium |
| 3 | `github.security_and_analysis.secret_scanning` — secret scanning enabled | low |
| — | `no_security_policy_found` | medium |

The `metric_sources` block is also passed to the AI model so it can weigh the reliability of each signal when generating its assessment.
