<div align="center">

<picture>
  <source media="(prefers-color-scheme: dark)" srcset=".github/assets/banner-dark.png">
  <source media="(prefers-color-scheme: light)" srcset=".github/assets/banner-light.png">
  <img src=".github/assets/banner-light.png" alt="Rifteo contexts" width="330">
</picture>

<br>

# Rifteo Contexts

Security engagement contexts for AI agents - load the right knowledge base before starting a pentest or audit. Served via MCP through [rifteo-context-mcp](https://github.com/rifteo/context-mcp).

[![License](https://img.shields.io/badge/license-MIT-blue)](LICENSE)
[![PyPI](https://img.shields.io/pypi/v/rifteo-context-mcp)](https://pypi.org/project/rifteo-context-mcp)
[![Issues](https://img.shields.io/github/issues/rifteo/contexts)](https://github.com/rifteo/contexts/issues)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen)](CONTRIBUTING.md)

</div>

## Available Contexts

| Context | What it covers |
|---|---|
| `web-app-pentest` | Full web app pentest methodology - recon, auth, injection, business logic |
| `api-security-review` | REST and GraphQL API security - BOLA, auth, rate limiting, data exposure |
| `cloud-audit` | AWS/Azure/GCP - IAM, storage exposure, networking, logging, secrets |
| `mobile-pentest` | Android and iOS - static analysis, traffic interception, storage, auth |
| `code-audit` | Source code security review - secrets, auth logic, injection sinks, crypto, dependencies |

## Quickstart

Install the MCP server:

```bash
pip install rifteo-context-mcp
```

Register with all detected agents at once:

```bash
rifteo-context install
```

Or register with a specific agent:

```bash
rifteo-context install --agent claude-code
rifteo-context install --agent cursor
rifteo-context install --agent gemini-cli
```

Then ask your agent:

```
list all available security contexts
get the web-app-pentest context
```

Supports 10 agents: Claude Code, Cursor, Windsurf, Gemini CLI, Cline, Kiro, Codex, OpenCode, Amp, Continue.

## Context Structure

Each context uses a 3-tier loading system:

```
web-app-pentest/
└── CONTEXT.md   <- contains L0, L1, and L2 sections
```

| Level | What it contains | When loaded |
|---|---|---|
| `L0` | One-sentence summary | Always - shown in listings |
| `L1` | Overview + when to use | Default load |
| `L2` | Full methodology | On demand |

## CONTEXT.md Format

```markdown
---
name: my-context
l0: One sentence describing what this context covers.
---

## L1 - Overview

When to use this context and what it covers at a high level.

---

## L2 - Full Methodology

Complete detailed content the agent uses during the engagement.
```

See [CONTEXT_GUIDE.md](CONTEXT_GUIDE.md) for the full format reference including optional fields.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Part of Rifteo

Part of the [Rifteo](https://github.com/rifteo) open security toolkit.

## License

MIT
