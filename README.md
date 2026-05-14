# AuditGuard Contexts

Security engagement contexts for AI agents — load the right knowledge base before starting a pentest or audit. Served via MCP through [auditguard-context-mcp](https://github.com/AuditGuard-Community/context-mcp).

## Available Contexts

| Context | What it covers |
|---|---|
| `web-app-pentest` | Full web app pentest methodology — recon, auth, injection, business logic |
| `api-security-review` | REST and GraphQL API security — BOLA, auth, rate limiting, data exposure |
| `cloud-audit` | AWS/Azure/GCP — IAM, storage exposure, networking, logging, secrets |
| `mobile-pentest` | Android and iOS — static analysis, traffic interception, storage, auth |

## Quickstart

```bash
npx auditguard-context add web-app-pentest
```

## Context Structure

Each context uses a 3-tier loading system inspired by [OpenViking](https://github.com/volcengine/OpenViking):

```
web-app-pentest/
└── CONTEXT.md   ← contains L0, L1, and L2 sections
```

| Level | What it contains | When loaded |
|---|---|---|
| `L0` | One-sentence summary | Always — shown in listings |
| `L1` | Overview + when to use | Default load |
| `L2` | Full methodology | On demand |

## CONTEXT.md Format

```markdown
---
name: my-context
l0: One sentence describing what this context covers.
---

## L1 — Overview

When to use this context and what it covers at a high level.

---

## L2 — Full Methodology

Complete detailed content the agent uses during the engagement.
```

## Contributing

1. Fork this repo
2. Create a folder named after your context
3. Add a `CONTEXT.md` following the format above
4. Open a pull request

## Part of AuditGuard

Part of the [AuditGuard](https://github.com/AuditGuard-Community) open security toolkit.

## License

MIT
