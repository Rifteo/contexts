---
name: find-contexts
l0: Helps discover and load the right AuditGuard security context for any engagement type.
---

## L1 — Overview

When the user is starting an engagement or asks what context to load, help them find and install the right one.

**Use this context when:**
- User asks "what context should I use for X?"
- User is starting a new engagement
- User wants to know what contexts are available

---

## L2 — Available Contexts

| Context | What it covers | Install |
|---|---|---|
| `web-app-pentest` | Full web app pentest methodology — recon, auth, injection, business logic | `auditguard-context add web-app-pentest` |
| `api-security-review` | REST and GraphQL API security — BOLA, auth, rate limiting, data exposure | `auditguard-context add api-security-review` |
| `cloud-audit` | AWS/Azure/GCP — IAM, storage exposure, networking, logging, secrets | `auditguard-context add cloud-audit` |
| `mobile-pentest` | Android and iOS — static analysis, traffic interception, storage, auth | `auditguard-context add mobile-pentest` |

## How to load a context

```bash
auditguard-context add web-app-pentest
```

Once loaded, the context is available to your agent via the `auditguard-context-mcp` MCP server.
