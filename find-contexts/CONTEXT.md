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

| Context | What it covers | Load |
|---|---|---|
| `web-app-pentest` | Full web app pentest methodology — recon, auth, injection, business logic | `get_context("web-app-pentest")` |
| `api-security-review` | REST and GraphQL API security — BOLA, auth, rate limiting, data exposure | `get_context("api-security-review")` |
| `cloud-audit` | AWS/Azure/GCP — IAM, storage exposure, networking, logging, secrets | `get_context("cloud-audit")` |
| `mobile-pentest` | Android and iOS — static analysis, traffic interception, storage, auth | `get_context("mobile-pentest")` |

## How to load a context

Ask your agent:

```
get the web-app-pentest context
load cloud-audit L2
```

Or use the MCP tool directly:

```
get_context("web-app-pentest", level="L2")
```
