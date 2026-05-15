---
name: api-security-review
l0: REST and GraphQL API security review — authentication, authorization, BOLA, input validation, and rate limiting.
---

## L1 — Overview

An API security review assesses REST and GraphQL APIs for vulnerabilities including broken authentication, BOLA/IDOR, injection, excessive data exposure, and misconfiguration.

**Use this context when:**
- Testing REST or GraphQL APIs
- Reviewing API authentication (JWT, OAuth, API keys)
- Looking for BOLA/IDOR or broken function-level authorization
- Checking for excessive data exposure or mass assignment
- Testing rate limiting and resource consumption

**Key focus areas:** OWASP API Security Top 10, BOLA, broken authentication, excessive data exposure, lack of resources and rate limiting, broken function-level authorization.

---

## L2 — Full Methodology

### Phase 1 — API Discovery

- Collect API endpoints from JS bundles, mobile apps, Swagger/OpenAPI docs
- Check `/api/docs`, `/swagger.json`, `/openapi.json`, `/api/v1/`
- Use `ffuf` with API-specific wordlists
- Intercept mobile app traffic via Burp proxy

---

### Phase 2 — Authentication & Authorization

- API key in URL (`?api_key=xxx`) — log exposure risk
- JWT testing — see `jwt-cracker` skill
- OAuth token scope — request minimal scope, try upgrading
- BOLA — change object IDs in requests (see `idor-hunter` skill)
- Broken function-level authorization — access admin endpoints with user token

---

### Phase 3 — Input Validation

- Injection in all parameters (SQLi, NoSQLi, command injection)
- Mass assignment — send undocumented fields (`role`, `is_admin`)
- Unrestricted file upload via API
- JSON/XML injection in request body

---

### Phase 4 — Rate Limiting & Resource Consumption

- Brute-force endpoints without lockout
- Large payload attacks — send oversized JSON arrays
- Nested GraphQL queries (query depth attack)
- Missing pagination — dump entire dataset in one request

---

### Phase 5 — Data Exposure

- Response contains sensitive fields not needed by the client
- Error messages leak stack traces, DB queries, internal paths
- Verbose 404/403 responses reveal internal structure

---

### Phase 6 — Reporting

Use `finding-writer` skill. Reference OWASP API Security Top 10 category in each finding.
