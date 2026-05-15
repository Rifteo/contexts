# Context Structure Guide

A complete reference for creating AuditGuard security contexts.

---

## What is a context?

A context is a security knowledge bundle the agent loads before starting an engagement. It gives the agent domain expertise — methodology, techniques, tools, and reporting guidance — for a specific type of security work.

Contexts are served to agents via the `auditguard-context-mcp` MCP server and retrieved on demand using the `get_context` tool.

---

## Minimal context

The only required file is `CONTEXT.md` inside a folder named after your context:

```
web-app-pentest/
└── CONTEXT.md
```

---

## CONTEXT.md format

```markdown
---
name: my-context
l0: One sentence describing what this context covers.
license: MIT
metadata:
  version: "1.0.0"
  author: AuditGuard
  tags: ["pentest", "web", "owasp"]
---

## L1 — Overview

When to use this context and what it covers at a high level.

---

## L2 — Full Methodology

Complete detailed content the agent uses during the engagement.
```

---

## Frontmatter fields

| Field | Required | Description |
|---|---|---|
| `name` | yes | Matches the folder name exactly |
| `l0` | yes | One sentence shown in `list_contexts` — keep it under 120 characters |
| `license` | no | License for the context (e.g. `MIT`) |
| `metadata.version` | no | Semantic version |
| `metadata.author` | no | Author name or GitHub username |
| `metadata.tags` | no | Array of tags for filtering and discovery |

---

## The 3-tier loading system

Each context has three levels of detail. The MCP server loads the right level based on what the agent needs.

| Level | What it contains | When used |
|---|---|---|
| **L0** | One sentence from the `l0` frontmatter field | Listings, quick discovery |
| **L1** | Overview — when to use, key focus areas, high-level scope | Default load at session start |
| **L2** | Full methodology — phases, techniques, tools, commands, reporting | Loaded when the agent needs deep detail |

This tiered approach keeps token usage low — the agent only loads full content when it needs it.

---

## Writing L1 — Overview

L1 is what the agent reads first. It should answer:
- **When to use this context** — what engagement types or user requests trigger it
- **Key focus areas** — the main topics covered
- **Scope** — what's in and what's out

Keep L1 under 30 lines. It should be scannable, not exhaustive.

```markdown
## L1 — Overview

A web application penetration test assesses the security of a web app by simulating real-world attacks.

**Use this context when:**
- Starting a web application pentest engagement
- Testing authentication, session management, or authorization

**Key focus areas:** OWASP Top 10, authentication bypass, IDOR, injection, business logic.
```

---

## Writing L2 — Full Methodology

L2 is the full content. Structure it as numbered phases with clear headings.

```markdown
## L2 — Full Methodology

### Phase 1 — Reconnaissance
...

### Phase 2 — Authentication Testing
...

### Phase 3 — Reporting
...
```

**Rules for L2:**
- Use numbered phases — agents follow sequential steps better than flat prose
- Include concrete commands, payloads, and tool names
- Reference relevant skills where applicable (e.g. "use `finding-writer` skill")
- End with a reporting phase — every methodology should produce structured output

**Three sections every L2 should include:**

### 1. Concrete payloads

Don't just describe what to test — include actual test strings, commands, and tool invocations. Agents follow examples better than abstract instructions.

```markdown
### Injection Testing

Test each input with:
- `' OR '1'='1` — classic SQLi probe
- `"><img src=x onerror=alert(document.domain)>` — reflected XSS
- `{{7*7}}` — SSTI detection
```

### 2. Validation gate

Before every finding is reported, the agent should verify it is real, reproducible, and impactful. Add this as the second-to-last phase in every L2:

```markdown
### Validation Gate

Before reporting any finding, confirm:
- [ ] Reproduced in a clean session using attacker-only credentials
- [ ] Affects other users or the system — not just the tester's own account
- [ ] Impact is demonstrated, not theoretical
- [ ] Evidence captured: HTTP request/response, screenshot, or command output
- [ ] Within the agreed engagement scope
```

### 3. False positive filter

Include a short list of common false positives and noise specific to this engagement type — findings that look real but don't belong in a report. Applies equally to pentests and audits.

```markdown
### False Positive Filter

Do not report without further investigation:
- Self-XSS (payload only executes in your own browser, no impact on others)
- Missing rate limiting on non-sensitive endpoints
- Clickjacking on pages with no sensitive actions
- Informational headers (X-Powered-By, Server version) without a working exploit chain
- Theoretical vulnerabilities with no demonstrated impact
```

---

## Workflow contexts

A workflow context is a special context type that chains a methodology context with relevant skills for a specific engagement type. It gives the agent an ordered sequence of steps and suggests which skills to use at each phase.

### Key rule — skills are recommendations, never requirements

A workflow context must not create hard dependencies on skills being installed. Always frame skill references as suggestions. The agent follows the workflow whether or not the recommended skills are available.

**Wrong:**
```markdown
### Step 3 — Run jwt-cracker skill
*(required — do not proceed without it)*
```

**Correct:**
```markdown
### Step 3 — Authentication testing
If the `jwt-cracker` skill is installed, activate it now.
Otherwise, manually test JWT weaknesses following the steps below.
```

### Naming

Workflow contexts use the suffix `-workflow`: `web-app-pentest-workflow`, `api-security-review-workflow`.

### Format

```markdown
---
name: web-app-pentest-workflow
l0: Ordered workflow for web app pentests — methodology + recommended skills for each phase.
---

## L1 — Overview

Load this at the start of a web app pentest. It walks through each phase in order
and recommends skills to activate where available.

---

## L2 — Full Workflow

### Phase 1 — Reconnaissance
[Full recon methodology here — enumerate endpoints, map attack surface, identify tech stack]

### Phase 2 — Authentication testing
[Full auth testing methodology here]
Recommended skill: `jwt-cracker`

### Phase 3 — Authorization testing
[Full authz testing methodology here]
Recommended skill: `idor-hunter`

### Phase 4 — Injection testing
[Full injection methodology here — XSS, SQLi, SSTI, etc.]
Recommended skills: `xss-hunter`, `ssti-hunter`

### Phase 5 — Findings
[Reporting guidance here]
Recommended skill: `finding-writer`
```

The workflow context is self-contained — it includes the full methodology and adds skill recommendations at the relevant phases. The agent loads one context and has everything it needs.

---

## Naming conventions

- Folder and `name` field must match exactly: `web-app-pentest/` → `name: web-app-pentest`
- Use lowercase kebab-case: `cloud-audit` not `CloudAudit`
- Be descriptive: `mobile-pentest` over `mobile`
- Use the engagement type as the name, not the tool: `api-security-review` not `burp-scan`

---

## l0 field rules

The `l0` field is the single most important field — it's what agents and users see when browsing available contexts.

- Must be a single inline string — no multiline YAML (`>` or `|`)
- Under 120 characters
- Describes **what** the context covers and **what kind of engagement** it's for
- No jargon abbreviations without expansion on first use

**Wrong:**
```yaml
l0: >
  A comprehensive context for web application security testing covering
  all phases of a pentest engagement.
```

**Correct:**
```yaml
l0: Web application penetration testing context — covers recon, authentication, authorization, injection, and business logic.
```

---

## Submitting a context

1. Fork this repo
2. Create a folder named after your context
3. Add a `CONTEXT.md` following this guide
4. Open a pull request

Once merged, your context is immediately discoverable via `auditguard-context-mcp`.
