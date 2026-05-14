---
name: cloud-audit
l0: Cloud security audit context — covers AWS, Azure, and GCP misconfigurations including IAM, storage, networking, and logging.
---

## L1 — Overview

A cloud security audit reviews cloud infrastructure for misconfigurations, excessive permissions, exposed resources, and compliance gaps across AWS, Azure, and GCP.

**Use this context when:**
- Auditing AWS, Azure, or GCP environments
- Reviewing IAM policies and permissions
- Checking for publicly exposed storage (S3, Blob, GCS)
- Assessing network security groups and firewall rules
- Reviewing logging, monitoring, and incident response readiness

**Key focus areas:** IAM least privilege, public exposure, encryption at rest/transit, logging gaps, network segmentation, secrets management.

---

## L2 — Full Methodology

### Phase 1 — IAM Review

**AWS:**
- List all IAM users, roles, policies: `aws iam get-account-authorization-details`
- Check for wildcard permissions (`*`) in policies
- MFA enforcement on root and IAM users
- Unused access keys (>90 days): `aws iam generate-credential-report`
- Overly permissive roles attached to EC2/Lambda

**Azure:**
- Review role assignments at subscription level
- Check for Owner/Contributor roles assigned to external users
- Privileged Identity Management (PIM) — are privileged roles time-bound?

**GCP:**
- Check for primitive roles (Owner, Editor) on service accounts
- Review workload identity federation config

---

### Phase 2 — Storage Exposure

**AWS S3:**
- `aws s3api list-buckets` → check each for public access
- `aws s3api get-bucket-acl --bucket <name>`
- `aws s3api get-bucket-policy --bucket <name>`

**Azure Blob:**
- Check containers with `PublicAccessLevel = Blob or Container`

**GCP Cloud Storage:**
- `gsutil iam get gs://bucket-name` — check for `allUsers` bindings

---

### Phase 3 — Network Security

- Security groups with `0.0.0.0/0` on sensitive ports (22, 3389, 1433)
- VPC flow logs enabled?
- Private resources exposed via public IPs
- Unused open ports on compute instances

---

### Phase 4 — Logging & Monitoring

- CloudTrail / Activity Log / Cloud Audit Logs enabled on all regions
- Log retention period (minimum 90 days recommended)
- Alerts on root login, IAM changes, security group changes
- GuardDuty / Microsoft Defender / Security Command Center enabled?

---

### Phase 5 — Secrets Management

- Hardcoded secrets in Lambda/Cloud Functions environment variables
- Secrets in EC2 user data scripts
- Use of secrets manager vs plaintext config files
- Key rotation policy for KMS/Key Vault keys

---

### Phase 6 — Reporting

Map each finding to CIS Benchmark control or relevant compliance framework (ISO 27001, SOC2, PCI-DSS). Use `finding-writer` skill for structured output.
