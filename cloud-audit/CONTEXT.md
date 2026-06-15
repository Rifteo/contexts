---
name: cloud-audit
l0: AWS, Azure, and GCP security audit — IAM, storage exposure, networking, secrets, encryption, logging, and compliance.
license: MIT
metadata:
  version: "0.0.1"
  author: AuditGuard
  tags: ["cloud", "aws", "azure", "gcp", "iam", "misconfiguration", "compliance", "cis", "soc2", "pci-dss"]
---

## L1 — Overview

A cloud security audit reviews cloud infrastructure for misconfigurations, excessive permissions, exposed resources, and compliance gaps across AWS, Azure, and GCP.

**Use this context when:**
- Auditing AWS, Azure, or GCP environments
- Reviewing IAM policies, roles, and permissions for least-privilege violations
- Checking for publicly exposed storage (S3, Azure Blob, GCS)
- Assessing network security groups, firewall rules, and VPC configurations
- Reviewing encryption posture at rest and in transit
- Assessing logging, monitoring, and incident response readiness
- Identifying hardcoded secrets in compute, serverless, and pipeline configs
- Mapping findings to CIS Benchmarks, ISO 27001, SOC 2, or PCI-DSS

**Key focus areas:** IAM least privilege, public exposure, encryption at rest/transit, logging gaps, network segmentation, secrets management, container security, serverless misconfigurations, compliance mapping.

**Out of scope:** Application-layer vulnerabilities (use `web-app-pentest` or `api-security-review`), OS-level exploitation, social engineering.

---

## L2 — Full Methodology

### Phase 1 — Pre-Engagement & Scoping

Before any active enumeration, establish scope and access level:

- Confirm which cloud accounts/subscriptions/projects are in scope
- Confirm access level: read-only auditor role, or broader permissions?
- Document the engagement type: configuration review only, or active exploitation allowed?
- Collect cloud account IDs, organization structure, and environment names (prod/staging/dev)
- Verify that audit logging is capturing your own activity (to avoid surprises for the client)

**Tooling setup:**
```bash
# AWS — verify caller identity before anything else
aws sts get-caller-identity

# Azure — confirm active subscription
az account show
az account list --output table

# GCP — confirm active project
gcloud config list
gcloud projects list
```

---

### Phase 2 — IAM & Identity Review

This is the highest-priority phase. IAM misconfigurations are the root cause of most cloud breaches.

#### AWS IAM

**Enumerate the full IAM posture:**
```bash
# Full account authorization details — users, groups, roles, policies
aws iam get-account-authorization-details --output json > iam_details.json

# List all IAM users
aws iam list-users --output table

# List all IAM roles
aws iam list-roles --output table

# List all customer-managed policies
aws iam list-policies --scope Local --output table

# Generate credential report (access key age, MFA status, password last used)
aws iam generate-credential-report
aws iam get-credential-report --output text --query Content | base64 -d > credential_report.csv
```

**Check for wildcard permissions (`*`):**
```bash
# Find policies with Action: * or Resource: *
aws iam get-account-authorization-details | \
  python3 -c "
import json, sys
data = json.load(sys.stdin)
for policy in data.get('Policies', []):
    for version in policy.get('PolicyVersionList', []):
        if version.get('IsDefaultVersion'):
            doc = version['Document']
            stmts = doc.get('Statement', [])
            if isinstance(stmts, dict): stmts = [stmts]
            for s in stmts:
                actions = s.get('Action', [])
                resources = s.get('Resource', [])
                if '*' in actions or '*' in resources:
                    print(f\"[WILDCARD] Policy: {policy['PolicyName']}\")
"
```

**MFA enforcement:**
```bash
# Check root MFA
aws iam get-account-summary | grep -i mfa

# Check per-user MFA devices
aws iam list-users --query 'Users[*].UserName' --output text | \
  xargs -I{} sh -c 'echo "User: {}"; aws iam list-mfa-devices --user-name {}'

# Users with console access but no MFA
aws iam list-users --output json | \
  python3 -c "
import json, sys, subprocess
users = json.load(sys.stdin)['Users']
for u in users:
    mfa = json.loads(subprocess.check_output(['aws','iam','list-mfa-devices','--user-name',u['UserName']]))
    if not mfa['MFADevices']:
        print(f\"[NO MFA] {u['UserName']}\")
"
```

**Unused access keys (>90 days):**
```bash
# From the credential report — check access_key_1_last_used_date column
# Keys unused for >90 days should be disabled/deleted
awk -F',' 'NR>1 && $11 != "N/A" && $11 != "no_information" {
  cmd = "date -d \""$11"\" +%s"; cmd | getline key_ts; close(cmd)
  now = systime()
  diff = (now - key_ts) / 86400
  if (diff > 90) print "[STALE KEY] User: "$1" Key1 last used: "$11" ("int(diff)" days ago)"
}' credential_report.csv
```

**Overly permissive roles on compute:**
```bash
# List EC2 instance profiles and their attached roles
aws ec2 describe-instances --query \
  'Reservations[*].Instances[*].[InstanceId,IamInstanceProfile.Arn]' \
  --output table

# List Lambda functions and their execution roles
aws lambda list-functions --query \
  'Functions[*].[FunctionName,Role]' --output table

# For each role, get attached policies and inline policies
aws iam list-attached-role-policies --role-name <ROLE_NAME>
aws iam list-role-policies --role-name <ROLE_NAME>
```

**Cross-account trust relationships:**
```bash
# Find roles with external trust (Principal not in your account)
aws iam list-roles --output json | python3 -c "
import json, sys
roles = json.load(sys.stdin)['Roles']
account_id = '<YOUR_ACCOUNT_ID>'
for r in roles:
    policy = r['AssumeRolePolicyDocument']
    stmts = policy.get('Statement', [])
    for s in stmts:
        principal = s.get('Principal', {})
        aws = principal.get('AWS', '') if isinstance(principal, dict) else str(principal)
        if isinstance(aws, list): aws = ' '.join(aws)
        if aws and account_id not in aws and aws != '*':
            print(f\"[CROSS-ACCOUNT TRUST] Role: {r['RoleName']} → {aws}\")
        elif aws == '*':
            print(f\"[PUBLIC TRUST] Role: {r['RoleName']} → Anyone!\")
"
```

**Password policy:**
```bash
aws iam get-account-password-policy
# Check: MinimumPasswordLength >= 14, RequireUppercase, RequireLowercase,
#         RequireNumbers, RequireSymbols, MaxPasswordAge <= 90,
#         PasswordReusePrevention >= 24
```

#### Azure IAM

```bash
# List all role assignments at subscription scope
az role assignment list --all --output table

# Find Owner/Contributor/User Access Administrator assignments
az role assignment list --all | \
  python3 -c "
import json, sys
assignments = json.load(sys.stdin)
high_priv = ['Owner','Contributor','User Access Administrator']
for a in assignments:
    if a['roleDefinitionName'] in high_priv:
        print(f\"[HIGH PRIV] {a['roleDefinitionName']} → {a['principalName']} ({a['principalType']}) on {a['scope']}\")
"

# Check for external/guest users with elevated roles
az ad user list --filter "userType eq 'Guest'" --output table

# List service principals with high-privilege roles
az role assignment list --all --query \
  "[?principalType=='ServicePrincipal'].[roleDefinitionName,principalName,scope]" \
  --output table

# Check Privileged Identity Management (PIM) — are privileged roles time-bound?
az rest --method GET \
  --url "https://management.azure.com/subscriptions/<SUB_ID>/providers/Microsoft.Authorization/roleEligibilitySchedules?api-version=2020-10-01"

# List custom role definitions
az role definition list --custom-role-only true --output table
```

#### GCP IAM

```bash
# List all IAM bindings at project level
gcloud projects get-iam-policy <PROJECT_ID> --format=json > gcp_iam.json

# Find primitive roles (Owner, Editor, Viewer) — these are overly broad
python3 -c "
import json
with open('gcp_iam.json') as f:
    policy = json.load(f)
primitive = ['roles/owner','roles/editor','roles/viewer']
for b in policy.get('bindings', []):
    if b['role'] in primitive:
        for m in b['members']:
            print(f\"[PRIMITIVE ROLE] {b['role']} → {m}\")
"

# Check for allUsers or allAuthenticatedUsers bindings (public access)
python3 -c "
import json
with open('gcp_iam.json') as f:
    policy = json.load(f)
for b in policy.get('bindings', []):
    for m in b['members']:
        if m in ['allUsers', 'allAuthenticatedUsers']:
            print(f\"[PUBLIC BINDING] {b['role']} → {m}\")
"

# List service accounts
gcloud iam service-accounts list --format=json

# Check service account key age (keys older than 90 days)
gcloud iam service-accounts list --format="value(email)" | while read sa; do
  gcloud iam service-accounts keys list --iam-account="$sa" \
    --format="table(name,validAfterTime,keyType)" 2>/dev/null
done

# Check workload identity federation config
gcloud iam workload-identity-pools list --location=global

# Check org-level IAM policy
gcloud organizations get-iam-policy <ORG_ID> --format=json
```

---

### Phase 3 — Storage Exposure

Publicly readable or writable storage is one of the most common and severe cloud misconfigurations.

#### AWS S3

```bash
# List all buckets
aws s3api list-buckets --output table

# For each bucket — check public access block settings
for bucket in $(aws s3api list-buckets --query 'Buckets[*].Name' --output text); do
  echo "=== $bucket ==="
  aws s3api get-public-access-block --bucket "$bucket" 2>/dev/null || \
    echo "[WARNING] No public access block configured"
done

# Check bucket ACL (look for AllUsers or AuthenticatedUsers grantees)
aws s3api get-bucket-acl --bucket <BUCKET_NAME>

# Check bucket policy (look for Principal: "*")
aws s3api get-bucket-policy --bucket <BUCKET_NAME> 2>/dev/null | \
  python3 -c "
import json, sys
policy = json.loads(json.load(sys.stdin)['Policy'])
for s in policy.get('Statement', []):
    p = s.get('Principal', '')
    if p == '*' or (isinstance(p, dict) and p.get('AWS') == '*'):
        print(f\"[PUBLIC POLICY] Effect: {s['Effect']}, Action: {s.get('Action')}\")
"

# Check if static website hosting is enabled (public by design)
aws s3api get-bucket-website --bucket <BUCKET_NAME> 2>/dev/null

# Check server-side encryption default
aws s3api get-bucket-encryption --bucket <BUCKET_NAME> 2>/dev/null || \
  echo "[NO ENCRYPTION] Bucket has no default encryption"

# Check versioning
aws s3api get-bucket-versioning --bucket <BUCKET_NAME>

# Check replication (cross-region/cross-account)
aws s3api get-bucket-replication --bucket <BUCKET_NAME> 2>/dev/null

# Check logging
aws s3api get-bucket-logging --bucket <BUCKET_NAME>

# Automated mass check with trufflehog for exposed secrets in public buckets
# trufflehog s3 --bucket <BUCKET_NAME>
```

#### Azure Blob Storage

```bash
# List all storage accounts
az storage account list --output table

# Check for public access allowed at account level
az storage account list | python3 -c "
import json, sys
accounts = json.load(sys.stdin)
for a in accounts:
    public = a.get('allowBlobPublicAccess', True)
    if public:
        print(f\"[PUBLIC BLOB] {a['name']} in {a['resourceGroup']}\")
"

# For each storage account, list containers with public access
for account in $(az storage account list --query '[*].name' --output tsv); do
  key=$(az storage account keys list --account-name "$account" --query '[0].value' --output tsv 2>/dev/null)
  if [ -n "$key" ]; then
    az storage container list --account-name "$account" --account-key "$key" \
      --query "[?properties.publicAccess!='None'].[name,properties.publicAccess]" \
      --output table 2>/dev/null | grep -v "^$" | \
      awk -v acct="$account" '{print "[PUBLIC CONTAINER] " acct " / " $0}'
  fi
done

# Check storage account network rules (is it locked to specific VNets/IPs?)
az storage account show --name <ACCOUNT_NAME> --query networkRuleSet

# Check HTTPS only
az storage account list --query "[?enableHttpsTrafficOnly==\`false\`].[name,resourceGroup]" --output table

# Check minimum TLS version
az storage account list --query "[?minimumTlsVersion!='TLS1_2'].[name,minimumTlsVersion]" --output table
```

#### GCP Cloud Storage

```bash
# List all buckets in project
gsutil ls

# Check IAM policy on each bucket (look for allUsers or allAuthenticatedUsers)
for bucket in $(gsutil ls); do
  echo "=== $bucket ==="
  gsutil iam get "$bucket" | python3 -c "
import json, sys
policy = json.load(sys.stdin)
for b in policy.get('bindings', []):
    for m in b['members']:
        if m in ['allUsers', 'allAuthenticatedUsers']:
            print(f\"[PUBLIC] Role: {b['role']} → {m}\")
"
done

# Check bucket ACLs
gsutil acl get gs://<BUCKET_NAME>

# Check default object ACL
gsutil defacl get gs://<BUCKET_NAME>

# Check logging
gsutil logging get gs://<BUCKET_NAME>

# Check versioning
gsutil versioning get gs://<BUCKET_NAME>

# Check uniform bucket-level access (preferred — disables legacy ACLs)
gsutil uniformbucketlevelaccess get gs://<BUCKET_NAME>
```

---

### Phase 4 — Network Security

#### AWS

```bash
# List all VPCs
aws ec2 describe-vpcs --output table

# List all security groups with rules open to 0.0.0.0/0 or ::/0
aws ec2 describe-security-groups --output json | python3 -c "
import json, sys
sgs = json.load(sys.stdin)['SecurityGroups']
sensitive_ports = [22, 3389, 1433, 3306, 5432, 27017, 6379, 9200, 8080, 8443]
for sg in sgs:
    for rule in sg.get('IpPermissions', []):
        from_port = rule.get('FromPort', 0)
        to_port = rule.get('ToPort', 65535)
        for cidr in rule.get('IpRanges', []):
            if cidr['CidrIp'] in ['0.0.0.0/0']:
                for p in sensitive_ports:
                    if from_port <= p <= to_port:
                        print(f\"[OPEN TO WORLD] SG: {sg['GroupId']} ({sg['GroupName']}) Port: {p}\")
        for cidr in rule.get('Ipv6Ranges', []):
            if cidr['CidrIpv6'] in ['::/0']:
                for p in sensitive_ports:
                    if from_port <= p <= to_port:
                        print(f\"[OPEN TO WORLD IPv6] SG: {sg['GroupId']} Port: {p}\")
"

# Check VPC Flow Logs — are they enabled on all VPCs?
aws ec2 describe-flow-logs --output table
# Cross-check against all VPC IDs:
aws ec2 describe-vpcs --query 'Vpcs[*].VpcId' --output text | tr '\t' '\n' | while read vpc; do
  logs=$(aws ec2 describe-flow-logs --filter "Name=resource-id,Values=$vpc" --query 'FlowLogs[*].FlowLogId' --output text)
  [ -z "$logs" ] && echo "[NO FLOW LOGS] VPC: $vpc"
done

# Check NACLs for overly permissive rules
aws ec2 describe-network-acls --output json | python3 -c "
import json, sys
nacls = json.load(sys.stdin)['NetworkAcls']
for n in nacls:
    for e in n.get('Entries', []):
        if e.get('CidrBlock') == '0.0.0.0/0' and e.get('RuleAction') == 'allow' and not e.get('Egress'):
            print(f\"[NACL OPEN] NACL: {n['NetworkAclId']} Rule: {e['RuleNumber']} → All traffic allowed inbound\")
"

# Public EC2 instances
aws ec2 describe-instances --query \
  'Reservations[*].Instances[?PublicIpAddress!=null].[InstanceId,PublicIpAddress,Tags[?Key==`Name`].Value|[0]]' \
  --output table

# Elastic IPs — are they all attached?
aws ec2 describe-addresses --output table

# Internet Gateways per VPC
aws ec2 describe-internet-gateways --output table

# Check for default VPCs (should be deleted in prod)
aws ec2 describe-vpcs --filters "Name=is-default,Values=true" --output table

# Check RDS instances not in a VPC or publicly accessible
aws rds describe-db-instances --query \
  'DBInstances[*].[DBInstanceIdentifier,PubliclyAccessible,DBSubnetGroup.VpcId]' \
  --output table

# FIX: aws es is deprecated — use aws opensearch instead
# List OpenSearch domain names then describe each one
aws opensearch list-domain-names --output text --query 'DomainNames[*].DomainName' | \
  tr '\t' '\n' | while read domain; do
    aws opensearch describe-domain --domain-name "$domain" \
      --query 'DomainStatus.[DomainName,Endpoint,AccessPolicies]' --output text
done
```

#### Azure

```bash
# List all Network Security Groups
az network nsg list --output table

# Find NSG rules allowing any source to sensitive ports
az network nsg list --query '[*].name' --output tsv | while read nsg; do
  rg=$(az network nsg show --name "$nsg" --query resourceGroup --output tsv 2>/dev/null)
  az network nsg rule list --nsg-name "$nsg" --resource-group "$rg" \
    --query "[?access=='Allow' && sourceAddressPrefix=='*'].[name,destinationPortRange,direction]" \
    --output table 2>/dev/null | grep -v "^$" | awk -v n="$nsg" '{print "[NSG OPEN] " n ": " $0}'
done

# Check for VMs with public IPs
az vm list-ip-addresses --output table

# Check Azure Firewall is deployed
az network firewall list --output table

# Check VNet peering (unexpected cross-VNet connectivity)
az network vnet peering list --vnet-name <VNET> --resource-group <RG> --output table

# Check DDoS protection plan
az network ddos-protection list --output table

# Check Azure Bastion for secure RDP/SSH access
az network bastion list --output table
```

#### GCP

```bash
# List all firewall rules open to 0.0.0.0/0
gcloud compute firewall-rules list --format=json | python3 -c "
import json, sys
rules = json.load(sys.stdin)
for r in rules:
    if '0.0.0.0/0' in r.get('sourceRanges', []):
        for allow in r.get('allowed', []):
            ports = allow.get('ports', ['ALL'])
            print(f\"[OPEN TO WORLD] Rule: {r['name']} Proto: {allow['IPProtocol']} Ports: {ports}\")
"

# List compute instances with external IPs
gcloud compute instances list --format=\
"table(name,zone,networkInterfaces[0].accessConfigs[0].natIP)"

# Check VPC Flow Logs enabled on subnets
gcloud compute networks subnets list --format=json | python3 -c "
import json, sys
subnets = json.load(sys.stdin)
for s in subnets:
    if not s.get('enableFlowLogs', False):
        print(f\"[NO FLOW LOGS] Subnet: {s['name']} in {s['region']}\")
"

# Check for default network (should be deleted)
gcloud compute networks list --filter="name=default"

# Check Cloud Armor security policies
gcloud compute security-policies list
```

---

### Phase 5 — Encryption & Data Protection

#### AWS

```bash
# Check EBS volumes not encrypted
aws ec2 describe-volumes \
  --query 'Volumes[?Encrypted==`false`].[VolumeId,State,Size]' \
  --output table

# Check default EBS encryption per region
aws ec2 get-ebs-encryption-by-default

# Check RDS encryption
aws rds describe-db-instances \
  --query 'DBInstances[?StorageEncrypted==`false`].[DBInstanceIdentifier,DBInstanceClass]' \
  --output table

# Check S3 bucket encryption (see Phase 3 commands)

# Check KMS key rotation
aws kms list-keys --output text --query 'Keys[*].KeyId' | tr '\t' '\n' | while read key; do
  rotation=$(aws kms get-key-rotation-status --key-id "$key" --query RotationEnabled --output text)
  [ "$rotation" = "False" ] && echo "[NO ROTATION] KMS Key: $key"
done

# Check Secrets Manager secrets with no rotation configured
aws secretsmanager list-secrets --output json | python3 -c "
import json, sys
secrets = json.load(sys.stdin)['SecretList']
for s in secrets:
    if not s.get('RotationEnabled', False):
        print(f\"[NO ROTATION] Secret: {s['Name']}\")
"

# Check ELB/ALB listener protocols — are any using HTTP instead of HTTPS?
aws elbv2 describe-listeners --load-balancer-arn <ALB_ARN> \
  --query 'Listeners[?Protocol==`HTTP`].[LoadBalancerArn,Port]' --output table

# Check CloudFront distributions for HTTPS enforcement
aws cloudfront list-distributions --query \
  'DistributionList.Items[?DefaultCacheBehavior.ViewerProtocolPolicy==`allow-all`].[Id,DomainName]' \
  --output table
```

#### Azure

```bash
# Check unencrypted managed disks
az disk list --query "[?encryptionSettingsCollection.enabled!=\`true\`].[name,resourceGroup]" --output table

# Check Azure SQL databases with TDE disabled
az sql db list --server <SERVER> --resource-group <RG> \
  --query "[?transparentDataEncryption.status!='Enabled'].[name]" --output table

# Check Key Vault key rotation policies
az keyvault key list --vault-name <VAULT_NAME> \
  --query "[*].[kid,attributes.expires]" --output table

# Check storage account encryption with customer-managed keys
az storage account list \
  --query "[?encryption.keySource!='Microsoft.Keyvault'].[name,encryption.keySource]" \
  --output table
```

#### GCP

```bash
# Check disks without customer-managed encryption keys (CMEK)
gcloud compute disks list --format=json | python3 -c "
import json, sys
disks = json.load(sys.stdin)
for d in disks:
    if not d.get('diskEncryptionKey', {}).get('kmsKeyName'):
        print(f\"[NO CMEK] Disk: {d['name']}\")
"

# Check Cloud SQL instances with no encryption
gcloud sql instances list --format=json | python3 -c "
import json, sys
instances = json.load(sys.stdin)
for i in instances:
    ssl = i.get('settings', {}).get('ipConfiguration', {}).get('requireSsl', False)
    if not ssl:
        print(f\"[NO SSL REQUIRED] SQL Instance: {i['name']}\")
"

# Check KMS key rotation
gcloud kms keys list --location=global --keyring=<KEYRING> \
  --format="table(name,rotationPeriod,nextRotationTime)"
```

---

### Phase 6 — Logging & Monitoring

Missing or incomplete logging is a critical gap — it means breaches go undetected.

#### AWS

```bash
# Check CloudTrail trails — all regions covered?
aws cloudtrail describe-trails --include-shadow-trails true --output json | python3 -c "
import json, sys
trails = json.load(sys.stdin)['trailList']
for t in trails:
    print(f\"Trail: {t['Name']} | Multi-region: {t.get('IsMultiRegionTrail')} | Log validation: {t.get('LogFileValidationEnabled')} | S3: {t['S3BucketName']}\")
"

# Check if CloudTrail logging is active
aws cloudtrail get-trail-status --name <TRAIL_NAME> --query 'IsLogging'

# Check CloudTrail log file validation
aws cloudtrail describe-trails --query \
  'trailList[?LogFileValidationEnabled==`false`].[Name]' --output table

# Check if management events are logged
aws cloudtrail get-event-selectors --trail-name <TRAIL_NAME>

# Check GuardDuty enabled in all regions
for region in $(aws ec2 describe-regions --query 'Regions[*].RegionName' --output text); do
  status=$(aws guardduty list-detectors --region "$region" --query 'DetectorIds' --output text 2>/dev/null)
  [ -z "$status" ] && echo "[GUARDDUTY DISABLED] Region: $region"
done

# Check AWS Config enabled
aws configservice describe-configuration-recorders --output table
aws configservice describe-delivery-channels --output table

# Check Security Hub enabled
aws securityhub get-enabled-standards --output table 2>/dev/null || \
  echo "[SECURITY HUB DISABLED]"

# Check CloudWatch alarms for critical events
aws cloudwatch describe-alarms --output table
# Should have alarms for: root login, IAM changes, security group changes,
# CloudTrail config changes, failed console logins

# Check SNS topics (alert destinations)
aws sns list-topics --output table

# Check CloudTrail log retention
aws s3api get-bucket-lifecycle-configuration --bucket <CLOUDTRAIL_BUCKET>
```

#### Azure

```bash
# FIX: Use subscription-level diagnostic settings (not resource-level)
az monitor diagnostic-settings subscription list --output table

# Check if Activity Log retention >= 90 days
az monitor log-profiles list --output json | python3 -c "
import json, sys
profiles = json.load(sys.stdin)
for p in profiles:
    days = p.get('retentionPolicy', {}).get('days', 0)
    enabled = p.get('retentionPolicy', {}).get('enabled', False)
    if not enabled or days < 90:
        print(f\"[SHORT RETENTION] Profile: {p['name']} Days: {days} Enabled: {enabled}\")
"

# Check Microsoft Defender for Cloud plans
az security pricing list --output table

# Check Log Analytics workspace exists
az monitor log-analytics workspace list --output table

# FIX: az sentinel is not a built-in CLI command — check for Microsoft Sentinel via Log Analytics
# Sentinel is deployed on top of a Log Analytics workspace; verify the workspace exists
# and confirm Sentinel is enabled via the portal or REST API
az monitor log-analytics workspace list \
  --query "[*].[name,resourceGroup,location,provisioningState]" --output table

# Check alerts configured in Defender for Cloud
az security alert list --output table
```

#### GCP

```bash
# Check Cloud Audit Logs configuration per service
gcloud projects get-iam-policy <PROJECT_ID> --format=json | python3 -c "
import json, sys
policy = json.load(sys.stdin)
for rule in policy.get('auditConfigs', []):
    print(f\"Service: {rule['service']}\")
    for log in rule.get('auditLogConfigs', []):
        print(f\"  Log type: {log['logType']}\")
"
# Should see DATA_READ, DATA_WRITE, ADMIN_READ for critical services

# Check Cloud Logging export sinks
gcloud logging sinks list --format=table

# Check Security Command Center enabled
gcloud scc findings list --organization=<ORG_ID> 2>/dev/null || \
  echo "[SCC] Check manually in Cloud Console"

# FIX: Use stable monitoring command (no alpha prefix needed)
gcloud monitoring alert-policies list --format=table 2>/dev/null

# Check log retention (default is 30 days — check for longer retention buckets)
gcloud logging buckets list --location=global
```

---

### Phase 7 — Secrets Management

Hardcoded or improperly stored secrets are consistently among the top findings in cloud audits.

#### AWS

```bash
# Check Lambda function environment variables for plaintext secrets
aws lambda list-functions --query 'Functions[*].FunctionName' --output text | \
  tr '\t' '\n' | while read fn; do
    env=$(aws lambda get-function-configuration --function-name "$fn" \
      --query 'Environment.Variables' --output json 2>/dev/null)
    echo "$env" | python3 -c "
import json, sys, re
env = json.load(sys.stdin)
if not env: sys.exit()
secret_patterns = re.compile(r'(password|secret|key|token|credential|pwd|passwd|api_key|private)', re.IGNORECASE)
for k, v in env.items():
    if secret_patterns.search(k):
        print(f'[PLAINTEXT SECRET] Function env var: {k}')
" 2>/dev/null
done

# Check EC2 instance user data for hardcoded secrets
aws ec2 describe-instances --query 'Reservations[*].Instances[*].InstanceId' \
  --output text | tr '\t' '\n' | while read id; do
    userdata=$(aws ec2 describe-instance-attribute \
      --instance-id "$id" --attribute userData \
      --query 'UserData.Value' --output text 2>/dev/null | base64 -d 2>/dev/null)
    echo "$userdata" | grep -iE '(password|secret|key|token|credential)' | \
      sed "s/^/[USER DATA SECRET] Instance $id: /"
done

# Check Secrets Manager vs SSM Parameter Store usage
aws secretsmanager list-secrets --output table
aws ssm describe-parameters --output table

# Check SSM parameters stored as String (not SecureString)
aws ssm describe-parameters --output json | python3 -c "
import json, sys
params = json.load(sys.stdin)['Parameters']
import re
secret_patterns = re.compile(r'(password|secret|key|token|credential)', re.IGNORECASE)
for p in params:
    if p['Type'] != 'SecureString' and secret_patterns.search(p['Name']):
        print(f\"[UNENCRYPTED PARAM] {p['Name']} (Type: {p['Type']})\")
"

# Check for secrets in CloudFormation templates (stack parameters/outputs)
aws cloudformation list-stacks --query \
  'StackSummaries[?StackStatus!=`DELETE_COMPLETE`].StackName' --output text | \
  tr '\t' '\n' | while read stack; do
    aws cloudformation describe-stacks --stack-name "$stack" \
      --query 'Stacks[0].Outputs[*].[OutputKey,OutputValue]' --output text 2>/dev/null | \
      grep -iE '(password|secret|key|token)' | \
      sed "s/^/[STACK OUTPUT SECRET] $stack: /"
done
```

#### Azure

```bash
# Check Key Vault secrets, keys, and certificates
az keyvault list --output table

# List secrets in a vault (values not shown without explicit get)
az keyvault secret list --vault-name <VAULT_NAME> --output table

# Check for secrets expiring soon or expired
az keyvault secret list --vault-name <VAULT_NAME> --output json | python3 -c "
import json, sys
from datetime import datetime, timezone
secrets = json.load(sys.stdin)
now = datetime.now(timezone.utc)
for s in secrets:
    exp = s.get('attributes', {}).get('expires')
    if exp:
        exp_dt = datetime.fromisoformat(exp.replace('Z', '+00:00'))
        days = (exp_dt - now).days
        if days < 30:
            print(f\"[EXPIRING] Secret: {s['id'].split('/')[-1]} Expires in {days} days\")
"

# Check App Service/Function App configuration for plaintext secrets
az webapp config appsettings list --name <APP_NAME> --resource-group <RG> \
  --output json | python3 -c "
import json, sys, re
settings = json.load(sys.stdin)
pattern = re.compile(r'(password|secret|key|token|credential)', re.IGNORECASE)
for s in settings:
    if pattern.search(s['name']) and not s['value'].startswith('@Microsoft.KeyVault'):
        print(f\"[PLAINTEXT SECRET] AppSetting: {s['name']}\")
"
```

#### GCP

```bash
# List Secret Manager secrets
gcloud secrets list --format=table

# Check for secrets not accessed recently (potentially orphaned)
gcloud secrets list --format=json | python3 -c "
import json, sys
from datetime import datetime, timezone
secrets = json.load(sys.stdin)
for s in secrets:
    labels = s.get('labels', {})
    print(f\"Secret: {s['name'].split('/')[-1]} Created: {s.get('createTime', 'unknown')}\")
"

# Check Cloud Functions environment variables
gcloud functions list --format=json | python3 -c "
import json, sys, re
funcs = json.load(sys.stdin)
pattern = re.compile(r'(password|secret|key|token|credential)', re.IGNORECASE)
for f in funcs:
    env = f.get('environmentVariables', {})
    for k in env:
        if pattern.search(k):
            print(f\"[PLAINTEXT SECRET] Function: {f['name']} EnvVar: {k}\")
"
```

---

### Phase 8 — Compute & Container Security

#### AWS EC2 & ECS/EKS

```bash
# Check for EC2 instances with IMDSv1 (allows SSRF → metadata access)
aws ec2 describe-instances --output json | python3 -c "
import json, sys
reservations = json.load(sys.stdin)['Reservations']
for r in reservations:
    for i in r['Instances']:
        imds = i.get('MetadataOptions', {})
        if imds.get('HttpTokens') != 'required':
            name = next((t['Value'] for t in i.get('Tags', []) if t['Key']=='Name'), i['InstanceId'])
            print(f\"[IMDSv1 ENABLED] Instance: {name} ({i['InstanceId']})\")
"

# Check EKS cluster — public API endpoint?
aws eks list-clusters --output text | tr '\t' '\n' | while read cluster; do
  endpoint_access=$(aws eks describe-cluster --name "$cluster" \
    --query 'cluster.resourcesVpcConfig.[endpointPublicAccess,endpointPrivateAccess]' \
    --output text)
  echo "Cluster: $cluster | Public/Private endpoint: $endpoint_access"
done

# Check EKS node groups for public nodes
aws eks list-nodegroups --cluster-name <CLUSTER_NAME> --output text | \
  tr '\t' '\n' | while read ng; do
    aws eks describe-nodegroup --cluster-name <CLUSTER_NAME> --nodegroup-name "$ng" \
      --query 'nodegroup.amiType' --output text
done

# Check ECS tasks running as privileged
aws ecs list-task-definitions --output text | tr '\t' '\n' | while read td; do
  privileged=$(aws ecs describe-task-definition --task-definition "$td" \
    --query 'taskDefinition.containerDefinitions[?privileged==`true`].name' \
    --output text 2>/dev/null)
  [ -n "$privileged" ] && echo "[PRIVILEGED CONTAINER] TaskDef: $td Containers: $privileged"
done

# Check ECR image scan findings
aws ecr describe-repositories --output text --query 'repositories[*].repositoryName' | \
  tr '\t' '\n' | while read repo; do
    aws ecr describe-image-scan-findings --repository-name "$repo" \
      --image-id imageTag=latest \
      --query 'imageScanFindings.findingSeverityCounts' \
      --output table 2>/dev/null
done
```

#### Kubernetes (EKS/AKS/GKE)

```bash
# Check RBAC — cluster-admin bindings
kubectl get clusterrolebindings -o json | python3 -c "
import json, sys
bindings = json.load(sys.stdin)['items']
for b in bindings:
    if b.get('roleRef', {}).get('name') == 'cluster-admin':
        subjects = b.get('subjects', [])
        for s in subjects:
            print(f\"[CLUSTER-ADMIN] {s.get('kind')}: {s.get('name')} ({s.get('namespace', 'cluster-wide')})\")
"

# Check for pods running as root
kubectl get pods --all-namespaces -o json | python3 -c "
import json, sys
pods = json.load(sys.stdin)['items']
for p in pods:
    ns = p['metadata']['namespace']
    name = p['metadata']['name']
    for c in p.get('spec', {}).get('containers', []):
        sc = c.get('securityContext', {})
        psc = p.get('spec', {}).get('securityContext', {})
        run_as = sc.get('runAsUser', psc.get('runAsUser', None))
        if run_as == 0 or run_as is None:
            print(f\"[ROOT/UNKNOWN UID] {ns}/{name} container: {c['name']}\")
"

# Check privileged containers
kubectl get pods --all-namespaces -o json | python3 -c "
import json, sys
pods = json.load(sys.stdin)['items']
for p in pods:
    ns = p['metadata']['namespace']
    name = p['metadata']['name']
    for c in p.get('spec', {}).get('containers', []):
        if c.get('securityContext', {}).get('privileged'):
            print(f\"[PRIVILEGED POD] {ns}/{name} container: {c['name']}\")
"

# Check for host network/PID/IPC access
kubectl get pods --all-namespaces -o json | python3 -c "
import json, sys
pods = json.load(sys.stdin)['items']
for p in pods:
    ns = p['metadata']['namespace']
    name = p['metadata']['name']
    spec = p.get('spec', {})
    if spec.get('hostNetwork'): print(f'[HOST NETWORK] {ns}/{name}')
    if spec.get('hostPID'): print(f'[HOST PID] {ns}/{name}')
    if spec.get('hostIPC'): print(f'[HOST IPC] {ns}/{name}')
"

# Check for default service account token auto-mount
kubectl get pods --all-namespaces -o json | python3 -c "
import json, sys
pods = json.load(sys.stdin)['items']
for p in pods:
    ns = p['metadata']['namespace']
    name = p['metadata']['name']
    automount = p.get('spec', {}).get('automountServiceAccountToken', True)
    if automount:
        print(f'[SA TOKEN MOUNTED] {ns}/{name}')
"

# Check for pods without resource limits
kubectl get pods --all-namespaces -o json | python3 -c "
import json, sys
pods = json.load(sys.stdin)['items']
for p in pods:
    ns = p['metadata']['namespace']
    name = p['metadata']['name']
    for c in p.get('spec', {}).get('containers', []):
        if not c.get('resources', {}).get('limits'):
            print(f'[NO RESOURCE LIMITS] {ns}/{name} container: {c[\"name\"]}')
"

# Check PodSecurityPolicy / OPA Gatekeeper / Kyverno policies
kubectl get psp 2>/dev/null || echo "PSP deprecated — check for Gatekeeper/Kyverno"
kubectl get constrainttemplate 2>/dev/null
kubectl get clusterpolicy 2>/dev/null

# Check network policies — is there a default deny?
kubectl get networkpolicies --all-namespaces -o table
```

---

### Phase 9 — Serverless & PaaS Security

#### AWS Lambda

```bash
# Check Lambda functions with public resource-based policies
aws lambda list-functions --query 'Functions[*].FunctionName' --output text | \
  tr '\t' '\n' | while read fn; do
    policy=$(aws lambda get-policy --function-name "$fn" --output json 2>/dev/null)
    echo "$policy" | python3 -c "
import json, sys
try:
    p = json.loads(json.load(sys.stdin)['Policy'])
    for s in p.get('Statement', []):
        principal = s.get('Principal', '')
        if principal == '*' or (isinstance(principal, dict) and principal.get('AWS') == '*'):
            print(f'[PUBLIC LAMBDA] $fn: Effect={s[\"Effect\"]} Action={s.get(\"Action\")}')
except: pass
" 2>/dev/null
done

# Check Lambda runtime versions (look for deprecated/EOL runtimes)
aws lambda list-functions \
  --query 'Functions[*].[FunctionName,Runtime]' --output table

# FIX: Expanded deprecated runtime list
# Deprecated runtimes to flag:
#   python2.7, python3.6, python3.7
#   nodejs10.x, nodejs12.x, nodejs14.x
#   dotnetcore2.1, dotnetcore3.1
#   ruby2.5, java8 (non-al2 variant)
aws lambda list-functions --output json | python3 -c "
import json, sys
fns = json.load(sys.stdin)['Functions']
deprecated = {
    'python2.7', 'python3.6', 'python3.7',
    'nodejs10.x', 'nodejs12.x', 'nodejs14.x',
    'dotnetcore2.1', 'dotnetcore3.1',
    'ruby2.5', 'java8'
}
for f in fns:
    runtime = f.get('Runtime', '')
    if runtime in deprecated:
        print(f\"[DEPRECATED RUNTIME] {f['FunctionName']}: {runtime}\")
"

# Check VPC attachment (is Lambda isolated from internet?)
aws lambda list-functions --output json | python3 -c "
import json, sys
fns = json.load(sys.stdin)['Functions']
for f in fns:
    if not f.get('VpcConfig', {}).get('VpcId'):
        print(f\"[NO VPC] Lambda: {f['FunctionName']} — can reach internet directly\")
"

# Check Lambda concurrency limits (no throttling = DoS risk)
aws lambda list-functions --output json | python3 -c "
import json, sys
fns = json.load(sys.stdin)['Functions']
for f in fns:
    if not f.get('ReservedConcurrentExecutions'):
        print(f\"[NO CONCURRENCY LIMIT] Lambda: {f['FunctionName']}\")
"
```

#### Azure Functions & App Service

```bash
# Check if App Service authentication is enabled
az webapp auth show --name <APP_NAME> --resource-group <RG> --output table

# Check for HTTPS-only enforcement
az webapp list --query "[?httpsOnly==\`false\`].[name,resourceGroup]" --output table

# Check minimum TLS version on App Service
az webapp list --query "[?siteConfig.minTlsVersion!='1.2'].[name,siteConfig.minTlsVersion]" --output table

# Check for client certificate requirement on APIs
az webapp show --name <APP_NAME> --resource-group <RG> \
  --query clientCertEnabled --output tsv
```

#### GCP Cloud Functions & Cloud Run

```bash
# Check Cloud Functions — are they publicly invokable?
gcloud functions get-iam-policy <FUNCTION_NAME> --region=<REGION> | \
  grep -A2 "allUsers\|allAuthenticatedUsers"

# Check Cloud Run services — are they publicly accessible?
gcloud run services list --format=json | python3 -c "
import json, sys
services = json.load(sys.stdin)
for s in services:
    annotations = s.get('metadata', {}).get('annotations', {})
    no_auth = annotations.get('run.googleapis.com/ingress-status', '')
    iam = s.get('status', {}).get('conditions', [])
    print(f\"Service: {s['metadata']['name']} Ingress: {annotations.get('run.googleapis.com/ingress', 'all')}\")
"

# Check Cloud Run IAM for allUsers
gcloud run services get-iam-policy <SERVICE_NAME> --region=<REGION>
```

---

### Phase 10 — Compliance & Benchmark Mapping

For each finding, map to the relevant control:

| Standard | Where to reference |
|---|---|
| CIS AWS Foundations Benchmark | https://www.cisecurity.org/benchmark/amazon_web_services |
| CIS Azure Foundations Benchmark | https://www.cisecurity.org/benchmark/azure |
| CIS GCP Foundations Benchmark | https://www.cisecurity.org/benchmark/google_cloud_computing_platform |
| ISO 27001:2022 | Annex A controls (A.5–A.8) |
| SOC 2 (Type II) | Trust Services Criteria (CC6, CC7, CC8, CC9) |
| PCI-DSS v4.0 | Requirements 1 (network), 2 (defaults), 7 (access), 8 (identity), 10 (logging) |
| NIST CSF | Identify / Protect / Detect / Respond / Recover functions |

**Mapping shorthand for findings:**
- IAM wildcard permissions → CIS AWS 1.16, ISO A.5.15, SOC2 CC6.1, PCI 7.2
- Public S3 bucket → CIS AWS 2.1.1, ISO A.8.12, SOC2 CC6.6, PCI 1.3
- No MFA on root → CIS AWS 1.5, ISO A.5.17, PCI 8.4
- No CloudTrail → CIS AWS 3.1, ISO A.8.15, SOC2 CC7.2, PCI 10.2
- Unencrypted EBS → CIS AWS 2.2.1, ISO A.8.24, PCI 3.5
- Security group open to world → CIS AWS 5.3, ISO A.8.21, PCI 1.2

---

### Phase 11 — Validation Gate

Before reporting any finding, confirm all of the following:

- [ ] Reproduced the misconfiguration using CLI/API commands (not just console screenshots)
- [ ] Confirmed the resource is actively in use (not a dev/test artifact clearly outside scope)
- [ ] Verified the impact is real — e.g. a public S3 bucket actually contains sensitive data, or a security group rule is reachable from the internet given the network path
- [ ] Evidence captured: full CLI command + output, or console screenshot + URL
- [ ] Finding is within agreed scope (account IDs, regions, resource types)
- [ ] Cross-checked against the false positive filter below
- [ ] Severity is justified — not inflated or deflated
- [ ] Compliance mapping is accurate for the specific control version (don't map to wrong CIS version)

---

### Phase 12 — False Positive Filter

Do not report without further investigation:

- **Public S3 bucket that is intentionally public** — verify it hosts a static website or public asset distribution; check the bucket policy for explicit intent or a "public-read" ACL put there by a CDN config
- **Cross-account IAM role with broad permissions** — verify the trusted account is not a legitimate vendor or internal account (e.g. AWS Config, Security Hub service roles)
- **Open port 443/80 on a security group** — web-facing services need these; only report if they expose non-web services (RDP, SSH, DB ports)
- **Primitive GCP roles on Compute Engine service agent** — Google-managed service accounts often use Editor; check that it is a Google-managed SA before flagging
- **KMS key without auto-rotation** — asymmetric KMS keys do not support auto-rotation; check key type before reporting
- **Lambda without VPC** — only a finding if the Lambda accesses internal VPC resources (RDS, ElastiCache); internet-only Lambdas don't need a VPC
- **Missing CloudTrail in a region with no resources** — not a finding if the region is genuinely unused (confirm with ec2 describe-regions)
- **"No encryption" on a non-sensitive public dataset** — weigh the actual data classification before marking as Critical
- **Short CloudTrail retention** — check if logs are streamed to a SIEM with longer retention before flagging the S3 bucket policy

---

### Phase 13 — Reporting

Every finding must include:

| Field | Content |
|---|---|
| **Title** | Short, action-oriented (e.g. "S3 Bucket Publicly Readable — Production Data Exposed") |
| **Severity** | Critical / High / Medium / Low / Informational |
| **Cloud Provider / Service** | AWS S3, Azure Blob, GCP Cloud Storage, etc. |
| **Affected Resource** | ARN, resource ID, or full path |
| **CIS Benchmark Reference** | Control number and title |
| **Other Compliance** | ISO / SOC2 / PCI references |
| **Steps to Reproduce** | Exact CLI command and output |
| **Evidence** | Command output or screenshot |
| **Impact** | What an attacker can do if this is exploited |
| **Recommendation** | Specific remediation step with example config or command |

**Severity guidance for cloud findings:**

- **Critical** — Direct data exposure (public bucket with PII/credentials), unauthenticated RCE on compute, complete loss of access control (public trust on IAM role)
- **High** — Wildcard IAM permissions, no MFA on privileged accounts, unencrypted sensitive data at rest, open RDP/SSH to world
- **Medium** — No logging/monitoring, missing rotation policy, IMDSv1 enabled, no flow logs, overly broad service roles
- **Low** — Short password policy, missing optional security features (Macie, GuardDuty) when other controls exist, informational header exposure
- **Informational** — Best practice deviations with no direct exploit path, e.g. verbose error messages in internal APIs

Use the `finding-writer` skill to convert raw notes into a structured finding ready for the final report.
