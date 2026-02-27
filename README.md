# ADPulse — Active Directory Security Scanner

ADPulse is an open-source Active Directory security auditing tool that connects to a domain controller via LDAP(S), runs 35 automated security checks, and produces detailed reports in console, JSON, and HTML formats.

It is designed for IT administrators, penetration testers, and security teams who need a fast, read-only assessment of AD misconfigurations and attack surface.

A PowerShell script named test_environment.ps1 is also included if you wish to set up your own vulnerable domain controller to test with.

---

## Features

### Security Checks (35 total)

| # | Check | Description |
|---|-------|-------------|
| 1 | **Password Policy** | Minimum length, history, complexity, lockout threshold, reversible encryption, fine-grained PSOs |
| 2 | **Privileged Accounts** | Membership of Domain Admins, Enterprise Admins, Schema Admins, and other sensitive groups; stale members, non-expiring passwords, passwords in descriptions, built-in Administrator status, krbtgt age |
| 3 | **Kerberos** | Kerberoastable accounts (SPNs on user objects), AS-REP roastable accounts, DES-only encryption, high-value targets combining adminCount=1 + SPN + PasswordNeverExpires |
| 4 | **Unconstrained Delegation** | Non-DC computers and user accounts trusted for unconstrained Kerberos delegation |
| 5 | **Constrained Delegation** | Accounts with protocol transition (S4U2Self) and standard constrained delegation targets |
| 6 | **ADCS / PKI** | ESC1, ESC2, ESC3, ESC6, ESC8, ESC9, ESC10, ESC11, ESC13, ESC15, weak key sizes, enrollee ACL enumeration |
| 7 | **Domain Trusts** | Bidirectional trusts without SID filtering, forest trusts, external trusts |
| 8 | **Account Hygiene** | Stale users/computers, never-logged-in accounts, PASSWD_NOTREQD flag, reversible encryption per-account, old passwords, duplicate SPNs |
| 9 | **Protocol Security** | LDAP signing/channel binding, DC operating system versions, domain/forest functional level, NTLMv1/WDigest guidance |
| 10 | **Group Policy Objects** | Disabled, orphaned, unlinked, and empty GPOs; excessive GPO count |
| 11 | **LAPS** | Legacy LAPS and Windows LAPS schema detection; computers without LAPS passwords |
| 12 | **LAPS Coverage** | Percentage-based coverage of all non-DC computers with a LAPS-managed password |
| 13 | **DNS & Infrastructure** | Wildcard DNS records, LLMNR/NetBIOS-NS poisoning guidance |
| 14 | **Domain Controllers** | Single-DC detection, legacy OS on DCs, FSMO roles, RODC password replication policy |
| 15 | **ACL / Permissions** | ESC4, ESC5, ESC7, DCSync rights on non-privileged principals, Protected Users group, delegation ACLs |
| 16 | **Optional Features** | AD Recycle Bin, Privileged Access Management (PAM) |
| 17 | **Replication Health** | Site count, site link replication intervals, nTDSDSA objects |
| 18 | **Service Accounts** | gMSA adoption, regular user service accounts, service accounts with adminCount=1 |
| 19 | **Miscellaneous Hardening** | Machine account quota, tombstone lifetime, Schema Admins/Enterprise Admins membership, Guest account, audit policy guidance |
| 20 | **Deprecated Operating Systems** | Enabled computer accounts reporting end-of-life Windows versions |
| 21 | **Legacy Protocols** | SMBv1 detection, SMB signing enforcement, null session acceptance (live network probes) |
| 22 | **Exchange** | Exchange Windows Permissions group (PrivExchange / CVE-2019-0686), Exchange Trusted Subsystem |
| 23 | **Protected Admin Users** | adminCount=1 inventory — orphaned, ghost (disabled), and stale accounts |
| 24 | **Passwords in Descriptions** | Keyword-based detection of credentials stored in the Description field of users, admins, and computers |
| 25 | **GPP / cpassword (MS14-025)** | Walks SYSVOL for Group Policy Preferences XML files containing `cpassword` attributes and decrypts them using Microsoft's publicly-known AES key |
| 26 | **AdminSDHolder ACL** | Reads the binary DACL on `CN=AdminSDHolder` and flags non-privileged principals with write access — these ACEs auto-propagate to all protected accounts every 60 minutes via SDProp |
| 27 | **SID History** | Detects accounts with `sIDHistory` populated; escalates to CRITICAL if any injected SID maps to a privileged group (Domain Admins, Enterprise Admins, etc.) |
| 28 | **Shadow Credentials** | Flags unexpected `msDS-KeyCredentialLink` entries on user and computer objects, enabling certificate-based authentication without knowing the account password |
| 29 | **RC4 / Legacy Kerberos Encryption** | Checks `msDS-SupportedEncryptionTypes` on service accounts, DCs, and admin accounts to identify those still permitting RC4-HMAC — the weak enctype attackers specifically request for offline cracking |
| 30 | **Foreign Security Principals in Privileged Groups** | Enumerates `CN=ForeignSecurityPrincipals` and flags any FSP from a trusted domain that is a member of a sensitive local group (Domain Admins, Backup Operators, etc.) |
| 31 | **Pre-Windows 2000 Compatible Access** | Checks whether `Everyone` or `Anonymous Logon` are members of this group, which enables unauthenticated SAMR/LSARPC enumeration from anywhere on the network |
| 32 | **Dangerous Constrained Delegation Targets** | Cross-references delegation targets against DC hostnames and flags accounts delegating to high-value service classes (`ldap/`, `cifs/`, `host/`, `gc/`, `krbtgt/`) on Domain Controllers |
| 33 | **Orphaned AD Subnets** | Finds subnets with no `siteObject` assignment, causing clients to receive a random DC and potentially routing authentication traffic across WAN links |
| 34 | **Legacy FRS SYSVOL Replication** | Detects whether SYSVOL is still replicating via the deprecated File Replication Service instead of DFSR, and flags stalled mid-migration states |
| 35 | **RBCD on Domain Object / DCs** | Checks `msDS-AllowedToActOnBehalfOfOtherIdentity` on the domain NC head and all DC computer objects — either configuration grants effective Domain Admin to the permitted principals via S4U2Proxy |

### Reporting

- **Console** — colour-coded terminal output with at-a-glance critical findings and key metrics
- **JSON** — machine-readable export for integration with SIEMs, ticketing systems, or custom dashboards
- **HTML** — self-contained dark-themed report with collapsible sections, severity badges, stat cards, scoring legend, and an ADCS template inventory

### Scoring

Every finding carries a risk-score deduction. The overall score starts at **100** and is reduced per finding:

| Score | Risk Level | Meaning |
|-------|-----------|---------|
| 80–100 | LOW | Good security posture, minor issues only |
| 60–79 | MEDIUM | Notable weaknesses that should be addressed |
| 40–59 | HIGH | Significant vulnerabilities present |
| 0–39 | CRITICAL | Severe risks — immediate remediation required |

---

## Requirements

- Python 3.8+
- Network access to a Domain Controller (port 636 for LDAPS, 389 for LDAP, 445 for SMB probes)
- A domain account with read access (no admin rights required for most checks)
- For check 25 (GPP/cpassword): SYSVOL must be accessible from the scanning host (UNC path on Windows, or Samba mount on Linux/macOS)

### Python Dependencies

```
ldap3>=2.9
colorama>=0.4.6
dnspython>=2.4.0
pycryptodome
weasyprint
```

---

## Installation

```bash
# Clone the repository
git clone https://github.com/yourorg/adpulse.git
cd adpulse

# (Recommended) Create a virtual environment
python -m venv venv
source venv/bin/activate        # Linux / macOS
venv\Scripts\activate           # Windows

# Install dependencies
pip install -r requirements.txt
```

---

## Usage

### Basic Scan

```bash
python ADPulse.py --domain corp.local --user jsmith --password 'P@ssw0rd!'
```

The DC IP is auto-resolved via DNS. All three report formats (console, JSON, HTML) are generated by default into a `Reports/` folder.

### Specify a Domain Controller

```bash
python ADPulse.py --domain corp.local --user jsmith --password 'P@ssw0rd!' --dc-ip 10.0.0.1
```

### Choose Report Format

```bash
# Console only
python ADPulse.py --domain corp.local --user jsmith --password 'P@ssw0rd!' --report console

# JSON only
python ADPulse.py --domain corp.local --user jsmith --password 'P@ssw0rd!' --report json

# HTML only
python ADPulse.py --domain corp.local --user jsmith --password 'P@ssw0rd!' --report html

# All formats (default)
python ADPulse.py --domain corp.local --user jsmith --password 'P@ssw0rd!' --report all
```

### Custom Output Directory

```bash
python ADPulse.py --domain corp.local --user jsmith --password 'P@ssw0rd!' --output-dir /tmp/scans
```

Reports are written to `<output-dir>/Reports/`.

### Disable Colour Output

```bash
python ADPulse.py --domain corp.local --user jsmith --password 'P@ssw0rd!' --no-color
```

### Full Argument Reference

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| `--domain` | Yes | — | Target AD domain (e.g. `corp.local`) |
| `--user` | Yes | — | Domain username |
| `--password` | Yes | — | Domain password |
| `--dc-ip` | No | Auto-resolved | Domain Controller IP address |
| `--report` | No | `all` | Report format: `console`, `json`, `html`, or `all` |
| `--output-dir` | No | `.` | Parent directory for the `Reports/` folder |
| `--no-color` | No | `false` | Disable colour in console output |

---

## Project Structure

```
adpulse/
├── ADPulse.py          # Entry point — argument parsing, orchestration
├── connector.py        # LDAP(S) connection, search helpers, SID resolution
├── checks.py           # All 35 security checks
├── models.py           # Finding and ScanResult data classes
├── report.py           # Console, JSON, and HTML report generation
├── __init__.py         # Package metadata
└── requirements.txt    # Python dependencies
```

---

## How It Works

1. **Connect** — ADPulse binds to the target DC over LDAPS (port 636) with automatic fallback to LDAP (port 389). Authentication is attempted via NTLM and SIMPLE bind.
2. **Scan** — Each of the 35 check functions queries AD via LDAP and, for certain checks, performs supplementary operations: lightweight network probes (SMBv1, signing, null sessions) against discovered hosts, SYSVOL filesystem traversal for GPP credential detection, and raw binary DACL parsing for ACL-based checks.
3. **Score** — Findings are assigned a severity (CRITICAL → INFO) and a point deduction. The overall score is `max(0, 100 - total_deductions)`.
4. **Report** — Results are rendered to the console and optionally exported as JSON and/or a self-contained HTML file.

All operations are **read-only**. ADPulse does not modify any AD objects, group memberships, GPOs, or ACLs.

---

## Security Considerations

- ADPulse requires valid domain credentials. Store and transmit credentials securely.
- The SMB probe checks (SMBv1, signing, null sessions) send raw TCP packets to port 445 on discovered hosts. Ensure you have authorisation to perform network-level testing.
- The GPP/cpassword check (check 25) reads files from SYSVOL. No files are modified or deleted.
- HTML reports may contain sensitive information (account names, group memberships, SPN details, decrypted GPP passwords). Treat all report formats as confidential and store them securely.
- Run ADPulse from a trusted, hardened workstation on the target network.

---

## Limitations

- **Registry-only settings** — NTLMv1 (`LmCompatibilityLevel`), WDigest (`UseLogonCredential`), LDAP signing (`ldapServerIntegrity`), and channel binding (`ldapEnforceChannelBinding`) cannot be read via LDAP. ADPulse flags these as manual verification items.
- **GPO content** — ADPulse checks GPO metadata (flags, version, SYSVOL path, links) but does not parse GPO settings files from SYSVOL (with the exception of the cpassword scan in check 25).
- **SYSVOL access** — Check 25 (GPP/cpassword) requires the scanning host to have filesystem access to SYSVOL. On Windows this is available via UNC path. On Linux/macOS the share must be mounted via Samba. If inaccessible, the check reports a manual verification notice.
- **ADCS ESC8** — The HTTP web enrollment check requires network reachability to the CA's `certsrv` endpoint.
- **SMB probes** — Firewalls or host-based rules may block port 445, causing false negatives for SMBv1/signing/null session checks.
- **Shadow credentials** — `msDS-KeyCredentialLink` entries added by legitimate Windows Hello for Business deployments will be reported and require manual review to distinguish from attacker-planted entries.
- **Size limits** — LDAP queries are capped at 10,000 results per search. Very large domains may require multiple runs or increased server-side limits.

---

## Contributing

Contributions are welcome. To add a new check:

1. Create a function in `checks.py` following the signature `def check_name(ad: ADConnector) -> Tuple[List[Finding], Dict]`.
2. Add it to the `checks` list inside `run_all_checks()`.
3. Add any new stat keys to `_SPECIAL_STATS` in `report.py` if they need dedicated rendering, or to `_build_stat_cards()` if they warrant a key-metric card.

---

## License

This project is released under the MIT License. See `LICENSE` for details.

---

## Disclaimer

ADPulse is provided as-is for **authorised security assessments only**. Always obtain written permission before scanning any Active Directory environment. The authors are not responsible for misuse or any damage caused by this tool.
