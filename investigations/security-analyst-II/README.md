# Security Analyst II — Module Overview

**Certification:** Security Analyst II ✅ Complete  
**Total Queries:** 107 across 5 modules  
**New Tables:** `NetworkFlow`, `DeviceInfo`, `DnsEvents`, `ProxyEvents`, `AIPrompts`

---

## Skills Unlocked at This Level

Building on Security Analyst I foundations, this tier introduces:

- **Network-layer analysis** — VLANs, DNS record types, protocol analysis, port profiling
- **C2 beacon detection** — DNS beaconing, proxy pattern matching, regex in KQL
- **Supply chain attack investigation** — multi-stage phishing → implant → lateral movement → exfiltration
- **AI system enumeration** — querying `AIPrompts` table, prompt injection analysis
- **Advanced joins** — `join kind=inner` across multiple tables, chained `let` bindings
- **Detection rule writing** — converting investigation findings into reusable KQL detections
- **Insider threat hunting** — NetworkFlow aggregation, data exfiltration volume analysis
- **ICS/OT context** — recognising industrial control system targeting patterns

---

## Modules

| # | Title | Attack Type | Queries | Key Techniques |
|---|---|---|---|---|
| 00 | KQL 101 — Intro to Kusto | Foundational Skills | 12 | Core operators, `let`, `in()` |
| 01 | Encryptodera — Ransomware & Insider Threat | Insider → Account Takeover → Ransomware + Parallel Data Exfil | 38 | T1486, T1003.001, T1484.001, T1567 |
| 02 | ValdoriaVotes — Election Interference | Phishing → Cred Harvest → AI Enumeration → Vendor Impersonation | 20 | T1566.002, T1056.003, T1583, T1530 |
| 03 | Whiskers & Wonders — Network & C2 | Network Fundamentals + Phishing → C2 Beaconing | 22 | T1071.001, T1071.004, T1572, T1566.002 |
| 04 | Solvi Systems — Supply Chain & ICS | Web Recon → Phishing → ecobug C2 → Lateral Movement → Exfil | 27 | T1190, T1583, T1021.002, T1567 |

---

## New KQL Operators Introduced

| Operator / Pattern | Used In |
|---|---|
| `summarize ... by` | NetworkFlow aggregation (Encryptodera Q26–Q28) |
| `top N by` | Find highest-volume exfil destination (Encryptodera Q26) |
| `sum(bytes)` | Total data exfiltrated (Encryptodera Q28) |
| `dcount()` | Distinct count in summarize (Encryptodera Q22) |
| `join kind=inner` | Cross-table correlation (Encryptodera Q25, Whiskers Q19) |
| `startswith` | Subnet-based filtering (Whiskers Q05) |
| `has_any()` | Multi-value OR matching (SolviSystems Q12) |
| `matches regex` | Pattern-based URL detection (Whiskers Detection 3) |
| `between (datetime .. datetime)` | Time-window filtering |
| `min(timestamp)` / `max(timestamp)` | First/last seen analysis |

---

## New Tables at This Level

| Table | Real Sentinel Equivalent | What It Contains |
|---|---|---|
| `NetworkFlow` | `AzureNetworkAnalytics_CL` / `VMConnection` | Raw network flow data — src/dest IP, port, protocol, bytes |
| `DeviceInfo` | `DeviceInfo` (MDE) | Hostname, IP, VLAN zone, host type |
| `DnsEvents` | `DnsEvents` / `DeviceNetworkEvents` | DNS query names, types, resolved IPs, client IPs |
| `ProxyEvents` | `CommonSecurityLog` (proxy source) | HTTP proxy logs — URL, domain, status code |
| `AIPrompts` | Custom / Azure OpenAI logs | AI system prompt/response logs, conversation IDs |

---

## MITRE ATT&CK Coverage — Security Analyst II (New Additions)

| Tactic | New Techniques |
|---|---|
| Reconnaissance | T1595 (Active Scanning), T1592 (Gather Host Info) |
| Resource Development | T1583 (Acquire Infrastructure) |
| Initial Access | T1190 (Exploit Public-Facing App) |
| Persistence | T1136 (Create Account), T1484.001 (GPO Modification) |
| Credential Access | T1003.001 (LSASS/Mimikatz) |
| Lateral Movement | T1021.002 (SMB Shares), T1534 (Internal Spearphishing) |
| Command & Control | T1071.001/T1071.004 (Web/DNS C2), T1572 (Protocol Tunneling) |
| Exfiltration | T1567 (Exfil over Web Service) |
| Impact | T1484.001 (Group Policy Modification) |
