# 📁 Security Analyst II — Module Overview

**Platform:** KC7 Cyber  
**Level:** Security Analyst II  
**Path:** 5 Modules | ~8.5 Hours | ✅ Complete  
**Focus:** Network-layer analysis, C2 detection, supply chain attacks, ICS targeting, advanced KQL joins, insider threat hunting.

---

## 🗂️ Investigations — Security Analyst II (All Complete)

| # | Title | Attack Type | Queries | Status |
|---|---|---|---|---|
| 00 | [KQL 101 — Intro to Kusto](./00-kql-101-intro.md) | Foundational Skills | 12 | ✅ Complete |
| 01 | [Encryptodera — Ransomware & Insider Threat](./01-encryptodera-ransomware-insider-threat.md) | Insider → Account Takeover → Ransomware + Parallel Data Exfil | 38 | ✅ Complete |
| 02 | [ValdoriaVotes — Election Interference](./02-valdoriavotes-election-interference.md) | Phishing → Cred Harvest → AI Enumeration → Vendor Impersonation | 20 | ✅ Complete |
| 03 | [Whiskers & Wonders — Network & C2](./03-whiskers-and-wonders-network-c2.md) | Network Fundamentals + Phishing → C2 Beaconing | 22 | ✅ Complete |
| 04 | [Solvi Systems — Supply Chain & ICS](./04-solvi-systems-supply-chain-ics.md) | Web Recon → Phishing → ecobug C2 → Lateral Movement → Exfil | 27 | ✅ Complete |

**Total queries in this module: 107**

---

## 🧠 Skills Unlocked at This Level

Building on Security Analyst I foundations, this tier introduces:

- **Network-layer analysis** — VLANs, DNS record types, protocol analysis, port profiling
- **C2 beacon detection** — DNS beaconing, proxy pattern matching, regex in KQL
- **Supply chain attack investigation** — multi-stage phishing → implant → lateral movement → exfiltration
- **AI system enumeration** — querying `AIPrompts` table, prompt injection analysis
- **Advanced joins** — `join kind=inner` across multiple tables, chained `let` bindings
- **Insider threat hunting** — NetworkFlow aggregation, data exfiltration volume analysis
- **ICS/OT context** — recognising industrial control system targeting patterns

---

## 🆕 New KQL Operators Introduced

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

## 🧰 New Tables at This Level

| KC7 Table | Real Sentinel Equivalent | What It Contains |
|---|---|---|
| `NetworkFlow` | `AzureNetworkAnalytics_CL` / `VMConnection` | Raw network flow data — src/dest IP, port, protocol, bytes |
| `DeviceInfo` | `DeviceInfo` (MDE) | Hostname, IP, VLAN zone, host type |
| `DnsEvents` | `DnsEvents` / `DeviceNetworkEvents` | DNS query names, types, resolved IPs, client IPs |
| `ProxyEvents` | `CommonSecurityLog` (proxy source) | HTTP proxy logs — URL, domain, status code |
| `AIPrompts` | Custom / Azure OpenAI logs | AI system prompt/response logs, conversation IDs |

---

## 🗺️ MITRE ATT&CK Coverage — New at This Level

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

---

## ➡️ Next Path: Security Analyst III

---

← [Back to Main README](../../README.md) | ← [Security Analyst I](../security-analyst-1/README.md)

*Part of the [KC7 KQL Query Repository](../../README.md)*
