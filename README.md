# 🛡️ KC7 KQL Query Repository

> A structured collection of KQL (Kusto Query Language) queries written during KC7 cybersecurity investigation modules — fully documented with inline comments, MITRE ATT&CK mappings, and real-world Microsoft Sentinel context.

![KC7](https://img.shields.io/badge/Platform-KC7%20Cyber-blue?style=flat-square)
![KQL](https://img.shields.io/badge/Language-KQL-orange?style=flat-square)
![MITRE](https://img.shields.io/badge/Framework-MITRE%20ATT%26CK-red?style=flat-square)
![Queries](https://img.shields.io/badge/Total%20Queries-79-purple?style=flat-square)
![Progress](https://img.shields.io/badge/Security%20Analyst%20I-100%25%20Complete-brightgreen?style=flat-square)
![Progress](https://img.shields.io/badge/Security%20Analyst%20II-100%25%20Complete-brightgreen?style=flat-square)

## 📂 Repository Structure

```
kc7-kql-queries/
├── README.md                                                    ← You are here
│
├── docs/
│   ├── mitre-attack-index.md                                    ← Master MITRE ATT&CK index (50+ techniques)
│   └── sentinel-table-reference.md                              ← KC7 → Sentinel table mappings + starter queries
│
└── investigations/
    ├── security-analyst-1/
    │   ├── README.md                                            ← SA-I module overview & skills reference
    │   ├── 01-rap-beef-phishing-account-takeover.md             ← 10 queries | OSINT → Account Takeover
    │   ├── 02-clouthaus-social-media-compromise.md              ← 15 queries | Fake Brand Deal → PII Exfil
    │   ├── 03-scandal-in-valdoria-political-mystery.md          ← 31 queries | Backdoor → SSH → Influence Op
    │   └── 04-jojos-hospital-ransomware.md                      ← 23 queries | SEO Poison → Cobalt Strike → LockByte
    │
    └── security-analyst-2/
        ├── README.md                                            ← SA-II module overview & skills reference
        ├── 00-kql-101-intro.md                                  ← 12 queries | Core KQL operators & patterns
        ├── 01-encryptodera-ransomware-insider-threat.md         ← 38 queries | Ransomware + Insider Data Exfil
        ├── 02-valdoriavotes-election-interference.md            ← 20 queries | Phishing → AI Enum → Vendor Impersonation
        ├── 03-whiskers-and-wonders-network-c2.md                ← 22 queries | Network Concepts + C2 Beaconing
        └── 04-solvi-systems-supply-chain-ics.md                 ← 27 queries | Supply Chain → ICS Targeting
```

---

## 🎯 About This Repository

This repo documents my hands-on KQL learning journey through KC7 — a free, realistic cybersecurity investigation game built on Azure Data Explorer. Each query is:

✅ Clearly titled with a one-line description  
✅ Explained in SOC context (what it detects and why it matters)  
✅ Fully commented with inline explanations  
✅ Mapped to MITRE ATT&CK techniques  
✅ Cross-referenced to real Microsoft Sentinel tables  

---

## 📚 Career Path Progress

### Security Analyst I — ✅ Complete
Monitor SIEM dashboards, triage alerts, write KQL queries, identify phishing and malicious indicators, perform IOC lookups.

| # | Module | Hours | Status |
|---|---|---|---|
| 1 | A Rap Beef: An Intro to Security Investigations | ~1.0 hr | ✅ Complete |
| 2 | How to Play KC7 | ~0.17 hr | ✅ Complete |
| 3 | CloutHaus: Social Media Leads to Compromise | ~1.0 hr | ✅ Complete |
| 4 | A Scandal in Valdoria: A Political Mystery | ~1.5 hrs | ✅ Complete |
| 5 | VirusTotal Fundamentals | ~1.5 hrs | ✅ Complete |
| 6 | Jojo's Hospital: A Ransomware Investigation | ~2.0 hrs | ✅ Complete |

### Security Analyst II — ✅ Complete
Network analysis, C2 detection, supply chain attacks, ICS targeting, advanced KQL joins and detection rule writing.

| # | Module | Hours | Status |
|---|---|---|---|
| 1 | KQL 101: Introduction to Kusto Query Language | ~0.5 hr | ✅ Complete |
| 2 | Encryptodera: Ransomware & Insider Threat | ~2.0 hrs | ✅ Complete |
| 3 | ValdoriaVotes: Election Interference | ~1.5 hrs | ✅ Complete |
| 4 | Whiskers & Wonders: Network Concepts & C2 | ~2.0 hrs | ✅ Complete |
| 5 | Solvi Systems: Supply Chain & ICS | ~2.5 hrs | ✅ Complete |

### Security Analyst III — ⏳ Pending

---

## 🗂️ Investigations

### Security Analyst I

| # | Title | Queries | Key Techniques | Link |
|---|---|---|---|---|
| 01 | A Rap Beef — Phishing & Account Takeover | 10 | T1593, T1566.002, T1078 | [→ Open](investigations/security-analyst-1/01-rap-beef-phishing-account-takeover.md) |
| 02 | CloutHaus — Social Media Leads to Compromise | 15 | T1566.002, T1056.003, T1114.003 | [→ Open](investigations/security-analyst-1/02-clouthaus-social-media-compromise.md) |
| 03 | A Scandal in Valdoria — A Political Mystery | 31 | T1059.001, T1572, T1491 | [→ Open](investigations/security-analyst-1/03-scandal-in-valdoria-political-mystery.md) |
| 04 | Jojo's Hospital — A Ransomware Investigation | 23 | T1189, T1219, T1046, T1486 | [→ Open](investigations/security-analyst-1/04-jojos-hospital-ransomware.md) |

### Security Analyst II

| # | Title | Queries | Key Techniques | Link |
|---|---|---|---|---|
| 00 | KQL 101 — Intro to Kusto | 12 | Core operators, `let`, `in()` | [→ Open](investigations/security-analyst-2/00-kql-101-intro.md) |
| 01 | Encryptodera — Ransomware & Insider Threat | 38 | T1486, T1003.001, T1484.001, T1567 | [→ Open](investigations/security-analyst-2/01-encryptodera-ransomware-insider-threat.md) |
| 02 | ValdoriaVotes — Election Interference | 20 | T1566.002, T1056.003, T1583, T1530 | [→ Open](investigations/security-analyst-2/02-valdoriavotes-election-interference.md) |
| 03 | Whiskers & Wonders — Network & C2 | 22 | T1071.001, T1071.004, T1572 | [→ Open](investigations/security-analyst-2/03-whiskers-and-wonders-network-c2.md) |
| 04 | Solvi Systems — Supply Chain & ICS | 27 | T1190, T1583, T1021.002, T1567 | [→ Open](investigations/security-analyst-2/04-solvi-systems-supply-chain-ics.md) |

**Total queries documented: 186 across 9 investigations**

---

## 🗺️ MITRE ATT&CK Coverage (50+ Unique Techniques)

| Tactic | Techniques Covered |
|---|---|
| Reconnaissance | T1589, T1589.002, T1590, T1591, T1592, T1593, T1595 |
| Resource Development | T1583, T1584 |
| Initial Access | T1189, T1190, T1566.002 |
| Execution | T1059, T1059.001, T1204.001, T1204.002 |
| Persistence | T1053, T1133, T1136 |
| Defence Evasion | T1036, T1036.007, T1070, T1078, T1562 |
| Credential Access | T1003.001, T1056.003 |
| Discovery | T1018, T1033, T1046, T1082 |
| Lateral Movement | T1021.002, T1534, T1570 |
| Collection | T1114.003, T1530, T1560 |
| Command & Control | T1071, T1071.001, T1071.004, T1219, T1572 |
| Exfiltration | T1567 |
| Impact | T1484.001, T1486, T1491 |

→ Full index: [docs/mitre-attack-index.md](docs/mitre-attack-index.md)

---

## 🧰 KC7 → Microsoft Sentinel Table Reference

### Security Analyst I Tables

| KC7 Table | Real Sentinel Equivalent |
|---|---|
| `Employees` | `IdentityInfo` |
| `InboundNetworkEvents` | `CommonSecurityLog` / `AzureNetworkAnalytics_CL` |
| `OutboundNetworkEvents` | `AzureNetworkAnalytics_CL` / `DeviceNetworkEvents` |
| `Email` | `EmailEvents` |
| `PassiveDns` | `DnsEvents` |
| `AuthenticationEvents` | `SigninLogs` / `AADSignInEventsBeta` |
| `ProcessEvents` | `DeviceProcessEvents` |
| `FileCreationEvents` | `DeviceFileEvents` |

### Security Analyst II Tables (New)

| KC7 Table | Real Sentinel Equivalent |
|---|---|
| `NetworkFlow` | `AzureNetworkAnalytics_CL` / `VMConnection` |
| `DeviceInfo` | `DeviceInfo` (MDE) |
| `DnsEvents` | `DnsEvents` / `DeviceNetworkEvents` |
| `ProxyEvents` | `CommonSecurityLog` (proxy source) |
| `AIPrompts` | Custom / Azure OpenAI logs |

→ Full reference with starter queries: [docs/sentinel-table-reference.md](docs/sentinel-table-reference.md)

---

## 👤 About Me

SOC Analyst in training — building practical threat hunting and incident response skills through KC7, KQL, and MITRE ATT&CK.

🔗 **Platform:** [KC7 Cyber](https://kc7cyber.com/profile/58c74f1f)  
📖 **Language:** KQL (Kusto Query Language)  
☁️ **Target Environment:** Microsoft Sentinel / Azure Data Explorer  
🎯 **Next Goal:** Security Analyst III certification

*Queries are written for educational purposes as part of the KC7 training platform.*
