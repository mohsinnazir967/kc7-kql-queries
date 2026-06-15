# 📁 Security Analyst I — Module Overview

**Platform:** KC7 Cyber
**Level:** Security Analyst I (Junior SOC Analyst)
**Path:** 6 Modules | ~6 Hours | ✅ Complete
**Focus:** Identifying basic signs of compromise, turning investigative questions into KQL queries, following evidence across log sources.

---

## 🗂️ Investigations — Security Analyst I (All Complete)

| # | Title | Attack Type | Queries | Status |
|---|-------|-------------|---------|--------|
| 01 | [A Rap Beef — Phishing & Account Takeover](./01-rap-beef-phishing-account-takeover.md) | OSINT → Spearphishing → Account Takeover | 10 | ✅ Complete |
| 02 | [CloutHaus — Social Media Leads to Compromise](./02-clouthaus-social-media-compromise.md) | Fake Brand Deal → Credential Harvest → PII Exfil | 15 | ✅ Complete |
| 03 | [A Scandal in Valdoria — A Political Mystery](./03-scandal-in-valdoria-political-mystery.md) | Spearphishing → PowerShell Backdoor → SSH Tunnel → Influence Op | 31 | ✅ Complete |
| 04 | [Jojo's Hospital — A Ransomware Investigation](./04-jojos-hospital-ransomware.md) | SEO Poisoning → Cobalt Strike → Lateral Movement → LockByte Ransomware | 23 | ✅ Complete |

**Total queries in this module: 79**

---

## 🧠 Skills Practised

- Filtering log tables by timestamp, IP, URL, filename, and hash
- Using `let` statements to build reusable dynamic variable sets
- Pivoting across multiple log sources: Email → Network → Auth → Endpoint → DNS
- Identifying attacker infrastructure via Passive DNS
- Detecting credential harvesting, MFA bypass, and account takeover
- Hunting for PowerShell execution and execution policy bypass
- Tracing SSH tunnelling via `plink.exe`
- Detecting post-compromise discovery commands (hands-on-keyboard activity)
- Identifying SEO poisoning and drive-by compromise delivery chains
- Tracing Cobalt Strike C2 beaconing and lateral movement
- Detecting ransomware deployment: encrypted file counts, affected hosts, ransom notes
- Identifying data staging, exfiltration, and track-clearing commands
- Mapping full kill chains to MITRE ATT&CK

---

## ➡️ Next Path: Security Analyst II → Security Analyst III

---

*Part of the [KC7 KQL Query Repository](../../README.md)*

---

← [Back to Main README](../../README.md) | → [Security Analyst II](../security-analyst-II/README.md)
