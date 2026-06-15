# 🗺️ MITRE ATT&CK Technique Index

Master index of every MITRE ATT&CK technique covered across all investigations in this repository.

---

## Full Technique Index

| Tactic | Technique | ID | Investigations |
|--------|-----------|-----|----------------|
| Reconnaissance | Search Open Websites/Domains | [T1593](https://attack.mitre.org/techniques/T1593/) | [01](../investigations/security-analyst-1/01-rap-beef-phishing-account-takeover.md), [04](../investigations/security-analyst-1/04-jojos-hospital-ransomware.md) |
| Reconnaissance | Gather Victim Identity Information | [T1589](https://attack.mitre.org/techniques/T1589/) | [01](../investigations/security-analyst-1/01-rap-beef-phishing-account-takeover.md), [02](../investigations/security-analyst-1/02-clouthaus-social-media-compromise.md) |
| Reconnaissance | Gather Victim Identity Information: Email Addresses | [T1589.002](https://attack.mitre.org/techniques/T1589/002/) | [01](../investigations/security-analyst-1/01-rap-beef-phishing-account-takeover.md) |
| Reconnaissance | Gather Victim Network Information | [T1590](https://attack.mitre.org/techniques/T1590/) | [01](../investigations/security-analyst-1/01-rap-beef-phishing-account-takeover.md) |
| Reconnaissance | Gather Victim Org Information | [T1591](https://attack.mitre.org/techniques/T1591/) | [03](../investigations/security-analyst-1/03-scandal-in-valdoria-political-mystery.md) |
| Resource Development | Compromise Infrastructure | [T1584](https://attack.mitre.org/techniques/T1584/) | [01](../investigations/security-analyst-1/01-rap-beef-phishing-account-takeover.md), [02](../investigations/security-analyst-1/02-clouthaus-social-media-compromise.md), [03](../investigations/security-analyst-1/03-scandal-in-valdoria-political-mystery.md), [04](../investigations/security-analyst-1/04-jojos-hospital-ransomware.md) |
| Initial Access | Drive-by Compromise (SEO Poisoning) | [T1189](https://attack.mitre.org/techniques/T1189/) | [04](../investigations/security-analyst-1/04-jojos-hospital-ransomware.md) |
| Initial Access | Spearphishing Link | [T1566.002](https://attack.mitre.org/techniques/T1566/002/) | [01](../investigations/security-analyst-1/01-rap-beef-phishing-account-takeover.md), [02](../investigations/security-analyst-1/02-clouthaus-social-media-compromise.md), [03](../investigations/security-analyst-1/03-scandal-in-valdoria-political-mystery.md), [04](../investigations/security-analyst-1/04-jojos-hospital-ransomware.md) |
| Execution | User Execution: Malicious Link | [T1204.001](https://attack.mitre.org/techniques/T1204/001/) | [01](../investigations/security-analyst-1/01-rap-beef-phishing-account-takeover.md), [02](../investigations/security-analyst-1/02-clouthaus-social-media-compromise.md) |
| Execution | User Execution: Malicious File | [T1204.002](https://attack.mitre.org/techniques/T1204/002/) | [03](../investigations/security-analyst-1/03-scandal-in-valdoria-political-mystery.md), [04](../investigations/security-analyst-1/04-jojos-hospital-ransomware.md) |
| Execution | PowerShell | [T1059.001](https://attack.mitre.org/techniques/T1059/001/) | [03](../investigations/security-analyst-1/03-scandal-in-valdoria-political-mystery.md) |
| Execution | Command & Scripting Interpreter | [T1059](https://attack.mitre.org/techniques/T1059/) | [04](../investigations/security-analyst-1/04-jojos-hospital-ransomware.md) |
| Persistence | Scheduled Task/Job | [T1053](https://attack.mitre.org/techniques/T1053/) | [03](../investigations/security-analyst-1/03-scandal-in-valdoria-political-mystery.md) |
| Persistence | External Remote Services | [T1133](https://attack.mitre.org/techniques/T1133/) | [01](../investigations/security-analyst-1/01-rap-beef-phishing-account-takeover.md) |
| Defence Evasion | Valid Accounts | [T1078](https://attack.mitre.org/techniques/T1078/) | [01](../investigations/security-analyst-1/01-rap-beef-phishing-account-takeover.md), [02](../investigations/security-analyst-1/02-clouthaus-social-media-compromise.md), [04](../investigations/security-analyst-1/04-jojos-hospital-ransomware.md) |
| Defence Evasion | Impair Defences (Execution Policy Bypass) | [T1562](https://attack.mitre.org/techniques/T1562/) | [03](../investigations/security-analyst-1/03-scandal-in-valdoria-political-mystery.md) |
| Defence Evasion | Masquerading | [T1036](https://attack.mitre.org/techniques/T1036/) | [02](../investigations/security-analyst-1/02-clouthaus-social-media-compromise.md) |
| Defence Evasion | Indicator Removal | [T1070](https://attack.mitre.org/techniques/T1070/) | [03](../investigations/security-analyst-1/03-scandal-in-valdoria-political-mystery.md), [04](../investigations/security-analyst-1/04-jojos-hospital-ransomware.md) |
| Credential Access | Phishing for Credentials | [T1056.003](https://attack.mitre.org/techniques/T1056/003/) | [02](../investigations/security-analyst-1/02-clouthaus-social-media-compromise.md) |
| Discovery | System Information Discovery | [T1082](https://attack.mitre.org/techniques/T1082/) | [04](../investigations/security-analyst-1/04-jojos-hospital-ransomware.md) |
| Discovery | System Owner/User Discovery | [T1033](https://attack.mitre.org/techniques/T1033/) | [03](../investigations/security-analyst-1/03-scandal-in-valdoria-political-mystery.md) |
| Discovery | Network Service Scanning | [T1046](https://attack.mitre.org/techniques/T1046/) | [04](../investigations/security-analyst-1/04-jojos-hospital-ransomware.md) |
| Lateral Movement | Lateral Tool Transfer | [T1570](https://attack.mitre.org/techniques/T1570/) | [04](../investigations/security-analyst-1/04-jojos-hospital-ransomware.md) |
| Collection | Email Forwarding Rule | [T1114.003](https://attack.mitre.org/techniques/T1114/003/) | [02](../investigations/security-analyst-1/02-clouthaus-social-media-compromise.md) |
| Collection | Archive Collected Data | [T1560](https://attack.mitre.org/techniques/T1560/) | [03](../investigations/security-analyst-1/03-scandal-in-valdoria-political-mystery.md), [04](../investigations/security-analyst-1/04-jojos-hospital-ransomware.md) |
| Collection | Data from Cloud Storage | [T1530](https://attack.mitre.org/techniques/T1530/) | [02](../investigations/security-analyst-1/02-clouthaus-social-media-compromise.md) |
| Command & Control | Remote Access Software (Cobalt Strike) | [T1219](https://attack.mitre.org/techniques/T1219/) | [04](../investigations/security-analyst-1/04-jojos-hospital-ransomware.md) |
| Command & Control | Application Layer Protocol | [T1071](https://attack.mitre.org/techniques/T1071/) | [01](../investigations/security-analyst-1/01-rap-beef-phishing-account-takeover.md) |
| Command & Control | Protocol Tunnelling (plink/SSH) | [T1572](https://attack.mitre.org/techniques/T1572/) | [03](../investigations/security-analyst-1/03-scandal-in-valdoria-political-mystery.md) |
| Exfiltration | Exfiltration Over Web Service | [T1567](https://attack.mitre.org/techniques/T1567/) | [02](../investigations/security-analyst-1/02-clouthaus-social-media-compromise.md), [03](../investigations/security-analyst-1/03-scandal-in-valdoria-political-mystery.md), [04](../investigations/security-analyst-1/04-jojos-hospital-ransomware.md) |
| Impact | Defacement / Influence Operations | [T1491](https://attack.mitre.org/techniques/T1491/) | [03](../investigations/security-analyst-1/03-scandal-in-valdoria-political-mystery.md) |
| Impact | Data Encrypted for Impact | [T1486](https://attack.mitre.org/techniques/T1486/) | [04](../investigations/security-analyst-1/04-jojos-hospital-ransomware.md) |

---

## Coverage by Investigation

| Investigation | Techniques Covered |
|---------------|-------------------|
| [01 — A Rap Beef](../investigations/security-analyst-1/01-rap-beef-phishing-account-takeover.md) | T1589.002, T1590, T1593, T1584, T1566.002, T1204.001, T1078, T1133, T1071 |
| [02 — CloutHaus](../investigations/security-analyst-1/02-clouthaus-social-media-compromise.md) | T1589, T1584, T1566.002, T1204.001, T1056.003, T1078, T1036, T1114.003, T1530, T1567 |
| [03 — Scandal in Valdoria](../investigations/security-analyst-1/03-scandal-in-valdoria-political-mystery.md) | T1591, T1584, T1566.002, T1204.002, T1059.001, T1053, T1070, T1562, T1033, T1560, T1572, T1567, T1491 |
| [04 — Jojo's Hospital](../investigations/security-analyst-1/04-jojos-hospital-ransomware.md) | T1593, T1584, T1189, T1566.002, T1204.002, T1059, T1219, T1082, T1046, T1078, T1570, T1560, T1567, T1070, T1486 |

**Total unique techniques documented: 32**

---

*Updated as new investigations are added. All techniques link to the official MITRE ATT&CK framework at attack.mitre.org*
