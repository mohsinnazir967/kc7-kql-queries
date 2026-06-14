# Encryptodera — Ransomware & Insider Threat

**Module:** Security Analyst II | **Environment:** Encryptodera Financial  
**Status:** ✅ Complete | **Queries:** 38  
**Attack Type:** Insider Threat → Account Compromise → Lateral Movement → Ransomware + Parallel Insider Data Exfil

---

## Module Overview

A two-part investigation at Encryptodera Financial. Part 1 traces a ransomware attack that encrypted 306 machines — originating from a disgruntled insider whose account was later hijacked by an external threat actor. Part 2 uncovers a parallel insider threat: a rogue employee exfiltrating cryptocurrency wallet data to an outside handler.

**Tables Used:** `Employees`, `Email`, `OutboundNetworkEvents`, `InboundNetworkEvents`, `AuthenticationEvents`, `ProcessEvents`, `FileCreationEvents`, `NetworkFlow`

---

## Attack Chain Summary

```
Barry Shmelly (insider/disgruntled)
  └─ Account hijacked by TA from 143.38.175.105
       └─ Phishing campaign → 9 employees targeted
            └─ Robin Kirby compromised
                 └─ systadmi_local_admin credentials stolen
                      └─ Lateral move → Valerie Orozco's machine (GJ95-LAPTOP)
                           └─ Mimikatz → domain admin credentials dumped
                                └─ DOMAIN_CONTROLLER_SERVER accessed
                                     └─ GPO deployed → 306 machines encrypted (.umadbro)

Parallel: Jane Smith (insider)
  └─ Colluding with elboss@westealurcrypto.com
       └─ ftp_client.exe + crypto_stealer.exe downloaded
            └─ Data exfiltrated to 182.56.23.121 (27 days, 208 KB total)
```

---

## Part 1: Ransomware Attack

---

### Q01 — Identify Employee by IP

```kql
// Find the employee associated with a given IP address
Employees
| where ip_addr == "10.10.0.216"
```

**Result:** Nakia Acosta | `nakia_acosta@encryptoderafinancial.com`

---

### Q02 — Count Emails Received

```kql
// How many emails did Nakia Acosta receive?
Email
| where recipient == "nakia_acosta@encryptoderafinancial.com"
```

**Answer:** 38 emails.

---

### Q03 — Distinct Senders from a Domain

```kql
// How many distinct senders came from bitbingersbanking.net?
Email
| where sender has "bitbingersbanking.net"
| distinct sender
```

**Answer:** 1204 distinct senders.

---

### Q04 — Count URLs Visited

```kql
// Identify employee Timothy Geffre and count distinct URLs visited
Employees
| where name == "Timothy Geffre"
// IP: 10.10.1.73

OutboundNetworkEvents
| where src_ip == "10.10.1.73"
| distinct url
| count
```

**Answer:** 92 distinct URLs.

---

### Q05 — PassiveDns Keyword Search

```kql
// How many domains in PassiveDns contain the word "money"?
PassiveDns
| where domain contains "money"
| distinct domain
| count
```

**Answer:** 15 domains. (`contains` used instead of `has` for substring matching within compound words)

---

### Q06 — Domain IP Resolution

```kql
// What IP does moneyppl.com resolve to?
PassiveDns
| where domain == "moneyppl.com"
| distinct ip
```

**Answer:** `211.152.115.93`

---

### Q07 — Barry Shmelly Profiling

```kql
// Look up the disgruntled employee Barry Shmelly
Employees
| where name contains "barry"
// Role: StackOverflow Copy Paster | IP: 10.10.0.1 | Host: IGOY-DESKTOP
```

---

### Q08 — Suspicious Outbound Browsing

```kql
// What was Barry browsing related to sensitive file transfers?
OutboundNetworkEvents
| where src_ip == "10.10.0.1"
```

**Key URLs:**
- `https://www.cybersecurity-insiders.com/safe-ways-to-transfer-sensitive-files` (Dec 26)
- `https://www.7-zip.org/a/7z2002-x64.exe` (Jan 15 — first visit)
- `https://www.wikihow.com/Use-a-USB-Flash-Drive` (USB research)

> **SOC Context:** Browsing file transfer and compression tools before a data theft event is a classic pre-exfiltration indicator. T1030 / T1560.

---

### Q09 — File Downloads (Insider Staging)

```kql
// What sensitive documents did Barry download inbound?
InboundNetworkEvents
| where src_ip == "10.10.0.1"
```

**Files downloaded:**
- `SECRET_MergersAndAcquisitions_Strategy2025.docx`
- `ExecutiveSalaryNegotiations.docx`
- `Encryptodera_Proprietary_Algorithms.zip`

---

### Q10 — Process Events on Barry's Machine

```kql
// What commands did Barry run? (zip with password securePass123, USB drive: SchmellyDrive)
ProcessEvents
| where hostname == "IGOY-DESKTOP"
```

---

### Q11 — Ransomware Note Discovery

```kql
// How many machines had the ransom note? When did it first appear?
FileCreationEvents
| where filename == "YOU_GOT_CRYTOED_SO_GIMME_CRYPTO.txt"
| distinct hostname
```

**Answer:** 306 machines. First seen: `2024-02-17T02:34:54Z` on `UL8R-MACHINE`.

> **MITRE:** T1486 — Data Encrypted for Impact

---

### Q12 — Encrypted Files on Patient Zero

```kql
// What files were encrypted on the first affected machine?
FileCreationEvents
| where hostname == "UL8R-MACHINE" and filename endswith "umadbro"
```

**Answer:** 50 files encrypted. Extension used: `.umadbro`

---

### Q13 — Ransomware Binary Arrival

```kql
// When did the ransomware executable first appear on UL8R-MACHINE?
FileCreationEvents
| where hostname == "UL8R-MACHINE" and filename == "files_go_byebye.exe"
```

**Answer:** `2024-02-17T02:30:50Z` — ransomware binary arrived 4 minutes before encryption started.

---

### Q14 — Process Activity Around Ransomware Deployment

```kql
// What commands ran on UL8R-MACHINE during the attack window?
ProcessEvents
| where hostname == "UL8R-MACHINE"
| where timestamp between (datetime("2024-02-16") .. datetime("2024-02-18"))
```

**Answer:** 23 commands. Key findings:
- Encoded PowerShell referencing `notification-finance-services.com`
- `gpupdate /force` ran immediately before the encoded PowerShell

> **MITRE:** T1059.001 — PowerShell | T1059 — Command and Scripting Interpreter

---

### Q15 — GPO-Based Ransomware Deployment

```kql
// How many devices ran the gpupdate /force command? (mass deployment indicator)
ProcessEvents
| where process_commandline == "gpupdate /force"
```

**Answer:** 306 machines — matching the ransom note count. This confirms GPO-based mass deployment from the domain controller.

> **MITRE:** T1484.001 — Group Policy Modification

---

### Q16 — Initial Discovery Commands

```kql
// How many machines ran systeminfo? (attacker reconnaissance)
ProcessEvents
| where process_commandline == "systeminfo"
```

**Answer:** 8 machines. First run: `2024-02-02T03:32:36Z` on `41QI-LAPTOP` — 15 days before encryption.

> **MITRE:** T1082 — System Information Discovery

---

### Q17 — Domain Enumeration

```kql
// Full nltest command used for domain controller discovery
ProcessEvents
| where process_commandline contains "nltest /dclist"
```

**Answer:** `cmd.exe /C nltest /dclist:encryptoderafinancial.com`

> **MITRE:** T1018 — Remote System Discovery

---

### Q18 — Malicious File on Patient Zero Host

```kql
// Find the double-extension masquerading executable on 41QI-LAPTOP
FileCreationEvents
| where hostname == "41QI-LAPTOP" and filename contains ".xlsx.exe"
```

**Answer:** `Company_Financials_Q1_2024_Review.xlsx.exe`

> **MITRE:** T1036.007 — Double File Extension masquerading

---

### Q19 — Remote Access Tool Deployment

```kql
// What file appeared seconds after the malicious .xlsx.exe?
FileCreationEvents
| where hostname == "41QI-LAPTOP"
| where timestamp >= datetime(2024-02-01T08:50:12.000Z)
```

**Answer:** `screenconnect_client.exe` — remote access trojan/RMM tool.

> **MITRE:** T1219 — Remote Access Software

---

### Q20 — Phishing Email Source

```kql
// Which email address sent the malicious .xlsx.exe link?
Email
| where link contains "Company_Financials_Q1_2024_Review.xlsx.exe"
```

**Answer:** `barry_shmelly@encryptoderafinancial.com` — Barry's hijacked account.

---

### Q21 — Account Compromise Verification

```kql
// What external IP logged into Barry's account on Feb 1?
AuthenticationEvents
| where username == "bashmelly"
```

**Answer:** `143.38.175.105` at `2024-02-01`. Barry's account was hijacked.

---

### Q22 — Lateral Movement via Compromised Admin Credentials

```kql
// How many IPs logged into the 8 machines where attacker ran systeminfo?
let hosts =
ProcessEvents
| where process_commandline == "systeminfo"
| distinct hostname;
AuthenticationEvents
| where hostname in (hosts)
| summarize dcount(hostname) by src_ip
| order by dcount_hostname desc
```

**Answer:** 2 IPs logged into multiple discovery targets. Sysadmin IP `10.10.0.138` accessed the domain controller.

---

### Q23 — Domain Controller Access

```kql
// Confirm successful logins and hostname from the sysadmin IP
AuthenticationEvents
| where src_ip == "10.10.0.138" and result == "Successful Login"
| distinct hostname
```

**Answer:** Logged into `DOMAIN_CONTROLLER_SERVER` using `lihenry_domain_admin`.

---

### Q24 — Credential Dumping (Mimikatz)

```kql
// Did the threat actor run mimikatz on Valerie Orozco's machine?
ProcessEvents
| where hostname == "GJ95-LAPTOP" and process_commandline contains "mimikatz"
```

**Answer:** `totally_not_mimikatz.exe "sekurlsa::logonpasswords"`

> **MITRE:** T1003.001 — LSASS Memory credential dumping

---

### Q25 — Insider Pivot: Who Used Stolen Local Admin Creds?

```kql
// Find non-IT employees using systadmi_local_admin credentials (lateral movement indicator)
let hosts = FileCreationEvents
| where filename has "screenconnect"
| distinct hostname;
AuthenticationEvents
| where hostname in (hosts)
| where username has "systadmi"
| where result has "Successful"
| join (
    Employees
    | project ip_addr, role, email_addr, name
) on $left.src_ip == $right.ip_addr
| project SourceIpName=name, a="who is a", SourceIpUserRole=role, b="logged onto", hostname, c="using", username, d="at", timestamp
```

**Answer:** Robin Kirby (non-IT role) was using `systadmi_local_admin` credentials — clear sign of compromise.

---

## Part 2: Insider Threat — Jane Smith

---

### Q26 — Top Data Recipient on Feb 5

```kql
// Which external IP received the most data on Feb 5th?
NetworkFlow
| where timestamp between (datetime(2024-02-05T00:00:00Z) .. datetime(2024-02-05T23:59:59Z))
| summarize total_bytes = sum(bytes) by dest_ip
| top 1 by total_bytes desc
```

**Answer:** `182.56.23.121` — 12,716 bytes on that day alone.

---

### Q27 — Exfiltration Timeline

```kql
// When was data first sent to this suspicious IP?
NetworkFlow
| where dest_ip == "182.56.23.121"
```

**Answer:** First connection `2024-01-21T13:28:33Z`. Data sent over 27 distinct days.

---

### Q28 — Total Data Exfiltrated

```kql
// Total bytes exfiltrated to the suspicious IP
NetworkFlow
| where dest_ip == "182.56.23.121"
| summarize total_bytes = sum(bytes)
```

**Answer:** 208,138 bytes total across the campaign.

---

### Q29 — Identify the Insider

```kql
// Which employee's IP was the sole sender to the exfil IP?
NetworkFlow
| where dest_ip == "182.56.23.121"
| distinct src_ip

// Resolve IP to employee
Employees
| where ip_addr == "10.10.0.2"
```

**Answer:** Jane Smith | `jane_smith@encryptoderafinancial.com` | Host: `GOTI-LAPTOP`

---

### Q30 — Suspicious Web Research

```kql
// What was Jane researching on the company network?
InboundNetworkEvents
| where src_ip == "10.10.0.2"
```

**Answer:** Jane was looking for the location of the company's **cold storage crypto wallets**.

---

### Q31 — Handler Communications

```kql
// Who was Jane emailing suspiciously?
Email
| where sender == "jane_smith@encryptoderafinancial.com" or recipient == "jane_smith@encryptoderafinancial.com"
```

**Answer:** Communicating with `elboss@westealurcrypto.com` — Jane's external handler.

---

### Q32 — Exfil Tooling

```kql
// What tools did Jane download for the operation?
FileCreationEvents
| where hostname == "GOTI-LAPTOP"
```

**Answer:**
- `ftp_client.exe` — data exfiltration tool
- `crypto_stealer.exe` — cryptocurrency theft tool

> **MITRE:** T1071 — Application Layer Protocol (FTP for exfil)

---

### Q33 — Exfiltration Path & Schedule

```kql
// What path and schedule did Jane configure for her exfil tool?
ProcessEvents
| where hostname == "GOTI-LAPTOP" and timestamp >= (datetime(2024-01-21))
```

**Answer:**
- Exfil path: `C:\Users\jasmith\ToTheMoon\`
- Schedule: **daily** (decoded from Base64 command)
- Password: `Ugot2muchCRYTOw3llt4k3it0FFurH4ND5` (Base64 → reverse decoded via CyberChef)

> **MITRE:** T1567 — Exfiltration Over Web Service | T1560 — Archive Collected Data

---

## MITRE ATT&CK Coverage

| Tactic | ID | Technique | Query |
|---|---|---|---|
| Reconnaissance | T1589 | Gather Victim Identity Info | Q07, Q08 |
| Initial Access | T1566.002 | Spearphishing Link | Q20 |
| Execution | T1059.001 | PowerShell | Q14 |
| Execution | T1204.002 | Malicious File | Q18 |
| Persistence | T1053 | Scheduled Task | Q33 |
| Defence Evasion | T1036.007 | Double File Extension | Q18 |
| Defence Evasion | T1070 | Indicator Removal | Q14 |
| Credential Access | T1003.001 | LSASS Memory (Mimikatz) | Q24 |
| Discovery | T1082 | System Information Discovery | Q16 |
| Discovery | T1018 | Remote System Discovery | Q17 |
| Lateral Movement | T1570 | Lateral Tool Transfer | Q19, Q25 |
| Command & Control | T1219 | Remote Access Software | Q19 |
| Collection | T1560 | Archive Collected Data | Q10 |
| Exfiltration | T1567 | Exfiltration Over Web Service | Q33 |
| Impact | T1486 | Data Encrypted for Impact | Q11–Q15 |
| Impact | T1484.001 | Group Policy Modification | Q15 |
