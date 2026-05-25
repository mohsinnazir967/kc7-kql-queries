# 🕵️ Investigation 04 — Ransomware Deployment Against a Hospital (LockByte)

**Module:** KC7 — Security Analyst I | *"Jojo's Hospital: A Ransomware Investigation"*
**Sentinel Tables:** `DeviceFileEvents`, `DeviceProcessEvents`, `AzureNetworkAnalytics_CL`, `DnsEvents`, `SigninLogs`, `IdentityInfo`
**Difficulty:** Easy → Medium
**Completed:** 2024

---

## 📋 Investigation Summary

Jojo's Hospital was targeted in a multi-stage ransomware attack. Attackers started with **SEO poisoning** — placing a fake sponsored search result for "Raising Cane's" that redirected hospital employees to download a malicious Word document embedding **Cobalt Strike**. After establishing a foothold they moved laterally to Anthony Davis's machine, performed network reconnaissance, exfiltrated patient records and network credentials, deployed **LockByte ransomware**, then cleared their tracks.

**Attack Chain:**
\`\`\`
SEO Poisoning → Malicious Doc → Cobalt Strike C2 → Lateral Movement
→ Network Recon → Data Exfiltration → Ransomware Deployment → Track Clearing
\`\`\`

---

## 🗺️ MITRE ATT&CK Mapping

| Phase | Technique | ID |
|---|---|---|
| Reconnaissance | Search Open Websites/Domains | [T1593](https://attack.mitre.org/techniques/T1593/) |
| Initial Access | Drive-by Compromise (SEO Poisoning) | [T1189](https://attack.mitre.org/techniques/T1189/) |
| Initial Access | Spearphishing Link | [T1566.002](https://attack.mitre.org/techniques/T1566/002/) |
| Execution | User Execution: Malicious File | [T1204.002](https://attack.mitre.org/techniques/T1204/002/) |
| Execution | Command & Scripting Interpreter | [T1059](https://attack.mitre.org/techniques/T1059/) |
| Command & Control | Remote Access Software (Cobalt Strike) | [T1219](https://attack.mitre.org/techniques/T1219/) |
| Discovery | System Information Discovery | [T1082](https://attack.mitre.org/techniques/T1082/) |
| Discovery | Network Service Scanning | [T1046](https://attack.mitre.org/techniques/T1046/) |
| Lateral Movement | Lateral Tool Transfer | [T1570](https://attack.mitre.org/techniques/T1570/) |
| Collection | Archive Collected Data | [T1560](https://attack.mitre.org/techniques/T1560/) |
| Exfiltration | Exfiltration Over Web Service | [T1567](https://attack.mitre.org/techniques/T1567/) |
| Defence Evasion | Indicator Removal (Clear Tracks) | [T1070](https://attack.mitre.org/techniques/T1070/) |
| Impact | Data Encrypted for Impact (Ransomware) | [T1486](https://attack.mitre.org/techniques/T1486/) |

---

## 🔍 Query 1 — Count Total Encrypted Files

**Description:** Counts all files with a `.encrypted` extension across the environment to establish the full blast radius of the ransomware deployment.

**Why it matters in a SOC context:**
The encrypted file count is the first metric needed for an incident report and executive briefing. 6,420 files signals an organisation-wide deployment — not a single-machine incident.

**MITRE ATT&CK:** [T1486 — Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486/)
**Real Sentinel Table:** `DeviceFileEvents`

\`\`\`kql
// Count all files with the .encrypted extension across all endpoints
// Result: 6,420 encrypted files — confirms widespread ransomware deployment
FileCreationEvents
| where filename endswith ".encrypted"
| count
\`\`\`

---

## 🔍 Query 2 — Count Affected Hostnames

**Description:** Counts distinct hostnames that had files encrypted, revealing how many machines were compromised by the ransomware spread.

**Why it matters in a SOC context:**
321 affected machines means the ransomware propagated laterally across the network — this requires organisation-wide network isolation, not single-machine containment.

**MITRE ATT&CK:** [T1486 — Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486/)
**Real Sentinel Table:** `DeviceFileEvents`

\`\`\`kql
// Count distinct hostnames with encrypted files — establishes lateral spread scale
// Result: 321 machines — confirms network-wide ransomware propagation
FileCreationEvents
| where filename endswith ".encrypted"
| distinct hostname
| count
\`\`\`

---

## 🔍 Query 3 — Retrieve Ransom Note Details

**Description:** Retrieves the full record for the ransom note file including its SHA256 hash, file path, and host — establishing Patient Zero and the ransomware variant fingerprint.

**Why it matters in a SOC context:**
The SHA256 hash identifies the specific ransomware variant for VirusTotal lookup and threat intelligence sharing. The file path reveals which user account was the execution point, and the hostname identifies Patient Zero.

**MITRE ATT&CK:** [T1486 — Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486/)
**Real Sentinel Table:** `DeviceFileEvents`

\`\`\`kql
// Retrieve full metadata for the ransom note dropped by the attackers
// Key findings:
// - Ransom note: We_Have_Your_Data_Pay_Up.txt
// - SHA256: 97c348e95c8a8aeb8808f76434d73a92bbcb6b4586788365762b22624990b018
// - Path: C:\Users\andavis\Documents\We_Have_Your_Data_Pay_Up.txt
// - Hostname: AMFB-MACHINE (ransomware execution point)
FileCreationEvents
| where filename == "We_Have_Your_Data_Pay_Up.txt"
\`\`\`

---

## 🔍 Query 4 — Identify the Employee on the Ransomware Host

**Description:** Retrieves the employee record for the hostname where the ransom note was found, confirming which user account was the ransomware execution point.

**Why it matters in a SOC context:**
Identifying the employee tied to the execution host determines whose account needs immediate lockout, what data they had access to, and whether they were also a victim or an unwitting insider.

**MITRE ATT&CK:** [T1486 — Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486/)
**Real Sentinel Table:** `IdentityInfo`

\`\`\`kql
// Retrieve the employee record for the user on the ransomware execution machine
// Result: Anthony Davis — account used across the full attack chain
Employees
| where hostname == "AMFB-MACHINE"
\`\`\`

---

## 🔍 Query 5 — Enumerate All Processes During Ransomware Window

**Description:** Retrieves all process events on Anthony Davis's machine during the confirmed ransomware execution window, reconstructing the full attacker playbook step by step.

**Why it matters in a SOC context:**
Process event analysis during a known attack window provides every command run, tool executed, and file interaction during the incident. This is the core forensic technique for ransomware timeline reconstruction.

**MITRE ATT&CK:** [T1059 — Command & Scripting Interpreter](https://attack.mitre.org/techniques/T1059/)
**Real Sentinel Table:** `DeviceProcessEvents`

\`\`\`kql
// Retrieve all process events on Anthony's machine during the ransomware execution window
// Result: 14 process events
// Key tools identified in results:
// - lockbyte_ransomer.exe      → ransomware binary
// - spread_ransomware.exe      → copy renamed and pushed to network share for lateral spread
// - patient_data_exporter.exe  → data theft tool used before encryption
ProcessEvents
| where hostname == "AMFB-MACHINE"
| where timestamp between (datetime(2024-06-17) .. datetime(2024-06-18))
\`\`\`

---

## 🔍 Query 6 — Identify Patient Data Exfiltration Tool Download

**Description:** Searches outbound network events for the download of the patient data exporter executable, revealing the attacker domain and exact timestamp.

**Why it matters in a SOC context:**
The download timestamp is a key timeline anchor — everything before it is recon/staging, everything after is execution/impact. The source domain adds a new IOC to block across all perimeter controls.

**MITRE ATT&CK:** [T1567 — Exfiltration Over Web Service](https://attack.mitre.org/techniques/T1567/)
**Real Sentinel Table:** `AzureNetworkAnalytics_CL`

\`\`\`kql
// Identify download source and timestamp for the patient data exfiltration tool
// Result:
// - Domain: secure-health-access.com (attacker-controlled C2/exfil server)
// - Timestamp: 2024-06-17T14:22:29Z
OutboundNetworkEvents
| where url has "patient_data_exporter.exe"
\`\`\`

---

## 🔍 Query 7 — Resolve Attacker Domain to IPs

**Description:** Resolves the attacker's primary exfiltration domain via Passive DNS, revealing the full hosting infrastructure behind it.

**Why it matters in a SOC context:**
A domain resolving to multiple IPs indicates load-balanced or redundant attacker infrastructure — a sign of an organised threat actor. Both IPs must be blocked at the firewall and searched across all log sources.

**MITRE ATT&CK:** [T1584 — Compromise Infrastructure](https://attack.mitre.org/techniques/T1584/)
**Real Sentinel Table:** `DnsEvents`

\`\`\`kql
// Resolve the attacker's exfiltration domain to its hosting IPs
// Result: 2 distinct IPs — 203.0.113.1 and 203.0.113.2
PassiveDns
| where domain == "secure-health-access.com"
| distinct ip
\`\`\`

---

## 🔍 Query 8 — Discover Additional Attacker Domains on Same Infrastructure

**Description:** Pivots from the two attacker IPs to enumerate all domains hosted on the same infrastructure, expanding the IOC set.

**Why it matters in a SOC context:**
`emr-help.net` (EMR = Electronic Medical Records) was deliberately named to appear legitimate to hospital staff. Discovering it on the same IPs reveals secondary attacker infrastructure that may have been used in earlier recon or could be repurposed for future campaigns.

**MITRE ATT&CK:** [T1584 — Compromise Infrastructure](https://attack.mitre.org/techniques/T1584/)
**Real Sentinel Table:** `DnsEvents`

\`\`\`kql
// Pivot from attacker IPs to discover all associated domains on the same infrastructure
// Result: emr-help.net — healthcare-themed domain designed to appear legitimate
PassiveDns
| where ip in ("203.0.113.1", "203.0.113.2")
| distinct domain
\`\`\`

---

## 🔍 Query 9 — Count Attacker Reconnaissance Requests to Hospital Website

**Description:** Counts all inbound web requests from the attacker IPs to the hospital's public website, quantifying their pre-attack reconnaissance.

**Why it matters in a SOC context:**
37 requests from attacker IPs confirms sustained pre-attack reconnaissance. Key searches (security bypass, patient records) reveal the attacker's intent weeks before the ransomware deployed — this activity establishes an earlier timeline anchor than the initial access event.

**MITRE ATT&CK:** [T1593 — Search Open Websites/Domains](https://attack.mitre.org/techniques/T1593/)
**Real Sentinel Table:** `CommonSecurityLog`

\`\`\`kql
// Count all inbound web requests from attacker IPs to the hospital website
// Result: 37 requests — confirms sustained pre-attack reconnaissance
// Key findings: attackers searched for "how to bypass security" and patient record URLs
// First patient search URL: https://jojoshospital.org/search=JoJo%27s+Hospital+patient+records
InboundNetworkEvents
| where src_ip in ("203.0.113.1", "203.0.113.2")
\`\`\`

---

## 🔍 Query 10 — Identify Attacker Login Using Stolen Credentials

**Description:** Searches authentication logs for logins from the attacker IPs, confirming which account was compromised and when authenticated access was first established.

**Why it matters in a SOC context:**
The login timestamp (May 20) vs ransomware deployment (June 17) reveals a ~28-day dwell time — the attacker had persistent authenticated access for nearly a month before detonating the ransomware. This is a critical finding for the breach notification timeline.

**MITRE ATT&CK:** [T1078 — Valid Accounts](https://attack.mitre.org/techniques/T1078/)
**Real Sentinel Table:** `SigninLogs`

\`\`\`kql
// Find authentication events from attacker IPs to confirm credential use
// Key findings:
// - Timestamp: 2024-05-20T00:00:00Z (28 days before ransomware detonation)
// - IP used: 203.0.113.1
// - Account: andavis (Anthony Davis) — credentials obtained via Cobalt Strike
AuthenticationEvents
| where src_ip in ("203.0.113.1", "203.0.113.2")
\`\`\`

---

## 🔍 Query 11 — Attribute Compromised Username to Employee Record

**Description:** Cross-references the compromised username from the authentication log to the Employees table to confirm the victim's full identity and profile.

**Why it matters in a SOC context:**
Confirming the name behind a compromised username is required for HR notification, account lockout requests, and incident documentation. It also scopes what systems and data the attacker could access with those credentials.

**MITRE ATT&CK:** [T1078 — Valid Accounts](https://attack.mitre.org/techniques/T1078/)
**Real Sentinel Table:** `IdentityInfo`

\`\`\`kql
// Confirm full employee identity behind the compromised username
// Result: Anthony Davis — credentials used for both recon login and ransomware execution
Employees
| where username == "andavis"
\`\`\`

---

## 🔍 Query 12 — Count Web Requests to the SEO Poisoning Domain

**Description:** Counts outbound web requests to the fake typosquat domain used in the SEO poisoning attack, revealing how many employees were exposed.

**Why it matters in a SOC context:**
SEO poisoning affects users who searched for something entirely legitimate. 24 unique employees clicking a fake sponsored search result means 24 potential victims — each endpoint must be independently investigated for the Cobalt Strike implant.

**MITRE ATT&CK:** [T1189 — Drive-by Compromise](https://attack.mitre.org/techniques/T1189/)
**Real Sentinel Table:** `AzureNetworkAnalytics_CL`

\`\`\`kql
// Count employees who visited the fake Raising Cane's typosquat domain
// raisinkanes.com (attacker) vs raisingcanes.com (legitimate) — one letter difference
// Result: 26 total requests from 24 unique internal IPs (24 employees exposed)
OutboundNetworkEvents
| where url contains "raisinkanes.com"
| distinct src_ip
| count
\`\`\`

---

## 🔍 Query 13 — Identify Malicious Redirect Chain Domains

**Description:** Traces the full redirect chain from the typosquat domain to the payload delivery hosts, uncovering the intermediate attacker domains used to evade URL detection.

**Why it matters in a SOC context:**
Multi-hop redirect chains obscure the final payload domain from URL-based security controls. Every hop in the chain is a separate IOC that must be blocked and hunted across all network logs — blocking only the typosquat domain without blocking the redirects leaves the payload delivery path open.

**MITRE ATT&CK:** [T1189 — Drive-by Compromise](https://attack.mitre.org/techniques/T1189/)
**Real Sentinel Table:** `AzureNetworkAnalytics_CL`

\`\`\`kql
// Identify redirect domain 1 — used to route victims from the typosquat to the payload
// Result: nothing-to-see-here.net (deliberately innocuous-sounding name)
OutboundNetworkEvents
| where url contains "raisinkanes.com"
    and url contains "nothing"

// Redirect domain 2 (identified via same pattern search):
// totally-legit-domain.com — both domains named to evade casual inspection
\`\`\`

---

## 🔍 Query 14 — Identify Malicious Payload Filenames

**Description:** Searches outbound network events through the redirect chain to identify the exact payload filenames delivered to victims.

**Why it matters in a SOC context:**
Knowing the exact filenames allows analysts to hunt across all endpoints using FileCreationEvents — finding every machine where either payload landed. A `.docx` disguised as a restaurant promo and a `.pdf` meal voucher are classic social engineering lures targeting non-technical staff.

**MITRE ATT&CK:** [T1204.002 — User Execution: Malicious File](https://attack.mitre.org/techniques/T1204/002/)
**Real Sentinel Table:** `AzureNetworkAnalytics_CL`

\`\`\`kql
// Identify the malicious payload filenames delivered via the redirect chain
// Result:
// - Raisin_Kane_Promo_Offer.docx          → malicious Word doc (drops Cobalt Strike)
// - Raisin_Kane_Free_Meal_Voucher.pdf     → secondary social engineering lure
OutboundNetworkEvents
| where url contains "nothing"
\`\`\`

---

## 🔍 Query 15 — Identify Patient Zero for the Malicious Document

**Description:** Searches file creation events for the first machine to receive the malicious `.docx`, identifying the initial access point of the SEO poisoning campaign.

**Why it matters in a SOC context:**
Patient Zero has the longest dwell time and likely the most complete attacker activity on disk. It is the priority machine for forensic investigation and containment — and its SHA256 hash enables cross-environment threat intelligence sharing.

**MITRE ATT&CK:** [T1204.002 — User Execution: Malicious File](https://attack.mitre.org/techniques/T1204/002/)
**Real Sentinel Table:** `DeviceFileEvents`

\`\`\`kql
// Find the first machine to download the malicious Word document
// Key findings:
// - Hostname: RQJQ-MACHINE (initial access Patient Zero)
// - Timestamp: 2024-05-01T09:56:50Z
// - SHA256: bd886046266b909a8ca5f19f16e5606baf73194a70632c81fdc44ef39ba29712
// - Browser: chrome.exe (victim used Google Chrome)
FileCreationEvents
| where filename == "Raisin_Kane_Promo_Offer.docx"
\`\`\`

---

## 🔍 Query 16 — Identify the Cobalt Strike Implant Dropped on Patient Zero

**Description:** Searches file creation events on the compromised machine for additional files dropped alongside the lure document — revealing the Cobalt Strike implant.

**Why it matters in a SOC context:**
Cobalt Strike is one of the most widely used C2 frameworks by ransomware operators. Its presence confirms this is a hands-on targeted operation. The filename is an IOC for cross-environment hunting and VirusTotal submission.

**MITRE ATT&CK:** [T1219 — Remote Access Software](https://attack.mitre.org/techniques/T1219/)
**Real Sentinel Table:** `DeviceFileEvents`

\`\`\`kql
// Hunt for all files created on Patient Zero — reveals Cobalt Strike implant
// Result: cobaltstrike.exe — C2 implant dropped via malicious Word macro
FileCreationEvents
| where hostname == "RQJQ-MACHINE"
\`\`\`

---

## 🔍 Query 17 — Confirm Malicious Document Execution via Process Log

**Description:** Retrieves the exact process command line used to open the malicious Word document on the victim machine, providing forensic evidence of execution.

**Why it matters in a SOC context:**
The process command line is forensic proof of execution — it appears in incident reports, legal documentation, and threat intelligence. It also confirms the Office version path and the user account (`evbrowne`) under which the document ran.

**MITRE ATT&CK:** [T1204.002 — User Execution: Malicious File](https://attack.mitre.org/techniques/T1204/002/)
**Real Sentinel Table:** `DeviceProcessEvents`

\`\`\`kql
// Confirm malicious Word document execution via process event log
// Full command: "C:\Program Files\Microsoft Office\Office16\WINWORD.EXE"
//               "C:\Users\evbrowne\Downloads\Raisin_Kane_Promo_Offer.docx"
ProcessEvents
| where hostname == "RQJQ-MACHINE"
| where timestamp between (datetime(2024-05-01) .. datetime(2024-05-02))
| where process_commandline contains "Raisin_Kane_Promo_Offer.docx"
\`\`\`

---

## 🔍 Query 18 — Identify Cobalt Strike C2 IP and Port

**Description:** Searches process events for Cobalt Strike execution, revealing the attacker's C2 server IP and the port used for command-and-control communication.

**Why it matters in a SOC context:**
Port 50050 is the default Cobalt Strike Team Server listener — its appearance in process logs alongside a `cobaltstrike.exe` filename is a near-certain detection signal. The C2 IP must be blocked at the firewall immediately and searched across all hosts for additional beacons.

**MITRE ATT&CK:** [T1219 — Remote Access Software](https://attack.mitre.org/techniques/T1219/)
**Real Sentinel Table:** `DeviceProcessEvents`

\`\`\`kql
// Retrieve Cobalt Strike C2 connection details from process logs
// Key findings:
// - C2 IP: 93.238.22.122
// - Port: 50050 (default Cobalt Strike Team Server listener port)
ProcessEvents
| where hostname == "RQJQ-MACHINE"
| where timestamp between (datetime(2024-05-01) .. datetime(2024-05-02))
| where process_commandline contains "cobalt"
\`\`\`

---

## 🔍 Query 19 — Identify Post-Compromise Discovery Commands on Patient Zero

**Description:** Searches for `systeminfo` and other discovery commands run by the attacker immediately after gaining access, confirming hands-on-keyboard activity.

**Why it matters in a SOC context:**
`systeminfo` is almost universally the first command a threat actor runs after establishing a foothold — it reveals OS version, patch level, domain membership, and hotfixes. Six discovery commands in sequence is a textbook hands-on attacker recon pattern that can be used to build a behavioural detection rule.

**MITRE ATT&CK:** [T1082 — System Information Discovery](https://attack.mitre.org/techniques/T1082/)
**Real Sentinel Table:** `DeviceProcessEvents`

\`\`\`kql
// Identify post-Cobalt Strike discovery commands on Patient Zero
// First command: systeminfo — standard initial attacker recon
// Result: 6 short discovery commands executed in sequence over 3 days
ProcessEvents
| where hostname == "RQJQ-MACHINE"
| where timestamp between (datetime(2024-05-01) .. datetime(2024-05-04))
| where process_commandline contains "systeminfo"
\`\`\`

---

## 🔍 Query 20 — Confirm Cobalt Strike Lateral Movement to Anthony Davis's Machine

**Description:** Searches process events on the second compromised machine for Cobalt Strike execution, confirming successful lateral movement and a second C2 beachhead.

**Why it matters in a SOC context:**
Cobalt Strike on a second machine 13 days after initial compromise confirms deliberate, slow lateral movement — a hallmark of pre-ransomware operations. The extended dwell time means the attacker had significant time to map the network and stage the ransomware payload.

**MITRE ATT&CK:** [T1570 — Lateral Tool Transfer](https://attack.mitre.org/techniques/T1570/)
**Real Sentinel Table:** `DeviceProcessEvents`

\`\`\`kql
// Confirm Cobalt Strike beachhead on Anthony Davis's machine
// Result: 2024-05-14T12:24:45Z — 13 days after initial Patient Zero compromise
// Confirms deliberate lateral movement as part of pre-ransomware staging
ProcessEvents
| where hostname == "AMFB-MACHINE"
| where process_commandline contains "cobalt"
\`\`\`

---

## 🔍 Query 21 — Identify Network Scanning Tool Used for Ransomware Staging

**Description:** Searches process events on Anthony Davis's machine during the reconnaissance phase to identify the tool used to map the hospital's internal network before deploying ransomware across 321 hosts.

**Why it matters in a SOC context:**
`advanced-ip-scanner.exe` is a free, legitimate tool routinely abused by ransomware operators to identify live hosts, open ports, and network shares before lateral deployment. Its presence during an active incident signals the attacker is actively mapping targets for ransomware spread — immediate network segmentation is required.

**MITRE ATT&CK:** [T1046 — Network Service Scanning](https://attack.mitre.org/techniques/T1046/)
**Real Sentinel Table:** `DeviceProcessEvents`

\`\`\`kql
// Identify network reconnaissance tool run in the days preceding ransomware deployment
// Result: advanced-ip-scanner.exe — used to enumerate 321+ machines on the hospital network
// This tool use directly preceded the ransomware spreading to 321 hosts
ProcessEvents
| where hostname == "AMFB-MACHINE"
| where timestamp between (datetime(2024-05-13) .. datetime(2024-05-17))
\`\`\`

---

## 🔍 Query 22 — Confirm Exfiltration Domain Used for Patient Data Theft

**Description:** Cross-references the exfiltration domain with outbound network events to confirm patient data transfers, completing the data breach evidence chain.

**Why it matters in a SOC context:**
Exfiltration of patient data (Protected Health Information / PHI) from a hospital is a HIPAA breach event requiring mandatory regulatory notification. Confirming the exfil domain, the three patient record archive paths, and the volume of data staged establishes the full scope of the data breach for legal and regulatory reporting.

**MITRE ATT&CK:** [T1567 — Exfiltration Over Web Service](https://attack.mitre.org/techniques/T1567/)
**Real Sentinel Table:** `AzureNetworkAnalytics_CL`

\`\`\`kql
// Confirm patient data exfiltration to the attacker-controlled exfil domain
// Three data archives exfiltrated from hospital network shares:
// - patient_data_1.zip → \\jojos-hospital-server\important_data\patient_records
// - patient_data_2.zip → \\jojos-hospital-server\important_data\archive\patient-records
// - patient_data_3.zip → \\jojos-hospital-server\important_data\old-patient-data
// Exfil destination: secure-health-access.com
OutboundNetworkEvents
| where url has "patient_data_exporter.exe"
\`\`\`

---

## 🔍 Query 23 — Detect Track-Clearing Command After Exfiltration

**Description:** Identifies the `del` command used by the attacker to delete the patient data zip files after exfiltration, covering their tracks before ransomware detonation.

**Why it matters in a SOC context:**
Track-clearing via wildcard `del` commands is one of the final pre-detonation steps in a ransomware operation. Identifying this command proves data was exfiltrated before encryption — establishing a double-extortion attack pattern and confirming a data breach separate from the ransomware event itself.

**MITRE ATT&CK:** [T1070 — Indicator Removal](https://attack.mitre.org/techniques/T1070/)
**Real Sentinel Table:** `DeviceProcessEvents`

\`\`\`kql
// Detect the track-clearing command executed after patient data exfiltration
// Full command: cmd.exe /c del C:\Users\andavis\Documents\patient_data_*.zip
// Wildcard deletion of all staged patient archives — run immediately before ransomware
ProcessEvents
| where hostname == "AMFB-MACHINE"
| where timestamp between (datetime(2024-06-17) .. datetime(2024-06-18))
| where process_commandline contains "del"   // Scope to deletion commands
\`\`\`

---

## 📌 Investigation Notes

### Key Indicators of Compromise

| Indicator | Value | Type |
|-----------|-------|------|
| Patient Zero Host | `RQJQ-MACHINE` | Host IOC |
| Ransomware Execution Host | `AMFB-MACHINE` (Anthony Davis) | Host IOC |
| Anthony Davis IP | `10.10.0.1` | Network IOC |
| SEO Poison Domain | `raisinkanes.com` | Domain IOC |
| Legitimate Domain | `raisingcanes.com` | Reference |
| Redirect Domain 1 | `nothing-to-see-here.net` | Domain IOC |
| Redirect Domain 2 | `totally-legit-domain.com` | Domain IOC |
| Lure Document | `Raisin_Kane_Promo_Offer.docx` | File IOC |
| Lure Doc SHA256 | `bd886046266b909a8ca5f19f16e5606baf73194a70632c81fdc44ef39ba29712` | Hash IOC |
| Lure PDF | `Raisin_Kane_Free_Meal_Voucher.pdf` | File IOC |
| Cobalt Strike Binary | `cobaltstrike.exe` | File IOC |
| C2 IP | `93.238.22.122` | Network IOC |
| C2 Port | `50050` (default Cobalt Strike port) | Network IOC |
| Ransomware Binary | `lockbyte_ransomer.exe` | File IOC |
| Network Spread Copy | `spread_ransomware.exe` | File IOC |
| Exfil Tool | `patient_data_exporter.exe` | File IOC |
| Exfil Domain | `secure-health-access.com` | Domain IOC |
| Exfil IP 1 | `203.0.113.1` | Network IOC |
| Exfil IP 2 | `203.0.113.2` | Network IOC |
| Related Domain | `emr-help.net` | Domain IOC |
| Network Recon Tool | `advanced-ip-scanner.exe` | Tool IOC |
| Stolen File 1 | `network_diagrams.pdf` | Exfiltrated Data |
| Stolen File 2 | `credentials.txt` | Exfiltrated Data |
| Stolen Archive | `important_network_info.zip` | Exfiltrated Data |
| Ransom Note | `We_Have_Your_Data_Pay_Up.txt` | File IOC |
| Ransom Note SHA256 | `97c348e95c8a8aeb8808f76434d73a92bbcb6b4586788365762b22624990b018` | Hash IOC |
| Track Clear Command | `cmd.exe /c del C:\Users\andavis\Documents\patient_data_*.zip` | Command IOC |
| Total Encrypted Files | `6,420` | Impact Metric |
| Affected Hosts | `321` | Impact Metric |
| Attacker Recon Requests | `37` inbound to hospital website | Impact Metric |
| Employees Exposed (SEO) | `24` unique IPs | Impact Metric |

### Attack Timeline

| Timestamp | Event |
|-----------|-------|
| Pre-attack | Attacker conducts 37 recon requests against `jojoshospital.org` |
| `2024-05-01T09:56:50Z` | Patient Zero (RQJQ-MACHINE) downloads `Raisin_Kane_Promo_Offer.docx` via Chrome |
| `2024-05-01` | `cobaltstrike.exe` dropped; C2 beacon established to `93.238.22.122:50050` |
| `2024-05-01 – 05-04` | 6 discovery commands run on RQJQ-MACHINE |
| `2024-05-14T12:24:45Z` | Cobalt Strike laterally moved to AMFB-MACHINE (Anthony Davis) |
| `2024-05-13 – 05-17` | Network scan with `advanced-ip-scanner.exe` — 321+ hosts identified |
| `2024-05-20T00:00:00Z` | Attacker logs in externally using Anthony Davis credentials (IP: `203.0.113.1`) |
| `2024-06-17T14:22:29Z` | `patient_data_exporter.exe` downloaded from `secure-health-access.com` |
| `2024-06-17` | Three patient data archives exfiltrated to `secure-health-access.com` |
| `2024-06-17` | Track clearing: `cmd.exe /c del ...patient_data_*.zip` |
| `2024-06-17` | `lockbyte_ransomer.exe` executed; `spread_ransomware.exe` pushed to network share |
| `2024-06-17 – 06-18` | **6,420 files encrypted across 321 hosts** |

---

## 🔗 References

- [MITRE ATT&CK — Data Encrypted for Impact (T1486)](https://attack.mitre.org/techniques/T1486/)
- [MITRE ATT&CK — Drive-by Compromise (T1189)](https://attack.mitre.org/techniques/T1189/)
- [MITRE ATT&CK — Remote Access Software / Cobalt Strike (T1219)](https://attack.mitre.org/techniques/T1219/)
- [MITRE ATT&CK — Indicator Removal (T1070)](https://attack.mitre.org/techniques/T1070/)
- [CISA — StopRansomware Guidance](https://www.cisa.gov/stopransomware)
- [Microsoft Sentinel — DeviceProcessEvents](https://learn.microsoft.com/en-us/azure/sentinel/normalization-schema-process-events)
- [Microsoft Sentinel — DeviceFileEvents](https://learn.microsoft.com/en-us/azure/monitor/reference/tables/devicefileevents)

---

*← [Back to Security Analyst I Module](./README.md) | [Back to Repository Root](../../README.md)*
