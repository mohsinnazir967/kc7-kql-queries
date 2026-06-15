# 🕵️ Investigation 01 — Spearphishing & Account Takeover via Credential Abuse

**Module:** KC7 — Security Analyst I | *"A Rap Beef"*
**Sentinel Tables:** `IdentityInfo`, `EmailEvents`, `CommonSecurityLog`, `DnsEvents`, `SigninLogs`
**Difficulty:** Beginner
**Completed:** 2024

---

## 📋 Investigation Summary

A threat intelligence contact tipped off the OWL Records SOC that a hacker using IP `18.66.52.227` — hired by rival label Dollar Currency Records (DCR) — was probing the company's infrastructure. The attacker exploited personal details that artist Dwake accidentally revealed in his rap lyrics (mother's maiden name, childhood street, pet name) to answer password-reset security questions and take over his account.

This investigation traces the full attack chain:

```
Reconnaissance → Phishing Delivery → User Execution → Credential Abuse → Account Takeover → Persistence
```

---

## 🗺️ MITRE ATT&CK Mapping

| Phase | Technique | ID |
|---|---|---|
| Reconnaissance | Search Open Websites/Domains | [T1593](https://attack.mitre.org/techniques/T1593/) |
| Reconnaissance | Gather Victim Identity Information: Email Addresses | [T1589.002](https://attack.mitre.org/techniques/T1589/002/) |
| Resource Development | Compromise Infrastructure | [T1584](https://attack.mitre.org/techniques/T1584/) |
| Initial Access | Spearphishing Link | [T1566.002](https://attack.mitre.org/techniques/T1566/002/) |
| Execution | Malicious Link (User Click) | [T1204.001](https://attack.mitre.org/techniques/T1204/001/) |
| Credential Access | Valid Accounts | [T1078](https://attack.mitre.org/techniques/T1078/) |
| Persistence | External Remote Services | [T1133](https://attack.mitre.org/techniques/T1133/) |
| Command & Control | Application Layer Protocol | [T1071](https://attack.mitre.org/techniques/T1071/) |

---

## 🔍 Query 1 — Identify the CEO

**Description:** Retrieves the employee record for the CEO role to establish a key target profile.

**Why it matters in a SOC context:**
Executives are high-value targets for Business Email Compromise (BEC), whaling, and espionage operations. Knowing who holds the CEO role helps analysts prioritise alert triage and correlate suspicious activity against VIP accounts.

**MITRE ATT&CK:** [T1589.002 — Gather Victim Identity Information: Email Addresses](https://attack.mitre.org/techniques/T1589/002/)
**Real Sentinel Table:** `IdentityInfo`

```kql
// Query the Employees table to find the record where role equals CEO
// Used to identify high-value targets for phishing or account compromise
Employees
| where role == "CEO"
```

---

## 🔍 Query 2 — Scope Suspicious Inbound Traffic from Known Malicious IP

**Description:** Filters inbound network events on a specific date range originating from the threat actor's IP to understand the scope of reconnaissance activity.

**Why it matters in a SOC context:**
Identifying all connections from a known-bad IP during a suspected attack window helps analysts establish a timeline and determine whether the attacker targeted one user or the entire organisation.

**MITRE ATT&CK:** [T1590 — Gather Victim Network Information](https://attack.mitre.org/techniques/T1590/)
**Real Sentinel Table:** `CommonSecurityLog` / `AzureNetworkAnalytics_CL`

```kql
// Filter InboundNetworkEvents to the suspected attack window (April 10, 2024)
// Scopes all web requests originating from the known threat actor IP
InboundNetworkEvents
| where timestamp between (datetime("2024-04-10T00:00:00") .. datetime("2024-04-11T00:00:00"))
| where src_ip has "18.66.52.227"   // Known attacker IP provided by threat intel contact
```

---

## 🔍 Query 3 — Identify Targeted Reconnaissance URLs

**Description:** Narrows inbound traffic from the threat actor IP to requests containing artist-specific keywords, confirming targeted OSINT-driven intelligence gathering.

**Why it matters in a SOC context:**
Attackers conducting pre-attack reconnaissance often query public-facing systems for specific personal details. Filtering URLs for personal keywords (names, pet names, street names) reveals *what* information was being harvested — in this case, directly mapping to the company's password-reset security questions.

**MITRE ATT&CK:** [T1593 — Search Open Websites/Domains](https://attack.mitre.org/techniques/T1593/)
**Real Sentinel Table:** `CommonSecurityLog` / `W3CIISLog`

```kql
// Further refine inbound traffic from attacker IP to URL hits containing
// artist-specific personal keywords: "washington" (childhood street) and "fluffy" (pet name)
// These map directly to OWL Records password-reset challenge questions,
// confirming the attacker was harvesting OSINT to prepare a credential attack
InboundNetworkEvents
| where timestamp between (datetime("2024-04-10T00:00:00") .. datetime("2024-04-11T00:00:00"))
| where url has_any ("washington", "fluffy")   // Keywords from Dwake's rap lyrics (OSINT)
| where src_ip has "18.66.52.227"              // Scoped to the confirmed threat actor IP
```

---

## 🔍 Query 4 — Passive DNS Lookup to Identify Attacker Infrastructure

**Description:** Resolves the attacker's IP to its associated domain name to confirm and document threat actor infrastructure used in the campaign.

**Why it matters in a SOC context:**
Pivoting from an IP to a domain is a core threat intelligence technique. Confirming the domain behind a malicious IP allows analysts to expand their search, block the full infrastructure (not just the IP), and correlate against email and web logs using the domain as an indicator.

**MITRE ATT&CK:** [T1584 — Compromise Infrastructure](https://attack.mitre.org/techniques/T1584/)
**Real Sentinel Table:** `DnsEvents`

```kql
// Resolve the attacker's IP in Passive DNS records to identify the phishing domain
// Result: betterlyrics4u.com — an attacker-controlled phishing domain
PassiveDns
| where ip == "18.66.52.227"   // Known threat actor IP → resolves to betterlyrics4u.com
```

---

## 🔍 Query 5 — Baseline the Email Table

**Description:** Samples 10 rows from the Email table to understand its schema before writing targeted queries.

**Why it matters in a SOC context:**
Before hunting in an unfamiliar log source, analysts should always baseline the data. Understanding field names, formats, and available columns prevents query errors and significantly speeds up the investigation.

**MITRE ATT&CK:** N/A *(exploratory / schema baseline query)*
**Real Sentinel Table:** `EmailEvents`

```kql
// Preview the Email table to understand available fields and data format
// Always do this before writing targeted queries against a new table
Email
| take 10
```

---

## 🔍 Query 6 — Hunt for Phishing Emails Containing Malicious Domain

**Description:** Searches the Email table for any messages containing a link to the attacker-controlled domain `betterlyrics4u.com`.

**Why it matters in a SOC context:**
After identifying attacker infrastructure via Passive DNS, hunting that domain in email logs is the critical next step to confirm phishing campaign delivery. This surfaces every recipient who received the malicious link, establishing the full scope of the attack.

**MITRE ATT&CK:** [T1566.002 — Phishing: Spearphishing Link](https://attack.mitre.org/techniques/T1566/002/)
**Real Sentinel Table:** `EmailEvents`

```kql
// Search all inbound emails for links pointing to the attacker-controlled phishing domain
// Confirms the phishing campaign delivery vector and scopes recipients
Email
| where link has "betterlyrics4u.com"
```

---

## 🔍 Query 7 — Identify All Employees Who Received the Phishing Email

**Description:** Uses a `let` statement to build a reusable set of phishing email recipients, then joins to the Employees table to reveal names, roles, and contact details of targeted staff.

**Why it matters in a SOC context:**
Knowing *which employees* received a phishing email is essential for scoping containment. It determines who needs immediate password resets, who to interview, and which accounts are at risk. Correlating email addresses to HR records reveals the organisational blast radius and whether any privileged accounts were targeted.

**MITRE ATT&CK:** [T1566.002 — Phishing: Spearphishing Link](https://attack.mitre.org/techniques/T1566/002/)
**Real Sentinel Table:** `EmailEvents` + `IdentityInfo`

```kql
// Step 1: Store all unique recipients of the phishing email in a reusable variable
let _target = Email
| where link has "betterlyrics4u.com"   // Filter to emails containing the malicious link
| distinct recipient;                    // De-duplicate to get unique recipient addresses only

// Step 2: Cross-reference phishing recipients against the Employees table
// Reveals full employee profiles (name, role, department) of everyone targeted
Employees
| where email_addr in (_target)          // Match employee records to phishing recipient list
```

---

## 🔍 Query 8 — Confirm Victim Clicked the Phishing Link

**Description:** Searches outbound network events for an internal host connecting to the phishing URL, confirming a user executed the malicious link.

**Why it matters in a SOC context:**
Receiving a phishing email is a threat. *Clicking the link* is a confirmed incident. This query moves the investigation from potential exposure to proven execution — triggering a severity escalation, mandatory IR procedures, and immediate account containment.

**MITRE ATT&CK:** [T1204.001 — User Execution: Malicious Link](https://attack.mitre.org/techniques/T1204/001/)
**Real Sentinel Table:** `AzureNetworkAnalytics_CL` / `CommonSecurityLog`

```kql
// Confirm that internal host 10.10.0.5 made an outbound connection
// to the full phishing URL — proving the victim clicked the malicious link
OutboundNetworkEvents
| where url == "http://betterlyrics4u.com/share/online/published/enter"   // Full phishing URL
| where src_ip == "10.10.0.5"    // Internal IP of the victim's workstation
```

---

## 🔍 Query 9 — Confirm External Authentication from Attacker IP

**Description:** Checks authentication logs for login attempts against the compromised user account (`dwaudrey`) originating from the external threat actor IP.

**Why it matters in a SOC context:**
A successful authentication using valid credentials from a known-malicious IP is a high-confidence indicator of account takeover. This query provides the forensic evidence needed to confirm credential compromise and justify immediate account lockout and password reset.

**MITRE ATT&CK:** [T1078 — Valid Accounts](https://attack.mitre.org/techniques/T1078/)
**Real Sentinel Table:** `SigninLogs` / `AADSignInEventsBeta`

```kql
// Hunt for authentication events on Dwake's account (username: dwaudrey)
// where the login originated from the threat actor's known external IP
// A match here confirms successful account takeover
AuthenticationEvents
| where username == "dwaudrey"          // Compromised employee account (Dwake)
| where src_ip == "18.66.52.227"        // Login source = confirmed threat actor IP
```

---

## 🔍 Query 10 — Detect Post-Compromise Persistent Access / C2 Activity

**Description:** Hunts for continued inbound network activity from the threat actor IP after the confirmed compromise date, specifically looking for the victim's username appearing in accessed URLs — indicating persistent access or data exfiltration.

**Why it matters in a SOC context:**
Post-compromise traffic from an attacker IP referencing a victim's account identifiers confirms the intrusion extended beyond initial access. This establishes the full dwell time of the attacker, supports evidence of persistent access or C2 communication, and is critical for scoping the complete incident response.

**MITRE ATT&CK:** [T1133 — External Remote Services](https://attack.mitre.org/techniques/T1133/) / [T1071 — Application Layer Protocol](https://attack.mitre.org/techniques/T1071/)
**Real Sentinel Table:** `CommonSecurityLog` / `AzureNetworkAnalytics_CL`

```kql
// After confirmed compromise (April 12 onward), hunt for continued attacker access
// Searching for victim's username in URLs accessed from the attacker's IP
// Indicates persistent access, session hijacking, or ongoing data exfiltration
InboundNetworkEvents
| where timestamp between (datetime("2024-04-12T00:00:00") .. datetime("2024-05-01T00:00:00"))  // Post-compromise window
| where url has "dwaudrey"          // Victim's username appearing in attacker-accessed URLs
| where src_ip has "18.66.52.227"   // Scoped to confirmed threat actor IP
```

---

## 📌 Investigation Notes

| Indicator | Value | Type |
|-----------|-------|------|
| Threat Actor IP | `18.66.52.227` | Network IOC |
| Phishing Domain | `betterlyrics4u.com` | Domain IOC |
| Phishing URL | `http://betterlyrics4u.com/share/online/published/enter` | URL IOC |
| Victim Username | `dwaudrey` (Dwake) | Identity |
| Victim Workstation | `10.10.0.5` | Network IOC |
| Attack Start Date | `2024-04-10` | Timeline |
| Compromise Confirmed | `2024-04-12` | Timeline |

---

## 🔗 References

- [KC7 Cyber — A Rap Beef Module](https://kc7cyber.com)
- [MITRE ATT&CK — Phishing: Spearphishing Link (T1566.002)](https://attack.mitre.org/techniques/T1566/002/)
- [MITRE ATT&CK — Valid Accounts (T1078)](https://attack.mitre.org/techniques/T1078/)
- [Microsoft Sentinel — EmailEvents Table](https://learn.microsoft.com/en-us/azure/sentinel/normalization-schema-email)
- [Microsoft Sentinel — SigninLogs Table](https://learn.microsoft.com/en-us/azure/monitor/reference/tables/signinlogs)

---

*← [Back to Security Analyst I Module](./README.md) | [Back to Repository Root](../../README.md)*
