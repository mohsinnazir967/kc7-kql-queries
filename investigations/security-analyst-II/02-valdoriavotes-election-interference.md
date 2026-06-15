# ValdoriaVotes — Election Interference & Credential Phishing

**Module:** Security Analyst II | **Environment:** ValdoriaVotes Government  
**Status:** ✅ Complete | **Queries:** 20  
**Attack Type:** Phishing Site → Credential Harvest → Account Takeover → AI System Enumeration → Vendor Impersonation

---

## Module Overview

An investigation into an election interference campaign targeting the Valdoria electoral commission. Threat actors built a convincing fake government domain, harvested credentials from election staff, used AI prompts to extract operational intelligence, and ultimately impersonated the Election Commissioner to obtain voting machine documentation from the vendor.

**Tables Used:** `Employees`, `Email`, `InboundNetworkEvents`, `OutboundNetworkEvents`, `PassiveDns`, `AuthenticationEvents`, `AIPrompts`

---

## Attack Chain Summary

```
Threat Actor infrastructure
  └─ IP: 55.49.227.170 (exposed in propaganda poster)
       └─ Domains: valdoriavotesgov.com (typosquat of valdoriavotes.gov)
            └─ Phishing page → Anderson Snooper credentials harvested
                 └─ TA logged in as "ansnooper" from 214.85.104.248
                      └─ AI System enumeration (subdomain guessing)
                           └─ Prompt injection → voting machine intel extracted
                                └─ Bobama account compromised
                                     └─ Email sent to help@dominosvotingsystems.com
                                          └─ ValdoriaVotingMachinesNetworkGuide.pdf received
```

---

## Queries

---

### Q01 — Identify Key Personnel

```kql
// Find the Deputy Commissioner
Employees
| where role == "Deputy Commissioner"
```

**Answer:** Hilary Binton

```kql
// Find supervisor roles
Employees
| where role contains "supervisor"
```

**Answer:** Barry Schmelly — Temp Election Support Staff Supervisor

---

### Q02 — Employee IP Lookup

```kql
// Get Barry Schmelly's full profile
Employees
| where name == "Barry Schmelly"
```

**Result:** IP `10.10.0.12` | Host `GCH3-DESKTOP` | Email `barry_schmelly@valdoriavotes.gov`

---

### Q03 — Email Volume Check

```kql
// How many emails did Barry Schmelly receive?
Email
| where recipient == "barry_schmelly@valdoriavotes.gov"
| count
```

**Answer:** 37 emails.

---

### Q04 — Process Activity on Suspect Machine

```kql
// How many distinct commands ran on Barry's machine?
ProcessEvents
| where hostname == "GCH3-DESKTOP"
| distinct process_commandline
```

**Answer:** 173 distinct commands.

---

### Q05 — Bulk URL Activity

```kql
// URLs visited by all employees named William
let will_ips =
Employees
| where name has "William"
| distinct ip_addr;
OutboundNetworkEvents
| where src_ip in (will_ips)
| distinct url
```

**Answer:** 217 distinct URLs.

---

### Q06 — Authentication Volume

```kql
// Auth attempts against all William accounts
let william_username =
Employees
| where name has "William"
| distinct username;
AuthenticationEvents
| where username in (william_username)
```

**Answer:** 183 authentication attempts.

---

### Q07 — Threat Actor IP in OSINT

```kql
// Check if the exposed IP 55.49.227.170 appears in inbound traffic
InboundNetworkEvents
| where src_ip == "55.49.227.170"
```

> **SOC Context:** A threat actor IP was inadvertently embedded in a propaganda poster — classic OPSEC failure that becomes an IOC. Always cross-reference discovered IPs against network logs.

---

### Q08 — PassiveDns Pivot on Threat Actor IP

```kql
// How many domains resolve to the threat actor's IP?
PassiveDns
| where ip == "55.49.227.170"
```

**Answer:** 2 domains. The Valdoria-related one: `valdoriavotesgov.com` (typosquat of `valdoriavotes.gov`).

> **MITRE:** T1583 — Acquire Infrastructure | T1584 — Compromise Infrastructure

---

### Q09 — Fake Domain IP Resolution

```kql
// All IPs the fraudulent domain has resolved to
PassiveDns
| where domain == "valdoriavotesgov.com"
```

---

### Q10 — Inbound Traffic from Phishing IPs

```kql
// Did the attackers probe our network from the fake domain's IPs?
let mal_ips =
PassiveDns
| where domain == "valdoriavotesgov.com"
| distinct ip;
InboundNetworkEvents
| where src_ip in (mal_ips)
```

**Answer:** 26 requests. Attackers were interested in: **new hires**, **election interference prevention**, **voting machines**, and **technical manuals**.

> **MITRE:** T1590 — Gather Victim Network Information | T1591 — Gather Victim Org Information

---

### Q11 — Employee Visits to Phishing Domain

```kql
// Did any employee browse to the fake domain?
OutboundNetworkEvents
| where url contains "valdoriavotesgov.com"
```

**Key findings:**
- First browse: `2024-10-07T10:46:45Z`
- Credentials entered: `2024-10-07T10:46:47Z` (2 seconds later)
- Username: `ansnooper` | IP: `10.10.0.4`

> **MITRE:** T1566.002 — Spearphishing Link | T1056.003 — Web Portal Capture

---

### Q12 — Identify Phished Employee

```kql
// Who does IP 10.10.0.4 belong to?
Employees
| where ip_addr == "10.10.0.4"
```

**Answer:** Anderson Snooper | Role: Temp Election Support Staff Lead

---

### Q13 — Confirm Threat Actor Login

```kql
// When did the threat actor log in using Snooper's harvested credentials?
let mal_ips =
PassiveDns
| where domain == "valdoriavotesgov.com"
| distinct ip;
AuthenticationEvents
| where username == "ansnooper" and src_ip in (mal_ips)
| where timestamp between (datetime(2024-10-05T10:46:47Z) .. datetime(2024-10-11T10:46:47Z))
```

**Answer:** Login at `2024-10-07T15:46:45Z` — exactly 5 hours after credential capture.

---

### Q14 — Email Communication Analysis

```kql
// Who was Anderson Snooper emailing?
Email
| where recipient == "anderson_snooper@valdoriavotes.gov" or sender == "anderson_snooper@valdoriavotes.gov"
```

**Answer:** Suspicious conversation with `barry_schmelly@valdoriavotes.gov` — Snooper was asking Schmelly how to gain access to voting machines. Schmelly mentioned an **AI System**.

---

### Q15 — AI System Subdomain Enumeration

```kql
// Snooper guessing AI system subdomains via URL pattern
InboundNetworkEvents
| where src_ip == "10.10.0.4"
```

**Findings:**
- First guessed subdomain: `ai`
- URL parameter pattern: `model=gpt-4o` at end of each URL
- Status code for failed guesses: `404`

> **MITRE:** T1592 — Gather Victim Host Information (active enumeration)

---

### Q16 — AI Prompt Injection — Voting Machine Intel

```kql
// Find conversation asking about voting machines
AIPrompts
| where prompt contains "voting machine"
```

**Answer:** Conversation ID `94bd6162-1323-402d-bccd-8fceaee5f230`

> **MITRE:** T1059 — Command and Scripting Interpreter (AI prompt abuse as execution)

---

### Q17 — AI Conversation Follow-up

```kql
// Read the full conversation thread
AIPrompts
| where conversation_id == "94bd6162-1323-402d-bccd-8fceaee5f230"
```

**Intel extracted by threat actor:**
- Votes are manually calculated using a **calculator** (not electronic)
- Voting machine vendor: **Dominos Voting Systems**
- Point of contact role: **Election Commissioner**

---

### Q18 — Target Identification

```kql
// Find the Election Commissioner
Employees
| where role == "Election Commissioner"
```

**Answer:** Arrack Bobama | Username: `arbobama` | Email: `arrack_bobama@valdoriavotes.gov`

---

### Q19 — Second Account Compromise

```kql
// When did the threat actor log into Bobama's account?
let mal_ips =
PassiveDns
| where domain == "valdoriavotesgov.com"
| distinct ip;
AuthenticationEvents
| where username == "arbobama" and result == "Successful Login" and src_ip in (mal_ips)
```

**Answer:** Login at `2024-10-16T00:00:00Z` from `214.85.104.248`.

---

### Q20 — Vendor Impersonation & Document Theft

```kql
// Email sent from compromised Bobama account to vendor
Email
| where sender == "arrack_bobama@valdoriavotes.gov"

// Vendor response — what document did they send?
Email
| where sender == "help@dominosvotingsystems.com"
```

**Answer:** Threat actors (as Bobama) emailed `help@dominosvotingsystems.com`. Vendor replied with `ValdoriaVotingMachinesNetworkGuide.pdf`.

> **MITRE:** T1534 — Internal Spearphishing | T1530 — Data from Cloud Storage

---

## MITRE ATT&CK Coverage

| Tactic | ID | Technique | Query |
|---|---|---|---|
| Reconnaissance | T1590 | Gather Victim Network Information | Q10 |
| Reconnaissance | T1591 | Gather Victim Org Information | Q10 |
| Reconnaissance | T1592 | Gather Victim Host Information | Q15 |
| Resource Development | T1583 | Acquire Infrastructure | Q08 |
| Initial Access | T1566.002 | Spearphishing Link | Q11 |
| Credential Access | T1056.003 | Web Portal Capture | Q11 |
| Discovery | T1033 | System Owner/User Discovery | Q12, Q18 |
| Command & Control | T1071 | Application Layer Protocol | Q13 |
| Collection | T1530 | Data from Cloud Storage | Q20 |
| Collection | T1114.003 | Email Forwarding Rule | Q14 |
| Impact | T1491 | Defacement / Influence Operations | Q07–Q10 |
