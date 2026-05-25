# 🕵️ Investigation 02 — Social Media Influencer Targeted via Fake Brand Deal

**Module:** KC7 — Security Analyst I | *"CloutHaus: Social Media Leads to Compromise"*
**Sentinel Tables:** `IdentityInfo`, `EmailEvents`, `AzureNetworkAnalytics_CL`, `DnsEvents`, `SigninLogs`
**Difficulty:** Easy
**Completed:** 2024

---

## 📋 Investigation Summary

A CloutHaus influencer, **Afomiya Storm**, received a spearphishing email disguised as a brand partnership offer from a fake "Dior" collaborations address. With MFA disabled on her account, the attacker successfully compromised her credentials through a fake login portal. Post-compromise, the attacker used her account to forward sensitive personal documents — payment details, passport scans, and bank statements — to attacker-controlled domains. The attacker's infrastructure was traced to China.

**Attack Chain:**
```
Phishing (Fake Brand Deal) → Credential Harvest → Account Takeover → Data Exfiltration (PII Forwarding)
```

---

## 🗺️ MITRE ATT&CK Mapping

| Phase | Technique | ID |
|---|---|---|
| Reconnaissance | Gather Victim Identity Information | [T1589](https://attack.mitre.org/techniques/T1589/) |
| Initial Access | Spearphishing Link | [T1566.002](https://attack.mitre.org/techniques/T1566/002/) |
| Credential Access | Phishing for Credentials (Fake Login Page) | [T1056.003](https://attack.mitre.org/techniques/T1056/003/) |
| Defence Evasion | Valid Accounts (no MFA) | [T1078](https://attack.mitre.org/techniques/T1078/) |
| Collection | Email Forwarding Rule | [T1114.003](https://attack.mitre.org/techniques/T1114/003/) |
| Exfiltration | Exfiltration Over Web Service | [T1567](https://attack.mitre.org/techniques/T1567/) |

---

## 🔍 Query 1 — Identify the Target Employee

**Description:** Searches the Employees table for the target by name to retrieve her full profile including email address, username, and role.

**Why it matters in a SOC context:**
Before investigating an account, analysts need the full identity record. This confirms the correct username, email address, and role — all of which are needed for subsequent queries across network, email, and auth logs.

**MITRE ATT&CK:** [T1589 — Gather Victim Identity Information](https://attack.mitre.org/techniques/T1589/)
**Real Sentinel Table:** `IdentityInfo`

```kql
// Retrieve Afomiya Storm's full employee profile
// Confirms: email_addr = afomiya_storm@clouthaus.com, username = afstorm
Employees
| where name contains "Afomiya"
```

---

## 🔍 Query 2 — Confirm the Target's Role

**Description:** Retrieves the unique role assigned to the target employee to understand her organisational function and likely attack surface.

**Why it matters in a SOC context:**
An influencer's role implies high social media access, brand relationships, and financial dealings — all of which are attractive to attackers impersonating brands. Role context shapes how you assess the phishing lure's plausibility.

**MITRE ATT&CK:** [T1589 — Gather Victim Identity Information](https://attack.mitre.org/techniques/T1589/)
**Real Sentinel Table:** `IdentityInfo`

```kql
// Retrieve the distinct role for Afomiya to establish her organisational function
// Result: Influencer Partner — a high-value target for fake brand deal phishing
Employees
| where name contains "Afomiya"
| distinct role
```

---

## 🔍 Query 3 — Check MFA Status

**Description:** Checks whether multi-factor authentication is enabled on the target's account — a critical security control that determines the impact of credential theft.

**Why it matters in a SOC context:**
MFA is the single most effective control against credential-based account takeover. If MFA is disabled, stolen credentials alone are sufficient for full account compromise. This check immediately escalates the severity of a phishing incident.

**MITRE ATT&CK:** [T1078 — Valid Accounts](https://attack.mitre.org/techniques/T1078/)
**Real Sentinel Table:** `IdentityInfo`

```kql
// Check if MFA is enabled on Afomiya's account
// Result: False — no MFA, meaning stolen credentials = full account access
Employees
| where name contains "Afomiya Storm"
| distinct mfa_enabled
```

---

## 🔍 Query 4 — Identify the Phishing Email

**Description:** Searches the target's inbound email for messages with brand-deal-related keywords that match the suspected phishing lure.

**Why it matters in a SOC context:**
Identifying the exact phishing email confirms the initial access vector, reveals the attacker's sender address and infrastructure, and provides the malicious URL that will be pivoted on across network logs.

**MITRE ATT&CK:** [T1566.002 — Phishing: Spearphishing Link](https://attack.mitre.org/techniques/T1566/002/)
**Real Sentinel Table:** `EmailEvents`

```kql
// Search Afomiya's inbox for emails matching a fake brand deal lure
// Filters on "exclusive" (subject keyword) or "dior" (brand name in link)
// Result: sender = collabs@dior-partners.com (attacker-controlled)
// Subject: [EXTERNAL] Exclusive Partnership Opportunity with Dior
// Link: https://super-brand-offer.com/login  ← credential harvesting page
Email
| where recipient == "afomiya_storm@clouthaus.com"
| where subject contains "exclusive" or links contains "dior"
```

---

## 🔍 Query 5 — Confirm the Victim Visited the Phishing Site

**Description:** Checks outbound network events for a connection to the phishing domain, confirming the target clicked the malicious link.

**Why it matters in a SOC context:**
This moves the incident from "phishing received" to "phishing executed." Confirming the user visited the credential harvesting page means credentials are likely compromised, and the response must escalate to immediate account lockdown.

**MITRE ATT&CK:** [T1204.001 — User Execution: Malicious Link](https://attack.mitre.org/techniques/T1204/001/)
**Real Sentinel Table:** `AzureNetworkAnalytics_CL`

```kql
// Confirm Afomiya's workstation connected to the phishing/credential harvesting domain
// Result: timestamp 2025-04-03T11:20:00Z, username afstorm — link was clicked
OutboundNetworkEvents
| where url contains "super-brand-offer.com"
```

---

## 🔍 Query 6 — Resolve Phishing Domain to IP

**Description:** Uses Passive DNS to resolve the phishing domain to its hosting IP address for infrastructure pivot.

**Why it matters in a SOC context:**
Resolving a phishing domain to an IP allows analysts to discover other domains hosted on the same infrastructure — revealing the full scope of the attacker's operation and additional indicators of compromise to block.

**MITRE ATT&CK:** [T1584 — Compromise Infrastructure](https://attack.mitre.org/techniques/T1584/)
**Real Sentinel Table:** `DnsEvents`

```kql
// Resolve the phishing domain to its hosting IP via Passive DNS
// Result: IP 198.51.100.12
PassiveDns
| where domain contains "super-brand-offer.com"
```

---

## 🔍 Query 7 — Enumerate All Attacker Domains on the Same IP

**Description:** Pivots from the resolved IP to discover all other domains hosted on the same attacker infrastructure.

**Why it matters in a SOC context:**
Threat actors frequently host multiple campaign domains on shared infrastructure. Discovering all domains on the same IP expands the indicator set for blocking and may reveal other ongoing campaigns or additional victims.

**MITRE ATT&CK:** [T1584 — Compromise Infrastructure](https://attack.mitre.org/techniques/T1584/)
**Real Sentinel Table:** `DnsEvents`

```kql
// Pivot from the attacker IP to enumerate all associated domains
// Result: 3 domains hosted on the same infrastructure
PassiveDns
| where ip contains "198.51.100.12"
| distinct domain
```

---

## 🔍 Query 8 — Identify the Attacker's Login IP and User Agent

**Description:** Reviews authentication events for the compromised account to identify the attacker's source IP and browser fingerprint used during account takeover.

**Why it matters in a SOC context:**
Post-phishing authentication events from foreign IPs confirm account takeover. The user agent provides additional attacker fingerprinting — an outdated/unusual browser string (like IE 5.0 in 2025) is a strong anomaly signal that can be used to build detection rules.

**MITRE ATT&CK:** [T1078 — Valid Accounts](https://attack.mitre.org/techniques/T1078/)
**Real Sentinel Table:** `SigninLogs`

```kql
// Review all authentication events for the compromised account
// Key findings:
// - src_ip: 182.45.67.89 (attacker's external IP — geolocated to China)
// - user_agent: Mozilla/5.0 (compatible; MSIE 5.0; Windows NT 5.2; Trident/4.1)
//   → IE 5.0 in 2025 is a major anomaly / attacker tool fingerprint
AuthenticationEvents
| where username == "afstorm"
```

---

## 🔍 Query 9 — Attribute Attacker IP to Known Infrastructure

**Description:** Resolves the attacker's login IP via Passive DNS to identify additional domains associated with the threat actor, including their country of origin.

**Why it matters in a SOC context:**
Attributing an attacker IP to a specific domain cluster and geography supports threat intelligence reporting, helps assess whether this is a targeted or opportunistic attack, and enables proactive blocking of related infrastructure.

**MITRE ATT&CK:** [T1584 — Compromise Infrastructure](https://attack.mitre.org/techniques/T1584/)
**Real Sentinel Table:** `DnsEvents`

```kql
// Resolve attacker's login IP to associated domains and geo-context
// Result:
// - dior-partners.com      ← the fake "Dior" sender domain
// - influencer-deals.net   ← exfiltration / data receipt domain
// - Country of origin: China
PassiveDns
| where ip contains "182.45.67.89"
```

---

## 🔍 Query 10 — Hunt for Financial Reconnaissance by Attacker

**Description:** Searches inbound network events from the attacker IP for access to payment-platform-related URLs, indicating financial reconnaissance of the victim or company.

**Why it matters in a SOC context:**
Attackers who compromise influencer accounts often conduct financial reconnaissance to intercept payments, redirect direct deposits, or harvest financial credentials. Hunting for payment keywords in attacker-originated traffic reveals this motive and adds urgency to remediation.

**MITRE ATT&CK:** [T1530 — Data from Cloud Storage](https://attack.mitre.org/techniques/T1530/)
**Real Sentinel Table:** `CommonSecurityLog`

```kql
// Hunt for attacker IP accessing URLs related to payment platforms
// Indicates financial reconnaissance or payment redirection intent
// Result: "venmo" found in accessed URLs
InboundNetworkEvents
| where src_ip == "182.45.67.89"
| where url has_any ("venmo", "paypal", "cashapp", "zelle", "stripe", "square", "bank")
```

---

## 🔍 Query 11 — Check for Other Attacker Web Activity (Decoy/Distraction)

**Description:** Checks for other attacker-originating inbound requests to identify diversionary or additional malicious activity.

**Why it matters in a SOC context:**
Attackers often perform decoy or distraction actions alongside their primary objective. Reviewing all attacker-IP traffic ensures no secondary attack activity is missed during the investigation.

**MITRE ATT&CK:** [T1036 — Masquerading](https://attack.mitre.org/techniques/T1036/)
**Real Sentinel Table:** `CommonSecurityLog`

```kql
// Scan all inbound activity from the attacker IP for URLs containing "fake"
// Result: "birthday party" — possible decoy/social engineering content
InboundNetworkEvents
| where src_ip == "182.45.67.89"
| where url contains "fake"
```

---

## 🔍 Query 12 — Detect Forwarded Emails (Data Exfiltration via Email)

**Description:** Searches for emails sent from the compromised account with "FORWARD" in the subject, indicating the attacker set up email forwarding rules to exfiltrate sensitive data.

**Why it matters in a SOC context:**
Email forwarding rules are one of the most common and dangerous post-compromise actions. They allow attackers to silently receive all future emails — including PII, financial data, and internal communications — without any further authentication. They persist even after a password reset if not explicitly removed.

**MITRE ATT&CK:** [T1114.003 — Email Collection: Email Forwarding Rule](https://attack.mitre.org/techniques/T1114/003/)
**Real Sentinel Table:** `EmailEvents`

```kql
// Detect emails forwarded outbound from Afomiya's account
// Result: All forwarded to noreply@influencer-deals.net (attacker-controlled domain)
Email
| where sender contains "afomiya_storm@clouthaus.com"
| where subject contains "FORWARD"
```

---

## 🔍 Query 13 — Identify Exfiltrated Payment Details

**Description:** Narrows forwarded email search to payment-related documents, confirming financial PII was exfiltrated.

**Why it matters in a SOC context:**
Forwarded payment details (direct deposit forms, bank account numbers) enable the attacker to redirect the victim's income, commit financial fraud, or sell the data. This constitutes a notifiable data breach in most jurisdictions.

**MITRE ATT&CK:** [T1114.003 — Email Collection: Email Forwarding Rule](https://attack.mitre.org/techniques/T1114/003/)
**Real Sentinel Table:** `EmailEvents`

```kql
// Confirm forwarding of payment-related emails to attacker domain
// Result subject: [EXTERNAL] [FORWARD] Afomiya's payment details – direct deposit form
// Recipient: noreply@influencer-deals.net
Email
| where sender contains "afomiya_storm@clouthaus.com"
| where subject contains "FORWARD"
| where subject contains "payment"
```

---

## 🔍 Query 14 — Identify Exfiltrated Passport Scan

**Description:** Checks for forwarded passport documents — government-issued identity document exfiltration.

**Why it matters in a SOC context:**
Passport data is among the most sensitive PII an attacker can obtain. It enables identity fraud, account takeover of financial institutions, and is a high-value commodity on criminal markets. This finding escalates the incident to a critical PII breach requiring regulatory notification.

**MITRE ATT&CK:** [T1114.003 — Email Collection: Email Forwarding Rule](https://attack.mitre.org/techniques/T1114/003/)
**Real Sentinel Table:** `EmailEvents`

```kql
// Confirm forwarding of passport identity document to attacker domain
// Result subject: [EXTERNAL] [FORWARD] Afomiya's passport scan – confidential
// Recipient: noreply@influencer-deals.net
Email
| where sender contains "afomiya_storm@clouthaus.com"
| where subject contains "FORWARD"
| where subject contains "passport"
```

---

## 🔍 Query 15 — Identify Exfiltrated Bank Statements

**Description:** Checks for forwarded bank statements, completing the picture of full financial PII exfiltration.

**Why it matters in a SOC context:**
Bank statements reveal account numbers, balances, transaction history, and recurring payments. Combined with payment details and passport scans, this constitutes a complete financial identity theft package. All three document types together indicate a highly targeted, financially motivated attack.

**MITRE ATT&CK:** [T1114.003 — Email Collection: Email Forwarding Rule](https://attack.mitre.org/techniques/T1114/003/)
**Real Sentinel Table:** `EmailEvents`

```kql
// Confirm forwarding of bank statement to attacker domain
// Result subject: [EXTERNAL] [FORWARD] Re: Re: Re: Afomiya's bank statement – confidential
// Recipient: noreply@influencer-deals.net
Email
| where sender contains "afomiya_storm@clouthaus.com"
| where subject contains "FORWARD"
| where subject contains "bank"
```

---

## 📌 Investigation Notes

| Indicator | Value | Type |
|-----------|-------|------|
| Victim Username | `afstorm` (Afomiya Storm) | Identity |
| Victim Email | `afomiya_storm@clouthaus.com` | Identity |
| MFA Enabled | `False` | Security Posture |
| Phishing Sender | `collabs@dior-partners.com` | Email IOC |
| Phishing Subject | `[EXTERNAL] Exclusive Partnership Opportunity with Dior` | Email IOC |
| Phishing URL | `https://super-brand-offer.com/login` | URL IOC |
| Phishing Domain IP | `198.51.100.12` | Network IOC |
| Attacker Login IP | `182.45.67.89` | Network IOC |
| Attacker Country | China | Attribution |
| Attacker Domains | `dior-partners.com`, `influencer-deals.net` | Domain IOC |
| Attacker User Agent | `Mozilla/5.0 (MSIE 5.0; Windows NT 5.2)` | Fingerprint |
| Exfil Recipient | `noreply@influencer-deals.net` | Email IOC |
| Data Exfiltrated | Payment details, passport scan, bank statements | PII Breach |
| Link Click Timestamp | `2025-04-03T11:20:00Z` | Timeline |

---

## 🔗 References

- [MITRE ATT&CK — Spearphishing Link (T1566.002)](https://attack.mitre.org/techniques/T1566/002/)
- [MITRE ATT&CK — Email Forwarding Rule (T1114.003)](https://attack.mitre.org/techniques/T1114/003/)
- [MITRE ATT&CK — Valid Accounts (T1078)](https://attack.mitre.org/techniques/T1078/)
- [Microsoft Sentinel — SigninLogs Table](https://learn.microsoft.com/en-us/azure/monitor/reference/tables/signinlogs)
- [Microsoft Sentinel — EmailEvents Table](https://learn.microsoft.com/en-us/azure/sentinel/normalization-schema-email)

---

*← [Back to Security Analyst I Module](./README.md) | [Back to Repository Root](../../README.md)*
