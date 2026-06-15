# Whiskers & Wonders — Network Concepts & C2 Beaconing

**Module:** Security Analyst II | **Environment:** Whiskers & Wonders Animal Sanctuary  
**Status:** ✅ Complete | **Queries:** 22  
**Attack Type:** Phishing → C2 Implant → DNS Beaconing → Network Compromise

---

## Module Overview

A two-part module. The first half introduces core network concepts using KQL against real network tables (VLANs, DNS, proxy, and flow data). The second half applies these skills to investigate an active C2 (Command & Control) beaconing campaign following a spearphishing attack against sanctuary employees.

**Tables Used:** `DeviceInfo`, `NetworkFlow`, `DnsEvents`, `ProxyEvents`, `Email`, `Employees`

---

## Network Architecture Overview

| VLAN | Subnet | Purpose |
|---|---|---|
| DMZ | 10.10.0.x | Internet-facing services (e.g. DonationPortal) |
| Servers | 10.10.1.x | Internal servers (MailServer01, DNS-Server) |
| Restricted | 10.10.2.x | DomainController |
| Workstations | 10.10.16.x | Employee workstations |

---

## Part 1: Network Fundamentals

---

### Q01 — VLAN Enumeration

```kql
// How many VLANs does Whiskers & Wonders have? Which has the most devices?
DeviceInfo
| summarize device_count = count() by vlan
| order by device_count desc
```

**Answer:** 5 VLANs. The `workstations` VLAN has the most devices.

---

### Q02 — DMZ Device Inventory

```kql
// Identify devices in the DMZ zone
DeviceInfo
| where vlan == "dmz"
| project name, ip_address, host_type
```

**Answer:** DonationPortal IP: `10.10.0.3`

---

### Q03 — Server VLAN Inventory

```kql
// List all server-zone devices
DeviceInfo
| where vlan == "servers"
| project name, ip_address
```

**Answer:** MailServer01 IP: `10.10.1.2`

---

### Q04 — Restricted Zone

```kql
// What's in the restricted zone?
DeviceInfo
| where vlan == "restricted"
| project name, ip_address, host_type
```

**Answer:** `DomainController` — the most sensitive asset, isolated in a restricted VLAN.

---

### Q05 — Subnet-to-VLAN Mapping

```kql
// Confirm which VLAN the 10.10.1.x subnet belongs to
DeviceInfo
| where ip_address startswith "10.10.1"
| project name, ip_address, vlan
| take 5
```

**Answer:** Servers VLAN.

---

### Q06 — DNS Server Location

```kql
// Find the DNS server
DeviceInfo
| where name == "DNS-Server"
| project name, ip_address, vlan
```

**Answer:** IP `10.10.1.7` in the Servers VLAN.

---

### Q07 — Top Destination Port

```kql
// What destination port carries the most traffic?
NetworkFlow
| summarize traffic = count() by dest_port
| order by traffic desc
| take 5
```

**Answer:** Port `25` (SMTP/email) has the most traffic.

---

### Q08 — Protocol Analysis

```kql
// What protocol does DNS primarily use?
NetworkFlow
| where dest_port == "53"

// What carries the majority of all traffic?
NetworkFlow
| summarize count_protocol = count() by protocol
| order by count_protocol desc
```

**Answer:** DNS = UDP. Majority of traffic = TCP.

---

### Q09 — DNS Record Lookup

```kql
// What IP does docs.google.com resolve to?
DnsEvents
| where query_name == "docs.google.com"
| where query_type == "A"
```

**Answer:** `152.52.146.99`. HTTP status code returned for that request: `200`.

> **Note:** DNS A records map a domain to an IPv4 address. Other types: AAAA (IPv6), MX (mail), CNAME (alias).

---

## Part 2: C2 Investigation

---

### Q10 — Reverse IP Lookup (IOC Discovery)

```kql
// What domain resolves to the suspicious IP 185.174.137.42?
DnsEvents
| where resolved_ips has "185.174.137.42"
| distinct query_name
```

**Answer:** `update-cdn-service.xyz` — a suspicious domain disguised as a CDN update service.

> **SOC Context:** Attackers frequently register domains that blend with legitimate infrastructure names. The `.xyz` TLD combined with CDN-mimicking language is a strong phishing indicator.

---

### Q11 — Scope of DNS Queries to Malicious Domain

```kql
// How many internal IPs queried this malicious domain?
DnsEvents
| where query_name contains "update-cdn-service.xyz"
| distinct client_ip
```

**Answer:** 3 distinct internal IPs compromised.

---

### Q12 — Network Traffic to C2 IP

```kql
// What port is the C2 using?
NetworkFlow
| where dest_ip == "185.174.137.42"
```

**Answer:** Port `443` (HTTPS) — C2 traffic blending into normal encrypted web traffic.

> **MITRE:** T1071.001 — Web Protocols (HTTPS for C2 communication)

---

### Q13 — C2 Beacon Pattern in Proxy Logs

```kql
// Repeated URL paths to C2 domain — classic beacon pattern
ProxyEvents
| where domain == "update-cdn-service.xyz"
| order by timestamp asc
```

**Recurring paths:** `/api/v1/status`, `/api/v1/config`, `/api/v1` — structured API-like beaconing.

> **MITRE:** T1572 — Protocol Tunneling | T1071 — Application Layer Protocol

---

### Q14 — Phishing Email Source

```kql
// What domain is impersonating the sanctuary in phishing emails?
Email
| where sender !endswith "@whiskersandwonders.org"
| where sender contains "whiskersandwonders"
| project timestamp, sender, recipient, subject
| distinct recipient
```

**Answer:** `whiskersandwonders-hr.com` — fake HR domain. 3 employees targeted.

> **MITRE:** T1566.002 — Spearphishing Link

---

### Q15 — Phishing Recipient Identification

```kql
// Get full details of all phishing emails from the fake HR domain
Email
| where sender contains "whiskersandwonders-hr.com"
```

**Targeted employees:**
- `alex_rivera@whiskersandwonders.org` → IP `10.10.16.7`
- `jessica_huang@whiskersandwonders.org` → IP `10.10.16.24`
- `david_okonkwo@whiskersandwonders.org` → IP `10.10.16.14`

**First phishing email sent:** `6/2/2025 4:00:00 PM`

---

### Q16 — Correlate Phishing Victims with C2 Beacons

```kql
// Cross-reference phishing recipients with C2 DNS queries
DnsEvents
| where query_name contains "update-cdn-service.xyz"
| distinct client_ip

// Confirm which phished employees are also beaconing
Employees
| where email_addr has_any (
    "alex_rivera@whiskersandwonders.org",
    "jessica_huang@whiskersandwonders.org",
    "david_okonkwo@whiskersandwonders.org"
)
| project ip_addr, name, email_addr, role
```

> **SOC Context:** Correlating email events with DNS and network logs confirms which phishing victims actually executed the payload. Not every phish results in compromise.

---

### Q17 — Time-to-Compromise Analysis

```kql
// How long between first phishing email and first C2 beacon?
DnsEvents
| where query_name contains "update-cdn-service.xyz"
| summarize first_query = min(timestamp) by client_ip
| order by first_query asc
```

**Answer:** ~7 hours between phishing email and first C2 beacon.

---

### Q18 — C2 Request Count

```kql
// How many times did the compromised machine contact the C2?
ProxyEvents
| where domain == "update-cdn-service.xyz"
```

**Answer:** 6 requests to the C2.

---

### Q19 — Identify Compromised Employee

```kql
// Join DNS beacon source IPs with employee data
DnsEvents
| where query_name contains "update-cdn-service.xyz"
| distinct client_ip
| join kind=inner (
    Employees | project ip_addr, name, username, role
) on $left.client_ip == $right.ip_addr
| project name, username, role
```

**Answer:** Alex Rivera — Development Officer.

---

## Detection Rules

Three reusable KQL detection rules derived from this investigation:

---

### Detection Rule 1 — DNS Query to Known C2

```kql
// ALERT: DNS query to known C2 domain
// Maps to: T1071.004 (DNS for C2), T1572 (Protocol Tunneling)
DnsEvents
| where query_name in ("update-cdn-service.xyz")
```

---

### Detection Rule 2 — Network Flow to C2 IP

```kql
// ALERT: Outbound connection to known C2 IP address
// Maps to: T1071.001 (Web Protocols)
NetworkFlow
| where dest_ip == "185.174.137.42"
```

---

### Detection Rule 3 — Proxy Pattern Match for C2 API Beacons

```kql
// ALERT: Structured API-path beaconing pattern on .xyz domains
// Maps to: T1572 (Protocol Tunneling)
ProxyEvents
| where url matches regex @"/api/v\d+/(status|config)"
| where domain endswith ".xyz"
```

---

### Detection Rule 4 — Beacon Timeline per Host

```kql
// Timeline analysis: beacon frequency per compromised IP
let c2_domain = "update-cdn-service.xyz";
let compromised_ips = DnsEvents
| where query_name contains c2_domain
| distinct client_ip;
DnsEvents
| where client_ip in (compromised_ips)
| where query_name contains c2_domain
| summarize
    first_beacon = min(timestamp),
    last_beacon = max(timestamp),
    total_queries = count()
  by client_ip
```

---

## MITRE ATT&CK Coverage

| Tactic | ID | Technique | Query |
|---|---|---|---|
| Initial Access | T1566.002 | Spearphishing Link | Q14, Q15 |
| Execution | T1204.001 | Malicious Link | Q15, Q17 |
| Command & Control | T1071.001 | Web Protocols (HTTPS C2) | Q12, Q13 |
| Command & Control | T1071.004 | DNS for C2 | Q10, Q11, Q17 |
| Command & Control | T1572 | Protocol Tunneling | Q13, Detection 3 |
| Discovery | T1046 | Network Service Scanning | Q07, Q08 |
