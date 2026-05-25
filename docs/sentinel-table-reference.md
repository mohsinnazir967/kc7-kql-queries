# 🧰 Microsoft Sentinel Table Reference

Maps KC7 training tables to their real-world Microsoft Sentinel equivalents. Use this when adapting KC7 queries for production Sentinel environments.

---

## Table Mapping

| KC7 Table | Sentinel Equivalent | Schema / Notes |
|-----------|---------------------|----------------|
| `Employees` | `IdentityInfo` | User identity records — name, UPN, role, department, MFA status |
| `InboundNetworkEvents` | `CommonSecurityLog` / `AzureNetworkAnalytics_CL` | Traffic arriving at the perimeter from external sources |
| `OutboundNetworkEvents` | `AzureNetworkAnalytics_CL` | Traffic leaving internal hosts to external destinations |
| `Email` | `EmailEvents` | Email metadata — sender, recipient, subject, links, attachments |
| `PassiveDns` | `DnsEvents` | DNS resolution records — domain ↔ IP mapping |
| `AuthenticationEvents` | `SigninLogs` / `AADSignInEventsBeta` | Login attempts, outcomes, source IPs, user agents |
| `ProcessEvents` | `DeviceProcessEvents` | Process creation events from endpoints (via MDE) |
| `FileCreationEvents` | `DeviceFileEvents` | File creation, modification, and deletion on endpoints |
| `OutboundNetworkEvents` | `DeviceNetworkEvents` | Endpoint-level outbound connections (via MDE) |

---

## Investigations × Tables Used

| Table | Investigation 01 | Investigation 02 | Investigation 03 |
|-------|:---:|:---:|:---:|
| `Employees` / `IdentityInfo` | ✅ | ✅ | ✅ |
| `Email` / `EmailEvents` | ✅ | ✅ | ✅ |
| `InboundNetworkEvents` | ✅ | ✅ | — |
| `OutboundNetworkEvents` | ✅ | ✅ | ✅ |
| `PassiveDns` / `DnsEvents` | ✅ | ✅ | ✅ |
| `AuthenticationEvents` / `SigninLogs` | ✅ | ✅ | — |
| `FileCreationEvents` / `DeviceFileEvents` | — | — | ✅ |
| `ProcessEvents` / `DeviceProcessEvents` | — | — | ✅ |

---

## Useful Sentinel KQL Starter Queries

### Detect external login from suspicious IP
```kql
SigninLogs
| where IPAddress == "<attacker_ip>"
| where ResultType == 0                       // 0 = Successful sign-in
| project TimeGenerated, UserPrincipalName, IPAddress, Location, AppDisplayName
```

### Hunt phishing emails by malicious domain
```kql
EmailEvents
| where Url has "<phishing_domain>"
| project Timestamp, SenderFromAddress, RecipientEmailAddress, Subject, Url
```

### Resolve suspicious IP to domain (Passive DNS equivalent)
```kql
DnsEvents
| where IPAddresses has "<attacker_ip>"
| distinct Name, IPAddresses
```

### Hunt for PowerShell with execution policy bypass
```kql
DeviceProcessEvents
| where ProcessCommandLine has "ExecutionPolicy" and ProcessCommandLine has "Bypass"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
```

### Detect plink.exe SSH tunnel activity
```kql
DeviceProcessEvents
| where FileName == "plink.exe"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
```

### Hunt for curl-based data exfiltration
```kql
DeviceProcessEvents
| where FileName == "curl.exe"
| where ProcessCommandLine has_any ("upload", "exfil", ".7z", ".zip")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
```

### Detect post-compromise discovery commands
```kql
DeviceProcessEvents
| where ProcessCommandLine has_any ("whoami", "ipconfig", "systeminfo", "net user", "tasklist")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
| order by Timestamp asc
```

### Detect email forwarding rules (post-account-takeover)
```kql
CloudAppEvents
| where ActionType == "Set-Mailbox"
| where RawEventData has "ForwardingSmtpAddress"
| project Timestamp, AccountDisplayName, RawEventData
```

---

*Table mappings are approximate — Sentinel schema varies by connector, data normalisation settings, and Microsoft Defender XDR integration.*
