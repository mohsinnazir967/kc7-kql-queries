# KQL 101 — Introduction to Kusto Query Language

**Module:** KQL 101 | **Environment:** Jojo's Hospital  
**Status:** ✅ Complete | **Queries:** 12

---

## Module Overview

A foundational module covering core KQL syntax and operators used throughout all KC7 investigations. Covers table exploration, filtering, projection, counting, `let` bindings, and multi-table correlation.

**Tables Used:** `Employees`, `Email`, `AuthenticationEvents`, `OutboundNetworkEvents`

---

## Queries

---

### Q01 — Preview Table Rows

```kql
// Preview the first 10 rows of the Employees table
Employees
| take 10
```

**Answer:** 10 rows returned. Job title information is in the `role` column.

---

### Q02 — Filter by Role

```kql
// Count all Pharmacists at the company
Employees
| where role == "Pharmacist"
```

**Answer:** 19 pharmacists.

---

### Q03 — Count All Employees

```kql
// Total employee headcount
Employees
| count
```

**Answer:** 321 employees.

---

### Q04 — Count Distinct Roles

```kql
// How many unique job roles exist?
Employees
| distinct role
| count
```

**Answer:** 23 distinct roles.

---

### Q05 — Compound Filter

```kql
// Radiologists named Richard
Employees
| where role == "Radiologist" and name has "Richard "
```

**Answer:** 2 results.

---

### Q06 — Project Specific Column

```kql
// Look up a specific employee's email address
Employees
| where name == "Noemi Tep"
| project email_addr
```

**Answer:** `noemi_tep@jojoshospital.org`

---

### Q07 — Partial String Match

```kql
// Find roles containing the word "security" (case-insensitive partial match)
Employees
| where role contains "security"
```

---

### Q08 — Email Keyword Search

```kql
// Count emails with "health" in the subject line
Email
| where subject has "health"
```

**Answer:** 613 emails.

---

### Q09 — External Email Filter

```kql
// Last external email received by Noemi Tep
Email
| where recipient == "noemi_tep@jojoshospital.org"
| where sender !contains "jojoshospital"
```

**Answer:** Sender `skirmishes.converts@yandex.com`

---

### Q10 — Authentication Event Filter

```kql
// Count failed login attempts from a specific IP
AuthenticationEvents
| where src_ip == "10.10.0.144" and result == "Failed Login"
```

**Answer:** 59 failed logins.

---

### Q11 — Let Binding for IP Lookup

```kql
// Identify all URLs visited by employees named Mary (multi-step using let)
let mary_ips =
Employees
| where name has "Mary"
| distinct ip_addr;
OutboundNetworkEvents
| where src_ip in (mary_ips)
```

**Answer:** 668 website visits.

---

### Q12 — Let Binding for Username Lookup

```kql
// Authentication attempts against all accounts named Mary
let mary_users =
Employees
| where name has "Mary"
| distinct username;
AuthenticationEvents
| where username in (mary_users)
```

**Answer:** 810 authentication attempts.

---

## Key KQL Concepts Introduced

| Operator | Purpose |
|---|---|
| `take N` | Preview N rows |
| `where` | Filter rows |
| `count` | Count rows |
| `distinct` | Deduplicate values |
| `project` | Select specific columns |
| `has` | Whole-word match (faster) |
| `contains` | Substring match |
| `!contains` | Negative substring match |
| `let` | Bind a subquery result to a variable |
| `in()` | Match against a list or subquery result |

---

## MITRE ATT&CK Techniques

*This module is introductory — no specific ATT&CK techniques are mapped. Techniques covered in investigation modules.*
