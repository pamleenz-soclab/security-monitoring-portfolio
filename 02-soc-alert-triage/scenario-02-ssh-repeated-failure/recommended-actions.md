# Recommended Actions: Repeated SSH Invalid-User Authentication Attempts

## 1. Summary

This document provides recommended response, hardening, and detection improvement actions for Scenario 02: Repeated SSH Invalid-User Authentication Attempts.

The investigation confirmed that three controlled SSH (Secure Shell) invalid-user authentication attempts were generated against the monitored Ubuntu endpoint `soc-lab-ubuntu-target-01`.

Wazuh generated alerts using rule ID `5710`:

- rule.description: `sshd: Attempt to login using a non-existent user`
- rule.level: `5`
- MITRE ATT&CK: `T1110.001 Password Guessing`, `T1021.004 SSH`

The activity was assessed as:

**True Positive — Authorized Lab Simulation**

No successful login or evidence of compromise was observed.

---

## 2. Immediate Response Actions

In this lab scenario, no emergency containment was required because the activity was authorized.

In a production environment, the following immediate actions should be considered.

| Action | Purpose |
|---|---|
| Review successful SSH logins after the failed attempts | Determine whether the failed attempts were followed by successful access |
| Validate the source IP | Determine whether the source is trusted, unknown, suspicious, or malicious |
| Check targeted username patterns | Identify whether the attacker is guessing common admin, service, or application usernames |
| Review affected host exposure | Confirm whether the SSH service is exposed to the internet |
| Preserve relevant logs | Keep endpoint logs, SIEM alerts, and firewall evidence for investigation |
| Escalate if successful login is observed | Treat as potential compromise if authentication succeeds after repeated failures |

---

## 3. Host Hardening Recommendations

### 3.1 Restrict SSH Access

SSH should not be broadly exposed to the internet unless required.

Recommended options:

- allow SSH only from trusted administrative IP addresses;
- use a VPN (Virtual Private Network) before allowing SSH access;
- use a bastion host or jump server;
- use a zero trust access gateway where available.

Example control objective:

| Control | Expected Result |
|---|---|
| Restrict SSH source IPs | Reduce internet-wide scanning and brute-force exposure |

---

### 3.2 Disable Password-Based SSH Authentication

Where operationally feasible, disable password authentication and use SSH key-based authentication.

Recommended SSH configuration direction:

| Setting | Recommended State |
|---|---|
| PasswordAuthentication | no |
| PubkeyAuthentication | yes |
| PermitRootLogin | prohibit-password or no |

This reduces the risk of password guessing and brute-force attacks.

---

### 3.3 Avoid Direct Root Login

Direct root SSH login should be avoided where possible.

Recommended approach:

1. Create a named administrative user.
2. Use SSH key-based authentication.
3. Grant administrative access through `sudo`.
4. Monitor privileged command execution.

This improves accountability and reduces the risk of direct privileged access abuse.

---

### 3.4 Use Rate Limiting or Temporary Blocking

For internet-facing Linux systems, consider tools or controls that slow down repeated authentication attempts.

Possible options:

| Option | Purpose |
|---|---|
| fail2ban | Temporarily block sources after repeated failed logins |
| UFW rate limiting | Limit repeated SSH connection attempts |
| Cloud firewall rules | Restrict access before traffic reaches the host |
| Security group rules | Limit access at the cloud network layer |

---

## 4. Monitoring Recommendations

### 4.1 Monitor Repeated Failed SSH Attempts

A single invalid-user login attempt may be low priority, especially on an internet-facing server. Repeated attempts from the same source IP are more suspicious.

Recommended detection logic:

| Field | Purpose |
|---|---|
| `data.srcip` | Identify repeated attempts from the same source |
| `agent.name` | Identify the targeted endpoint |
| `data.srcuser` | Track attempted username |
| `rule.id` | Filter SSH invalid-user events |
| `timestamp` | Apply a time window |
| `location` | Identify duplicate log ingestion sources |

Suggested threshold:

| Parameter | Suggested Value |
|---|---|
| Time window | 5 to 10 minutes |
| Threshold | 3 or more failed invalid-user attempts |
| Group by | source IP, destination host, username |

---

### 4.2 Review Successful Logins After Failures

Repeated failures are more concerning if followed by a successful login.

Recommended query logic:

| Question | Purpose |
|---|---|
| Did the same source IP later authenticate successfully? | Identify possible successful brute force |
| Did the same username later authenticate successfully? | Identify possible credential compromise |
| Did any privileged account log in after the failures? | Identify higher-impact access |
| Was the login from an unusual location or network? | Identify suspicious access context |

---

### 4.3 Monitor for Username Guessing Patterns

Repeated invalid usernames may indicate username enumeration or automated scanning.

Examples of suspicious username patterns:

- `admin`
- `administrator`
- `root`
- `test`
- `support`
- `ftpadmin`
- service account names
- application-specific account names

The test username `m2test0507` was authorized lab activity, but in production similar repeated invalid usernames should be reviewed.

---

## 5. Detection Engineering Improvements

### 5.1 Address Duplicate Log Ingestion

In this scenario, Wazuh displayed 6 alert records even though the endpoint recorded 3 core SSH invalid-user events.

The reason was duplicate ingestion from two Linux log sources:

- `/var/log/auth.log`
- `journald`

Recommended tuning options:

| Option | Advantage | Risk |
|---|---|---|
| Use `/var/log/auth.log` as the primary SSH authentication source | Simple and easy to validate | May miss some systemd journal-only events |
| Use `journald` as the primary source | More modern and structured | May be less familiar for simple file-based investigation |
| Keep both sources and deduplicate in queries | Better coverage | Requires careful dashboard and rule tuning |
| Keep both but document count differences | Preserves visibility | Analysts must avoid overcounting |

Recommended approach for this lab:

**Keep both sources for learning, but document duplicate ingestion clearly in reports.**

Recommended approach for production:

**Select a primary authentication log source or apply deduplication logic to avoid inflated alert counts.**

---

### 5.2 Build a Correlation Rule

A useful future detection rule would identify repeated failed SSH activity instead of treating each event separately.

Example detection objective:

| Field | Description |
|---|---|
| Detection Objective | Detect repeated SSH invalid-user attempts from the same source IP against the same host |
| Data Source | Linux authentication logs collected by Wazuh |
| Rule Type | Correlation / threshold-based detection |
| Time Window | 5 to 10 minutes |
| Threshold | 3 or more events |
| Grouping | source IP, destination host, username |
| MITRE ATT&CK | T1110.001 Password Guessing, T1021.004 SSH |

---

### 5.3 Separate Raw Event Count from Alert Count

SOC reports should distinguish between:

| Count Type | Meaning |
|---|---|
| Raw endpoint event count | Number of actual events recorded by the endpoint |
| SIEM alert count | Number of alerts generated by SIEM collection and detection logic |
| Dashboard hit count | Number of searchable records displayed in the dashboard |

For this scenario:

| Source | Count |
|---|---|
| `/var/log/auth.log` core invalid-user events | 3 |
| Wazuh alert records | 6 |
| Reason | Duplicate ingestion from `/var/log/auth.log` and `journald` |

---

## 6. Production Response Checklist

If this alert occurred in a production environment, an analyst should check:

- Was the source IP known or trusted?
- Was the target host internet-facing?
- How many failed attempts occurred?
- Were the attempts concentrated in a short time window?
- Which usernames were attempted?
- Did any successful login occur after the failures?
- Did the same source IP target other hosts?
- Did the same username appear across multiple hosts?
- Are there firewall, VPN, or cloud security logs for the same source?
- Should the source IP be blocked or rate limited?
- Should SSH exposure be reduced?
- Is a detection tuning change required?

---

## 7. Lab Follow-Up Actions

For this lab environment, the following follow-up actions are recommended:

1. Keep the current evidence files for Scenario 02.
2. Add sanitized screenshots to the portfolio.
3. Add sanitized endpoint and Wazuh alert samples.
4. Document duplicate ingestion as a detection engineering finding.
5. Use this scenario as a baseline before testing stronger SSH brute-force-style behavior.
6. Compare this case with a future benign authentication failure case.
7. Compare this case with a future port scanning investigation.

---

## 8. Final Recommendation

This scenario should be retained in the portfolio because it demonstrates:

- endpoint log validation;
- Wazuh alert verification;
- MITRE ATT&CK mapping;
- SOC-style triage;
- raw log versus SIEM alert count comparison;
- duplicate ingestion analysis;
- practical detection engineering reasoning.

The most important security recommendation is:

**Do not rely only on SIEM alert counts. Validate alerts against raw endpoint logs and understand how each log source is collected.**