# Alert Triage Note: Repeated SSH Invalid-User Authentication Attempts

## Alert Name

Repeated SSH invalid-user authentication attempts against Linux endpoint

## Initial Question

Is this activity an authentication attack, a benign administrative mistake, or an authorized lab simulation?

## Triage Decision

**True Positive — Authorized Lab Simulation**

The activity represents a true SSH (Secure Shell) invalid-user authentication pattern from a logging and detection perspective. Multiple invalid-user SSH attempts were observed against the monitored Ubuntu endpoint.

However, the activity was intentionally generated in an authorized lab environment. No successful login or evidence of compromise was observed.

## Environment

| Field | Value |
|---|---|
| SIEM / XDR Platform | Wazuh |
| Monitored Endpoint | soc-lab-ubuntu-target-01 |
| Endpoint Operating System | Ubuntu 22.04.5 LTS |
| Wazuh Agent ID | 001 |
| Wazuh Agent IP | 10.126.0.3 |
| Wazuh Manager | soc-lab-wazuh-server |
| Test Username | m2test0507 |
| Log Source | /var/log/auth.log and journald |

## Data Sources Reviewed

| Data Source | Purpose |
|---|---|
| Ubuntu `/var/log/auth.log` | Validate raw Linux authentication events |
| Wazuh `alerts.log` | Confirm Wazuh alert generation |
| Wazuh `alerts.json` | Review structured alert fields |
| Wazuh Dashboard | Confirm searchable alert visibility and event details |

## Evidence Summary

Three controlled SSH invalid-user authentication attempts were generated against the Ubuntu target endpoint.

The Ubuntu endpoint recorded 3 core `Invalid user m2test0507` events in `/var/log/auth.log`.

Wazuh displayed 6 alert records for the same activity because the events were collected from two locations:

- `/var/log/auth.log`
- `journald`

This duplicate ingestion caused each endpoint event to appear twice in Wazuh.

## Key Observed Fields

| Field | Observed Value |
|---|---|
| agent.id | 001 |
| agent.name | soc-lab-ubuntu-target-01 |
| agent.ip | 10.126.0.3 |
| manager.name | soc-lab-wazuh-server |
| decoder.name | sshd |
| data.srcuser | m2test0507 |
| location | journald and /var/log/auth.log |
| rule.id | 5710 |
| rule.level | 5 |
| rule.description | sshd: Attempt to login using a non-existent user |
| rule.groups | syslog, sshd, authentication_failed, invalid_login |

## Timeline

| Time | Event |
|---|---|
| May 7, 2026 03:31 UTC | Scenario start time recorded |
| May 7, 2026 03:46 UTC | First invalid-user SSH attempt observed |
| May 7, 2026 03:49 UTC | Additional invalid-user SSH attempts observed |
| May 7, 2026 03:53 UTC | Endpoint evidence files saved |
| May 7, 2026 04:04 UTC | Wazuh alert evidence files saved |
| May 7, 2026 04:18 UTC | Wazuh location count confirmed duplicate ingestion |
| May 7, 2026 15:46–15:49 NZT | Wazuh Dashboard displayed 6 hits for `m2test0507` |

## MITRE ATT&CK Mapping

| Tactic | Technique ID | Technique | Reason |
|---|---|---|---|
| Credential Access | T1110.001 | Password Guessing | The activity involved repeated authentication attempts using a non-existent account name |
| Lateral Movement | T1021.004 | SSH | The activity targeted the SSH remote access service |

## Severity

**Lab context:** Low

The activity was authorized and controlled. No successful login was observed.

**Production context:** Medium

If observed on an internet-facing production server, repeated invalid-user SSH attempts may indicate internet scanning, password guessing, brute-force activity, or early-stage unauthorized access attempts.

## Confidence

**High**

The assessment is high confidence because the activity was confirmed across multiple sources:

- raw endpoint authentication logs;
- Wazuh server alert logs;
- Wazuh structured JSON alerts;
- Wazuh Dashboard event details.

## Impact

No compromise was observed in the lab environment.

Potential production impact would include:

- increased risk of unauthorized access attempts;
- possible credential guessing activity;
- increased SOC alert noise;
- need to verify whether any successful login followed the failed attempts.

## Recommended Actions

- Restrict SSH access to trusted source IP addresses where possible.
- Disable password-based SSH authentication if operationally feasible.
- Use SSH key-based authentication for administrative access.
- Monitor repeated failed authentication attempts by source IP, target host, and username.
- Review successful SSH logins after repeated failures.
- Consider temporary blocking or rate limiting for aggressive sources.
- Review duplicate log ingestion from `/var/log/auth.log` and `journald`.

## Detection Improvement

The Wazuh alert count was higher than the raw endpoint event count because the same SSH events were collected from both `/var/log/auth.log` and `journald`.

Detection tuning should review whether both sources are required. If both are retained, dashboards and reports should account for duplicate ingestion to avoid inflated alert counts.

A future correlation rule could focus on:

- same source IP;
- same destination host;
- repeated failed SSH attempts;
- short time window;
- invalid or suspicious usernames.

## Final Assessment

This alert is assessed as:

**True Positive — Authorized Lab Simulation**

The event pattern was real from a detection perspective, but it was intentionally generated as part of a controlled SOC lab scenario. No successful login or confirmed compromise was identified.