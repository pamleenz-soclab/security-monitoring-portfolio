# Data Source Inventory

## Purpose

This file documents available security data sources in the SOC lab and explains what each source can prove during an investigation.

## Data Sources

| Data Source | Location | Asset | Purpose | Used in Scenario 01 |
|---|---|---|---|---|
| Linux authentication log | `/var/log/auth.log` | Ubuntu Target | Records SSH login attempts, invalid users, accepted sessions, and authentication failures | Yes |
| Wazuh Agent configuration | `/var/ossec/etc/ossec.conf` | Ubuntu Target | Defines which logs the agent collects | Yes |
| Wazuh alert log | `/var/ossec/logs/alerts/alerts.log` | Wazuh Server | Stores Wazuh text-format alerts | Yes |
| Wazuh JSON alert log | `/var/ossec/logs/alerts/alerts.json` | Wazuh Server | Stores structured Wazuh alerts | Optional |
| Wazuh Dashboard Events | Threat Hunting → Events | Wazuh Dashboard | Investigator-facing event view | Yes |
| Wazuh Agent status | Dashboard Endpoints page | Wazuh Dashboard | Confirms endpoint is active and reporting | Yes |

## Key Fields for SSH Authentication Investigation

| Field | Meaning | Example |
|---|---|---|
| `timestamp` | Dashboard event time | `Apr 30, 2026 @ 18:47:12.620` |
| `agent.name` | Monitored endpoint name | `soc-lab-ubuntu-target-01` |
| `agent.id` | Wazuh Agent ID | `001` |
| `agent.ip` | Endpoint private IP | `10.126.0.3` |
| `data.srcip` | Source IP of SSH attempt | `49.227.160.67` |
| `data.srcport` | Source ephemeral port | `63881` |
| `data.srcuser` | Username used in SSH attempt | `fake-admin` |
| `location` | Original log source path | `/var/log/auth.log` |
| `decoder.name` | Wazuh decoder | `sshd` |
| `full_log` | Raw log evidence | `Invalid user fake-admin from 49.227.160.67 port 63881` |
| `rule.id` | Wazuh rule ID | `5710` |
| `rule.level` | Wazuh severity level. Wazuh rule levels range from 0 to 16; level 5 indicates a low-to-medium severity authentication event. | `5` |
| `rule.description` | Alert description | `sshd: Attempt to login using a non-existent user` |
| `rule.groups` | Alert categories | `syslog, sshd, authentication_failed, invalid_login` |
| `rule.mitre.id` | MITRE ATT&CK mapping | `T1110.001, T1021.004` |
| `rule.mitre.tactic` | MITRE tactic | `Credential Access, Lateral Movement` |
| `rule.mitre.technique` | MITRE technique | `Password Guessing, SSH` |

## Lessons Learned

The initial SSH test generated raw logs in `/var/log/auth.log`, but Wazuh did not alert until the Wazuh Agent was configured to collect that file.

```text
No log collection means no SIEM visibility.
```
