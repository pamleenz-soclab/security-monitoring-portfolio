# Investigation Report: SSH Invalid User Authentication Attempts

## Case Information

| Field | Value |
|---|---|
| Case ID | SOC-LAB-SCENARIO-01 |
| Report Title | SSH Invalid User Authentication Attempt Investigation |
| Environment | DigitalOcean cloud-hosted SOC lab |
| Affected Asset | `soc-lab-ubuntu-target-01` |
| Detection Platform | Wazuh SIEM / XDR |
| Data Sources | `/var/log/auth.log`, Wazuh Dashboard, `/var/ossec/logs/alerts/alerts.log` |
| Assessment | True Positive - authorized lab simulation |
| Severity | Low in lab context; Medium if seen in production |
| Confidence | High |

## Executive Summary

Multiple SSH invalid-user authentication attempts were observed against the monitored Ubuntu endpoint `soc-lab-ubuntu-target-01`.

The activity targeted the non-existent user account `fake-admin` from a source public IP address. The raw Linux authentication log confirmed at least 3 invalid-user attempts, while Wazuh generated 6 related alert log entries and displayed the events in the Threat Hunting dashboard.

This was an authorized lab simulation designed to validate the monitoring pipeline from endpoint logging to Wazuh alerting.

## Scope

This investigation focuses on the Apr 30 test event, because it completed the full detection chain.

| Item | Value |
|---|---|
| Time Window | Apr 30 06:47:10-06:47:11 raw Linux log time |
| Source IP | `<SOURCE_IP>` |
| Target Asset | `soc-lab-ubuntu-target-01` |
| Target Agent ID | `001` |
| Target Agent IP | `10.126.0.3` |
| Target Service | SSH / TCP 22 |
| Target User | `fake-admin` |
| Log Source | `/var/log/auth.log` |
| Wazuh Rule ID | `5710` |

Earlier Apr 28 test events were excluded from the main investigation because the Wazuh Agent had not yet been configured to collect `/var/log/auth.log`.

## Environment Context

| Component | Value |
|---|---|
| Cloud Provider | DigitalOcean |
| Region | Sydney SYD1 |
| VPC | default-syd1 |
| Wazuh Server | `soc-lab-wazuh-server` |
| Ubuntu Target | `soc-lab-ubuntu-target-01` |
| Wazuh Agent Version | v4.14.5 |
| Agent Status | Active |

## Evidence Collected

### Evidence 1 - Ubuntu Target Raw Authentication Log

File saved on Ubuntu Target:

```bash
/root/scenario-01-ssh-auth/authlog-fake-admin.txt
```

Confirmed count:

```bash
grep "Apr 30 06:47" /var/log/auth.log | grep "Invalid user fake-admin" | wc -l
```

Result:

```text
3
```

Representative raw log:

```text
Apr 30 06:47:11 soc-lab-ubuntu-target-01 sshd[50661]: Invalid user fake-admin from <SOURCE_IP> port 63881
```

This confirms that the Ubuntu endpoint recorded invalid SSH login attempts against the non-existent user `fake-admin`.

### Evidence 2 - Wazuh Server Alert Log

File saved on Wazuh Server:

```bash
/root/scenario-01-ssh-auth/wazuh-alerts-fake-admin.txt
```

Confirmed count:

```bash
grep "Apr 30 06:47" /var/ossec/logs/alerts/alerts.log | grep "Invalid user fake-admin" | wc -l
```

Result:

```text
6
```

This confirms that Wazuh Server received and parsed the SSH invalid-user activity from the target endpoint.

### Evidence 3 - Wazuh Dashboard Event

| Field | Value |
|---|---|
| `agent.name` | `soc-lab-ubuntu-target-01` |
| `agent.id` | `001` |
| `agent.ip` | `10.126.0.3` |
| `data.srcip` | `<SOURCE_IP>` |
| `data.srcport` | `63881` |
| `data.srcuser` | `fake-admin` |
| `location` | `/var/log/auth.log` |
| `decoder.name` | `sshd` |
| `rule.id` | `5710` |
| `rule.level` | `5` |
| `rule.description` | `sshd: Attempt to login using a non-existent user` |
| `rule.groups` | `syslog, sshd, authentication_failed, invalid_login` |
| `rule.mitre.id` | `T1110.001`, `T1021.004` |
| `rule.mitre.tactic` | Credential Access, Lateral Movement |
| `rule.mitre.technique` | Password Guessing, SSH |

## Timeline of Events

| Time | Event |
|---|---|
| Apr 28 03:07:16-03:07:18 | Initial SSH invalid-user simulation generated logs on Ubuntu Target, but Wazuh did not alert because `/var/log/auth.log` was not yet collected. |
| Apr 30 | Wazuh Agent configuration was updated to collect `/var/log/auth.log`. |
| Apr 30 06:47:10-06:47:11 | New SSH invalid-user attempts were generated against `soc-lab-ubuntu-target-01`. |
| Apr 30 06:47 | Ubuntu Target recorded 3 invalid-user attempts in `/var/log/auth.log`. |
| Apr 30 06:47 | Wazuh Server received 6 related alert log entries. |
| Later review | Wazuh Dashboard displayed the events under Threat Hunting -> Events. |

## Timezone Note

The Wazuh Dashboard may display timestamps using the browser or local timezone, while `full_log` shows the raw Linux log timestamp.

For this investigation, the technical timeline is based on raw Linux authentication log time.

Suggested report statement:

```text
All technical timestamps in this report are based on raw Linux authentication logs. Dashboard timestamps may be displayed in the browser's local timezone.
```

## Analysis

The raw authentication logs show that a source IP attempted to authenticate to SSH using the non-existent account `fake-admin`.

The activity matched Wazuh rule:

```text
rule.id: 5710
rule.description: sshd: Attempt to login using a non-existent user
```

The alert is mapped by Wazuh to MITRE ATT&CK Enterprise techniques:

| MITRE ID | Technique | Relevance |
|---|---|---|
| `T1110.001` | Password Guessing | The activity involved an attempted SSH login using a guessed or non-existent account. |
| `T1021.004` | SSH | The activity targeted SSH remote access. |

The available evidence supports an attempted SSH invalid-user authentication event. It does not prove a successful login, confirmed compromise, or successful lateral movement.

## Impact Assessment

In this lab environment, there was no confirmed compromise.

In a production environment, similar activity could indicate:

- SSH username guessing;
- password guessing preparation;
- internet-wide scanning;
- attempted access to exposed Linux servers;
- possible credential attack if valid usernames are later discovered.

No successful login was observed for the tested user.

## Root Cause / Detection Finding

The initial Apr 28 test produced logs on the endpoint but did not appear in Wazuh because the agent was not yet collecting `/var/log/auth.log`.

After adding the following `localfile` configuration to the Wazuh Agent, the detection chain worked correctly:

```xml
<localfile>
  <log_format>syslog</log_format>
  <location>/var/log/auth.log</location>
</localfile>
```

This finding shows that endpoint logging alone is not enough. The SIEM pipeline must also collect, parse, and alert on the relevant log source.

## Recommended Actions

See `recommended-actions.md` for detailed commands and operational steps.

Summary:

1. Verify whether any successful SSH login occurred from the same source IP.
2. Restrict SSH exposure to trusted source IPs or VPN ranges.
3. Use SSH key-based authentication.
4. Disable direct root SSH login.
5. Deploy Fail2ban or equivalent rate-limiting controls.
6. Block confirmed malicious source IPs when appropriate.
7. Improve Wazuh detection with correlation for repeated invalid-user events.
8. Standardize investigation timestamps.

## Detection Improvement

| Area | Improvement |
|---|---|
| Log Collection | Ensure `/var/log/auth.log` is collected by all Linux endpoints. |
| Correlation | Create a higher-severity rule for repeated invalid users from the same source IP within a short time window. |
| Enrichment | Add GeoIP, asset criticality, and known scanner reputation context. |
| Response | Add a response playbook for repeated SSH failures. |
| Dashboard | Standardize dashboard timezone to UTC or explicitly document timezone handling. |

## Final Conclusion

The investigation confirmed that `soc-lab-ubuntu-target-01` generated SSH invalid-user authentication logs and that Wazuh successfully collected, parsed, and displayed them as security alerts after the agent log collection configuration was corrected.

This validates the core monitoring pipeline:

```text
SSH invalid login attempt
-> Ubuntu /var/log/auth.log
-> Wazuh Agent
-> Wazuh Server
-> Wazuh Dashboard
-> SOC-style alert triage
```

Final assessment:

```text
True Positive - Authorized Lab Simulation
```
