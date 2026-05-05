# Alert Triage Template

## Case Information

| Field | Value |
|---|---|
| Case ID | SOC-LAB-SCENARIO-01 |
| Alert Name | SSH Invalid User Authentication Attempts |
| Analyst | Panpan Li |
| Date / Time | Apr 30 06:47:10-06:47:11 raw Linux log time |
| Environment | DigitalOcean cloud-hosted Wazuh SIEM / XDR lab |
| Affected Asset | `soc-lab-ubuntu-target-01` |
| Source IP | `<SOURCE_IP>` |
| Target User | `fake-admin` |
| Detection Platform | Wazuh SIEM / XDR |
| Severity | Low in lab context; Medium if observed in production |
| Confidence | High - confirmed by raw endpoint log, Wazuh alert log, and Dashboard event fields|
| Assessment | True Positive - Authorized Lab Simulation |

## Initial Question

Is this SSH authentication failure activity a real security event, a false positive, or benign authorized activity?

## Data Sources Reviewed

| Data Source | Reviewed? | Notes |
|---|---|---|
| SIEM alert | Yes | Wazuh Dashboard showed rule `5710` events for `soc-lab-ubuntu-target-01`. |
| Raw endpoint log | Yes | `/var/log/auth.log` confirmed invalid SSH user attempts. |
| Firewall log | No | Not collected in this scenario. |
| Network telemetry | No | Not collected in this scenario. Future improvement: add VPC flow logs, packet capture, Zeek, Suricata, or firewall logs. |
| Endpoint process telemetry | No | Not required for this SSH authentication investigation. |
| Login history | Optional | Can be checked with `last -i` and `grep "Accepted" /var/log/auth.log` to confirm whether successful login occurred. |

## Evidence

| Evidence | Finding |
|---|---|
| Raw log entry | `Apr 30 06:47:11 soc-lab-ubuntu-target-01 sshd[50661]: Invalid user fake-admin from <SOURCE_IP> port 63881` |
| SIEM rule | Wazuh rule `5710`: `sshd: Attempt to login using a non-existent user` |
| Source IP | `<SOURCE_IP>` |
| Target account | `fake-admin` |
| Time window | Apr 30 06:47:10-06:47:11 raw Linux log time |
| Successful login observed? | No evidence of successful login was observed for `fake-admin` in this investigation. |

## Timeline

| Time | Event |
|---|---|
| Apr 28 03:07:16-03:07:18 | Initial SSH invalid-user simulation generated logs on the Ubuntu target, but Wazuh did not alert because `/var/log/auth.log` was not yet collected by the Wazuh Agent. |
| Apr 30 | Wazuh Agent configuration was updated to collect `/var/log/auth.log`. |
| Apr 30 06:47:10-06:47:11 | New SSH invalid-user attempts were generated against `soc-lab-ubuntu-target-01` using the test username `fake-admin`. |
| Apr 30 06:47 | Ubuntu Target recorded 3 invalid-user log entries in `/var/log/auth.log`. |
| Apr 30 06:47 | Wazuh Server received 6 related alert log entries in `/var/ossec/logs/alerts/alerts.log`. |
| Later review | Wazuh Dashboard displayed the events under Threat Hunting -> Events with rule ID `5710`. |

## MITRE ATT&CK Mapping

| MITRE ID | Technique | Relevance |
|---|---|---|
| `T1110.001` | Password Guessing | The activity involved an attempted SSH login using a guessed or non-existent username. |
| `T1021.004` | SSH | The authentication attempt targeted SSH remote access. |

## Assessment

This alert is assessed as a **True Positive - Authorized Lab Simulation**.

The activity was real from a logging and detection perspective: the Ubuntu endpoint recorded invalid SSH user attempts, and Wazuh collected, parsed, and displayed the corresponding alerts. However, the activity was intentionally generated as part of an authorized lab exercise, so it does not indicate a real compromise.

## Impact

In this lab environment, the impact is low because the activity was authorized and no successful login was observed.

In a real enterprise environment, similar activity could indicate SSH username guessing, password guessing, or internet-wide scanning against an exposed Linux server. If followed by successful login events, the incident would need to be escalated for account compromise and host investigation.

## Recommended Actions

| Action | Purpose | Status |
|---|---|---|
| Review successful login records | Confirm whether compromise occurred | Recommended |
| Restrict SSH exposure | Reduce attack surface by limiting SSH to trusted IPs or VPN ranges | Recommended |
| Disable password authentication | Reduce password guessing risk by requiring SSH key-based login | Recommended after key-based access is tested |
| Add correlation rule | Improve detection of repeated invalid-user attempts from the same source IP | Recommended |

## Detection Improvement

The main detection gap discovered during this scenario was that the Wazuh Agent was initially not collecting `/var/log/auth.log`. After adding `/var/log/auth.log` to the Wazuh Agent `localfile` configuration and restarting the agent, Wazuh successfully received and displayed the SSH invalid-user alerts.

Future improvements should include a higher-severity Wazuh correlation rule for repeated rule `5710` events from the same source IP, collection of network telemetry such as VPC flow logs or packet capture, and consistent timestamp handling between raw Linux logs and Dashboard display time.

## Final Conclusion

The investigation confirmed that `soc-lab-ubuntu-target-01` generated SSH invalid-user authentication logs and that Wazuh successfully collected, parsed, and displayed them after `/var/log/auth.log` collection was enabled.

The final triage decision is **True Positive - Authorized Lab Simulation**. No successful login or confirmed compromise was observed.
