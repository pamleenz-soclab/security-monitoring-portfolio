# Month 2 Summary: Authentication Investigation, Benign Positive Analysis, and Port Scanning Detection Gap

## Overview

Month 2 focused on identity authentication investigation, alert validation, multi-source evidence correlation, and detection gap analysis.

The work continued the enterprise-style SOC (Security Operations Center) and Security Engineering portfolio by investigating controlled security events using Linux logs, Wazuh SIEM / XDR (Security Information and Event Management / Extended Detection and Response), raw endpoint evidence, and network packet evidence.

## Completed Scenarios

| Scenario | Title | Final Assessment | Main Learning |
|---|---|---|---|
| Scenario 02 | Repeated SSH Invalid-User Authentication Attempts | True Positive — Authorized Lab Simulation | Repeated invalid-user SSH activity can resemble brute-force behavior, and Wazuh alert counts can be inflated by duplicate log ingestion |
| Scenario 03 | Benign Authentication Failure Case | Benign Positive | A technically valid alert can still be benign when the activity is isolated, controlled, and explainable |
| Scenario 04 | Port Scanning Investigation and Detection Gap Analysis | Detection Gap | Network-layer activity may be visible in tcpdump but not clearly alerted by a host-log-focused Wazuh configuration |

## Scenario 02: Repeated SSH Invalid-User Authentication Attempts

Scenario 02 simulated repeated SSH (Secure Shell) login attempts using a non-existent username.

The Ubuntu Target recorded three core invalid-user events in `/var/log/auth.log`.

Wazuh generated six relevant SSH Rule 5710 alert records because the same events were collected from two Linux log sources:

- `/var/log/auth.log`
- `journald`

This demonstrated that SIEM alert count does not always equal actual endpoint event count.

### Key Takeaways

- Raw endpoint logs are necessary for validating SIEM alert volume.
- Duplicate ingestion can inflate alert counts.
- Repeated invalid-user activity should be treated as suspicious in a production context.
- Wazuh Rule 5710 is useful for detecting SSH login attempts using non-existent users.
- MITRE ATT&CK mapping helped frame the activity as password guessing and SSH remote service activity.

## Scenario 03: Benign Authentication Failure Case

Scenario 03 simulated a single benign SSH authentication failure using a known test username.

The Ubuntu Target recorded one core SSH invalid-user event.

Wazuh generated two relevant SSH Rule 5710 alert records because the same event was collected from both `/var/log/auth.log` and `journald`.

The final assessment was Benign Positive.

The event was real and correctly detected, so it was not a false positive. However, the context showed that it was isolated, controlled, and not associated with compromise.

### Key Takeaways

- A true alert is not automatically malicious.
- Context is required to distinguish malicious activity from benign activity.
- Frequency, source, username, successful-login evidence, and follow-on behavior affect triage decisions.
- Broad keyword searches can over-collect unrelated alerts.
- Filtering by `rule.id`, `rule.description`, `decoder.name`, and log source improves investigation accuracy.

## Scenario 04: Port Scanning Investigation and Detection Gap Analysis

Scenario 04 simulated controlled TCP (Transmission Control Protocol) port probing from the MacBook to the Ubuntu Target.

Because Nmap was not available on the MacBook, `nc` / Netcat was used to generate controlled TCP connection attempts.

The Ubuntu Target confirmed the activity using `tcpdump`, which showed TCP SYN packets from the same source IP to multiple destination ports.

The authentication log only recorded an SSH connection closure for the `22/tcp` probe.

Wazuh did not generate a clear port-scan alert during the scan time window.

The final assessment was Detection Gap.

### Key Takeaways

- Scanner-side results and target-side observed traffic may differ.
- Authentication logs do not reliably capture network-layer port scanning.
- tcpdump is useful for validating network activity at the target.
- No alert does not mean no activity.
- Reliable port-scan detection requires network telemetry such as firewall logs, UFW logs, Zeek, Suricata, Security Onion, cloud firewall logs, or flow logs.

## Evidence Sources Used

| Evidence Source | Used For |
|---|---|
| `/var/log/auth.log` | Validate Linux SSH authentication events |
| `journald` | Confirm duplicate ingestion behavior |
| Wazuh `alerts.json` | Validate Wazuh alert records and rule metadata |
| Wazuh Dashboard | Review alert fields, rule ID, rule level, and MITRE ATT&CK mapping |
| `ss -tulpen` | Establish listening-port baseline before port probing |
| `nc` / Netcat | Generate controlled TCP port probing activity |
| `tcpdump` | Confirm target-observed network traffic |
| Sanitized evidence files | Preserve public portfolio evidence without exposing sensitive public IP addresses |

## MITRE ATT&CK Mapping

| Scenario | Technique ID | Technique | Tactic |
|---|---|---|---|
| Scenario 02 | T1110.001 | Password Guessing | Credential Access |
| Scenario 02 | T1021.004 | SSH | Lateral Movement |
| Scenario 03 | T1110.001 | Password Guessing | Credential Access |
| Scenario 03 | T1021.004 | SSH | Lateral Movement |
| Scenario 04 | T1595 | Active Scanning | Reconnaissance |
| Scenario 04 | T1046 | Network Service Discovery | Discovery |

## Detection Engineering Observations

### 1. SIEM Alert Count vs Actual Event Count

Scenario 02 and Scenario 03 showed that Wazuh alert count may be higher than the actual endpoint event count when the same event is collected from multiple sources.

Observed pattern:

- One endpoint event can appear once from `/var/log/auth.log`
- The same event can also appear once from `journald`
- The SIEM may therefore display two alert records for one real event

### 2. Keyword Search Can Over-Collect

Scenario 03 showed that a broad keyword search can return unrelated alerts if the same keyword appears in investigation commands.

Better filters include:

- `rule.id`
- `rule.description`
- `decoder.name`
- `location`
- `full_log`

### 3. Host Logs Are Not Enough for Network Scanning

Scenario 04 showed that host authentication logs are not sufficient to detect most network-layer port probing.

The current Wazuh configuration is effective for SSH authentication monitoring, but it does not provide reliable port-scan detection without additional telemetry.

## Practical SOC Lessons

| Lesson | Explanation |
|---|---|
| Validate SIEM alerts against raw logs | SIEM output should be verified with endpoint evidence |
| Do not rely only on alert count | Alert count may be inflated by duplicate ingestion |
| Classify alerts using context | A true alert may be malicious, benign, or part of authorized testing |
| Use precise filters | Rule-based filtering is more reliable than keyword-only search |
| Preserve evidence | Sanitized logs, screenshots, and summaries make the investigation reproducible |
| Identify detection gaps | Lack of alerting can reveal missing telemetry or missing detection logic |

## Portfolio Value

Month 2 added three important enterprise-style investigation types to the portfolio:

1. Suspicious repeated authentication activity
2. Benign positive authentication activity
3. Network scanning detection gap

Together, these scenarios show the ability to:

- Investigate authentication alerts
- Validate SIEM detections
- Compare raw logs and SIEM records
- Explain true positive, benign positive, and detection gap outcomes
- Map activity to MITRE ATT&CK
- Document evidence in a public, sanitized portfolio format
- Translate technical findings into detection engineering improvements

## Interview Story

A concise interview explanation could be:

During Month 2 of my security monitoring portfolio, I investigated three related scenarios in a Wazuh-based lab. First, I simulated repeated SSH invalid-user attempts and validated that Wazuh Rule 5710 detected the activity, but I also found that alert counts were inflated because the same events were collected from both `/var/log/auth.log` and `journald`. Then I created a benign authentication failure case to show that a valid alert is not always malicious and should be classified based on context. Finally, I performed controlled TCP port probing and confirmed the scan with tcpdump, but Wazuh did not generate a clear port-scan alert. That helped me document a detection gap and explain why network telemetry such as firewall logs, Zeek, Suricata, or flow logs is needed for reliable port-scan detection.

## Final Month 2 Assessment

Month 2 successfully expanded the portfolio from basic SSH alert validation into more realistic SOC and Security Engineering reasoning.

The key improvement was moving beyond “did the alert fire?” toward deeper questions:

- What actually happened on the endpoint?
- Did the SIEM alert count match the raw event count?
- Is the alert malicious, benign, or part of authorized testing?
- What evidence source confirms the activity?
- What did the current monitoring configuration fail to detect?
- What telemetry or detection logic should be added next?

This creates a stronger foundation for future work in network security monitoring, detection engineering, threat hunting, and incident response.
