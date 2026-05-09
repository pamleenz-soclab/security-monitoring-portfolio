# Investigation Report: Repeated SSH Invalid-User Authentication Attempts

## 1. Executive Summary

This report documents a controlled SSH (Secure Shell) invalid-user authentication investigation conducted in a Wazuh SIEM / XDR (Security Information and Event Management / Extended Detection and Response) lab environment.

Three controlled SSH invalid-user authentication attempts were generated against the monitored Ubuntu endpoint `soc-lab-ubuntu-target-01` using the test username `m2test0507`.

The Ubuntu endpoint recorded 3 core `Invalid user m2test0507` events in `/var/log/auth.log`. Wazuh displayed 6 alert records for the same activity because the same SSH authentication events were ingested from two Linux log sources:

- `/var/log/auth.log`
- `journald`

The alert was assessed as:

**True Positive — Authorized Lab Simulation**

No successful login or evidence of compromise was observed.

---

## 2. Scope

| Item | Details |
|---|---|
| Scenario | Scenario 02: Repeated SSH Invalid-User Authentication Attempts |
| Investigation Type | Authentication attack investigation |
| SIEM / XDR Platform | Wazuh |
| Wazuh Manager | soc-lab-wazuh-server |
| Monitored Endpoint | soc-lab-ubuntu-target-01 |
| Endpoint Operating System | Ubuntu 22.04.5 LTS |
| Wazuh Agent ID | 001 |
| Wazuh Agent IP | 10.126.0.3 |
| Test Username | m2test0507 |
| Source IP | [SOURCE_IP_REDACTED] |
| Log Sources | `/var/log/auth.log`, `journald`, Wazuh alerts |
| Scenario Status | Authorized lab simulation |

---

## 3. Initial Detection

The activity was detected through Wazuh Security Events after repeated SSH invalid-user authentication attempts were generated against the monitored Ubuntu endpoint.

The key Wazuh alert was:

| Field | Value |
|---|---|
| rule.id | 5710 |
| rule.level | 5 |
| rule.description | sshd: Attempt to login using a non-existent user |
| decoder.name | sshd |
| data.srcuser | m2test0507 |
| agent.name | soc-lab-ubuntu-target-01 |
| location | `/var/log/auth.log` and `journald` |

---

## 4. Investigation Questions

The investigation focused on the following questions:

1. Did the monitored endpoint record the SSH invalid-user attempts?
2. Did Wazuh generate alerts for the activity?
3. How many actual endpoint authentication events occurred?
4. Why did Wazuh show more alerts than the raw endpoint event count?
5. Was there any successful login or evidence of compromise?
6. What detection engineering improvements should be considered?

---

## 5. Data Sources Reviewed

| Data Source | Purpose |
|---|---|
| Ubuntu `/var/log/auth.log` | Validate raw endpoint authentication events |
| Wazuh `/var/ossec/logs/alerts/alerts.log` | Confirm Wazuh alert generation |
| Wazuh `/var/ossec/logs/alerts/alerts.json` | Review structured alert data |
| Wazuh Dashboard | Confirm visual alert evidence and event details |
| Screenshot evidence | Document filtered events and key Wazuh fields |

---

## 6. Test Activity Description

Three controlled SSH invalid-user authentication attempts were generated from a trusted test source against the Ubuntu target endpoint.

The test username was:

```text
m2test0507
```

The username did not exist on the target system. The target SSH service rejected the authentication attempts.

The observed endpoint behavior was:

```text
Invalid user m2test0507 from [SOURCE_IP_REDACTED]
Connection closed by invalid user m2test0507 [SOURCE_IP_REDACTED] [preauth]
```

This activity represents a brute-force-style authentication pattern from a detection perspective, although it was intentionally generated in an authorized lab environment.

---

## 7. Evidence Collected

### 7.1 Endpoint Raw Log Evidence

The Ubuntu endpoint recorded 3 core `Invalid user m2test0507` events in `/var/log/auth.log`.

Evidence file:

```text
../../evidence/sanitized-samples/scenario-02/authlog-m2test0507-sanitized.txt
```

Expected sanitized example:

```text
May  7 03:46:41 soc-lab-ubuntu-target-01 sshd[PID]: Invalid user m2test0507 from [SOURCE_IP_REDACTED] port [SOURCE_PORT] ssh2
May  7 03:49:48 soc-lab-ubuntu-target-01 sshd[PID]: Invalid user m2test0507 from [SOURCE_IP_REDACTED] port [SOURCE_PORT] ssh2
May  7 03:49:58 soc-lab-ubuntu-target-01 sshd[PID]: Invalid user m2test0507 from [SOURCE_IP_REDACTED] port [SOURCE_PORT] ssh2
```

Endpoint event count:

```text
3
```

---

### 7.2 Wazuh Alert Evidence

Wazuh generated alerts for the same activity.

Evidence file:

```text
../../evidence/sanitized-samples/scenario-02/wazuh-alerts-m2test0507-sanitized.txt
```

Wazuh displayed 6 alert records for `m2test0507`.

This did not mean 6 separate SSH attempts occurred. Further investigation showed that each of the 3 endpoint events appeared twice in Wazuh because the same events were collected from both `/var/log/auth.log` and `journald`.

---

### 7.3 Wazuh Location Count Evidence

Evidence file:

```text
../../evidence/sanitized-samples/scenario-02/wazuh-location-count.txt
```

Observed location count:

```text
3 "location":"/var/log/auth.log"
3 "location":"journald"
```

This confirms duplicate ingestion across two Linux log sources.

---

### 7.4 Dashboard Screenshot Evidence

| Screenshot | Description |
|---|---|
| `../../screenshots/scenario-02/01-scenario-02-dashboard-filtered-events.png` | Wazuh Dashboard filtered events showing 6 hits for `m2test0507` |
| `../../screenshots/scenario-02/02-scenario-02-event-detail-core-fields.png` | Event details showing agent, source user, decoder, location, and full log |
| `../../screenshots/scenario-02/03-scenario-02-event-detail-rule-mitre-fields.png` | Event details showing rule ID, severity, groups, and MITRE ATT&CK mapping |

---

## 8. Timeline of Events

| Time | Event |
|---|---|
| May 7, 2026 03:31 UTC | Scenario start time recorded |
| May 7, 2026 03:46 UTC | First SSH invalid-user authentication attempt observed |
| May 7, 2026 03:49 UTC | Additional SSH invalid-user authentication attempts observed |
| May 7, 2026 03:53 UTC | Endpoint evidence files saved |
| May 7, 2026 04:04 UTC | Wazuh alert evidence files saved |
| May 7, 2026 04:18 UTC | Wazuh location count confirmed duplicate ingestion |
| May 7, 2026 15:46–15:49 NZT | Wazuh Dashboard displayed 6 hits for `m2test0507` |

Timezone note:

The Ubuntu endpoint logs used UTC (Coordinated Universal Time). The Wazuh Dashboard displayed events in local browser time, which appeared as NZT (New Zealand Time). This explains the difference between raw Linux log time and Dashboard display time.

---

## 9. Key Findings

### Finding 1: The endpoint recorded repeated SSH invalid-user attempts

The Ubuntu endpoint recorded 3 core `Invalid user m2test0507` events in `/var/log/auth.log`.

This confirms that the authentication attempts occurred at the endpoint level.

---

### Finding 2: Wazuh successfully generated alerts

Wazuh generated alerts using rule ID `5710`.

The rule description was:

```text
sshd: Attempt to login using a non-existent user
```

This confirms that the Wazuh Agent collected the relevant authentication events and the Wazuh Manager applied the expected detection rule.

---

### Finding 3: Wazuh alert count was higher than raw endpoint event count

The endpoint recorded 3 core events, while Wazuh displayed 6 alert records.

The reason was duplicate ingestion from two Linux log sources:

- `/var/log/auth.log`
- `journald`

This is a detection engineering issue because duplicate ingestion can inflate alert counts and increase SOC (Security Operations Center) noise.

---

### Finding 4: No successful login was observed

No evidence of successful SSH authentication was observed after the failed invalid-user attempts.

No compromise indicators were identified during this investigation.

---

## 10. MITRE ATT&CK Mapping

| Tactic | Technique ID | Technique | Reason |
|---|---|---|---|
| Credential Access | T1110.001 | Password Guessing | The activity involved repeated authentication attempts using a non-existent username |
| Lateral Movement | T1021.004 | SSH | The activity targeted the SSH remote access service |

Although no successful login occurred, the behavior is relevant to credential access monitoring because repeated invalid-user attempts can indicate password guessing, internet scanning, or brute-force-style activity.

---

## 11. Impact Assessment

### Lab Environment Impact

| Area | Assessment |
|---|---|
| System compromise | No evidence observed |
| Successful login | Not observed |
| Data access | Not observed |
| Service disruption | Not observed |
| Severity | Low |

The activity was authorized and controlled.

### Production Environment Impact

If observed on an internet-facing production server, this activity would require further investigation.

Potential production risks include:

- password guessing;
- brute-force activity;
- automated internet scanning;
- attempts to identify valid usernames;
- increased SOC alert noise;
- possible follow-up login attempts using valid credentials.

Production severity would be assessed as:

```text
Medium
```

especially if repeated attempts were followed by successful authentication.

---

## 12. Containment and Remediation

No containment action was required in the lab environment because the activity was authorized.

For a production environment, recommended actions would include:

1. Review successful SSH logins after the failed attempts.
2. Confirm whether the source IP is known, trusted, or malicious.
3. Restrict SSH access to trusted administrative IP addresses.
4. Disable password-based SSH authentication where possible.
5. Enforce SSH key-based authentication.
6. Consider rate limiting or temporary blocking for aggressive sources.
7. Review whether SSH should be exposed directly to the internet.
8. Use a bastion host, VPN (Virtual Private Network), or zero trust access gateway for administrative access.

---

## 13. Detection Engineering Notes

### Duplicate Log Ingestion

The most important detection engineering observation in this scenario is duplicate ingestion.

The same SSH authentication events were ingested from both:

```text
/var/log/auth.log
journald
```

This resulted in:

```text
3 raw endpoint events
6 Wazuh alert records
```

This can affect SOC workflows because inflated alert counts may cause analysts to overestimate the scale of an activity.

### Recommended Tuning Options

Possible tuning options include:

1. Select one primary SSH authentication log source.
2. Keep both sources but apply deduplication logic.
3. Build dashboard queries that group alerts by:
   - source IP;
   - destination host;
   - username;
   - timestamp;
   - rule ID;
   - log message.
4. Create a correlation rule for repeated failed SSH activity within a short time window.
5. Separate raw event count from alert record count in reports.

---

## 14. Detection Improvement Opportunity

A future detection rule could focus on repeated SSH failed authentication attempts using the following logic:

```text
Detect when the same source IP generates multiple failed SSH authentication attempts against the same destination host within a defined time window.
```

Suggested correlation fields:

| Field | Purpose |
|---|---|
| `data.srcip` | Identify repeated attempts from the same source |
| `agent.name` | Identify the targeted endpoint |
| `data.srcuser` | Track attempted username |
| `rule.id` | Filter relevant SSH invalid-user events |
| `timestamp` | Apply a time window |
| `location` | Identify and handle duplicate ingestion |

Suggested time window:

```text
5 to 10 minutes
```

Suggested threshold:

```text
3 or more failed invalid-user attempts
```

---

## 15. Limitations

This scenario has several limitations:

1. The activity was generated in a controlled lab environment.
2. Only Linux SSH authentication logs were analyzed.
3. No packet capture was collected for this scenario.
4. No Windows Event Log data was involved.
5. No successful login occurred, so post-authentication investigation was not required.
6. The test did not use high-volume brute-force tooling.

These limitations are acceptable for this scenario because the objective was to validate SSH authentication log collection, Wazuh alert generation, alert triage, and duplicate ingestion analysis.

---

## 16. Conclusion

This investigation confirmed that Wazuh successfully detected SSH invalid-user authentication attempts against the monitored Ubuntu endpoint.

The endpoint recorded 3 core `Invalid user m2test0507` events. Wazuh displayed 6 alert records because each event was collected from both `/var/log/auth.log` and `journald`.

The alert was assessed as:

```text
True Positive — Authorized Lab Simulation
```

No successful login or evidence of compromise was observed.

The main detection engineering lesson from this scenario is that alert counts must be validated against raw endpoint logs. Duplicate ingestion can inflate SIEM alert counts and should be considered during SOC triage and detection tuning.