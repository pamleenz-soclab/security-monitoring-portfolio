# Investigation Report: Benign SSH Authentication Failure

## Executive Summary

A single SSH (Secure Shell) authentication failure was generated against the Ubuntu target endpoint using the non-existent username `m2benign0509`.

The activity triggered Wazuh SIEM / XDR Rule 5710, which detects attempts to log in using a non-existent SSH user. Raw Linux logs confirmed one actual invalid-user SSH event. Wazuh displayed two relevant SSH alert records because the same event was collected from both `/var/log/auth.log` and `journald`.

No successful login, repeated brute-force pattern, or evidence of compromise was observed.

The final assessment is Benign Positive.

## Scope

| Field | Value |
|---|---|
| Scenario | Scenario 03: Benign Authentication Failure Case |
| Target endpoint | `soc-lab-ubuntu-target-01` |
| Test username | `m2benign0509` |
| Source IP | `[SOURCE_IP_REDACTED]` |
| Raw log source | `/var/log/auth.log` |
| Additional log source | `journald` |
| Detection platform | Wazuh SIEM / XDR |
| Timezone note | Raw logs use UTC; Wazuh Dashboard displays browser local time |

## Initial Detection

The event was detected by Wazuh Rule 5710:

| Field | Value |
|---|---|
| Rule ID | `5710` |
| Rule level | `5` |
| Rule description | `sshd: Attempt to login using a non-existent user` |
| Rule groups | `syslog`, `sshd`, `authentication_failed`, `invalid_login` |

## MITRE ATT&CK Mapping

| Tactic | Technique ID | Technique |
|---|---|---|
| Credential Access | T1110.001 | Password Guessing |
| Lateral Movement | T1021.004 | SSH |

Although Wazuh maps this behavior to password guessing and SSH remote services, the investigation context indicates a single benign authentication mistake rather than malicious brute-force activity.

## Raw Log Validation

The Ubuntu target recorded one core SSH invalid-user event:

```text
May  9 03:03:03 soc-lab-ubuntu-target-01 sshd[162845]: Invalid user m2benign0509 from [SOURCE_IP_REDACTED] port 59491
```

The related connection closure event was:

```text
May  9 03:03:03 soc-lab-ubuntu-target-01 sshd[162845]: Connection closed by invalid user m2benign0509 [SOURCE_IP_REDACTED] port 59491 [preauth]
```

The core invalid-user event count was:

```text
1
```

This confirms that the actual SSH invalid-user attempt occurred once.

## Wazuh Alert Validation

Wazuh generated two relevant SSH Rule 5710 alert records for the same test username.

The Wazuh location count was:

```text
1 "location":"/var/log/auth.log"
1 "location":"journald"
```

This means the single endpoint event was collected from two Linux log sources.

The correct interpretation is:

```text
Actual SSH invalid-user attempt count: 1
Relevant Wazuh SSH Rule 5710 alert count: 2
Reason: duplicate ingestion from /var/log/auth.log and journald
```

## Keyword Search Observation

A broad Dashboard search for `m2benign0509` initially returned six hits.

Only two of those hits were relevant SSH Rule 5710 alerts. The other four were sudo-related alerts generated because earlier investigation commands contained the same test username.

This demonstrates that broad keyword search can over-collect unrelated alerts.

The relevant SSH events were isolated by filtering on:

```text
m2benign0509 AND rule.id:5710
```

## Timeline of Events

| Time | Timezone | Source | Event |
|---|---|---|---|
| May 9 03:03:03 | UTC | `/var/log/auth.log` | Invalid user `m2benign0509` recorded by sshd |
| May 9 03:03:03 | UTC | `/var/log/auth.log` | Connection closed before authentication |
| May 9 15:03:04 | NZT | Wazuh Dashboard | Rule 5710 alert displayed |
| May 9 15:03:04 | NZT | Wazuh Dashboard | Two relevant SSH Rule 5710 hits observed |

## Analysis

The event was detected correctly by Wazuh.

However, the security meaning of the event is different from Scenario 02. Scenario 02 involved repeated invalid-user activity, while Scenario 03 involved a single controlled authentication failure.

A single invalid-user SSH event may occur when:

- An administrator mistypes a username
- A user selects the wrong account
- A scripted test uses a placeholder account
- A controlled lab simulation is performed

In this case, the test username was known, the behavior was isolated, and no follow-on suspicious activity was observed.

## Comparison with Scenario 02

| Item | Scenario 02 | Scenario 03 |
|---|---|---|
| Activity | Repeated SSH invalid-user attempts | Single benign SSH invalid-user failure |
| Pattern | Repeated | Isolated |
| Raw core event count | 3 | 1 |
| Relevant Wazuh SSH alert count | 6 | 2 |
| Duplicate ingestion observed | Yes | Yes |
| Security interpretation | Suspicious brute-force-style behavior | Benign administrator or lab mistake |
| Final assessment | True Positive — Authorized Lab Simulation | Benign Positive |
| Evidence of compromise | Not observed | Not observed |

## Assessment

Benign Positive.

The event was real and correctly detected, so it is not a false positive. However, based on the isolated pattern, known test context, lack of successful login, and lack of additional suspicious activity, the event is assessed as benign.

## Impact Assessment

| Impact Area | Result |
|---|---|
| Account compromise | Not observed |
| Successful SSH login | Not observed |
| Repeated password guessing | Not observed |
| Host compromise | Not observed |
| Business impact | None in lab context |
| Required containment | Not required |

## Conclusion

Scenario 03 demonstrates that alert interpretation requires context.

Wazuh Rule 5710 correctly detected an invalid SSH username attempt, but the event should not automatically be treated as malicious. Raw log validation, alert filtering, source correlation, and pattern analysis showed that the event was a benign positive.

This case provides a useful comparison against Scenario 02 and strengthens the portfolio's coverage of true positive, benign positive, and false-positive-style investigation reasoning.
