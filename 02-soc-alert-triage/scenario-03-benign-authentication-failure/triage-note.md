# Alert Triage Note: Benign SSH Authentication Failure

## Alert Name

SSH login attempt using a non-existent user

## Initial Question

Is this alert malicious activity, a false positive, or a benign positive?

## Alert Summary

| Field | Value |
|---|---|
| Detection platform | Wazuh SIEM / XDR |
| Rule ID | `5710` |
| Rule level | `5` |
| Rule description | `sshd: Attempt to login using a non-existent user` |
| Target host | `soc-lab-ubuntu-target-01` |
| Test username | `m2benign0509` |
| Source IP | `[SOURCE_IP_REDACTED]` |
| Assessment | Benign Positive |

## Data Sources Reviewed

| Data Source | Purpose |
|---|---|
| `/var/log/auth.log` | Validate raw Linux SSH authentication evidence |
| `journald` | Confirm duplicate Linux log source ingestion |
| Wazuh `alerts.json` | Validate Wazuh alert generation and rule fields |
| Wazuh Dashboard | Review alert details, rule ID, severity, and MITRE ATT&CK mapping |

## Evidence

### Raw Linux Authentication Log

The Ubuntu target recorded one core SSH invalid-user event:

```text
May  9 03:03:03 soc-lab-ubuntu-target-01 sshd[162845]: Invalid user m2benign0509 from [SOURCE_IP_REDACTED] port 59491
```

The same SSH session also produced a related pre-authentication connection closure log:

```text
May  9 03:03:03 soc-lab-ubuntu-target-01 sshd[162845]: Connection closed by invalid user m2benign0509 [SOURCE_IP_REDACTED] port 59491 [preauth]
```

### Wazuh Alert Evidence

Wazuh generated two relevant SSH Rule 5710 alert records.

The alert locations were:

```text
1 "location":"/var/log/auth.log"
1 "location":"journald"
```

This indicates duplicate ingestion of the same SSH event from two Linux log sources.

## Timeline

| Time | Source | Event |
|---|---|---|
| May 9 03:03:03 UTC | `/var/log/auth.log` | Invalid SSH user `m2benign0509` observed |
| May 9 03:03:03 UTC | `/var/log/auth.log` | SSH connection closed before authentication |
| May 9 15:03:04 NZT | Wazuh Dashboard | Rule 5710 alert displayed in browser local time |
| May 9 15:03:04 NZT | Wazuh Dashboard | Two relevant Rule 5710 hits observed |

## Assessment

Benign Positive.

The alert was technically valid because the SSH invalid-user event genuinely occurred and was correctly detected by Wazuh Rule 5710.

However, the activity consisted of a single controlled authentication failure using a known lab test username. There was no repeated pattern, no successful login, and no evidence of compromise.

Therefore, this alert is assessed as benign positive rather than malicious activity.

## Impact

No confirmed security compromise was identified.

| Impact Area | Assessment |
|---|---|
| Successful login | Not observed |
| Repeated brute-force pattern | Not observed |
| Privilege escalation | Not observed |
| Persistence | Not observed |
| Data access | Not observed |
| Service disruption | Not observed |

## Recommended Action

No emergency containment action is required for this lab scenario.

Recommended actions:

1. Document the event as a benign positive.
2. Keep the event as a comparison case against repeated invalid-user SSH activity.
3. Use precise filters such as `rule.id:5710` when reviewing Wazuh alerts.
4. Continue validating Wazuh alert counts against raw endpoint logs.

## Detection Improvement

This scenario highlights two detection engineering lessons:

1. Broad keyword searches may collect unrelated alerts if the keyword appears in investigation commands.
2. SIEM alert counts may be inflated when the same Linux event is collected from both `/var/log/auth.log` and `journald`.

Future investigation should filter by:

- `rule.id`
- `rule.description`
- `decoder.name`
- `location`
- `full_log`
