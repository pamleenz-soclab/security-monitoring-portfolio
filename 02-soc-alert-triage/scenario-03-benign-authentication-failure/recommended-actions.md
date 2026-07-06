# Recommended Actions: Benign SSH Authentication Failure

## Summary

This scenario produced a valid Wazuh SSH alert for a non-existent username. The event was assessed as Benign Positive because it was isolated, controlled, and showed no evidence of compromise.

No urgent containment action is required in the lab environment.

## Immediate Action

| Action | Required? | Reason |
|---|---|---|
| Block source IP | No | The activity was a controlled lab test |
| Disable account | No | The username did not exist |
| Reset password | No | No valid account was affected |
| Isolate host | No | No compromise evidence was observed |
| Escalate as incident | No | Single benign authentication failure only |

## Recommended SOC Actions

1. Record the alert as a benign positive.
2. Preserve the sanitized evidence for portfolio documentation.
3. Validate SIEM alert count against raw endpoint logs.
4. Use specific filters such as `rule.id:5710` instead of broad keyword-only searches.
5. Compare the case against repeated invalid-user authentication patterns.

## Detection Engineering Recommendations

### 1. Avoid relying only on keyword search

A broad search for the test username returned unrelated sudo alerts because previous investigation commands contained the same username.

Future investigations should filter by fields such as:

- `rule.id`
- `rule.description`
- `decoder.name`
- `program_name`
- `location`
- `full_log`

### 2. Account for duplicate ingestion

The same SSH event appeared in Wazuh from two sources:

```text
/var/log/auth.log
journald
```

This can inflate alert counts.

SOC analysts should distinguish between:

```text
number of alert records
```

and:

```text
number of actual endpoint events
```

### 3. Define benign-positive criteria

A single SSH invalid-user event may be treated as benign when all of the following are true:

- The username is known to be part of an authorized test or expected user mistake
- The event is isolated
- No successful login follows
- No repeated attempts are observed
- No additional suspicious behavior is detected from the same source

### 4. Define suspicious criteria

The same Wazuh Rule 5710 alert should be treated as more suspicious when one or more of the following are observed:

- Multiple invalid usernames
- High event frequency
- Repeated attempts from the same source IP
- Attempts across multiple hosts
- Successful login after failed attempts
- Activity from unfamiliar or high-risk source locations
- Follow-on privilege escalation or persistence indicators

## Suggested Production Response

In a production environment, a single invalid-user SSH event should usually be triaged as low severity unless supported by additional suspicious context.

Recommended production handling:

1. Check whether the source IP belongs to an administrator, VPN range, monitoring tool, or known scanner.
2. Check whether the username resembles a legitimate internal username.
3. Review recent successful SSH logins from the same source IP.
4. Review repeated authentication failures within a defined time window.
5. Escalate only if repeated, distributed, or followed by successful authentication.

## Hardening Recommendations

Even though this lab case was benign, production SSH exposure should still be hardened.

Recommended controls:

| Control | Purpose |
|---|---|
| Disable password authentication | Reduce password guessing risk |
| Use public key authentication | Improve SSH authentication security |
| Restrict SSH source IPs | Reduce external attack surface |
| Use VPN or bastion host | Centralize administrative access |
| Enable MFA where possible | Add identity assurance |
| Monitor invalid-user frequency | Detect brute-force-style activity |
| Alert on successful login after failures | Identify possible compromise |

## Portfolio Learning Point

This scenario demonstrates that not all true alerts are malicious.

The correct classification is:

```text
Benign Positive
```

The alert was real, the detection was valid, but the activity was explainable and low risk in context.
