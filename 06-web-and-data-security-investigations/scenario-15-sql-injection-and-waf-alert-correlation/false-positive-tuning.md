# False-Positive Tuning

## Observed issue

Forty-six SQLi candidates were assessed as likely false positives. Every candidate was a Rule 942100-only match. Thirty-six targeted `/wp-login.php`; other examples involved WordPress-style session-cookie values.

### Password example

- Variable: `ARGS:pwd`
- Raw value: `admin123%21%40%23`
- Decoded value: `admin123!@#`
- Rule: 942100 only
- Assessment: ordinary password punctuation misclassified by libinjection

### Cookie example

A stable session-cookie structure containing a hash and `||timestamp||timestamp` delimiters was classified by libinjection without specialist SQLi-rule support.

## Tuning principles

1. Do not disable Rule 942100 globally.
2. Retain the event for telemetry and trend analysis.
3. Lower priority when Rule 942100 is the only SQLi rule and the variable is a known password or session cookie.
4. Require additional SQLi rule support, explicit SQL syntax or burst behaviour for high-severity escalation.
5. Apply exclusions to the narrowest Host, route and variable scope.
6. Validate every exclusion against malicious and benign regression fixtures.
7. Review decoded and raw values together to avoid normalisation mistakes.

## Suggested triage tiers

| Tier | Conditions | Action |
|---|---|---|
| High | Specialist SQLi rule or two or more Rule 942 IDs plus repeated activity | Immediate SOC escalation |
| Medium | Rule 942100 plus explicit SQL syntax or unusual parameter context | Analyst review |
| Low | Rule 942100 only in password/known session cookie, no peer rule | Retain, aggregate and periodically review |

## Regression criteria

A tuning change is acceptable only if:

- Known password and cookie fixtures no longer create high-priority incidents.
- UNION, Boolean and time-based fixtures remain detected.
- Raw and decoded forms are both tested.
- Final enforcement logging remains visible.
