# Generic Correlation Rules

## Multi-rule transaction

Group WAF events by transaction ID. Raise high priority when a transaction contains at least two distinct Rule 942xxx IDs or any specialist rule in `{942160, 942190, 942360}`.

## Burst rule

Within five minutes, group by trusted source IP, Host and User-Agent. Alert when there are at least 20 SQLi transactions, at least three distinct request targets or at least two distinct SQLi rule IDs.

## Enforcement-validation rule

Find transactions with SQLi rule matches and HTTP 403 where the final-action field is empty or does not indicate deny/intercept/drop. Route these to telemetry-quality review rather than labelling them blocked.

## False-positive review rule

Lower priority when Rule 942100 is the only SQLi rule and the matched variable is a password or approved session cookie. Never globally suppress the rule without regression testing.
