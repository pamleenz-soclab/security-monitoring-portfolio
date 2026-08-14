# Recommended Actions

## Prioritised response plan

| Priority | Action | Suggested owner | Validation |
|---|---|---|---|
| P0 | Preserve WAF, proxy, application and database evidence for the affected window | SOC / Platform | Retained data is inventoried and integrity-checked |
| P0 | Verify WAF policy mode, anomaly threshold and final disruptive-action logging | Security Engineering | A controlled non-production test produces an explicit final disposition |
| P1 | Apply temporary edge rate limits or source blocking where business and false-positive risk permit | SOC / Network Security | Malicious burst volume falls without affecting legitimate traffic |
| P1 | Review targeted routes and parameters for parameterised-query use and strict input validation | Application Security | Code review and regression tests confirm user input is not concatenated into SQL |
| P1 | Propagate a stable request ID across WAF, proxy and application tiers | Platform / Web Engineering | The same request can be followed end to end |
| P2 | Add database audit coverage and least-privilege review for application accounts | Database Engineering / IAM | Query/error events are attributable and access is limited to required schemas |

## Detection engineering improvements

1. Alert on specialist SQLi rule families and on multiple distinct Rule 942xxx IDs within one transaction.
2. Create burst detections by trusted source address, Host and User-Agent, requiring both volume and request/rule diversity.
3. Keep `rule match`, configured engine mode and final enforcement as separate fields.
4. Preserve raw request targets plus bounded decoded representations; do not recursively decode without limits.
5. Keep Rule 942100 password/cookie context as a lower-priority review path unless peer SQLi signals or explicit SQL syntax are present.
6. Flag HTTP 403 responses that lack an explicit WAF interception marker for telemetry-quality review rather than calling them blocked.

## Escalation and containment boundaries

- Escalate to application/database teams when response differentials, SQL errors, backend audit events or other evidence suggests query execution.
- Isolate a production web server only when host telemetry supports compromise such as Web shell creation, suspicious child processes, credential theft or outbound C2; a WAF SQLi alert alone is insufficient.
- Prefer narrow WAF exclusions scoped to known-good Host/route/parameter context. Do not globally disable Rule 942100 to solve contextual false positives.
