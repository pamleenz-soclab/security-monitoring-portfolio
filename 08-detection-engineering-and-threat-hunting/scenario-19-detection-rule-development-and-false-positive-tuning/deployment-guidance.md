# Deployment Guidance

Recommended deployment forms:

- R19-01: scheduled cloud-identity analytic anchored on successful MFA authentication.
- R19-02: endpoint analytic combining scheduled-task and process/network telemetry; keep atomic primitives as supporting signals.
- R19-03: scheduled WAF analytics; multi-rule transaction can be higher confidence than burst-only branch.
- R19-04: scheduled cloud audit/sign-in correlation keyed on stable service-principal and credential IDs.
- R19-05: near-real-time Windows privilege-change alert with governed privileged-group enrichment.
- R19-06: scheduled DNS correlation after exact-event deduplication; completion marker affects confidence, not trigger.

Before production deployment, validate table/index/sourcetype scope, time zones, late arrival, source clocks, field extraction, null/multivalue semantics, query cost, alert entity output and suppression governance. Performance and cost are `Not tested` in this portfolio.
