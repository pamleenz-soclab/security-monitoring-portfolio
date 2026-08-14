# Triage Note

**Alert type:** SQL injection / OWASP CRS Rule 942xxx  
**Priority:** High for correlated multi-rule and burst activity  
**Final scenario result:** **Attempted**

## What happened

The anonymised source `100.77.175.132` generated 3,465 related requests to `df7754e.hu` over approximately 5.5 hours. Of these, 3,396 were SQLi-related. The sequence included Boolean, UNION, concatenated and time-based payload variants and used a fixed browser-like User-Agent; the volume and systematic variation support a high-confidence inference of automation.

## Key evidence

- Multiple SQLi rules, including 942100, 942160, 942190 and 942360.
- Repeated `sleep(15)` requests returned in 57.704 ms and 56.976 ms.
- HTTP outcomes included 403, 503, 301, 302, 404 and 400.
- No final `Action: Intercepted`, `Access denied` or blocking-rule marker was observed in the validated SQLi transactions.
- No application, database or endpoint telemetry was available.

## Triage decision

Escalate as a sustained SQL injection attempt with high-confidence evidence of automation. Do not report successful exploitation or confirmed WAF blocking. Treat Rule 942100-only password/cookie matches as lower-confidence candidates pending context review.

## Immediate actions

1. Preserve WAF and web/application logs using a shared request ID.
2. Rate-limit or temporarily block the source at the trusted edge where operationally appropriate.
3. Verify the WAF enforcement mode and anomaly threshold.
4. Review targeted routes and parameters for parameterised-query use.
5. Search application and database logs for the selected transaction time window.
