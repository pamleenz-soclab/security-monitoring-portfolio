# Remediation Plan

| Priority | Action | Suggested owner | Target | Validation |
|---|---|---|---|---|
| P0 | Preserve relevant WAF/proxy/application/database evidence | SOC / Platform | Immediate | Hash and inventory retained data |
| P0 | Confirm WAF enforcement mode and final-action logging | Security Engineering | 24 hours | Controlled benign test in non-production shows explicit disposition |
| P1 | Review targeted endpoints and parameters | Application Security | 3 business days | Code review confirms parameterised queries |
| P1 | Implement trusted source-IP and request-ID handling | Platform / Web Engineering | 2 weeks | Same request ID visible across all tiers |
| P1 | Deploy SQLi burst and multi-rule correlations | Detection Engineering | 2 weeks | Replay sanitised fixtures and verify alert creation |
| P2 | Add database audit coverage | Database Engineering | 30 days | Query/error events attributable to application request IDs |
| P2 | Establish WAF false-positive regression tests | Security Engineering | 30 days | Password/cookie fixtures do not create high-priority incidents |
| P2 | Review application database privileges | Database / IAM | 30 days | Account access is limited to required schemas and operations |

## Closure criteria

- Final WAF action is explicitly logged and queryable.
- WAF, proxy, application and database telemetry share a stable correlation ID.
- High-signal SQLi test cases are detected.
- Known Rule 942100 password/cookie false positives are tuned narrowly.
- No global rule disablement is used as a substitute for contextual tuning.
