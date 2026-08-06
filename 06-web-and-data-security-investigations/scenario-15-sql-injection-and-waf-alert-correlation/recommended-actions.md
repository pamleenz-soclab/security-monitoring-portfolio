# Recommended Actions

## Immediate containment and validation

1. Verify the WAF policy mode, anomaly threshold and final disruptive-action logging.
2. Apply temporary edge rate limits or source blocking where business and false-positive risk permit.
3. Preserve WAF, reverse-proxy, application and database logs for the affected window.
4. Search trusted application logs for the selected transaction IDs, source, Host, route and timestamp.
5. Review targeted parameters for server-side parameterisation and strict input validation.
6. Confirm that error responses do not expose SQL syntax, stack traces or database details.

## Detection improvements

1. Alert on multiple SQLi rule families within the same transaction.
2. Create burst detections by trusted source address, Host, User-Agent and parameter.
3. Separate `rule match`, `recommended action`, `configured mode` and `final enforcement` fields.
4. Preserve raw request target plus bounded decoded representations.
5. Monitor Rule 942100-only alerts separately from multi-rule high-confidence alerts.
6. Add correlation checks for HTTP 403 without a WAF interception marker.

## Long-term remediation

1. Use parameterised queries or prepared statements throughout the application.
2. Remove dynamic SQL construction from user-controlled values.
3. Apply least privilege to application database accounts.
4. Enable database auditing for authentication, error, schema-access and high-risk query classes.
5. Propagate a stable request ID through WAF, proxy, application and database logs.
6. Add secure code review and automated SQLi tests to the release pipeline.
7. Establish WAF rule regression tests before exclusions or threshold changes are deployed.
