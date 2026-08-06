# Executive Summary

A production-derived ModSecurity dataset was analysed to determine whether SQL injection alerts represented scanning, attempted exploitation, successful WAF blocking or successful compromise.

The investigation confirmed a sustained automated SQL injection campaign. The dominant anonymised source generated 3,396 SQLi-related requests over approximately five and a half hours, using Boolean, UNION and time-based techniques. Multiple OWASP CRS SQLi rules detected the activity.

The final outcome is **Attempted**. Although many requests returned HTTP 403, the validated SQLi transactions did not record a final WAF interception or blocking-evaluation marker. The 403 responses could not be conclusively attributed to WAF enforcement. Repeated `sleep(15)` requests completed in tens of milliseconds, so the expected delay effect was not observed.

No independent application, database or endpoint telemetry was available. Successful SQL execution, data access, Web shell creation, command execution and business impact therefore remain unconfirmed.

The main engineering lessons are to preserve a shared request ID across WAF, proxy, application and database telemetry; record final enforcement separately from rule matches; and tune Rule 942100-only alerts using parameter and cookie context rather than disabling the rule globally.
