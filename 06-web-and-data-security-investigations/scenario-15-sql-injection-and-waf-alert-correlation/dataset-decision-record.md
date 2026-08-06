# Dataset Decision Record

## Decision

Use **A Thirty-Day Dataset of Malicious HTTP Requests Blocked by OWASP ModSecurity on a Production Web Server**, Zenodo record `17178461`, as the single-event-source dataset for Scenario 15.

## Selection criteria

The selected source provides native ModSecurity audit transactions with stable transaction IDs, raw request lines, request headers, selected request bodies, rule messages, matched variables, response headers and timing fields. It is safe for offline analysis and has a clear CC BY 4.0 attribution requirement.

## Why it was selected

- Production-derived WAF telemetry rather than screenshots or standalone payload lists.
- Stable ModSecurity transaction boundaries support request-to-rule-to-response reconstruction.
- SQLi coverage includes libinjection, time-based, UNION and concatenated patterns.
- File size is practical for local macOS analysis.
- The source record and integrity values are preserved.

## Alternatives considered

| Candidate | Strength | Reason not selected as primary evidence |
|---|---|---|
| AIT multi-source log dataset | Rich multi-source telemetry and ground truth | No verified SQLi plus ModSecurity/WAF event matching this scenario |
| CyberDefenders web investigation | Strong PCAP-based exploit reconstruction | No WAF rule/action telemetry |
| OWASP CRS/go-ftw tests | Excellent rule-regression material | Test cases rather than a production incident |
| Splunk Attack Data | Reputable structured attack-data repository | No verified single package meeting SQLi + WAF + independent backend requirements |
| SQLi payload corpora | Useful for tuning and ML research | No transaction, enforcement or exploit-outcome evidence |

## Accepted limitations

The dataset does not provide an independent web access log, application log, database audit or endpoint telemetry. The project therefore does not manufacture a complete attack chain by joining unrelated sources. Missing telemetry is recorded as `Not available` or `Detection gap`.

## Decision status

**Accepted with telemetry limitations.** The dataset supports a defensible `Attempted` result and a strong investigation of the distinction between WAF detection, HTTP status and actual enforcement.
