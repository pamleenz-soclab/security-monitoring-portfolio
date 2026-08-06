# Detection Engineering

## Detection objectives

1. Detect high-confidence SQLi transactions using specialised Rule 942xxx combinations.
2. Detect sustained SQLi bursts from the same trusted source, Host and User-Agent.
3. Distinguish WAF detection from final enforcement.
4. Identify 403 responses without a recorded interception marker.
5. Reduce priority for Rule 942100-only password and session-cookie matches.

## Normalised fields

| Concept | Suggested field |
|---|---|
| Event time | `timestamp` / `TimeGenerated` |
| Transaction ID | `waf.transaction_id` |
| Trusted client address | `source.ip` |
| Forwarded address | `http.request.headers.x_forwarded_for` with trust flag |
| Host | `url.domain` / `http.host` |
| Method | `http.request.method` |
| Raw target | `url.original` |
| Path | `url.path` |
| Matched variable | `waf.matched_variable` |
| Rule ID | `waf.rule.id` |
| Rule message | `waf.rule.message` |
| Severity | `event.severity` |
| Engine mode | `waf.engine_mode` |
| Final action | `waf.action` |
| Response status | `http.response.status_code` |
| Duration | `event.duration` |

## High-confidence logic

Prioritise a transaction when one or more of the following applies:

- Rule 942160, 942190 or 942360 is present.
- Two or more distinct SQLi Rule 942xxx IDs occur in one transaction.
- Explicit SQL syntax appears in a matched argument and activity repeats from the same source/Host.
- Time-based patterns repeat but do not rely on one slow request as proof.

## Disposition logic

Do not map HTTP 403 directly to `blocked`. Require a final enforcement field or explicit interception marker. Preserve three separate attributes:

- `detection_observed`
- `configured_or_engine_mode`
- `final_enforcement_observed`

## Included content

- Sigma-style rules in `detections/sigma/`
- KQL in `queries/sentinel/`
- SPL in `queries/splunk/`
- ES|QL in `queries/elastic/`
- Vendor-neutral correlation logic in `queries/generic/`
