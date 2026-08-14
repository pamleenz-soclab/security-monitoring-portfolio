# Detection Engineering

## Detection objectives

1. Detect high-confidence SQLi events using specialised Rule 942xxx signals.
2. Correlate multiple SQLi rules within the same transaction ID.
3. Detect sustained SQLi bursts from the same trusted source, Host and User-Agent using both volume and diversity thresholds.
4. Distinguish WAF detection from final enforcement.
5. Identify 403 responses without a recorded interception marker.
6. Reduce priority for Rule 942100 password/session-cookie context when peer SQLi evidence is absent.

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
- Time-based patterns repeat, while response delay is treated as exploitation evidence only when supported by a reproducible baseline difference.

The Sigma rules are single-event examples. Transaction-level multi-rule and burst correlation is implemented in the generic and vendor-query examples.

## Burst threshold

The included burst queries require at least **20 distinct transactions in five minutes** and also require either **three distinct request paths** or **two distinct SQLi rule IDs**. This reduces escalation based on volume alone.

## Disposition logic

Do not map HTTP 403 directly to `blocked`. Require a final enforcement field or explicit interception marker. Preserve three separate attributes:

- `detection_observed`
- `configured_or_engine_mode`
- `final_enforcement_observed`

## Included content

- Sigma-style event rules in `detections/sigma/`
- Vendor-neutral correlation logic in `detections/generic/`
- Microsoft Sentinel KQL in `queries/sentinel/`
- Splunk SPL in `queries/splunk/`
- Elastic ES|QL in `queries/elastic/`
- Conceptual field mapping in `queries/generic/`

The vendor queries are schema examples and require local field mapping and platform-side testing before production deployment.
