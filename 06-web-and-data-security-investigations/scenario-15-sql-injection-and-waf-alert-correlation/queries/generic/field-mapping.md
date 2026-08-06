# Generic Field Mapping

The query examples use conceptual fields. Map them to local data before production deployment.

| Concept | Sentinel example | Splunk example | Elastic example |
|---|---|---|---|
| Transaction ID | `TransactionId_s` | `transaction_id` | `waf.transaction_id` |
| Source IP | `ClientIP_s` | `src_ip` | `source.ip` |
| Host | `Host_s` | `host` | `url.domain` |
| Rule ID | `RuleId_s` | `rule_id` | `waf.rule.id` |
| Matched variable | `MatchedVariable_s` | `matched_variable` | `waf.matched_variable` |
| Final action | `Action_s` | `action` | `waf.action` |
| Response status | `HttpStatus_d` | `status` | `http.response.status_code` |

Validate whether the action field represents a configured recommendation, engine mode or final executed disposition before using it for incident outcome.
