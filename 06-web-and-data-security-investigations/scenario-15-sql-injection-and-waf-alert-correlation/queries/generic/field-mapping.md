# Generic Field Mapping

The query examples use conceptual fields. Map them to the deployed product schema before testing or production use.

| Concept | Sentinel example | Splunk example | Elastic example |
|---|---|---|---|
| Event time | `TimeGenerated` | `_time` | `@timestamp` |
| Transaction ID | `TransactionId_s` | `transaction_id` | `waf.transaction_id` |
| Trusted source IP | `ClientIP_s` | `src_ip` | `source.ip` |
| Host | `Host_s` | `host` | `url.domain` |
| User-Agent | `UserAgent_s` | `user_agent` | `user_agent.original` |
| HTTP method | `HttpMethod_s` | `http_method` | `http.request.method` |
| Request path | `RequestPath_s` | `uri_path` | `url.path` |
| Rule ID | `RuleId_s` | `rule_id` | `waf.rule.id` |
| Rule message | `RuleMessage_s` | `rule_message` | `waf.rule.message` |
| Matched variable | `MatchedVariable_s` | `matched_variable` | `waf.matched_variable` |
| Final action | `Action_s` | `action` | `waf.action` |
| Response status | `HttpStatus_d` | `status` | `http.response.status_code` |

Validate the trusted proxy chain before treating a forwarded address as the client source. Also verify that the action field represents the final executed disposition rather than a rule recommendation or configured engine mode.
