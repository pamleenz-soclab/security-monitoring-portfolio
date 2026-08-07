# Detection Health Monitoring

Detection health should measure pipeline quality separately from alert volume. Recommended health signals include source-event volume, percentage of records missing mandatory fields, ingestion delay, clock skew, duplicate rate, parse failures, rule execution errors, alert count by rule/entity, suppression count, analyst classification distribution and changes in enrichment coverage.

Suggested guardrails include: alert when R19-04 credential ID coverage drops, when R19-05 privileged-group enrichment cannot resolve stable IDs, when R19-06 duplicate rate changes sharply, or when R19-01 MFA failure events lose user/source-IP fields.

Do not interpret a sudden drop in alerts as proof that malicious behaviour stopped; it can be a telemetry or schema failure.
