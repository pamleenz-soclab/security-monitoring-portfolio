# Alert Triage Template

## Case Information

| Field | Value |
|---|---|
| Case ID |  |
| Alert Name |  |
| Analyst |  |
| Date / Time |  |
| Environment |  |
| Affected Asset |  |
| Source IP |  |
| Target User |  |
| Detection Platform |  |
| Severity |  |
| Confidence |  |
| Assessment | True Positive / False Positive / Benign Positive |

## Initial Question

What question is this alert asking the analyst to answer?

## Data Sources Reviewed

| Data Source | Reviewed? | Notes |
|---|---|---|
| SIEM alert |  |  |
| Raw endpoint log |  |  |
| Firewall log |  |  |
| Network telemetry |  |  |
| Endpoint process telemetry |  |  |
| Login history |  |  |

## Evidence

| Evidence | Finding |
|---|---|
| Raw log entry |  |
| SIEM rule |  |
| Source IP |  |
| Target account |  |
| Time window |  |
| Successful login observed? | Yes / No |

## Timeline

| Time | Event |
|---|---|
|  |  |
|  |  |

## MITRE ATT&CK Mapping

| MITRE ID | Technique | Relevance |
|---|---|---|
|  |  |  |

## Assessment

State the final triage decision.

## Impact

Describe what this means in a real enterprise environment.

## Recommended Actions

| Action | Purpose | Status |
|---|---|---|
| Review successful login records | Confirm whether compromise occurred |  |
| Restrict SSH exposure | Reduce attack surface |  |
| Disable password authentication | Reduce password guessing risk |  |
| Add correlation rule | Improve detection |  |

## Detection Improvement

Explain what should be improved in logging, detection, enrichment, or response.

## Final Conclusion

Summarize the investigation result in 2–4 sentences.
