# Detection Gap Analysis

A **Detection Gap** is registered only when:

1. required telemetry is Available or sufficiently Partial;
2. the behaviour is Observed;
3. current alerting coverage is `No detection`, `Hunt only`, or materially incomplete; and
4. the gap is not primarily caused by missing telemetry.

## Confirmed register

| gap_id | hunt_id | behaviour | telemetry_status | observed_status | current_detection_status | gap_classification | evidence_reference | reasoning | recommended_detection_opportunity | priority |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| DG-02 | HC-03 | Suspicious PowerShell with correlated follow-on context | Available | Observed | No detection | Detection gap | scenario10:process-chain.csv;powershell-behaviour-summary.csv | Observed endpoint behaviour has no Scenario10 rule artifact in the inventory. | Create a high-signal PowerShell primitive enriched with same-ProcessGuid child/file/network activity. | High |

Only one confirmed detection gap remains after precision review.

## Why DG-01 and DG-03 were withdrawn

HC-01 originally appeared to be hunt-only follow-on activity, but Scenario 17 already contains an applicable follow-on correlation KQL.

HC-05 originally appeared to be an end-to-end hunt-only SMBExec chain, but Scenario 13 already contains explicit Sentinel and Splunk multi-event correlation for the core remote-service sequence.

Their remaining differences are **partial-coverage / enrichment questions**, not defensible statements that no detection exists.
