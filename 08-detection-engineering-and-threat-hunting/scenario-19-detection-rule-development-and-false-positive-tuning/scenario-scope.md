# Scenario Scope

## In scope

This scenario evaluates detection lifecycle engineering for six known behaviours selected from completed investigations. Work includes canonical field mapping, minimal public fixtures, local logic evaluation, false-positive analysis, tuning, regression, version history, cross-platform semantic review, deployment guidance, and detection-health design.

## Out of scope

This scenario does not conduct an enterprise-wide hunt, ATT&CK coverage assessment, unknown-behaviour discovery, production SIEM rollout, raw-evidence republication, performance benchmarking, or claims of enterprise precision/recall. Those boundaries intentionally preserve Scenario 20 for threat hunting and coverage assessment.

## Evidence boundaries

Rule match does not prove attack success or incident maliciousness. Missing mandatory telemetry produces `Unable to evaluate`, not a True Negative. Approved activity can be a Benign Positive. The source investigations provide processed/sanitised evidence; Scenario 19 does not copy their raw/working evidence.
