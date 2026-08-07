# Scenario 19 — Detection Rule Development and False-Positive Tuning

**Priority:** Flagship
**Domain:** Detection Engineering and Threat Hunting
**Status:** Complete portfolio scenario; production deployment not claimed

## Objective

This scenario converts investigation evidence from Scenarios 01–18 into a tested detection-engineering lifecycle rather than investigating a new incident. Six rules were selected because their processed evidence supported explicit requirements, malicious/benign controls, tuning, regression, or cross-platform comparison.

## Detection engineering lifecycle demonstrated

`Requirement -> Threat behaviour -> Data source -> Canonical mapping -> v1 broad rule -> fixtures -> test -> FP/FN analysis -> v2 tuning -> source-evidence review -> v3 candidate -> regression -> platform comparison -> deployment/health guidance`

## Final rule set

| Rule | Detection | Main engineering lesson |
|---|---|---|
| R19-01 | MFA denial/timeout -> success | Session ID is enrichment, not a mandatory failure-event key |
| R19-02 | Scheduled task -> SYSTEM PowerShell | Token-only tuning is insufficient; correlate follow-on activity |
| R19-03 | SQLi multi-rule/burst | Distinct transaction counting and evidence-informed threshold tuning |
| R19-04 | Credential add -> SP sign-in | Stable service-principal + credential IDs and semantic portability |
| R19-05 | Privileged group addition | Benign Positive is not the same as False Positive |
| R19-06 | Structured DNS chunk transfer | Dedup before threshold; completion is confidence, not trigger |

## Test status

The included local Python evaluator validates canonical rule logic only. It is **not** a SIEM implementation. Native Sentinel, Splunk, Elastic and Sigma execution, production performance, query cost, and enterprise-scale false-positive rates are **Not tested**.

The final v3 public regression suite uses synthetic and sanitised-derived minimal fixtures. Source-derived fixtures preserve behaviour and timing relationships while replacing identifiers and potentially sensitive fields.

## Reproduce

```bash
bash scripts/safe-reproduce.sh
```

See `detection-engineering.md`, `test-methodology.md`, `cross-platform-portability.md`, and `deployment-guidance.md` for evidence boundaries and deployment caveats.
