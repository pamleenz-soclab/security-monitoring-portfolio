# Scenario 20 — Threat Hunting and Detection Coverage Assessment

- **Priority:** Flagship
- **Domain:** Detection Engineering and Threat Hunting
- **Status:** Complete

## Objective

This scenario evaluates detection and telemetry coverage by testing eight threat-hunting hypotheses against processed evidence from prior portfolio scenarios. It does **not** repeat Scenario 19 rule development, tuning, or regression testing.

The workflow is:

```text
Threat Hunting Hypothesis
→ Available Telemetry
→ Local Hunt Logic
→ Entity / Behaviour Pivot
→ Evidence Review
→ Hunt Finding
→ Coverage Assessment
→ Detection Gap / Logging Gap
→ Detection Opportunity
```

## Results

- Formal hunts: **8**
- Supported: **5**
- Negative hunt results: **2**
- Unable to assess: **1**
- Confirmed detection gaps: **1**
- Logging / visibility gaps: **8**
- Detection opportunities: **7**
- Original processed hunt inputs: **39**
- Material coverage-reference artifacts: **8**

### Hunt outcomes

| hunt_id | outcome | coverage conclusion |
| --- | --- | --- |
| HC-01 | Supported | MFA primitive detected; post-auth activity is **Partially detected** because Scenario 17 follow-on logic covers 4/5 reviewed activities. |
| HC-03 | Supported | **Confirmed Detection Gap**: suspicious PowerShell plus correlated child/file/network context is observable, but no dedicated Scenario 10 detection artifact was present in reviewed repository state `7f0f92b`. |
| HC-05 | Supported | Core SMBExec sequence already has correlation logic; the expanded chain is **Partially detected**. |
| HC-07 | Negative hunt result | No SQLi-family transaction remained outside the corrected R19-03 high-confidence approximation in the reviewed WAF dataset. |
| HC-08 | Unable to assess | Backend SQL execution/impact cannot be confirmed because application/database visibility is missing. |
| HC-09 | Supported | Structured DNS primitive is detected; collection/staging/outcome and exact process-to-flow attribution remain broader hunt/visibility layers. |
| HC-10 | Supported | Credential-to-sign-in is detected; token-to-API activity is observed as a separate coverage layer and exact per-request permission attribution is unavailable. |
| HC-12 | Negative hunt result | Post-change use was not observed in selected host telemetry; cross-host follow-on is unavailable. |

## Key conclusions

1. **Threat hunting and detection are not interchangeable.** A hunt may extend beyond an alert without proving that no detection exists.
2. **Only one confirmed detection gap remained after precision review: HC-03.**
3. **Logging gaps are separate engineering problems.** Missing application/database logs or stable join identifiers cannot be repaired by adding another rule.
4. **Negative results remain bounded.** `Not observed` in reviewed telemetry is not evidence that a behaviour never occurred.
5. **Coverage is assessed by behaviour and attack step**, not by counting ATT&CK techniques or rule files.
6. **Repository analytics are semantic coverage references, not evidence of live production deployment.**

## Provenance boundary

Scenario 20 preserves the original SHA-256 ledger for **39 processed hunt inputs**. A Git-history review found that **15** of those recorded hashes map to reachable committed blobs, while **24** do not match any reachable Git commit. The 24 unmatched hashes are therefore retained as **historical local-analysis provenance** and are explicitly marked as not Git-reproducible; they are not silently rewritten to match newer files.

The **8 material detection/query/specification references** used for the final coverage precision review are pinned to reviewed repository state `7f0f92b`.

See `evidence/processed/source-sha256-records.tsv`.

## Reproducibility boundary

The hunt results were produced with local Python analysis over processed evidence. The original one-off evaluator is not published here as a production hunting engine. The repository publishes the hunt semantics, processed findings, coverage matrices, and bounded provenance.

`scripts/validate_portfolio.py` validates the **published evidence package**: cross-table consistency, result counts, source-provenance status, committed source hashes where reproducible, coverage-reference hashes, line endings, and Git safety. It does **not** claim to re-execute the eight hunts or emulate Sentinel/Splunk/Elastic runtime behaviour.

## Main artifacts

- [Scenario Scope](scenario-scope.md)
- [Hunting Methodology](hunting-methodology.md)
- [Hunt Hypotheses](hunt-hypotheses.md)
- [Hunt Query Guide](hunt-query-guide.md)
- [Hunt Findings](hunt-findings.md)
- [Detection Coverage Assessment](detection-coverage-assessment.md)
- [Detection Gap Analysis](detection-gap-analysis.md)
- [Logging Gap Analysis](logging-gap-analysis.md)
- [Detection Opportunities](detection-opportunities.md)
- [Cross-Domain Correlation](cross-domain-correlation.md)
- [Lessons Learned](lessons-learned.md)
- [Source and License Record](source-and-license-record.md)

Structured evidence is under `evidence/processed/`. Raw and working evidence remain local and Git-ignored.
