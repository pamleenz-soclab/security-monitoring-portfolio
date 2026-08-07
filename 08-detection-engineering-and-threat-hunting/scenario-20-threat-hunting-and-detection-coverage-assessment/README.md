# Scenario 20 — Threat Hunting and Detection Coverage Assessment

- **Priority:** Flagship
- **Domain:** Detection Engineering and Threat Hunting
- **Status:** Complete

## Objective

This scenario evaluates detection and telemetry coverage by actively testing threat-hunting hypotheses against processed evidence from prior portfolio scenarios. It does **not** repeat Scenario 19 rule development, tuning, or regression testing.

The workflow is:

```text
Threat Hunting Hypothesis
→ Available Telemetry
→ Local Hunt Query
→ Entity / Behaviour Pivot
→ Evidence Review
→ Hunt Finding
→ Coverage Assessment
→ Detection Gap / Logging Gap
→ Detection Opportunity
```

## Final Stage 2 results

- Formal hunts executed: **8**
- Supported hypotheses: **5**
- Negative hunt results: **2**
- Unable to assess: **1**
- Confirmed detection gaps: **1**
- Logging / visibility gaps: **8**
- Detection opportunities: **7**
- Source processed files read: **39**
- Source-file read failures: **0**

### Hunt outcomes

| hunt_id | domain | outcome | finding | coverage_implication |
| --- | --- | --- | --- | --- |
| HC-01 | Identity / Cloud | Supported | MFA sequence had 5 correlated follow-on activity record(s) in the exploratory post-success window. | R19-01 covers the MFA failure-to-success sequence; Scenario 17's existing follow-on KQL covers 4/5 observed post-auth activities. Remaining activity is a partial-coverage item, not a confirmed 'no detection exists' finding. |
| HC-03 | Endpoint / Process | Supported | PowerShell observed=True; linked child=2, file=6, network=1. | Observed behaviour is richer than a single PowerShell event and exposes a concrete detection gap. |
| HC-05 | Endpoint / Network / Lateral Movement | Supported | Principal chain stages observed: 4/4 (auth=True, SMB445=True, service-control=True, remote-process=True). | Scenario 13 already has a high-confidence multi-event SMBExec correlation for the core authentication + svcctl + service-install sequence. The broader hunt adds remote process/follow-on context, so the expanded chain is Partially detected rather than Hunt only. |
| HC-07 | Network / Web | Negative hunt result | Reviewed 3396 SQLi-family transaction(s) using corrected R19-03 semantics: Branch-A matches=2811, Branch-B participants=3378, outside high-confidence coverage=0. | R19-03 remains the high-confidence detection baseline. No lower-confidence transaction remained outside the corrected high-confidence approximation in this dataset. |
| HC-08 | Web / Application / Database | Unable to assess | 3 required independent/backend telemetry source(s) are explicitly unavailable; backend SQL execution and business impact cannot be confirmed. | Primary limitation is logging/visibility, not another WAF detection rule. |
| HC-09 | Network / DNS / Endpoint | Supported | Staging=True; compression/encoding=True; DNS evidence=True; transfer outcome=True; exact process-to-flow join remains limited. | R19-06 covers the DNS primitive; broader chain remains hunt/correlation coverage with join-key visibility limits. |
| HC-10 | Cloud Identity / Privilege | Supported | Suspicious credential candidates=5; SP sign-ins=4; confirmed token-to-API correlation rows=7. | R19-04 covers credential-to-sign-in; API use is a separate coverage layer and exact permission attribution remains a logging gap. |
| HC-12 | Identity / Windows Privilege | Negative hunt result | Membership addition observed for target 'ATTACKRANGE\T1136.001_Admin'. Post-change target authentication/privilege/process use was not observed in selected telemetry; cross-host follow-on is unavailable. | R19-05 covers the membership change only; post-change-use hunt is negative and environment-wide use is unassessable. |

## Key conclusions

1. **Threat hunting and detection are not interchangeable.** HC-01 and HC-05 showed that broader hunting can extend beyond existing detection logic without proving that a detection is absent.
2. **One confirmed detection gap remained after precision review.** HC-03 had observable PowerShell/process/file/network telemetry but no dedicated Scenario 10 detection-rule artifact in the repository inventory.
3. **Logging gaps were kept separate from detection gaps.** HC-08 could not establish backend SQL execution because required application/database telemetry was unavailable.
4. **Negative results were retained.** HC-07 and HC-12 are bounded negative hunts; neither is interpreted as proof that the behaviour never occurred.
5. **Coverage was assessed by behaviour and attack step, not by counting ATT&CK techniques or rule files.**
6. **Repository analytics are not assumed to be live production deployments.**

## Important engine boundary

The hunting logic was executed by a transparent **local Python evaluator** over processed evidence. It is **not** native Microsoft Sentinel, Splunk, Elastic, Sigma, Wazuh, Zeek, or Suricata execution. Existing platform-native query/rule files are used as semantic coverage references only.

## Main artifacts

- [Executive Summary](executive-summary.md)
- [Scenario Scope](scenario-scope.md)
- [Hunting Methodology](hunting-methodology.md)
- [Hunt Hypotheses](hunt-hypotheses.md)
- [Hunt Query Guide](hunt-query-guide.md)
- [Hunt Findings](hunt-findings.md)
- [Negative Hunt Findings](negative-hunt-findings.md)
- [Detection Coverage Assessment](detection-coverage-assessment.md)
- [Telemetry Coverage Assessment](telemetry-coverage-assessment.md)
- [Detection Gap Analysis](detection-gap-analysis.md)
- [Logging Gap Analysis](logging-gap-analysis.md)
- [Detection Opportunities](detection-opportunities.md)
- [Attack Chain Coverage](attack-chain-coverage.md)
- [Cross-Domain Correlation](cross-domain-correlation.md)
- [Interview Walkthrough](interview-walkthrough.md)
- [Validation Checklist](validation-checklist.md)

Final evidence is under `evidence/processed/`. Local inventory, correction, and intermediate analysis material belongs under `evidence/working/` and should not be published as final evidence.
