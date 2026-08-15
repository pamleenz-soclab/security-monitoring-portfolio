# Scenario 17 — Cloud Identity and MFA Anomaly Investigation

## Executive result

A deterministic synthetic Microsoft Entra and Microsoft 365 event package was investigated as a single identity incident. The investigation confirmed a distributed password spray against five users, correct-password use against `USER-001`, repeated Microsoft Authenticator denials and timeouts, a later successful number-matching MFA event, session creation, non-interactive token activity, registration of additional security information, creation of an external-forwarding inbox rule, and download of three confidential finance files.

The final identity conclusion is:

> **Confirmed account compromise**

The conclusion is not based on location, risk score, or MFA success alone. It requires the combined evidence of successful authentication, stable identifier correlation, follow-on activity, and user verification that the session and actions were unauthorized.

## Investigation chain

```text
Distributed password spray
→ Correct primary authentication for USER-001
→ MFA denied / timeout / denied / timeout
→ Microsoft Authenticator number matching success
→ Conditional Access MFA controls satisfied
→ Report-only device policy failure did not block
→ SESSION-001 created
→ Non-interactive token activity
→ Security-information registration
→ External-forwarding inbox rule
→ Confidential file downloads
→ User verification of unauthorized activity
→ Session revocation, password reset, and removal of unauthorized method
```

## Key distinctions

- The approved Sydney endpoint was a corporate VPN exit and is classified as a **Benign anomaly**.
- GeoIP and calculated travel speed are investigative leads, not proof of physical travel.
- MFA success confirms completion of a method, not that the legitimate user intended to approve it.
- Non-interactive sign-ins represent background token or application activity and are not additional MFA approvals.
- `reportOnlyFailure` records a policy evaluation; it does not enforce a block.
- Identity Protection risk events corroborate the case but do not prove compromise.
- The separate IMAP/ROPC attempt was blocked by Conditional Access and is classified as an **Unsuccessful attack**.
- The service principal and managed identity events were expected workload activity and are classified as **Benign**.

## Dataset

No sufficiently complete and freely accessible public dataset was available. CyberDefenders AzureSpray was the strongest initial candidate but failed the acquisition gate because the retired lab required Premium access and did not expose evidence files to the authenticated free account.

This scenario therefore uses a deterministic, explicitly synthetic dataset whose field semantics follow Microsoft Entra, Azure Monitor, Microsoft Graph, Identity Protection, Conditional Access, and Microsoft 365 audit concepts. It is not a byte-for-byte portal or Graph export.

## Evidence classes

| Class | Meaning |
|---|---|
| Telemetry-confirmed fact | Directly recorded in sign-in, authentication, Conditional Access, audit, or session telemetry |
| Platform-generated risk | Microsoft-style risk label or score used as a lead |
| Business/user verification | Authorization and user-context evidence from the incident ticket |
| Ground truth | Synthetic scenario author statement, checked only after independent assessment |
| Inference | Conclusion supported by multiple independent facts |
| Not observed | Behavior was not found in telemetry suitable for observing it |
| Not available | Required telemetry was absent |
| Detection gap | Product, license, retention, export, or dataset limitation |

## Repository structure

```text
evidence/raw/          Created locally by the reproduction wrapper; Git ignored
evidence/working/      Created locally for databases and intermediate outputs; Git ignored
evidence/processed/    Sanitised, publishable evidence
detections/            KQL, SPL, ES|QL, and generic detection content
queries/               Investigation queries organised by purpose
scripts/               Reproducible generation, parsing, correlation, validation, and sanitisation
```

## Reproduction

```bash
REPO_ROOT="$(git rev-parse --show-toplevel)"
SCENARIO_DIR="$REPO_ROOT/07-cloud-identity-and-privilege-investigations/scenario-17-cloud-identity-and-mfa-anomaly-investigation"

bash "$SCENARIO_DIR/scripts/safe-reproducibility-wrapper.sh"
```

The wrapper performs no network activity. It generates the local synthetic evidence, runs the first-pass parser and precise correlation, builds public evidence, then runs sanitisation and portfolio validation.

## Principal outputs

- `triage-note.md`
- `investigation-report.md`
- `containment-decision-record.md`
- `evidence/processed/cloud-identity-event-timeline.csv`
- `evidence/processed/account-compromise-assessment.csv`
- `detection-engineering.md`
- `detections/`
- `queries/`

## Operational mapping note

The synthetic Microsoft 365 audit records intentionally carry a session alias so the portfolio can demonstrate deterministic cross-source correlation. Production Microsoft Sentinel `OfficeActivity` data should not be assumed to expose the Entra `SessionId`; operational follow-on queries therefore use supported Office audit fields plus user, IP and time context instead of claiming a direct session-ID join.

## References

- https://learn.microsoft.com/en-us/entra/identity/monitoring-health/concept-sign-ins
- https://learn.microsoft.com/en-us/entra/identity/monitoring-health/concept-noninteractive-sign-ins
- https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/signinlogs
- https://learn.microsoft.com/en-us/entra/identity/authentication/howto-mfa-reporting
- https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-conditional-access-report-only
- https://learn.microsoft.com/en-us/entra/id-protection/concept-identity-protection-risks
- https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-password-spray
