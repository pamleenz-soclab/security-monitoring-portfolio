# Evidence Inventory

## Evidence sources

| Source | Records |
| --- | --- |
| Api Activity | 7 |
| App Role Assignments | 4 |
| Application Objects | 3 |
| Credential Metadata | 5 |
| Directory Audit | 18 |
| Directory Role Assignments | 1 |
| Oauth Grants | 2 |
| Platform Risk | 1 |
| Service Principal Objects | 4 |
| Service Principal Signins | 4 |
| User Signins | 2 |

## Principal files

| Processed evidence | Purpose |
|---|---|
| `cloud-privilege-event-timeline.csv` | Unified 32-record timeline |
| `principal-and-object-mapping.csv` | User, application, and service-principal identifiers |
| `oauth-consent-analysis.csv` | Delegated grant and consent-type analysis |
| `role-assignment-analysis.csv` | Application permissions and Entra directory role |
| `credential-change-analysis.csv` | Credential metadata, validity, approval, and later use |
| `service-principal-signin-analysis.csv` | Credential type, resource, location, IP, and stable token IDs |
| `api-and-resource-activity-analysis.csv` | Graph operations and resource impact |
| `precise-cloud-privilege-correlation.csv` | Stable-ID evidence joins and interpretation boundaries |
| `cloud-privilege-abuse-assessment.csv` | Final incident labels and limitations |
| `sanitised-evidence-excerpts.tsv` | Small publishable evidence excerpts |

## Evidence-handling status

- Raw evidence: local, generated, Git ignored.
- Working evidence: local, Git ignored.
- Processed evidence: sanitised and publishable.
- Ground truth: excluded from first-pass and final telemetry assessment.
- Original raw modification: none reported by acquisition records.
- Synthetic package validator: `PASS`.
- Git-aware validator: `PASS`.

## Integrity note

`source-sha256-records.tsv` records the hashes generated for the local synthetic source package. Because raw files are intentionally not distributed in this portfolio ZIP, a reviewer can verify those hashes only after reproducing the package with the included generator.
