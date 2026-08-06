# Evidence Inventory

## Original evidence — local only

| Item | Location | Git policy | Purpose |
|---|---|---|---|
| `owasp.zip` | `evidence/raw/` | Ignored | Original Zenodo archive |
| Extracted ModSecurity logs | `evidence/working/extracted/` | Ignored | Native audit transactions |
| First-pass parser output and SQLite | `evidence/working/first-pass/` | Ignored | Broad profiling and candidate generation |
| Precise-validation output | `evidence/working/precise-validation/` | Ignored | Representative transaction validation |

## Publishable processed evidence

| File | Description |
|---|---|
| `web-request-timeline.csv` | Sanitised dominant-source timeline with payload families, rules, responses and evidence boundaries |
| `waf-alert-summary.csv` | SQLi rule inventory and interpretation |
| `waf-and-server-correlation.csv` | Representative ModSecurity request/rule/response correlation and missing independent access-log evidence |
| `request-outcome-assessment.csv` | Campaign and representative transaction outcomes |
| `source-ip-and-user-agent-summary.csv` | Aggregated anonymised source/host/User-Agent activity |
| `encoding-and-normalisation-analysis.csv` | Raw/decoded representation examples and decoding limits |
| `application-and-database-evidence.csv` | Explicit backend telemetry availability assessment |
| `follow-on-activity-analysis.csv` | Web shell, process, credential and exfiltration evidence boundaries |
| `detection-gap-analysis.csv` | Telemetry and analytical gaps |
| `sanitised-evidence-excerpts.tsv` | Minimal representative payload and rule evidence |
| `false-positive-examples.csv` | Rule 942100-only contextual false-positive candidates |
| `source-sha256-records.tsv` | Original archive SHA-256 record |
| `analysis-artifact-sha256-records.tsv` | Hashes for uploaded analytical result packages |
| `event-summary.tsv` | Compact key metrics and final labels |

## Data handling

No original Cookie, Authorization, token or session values are included in the processed evidence. Payloads are reduced to the minimum fragments required to support the investigation. Raw, decoded and normalised representations remain distinct.
