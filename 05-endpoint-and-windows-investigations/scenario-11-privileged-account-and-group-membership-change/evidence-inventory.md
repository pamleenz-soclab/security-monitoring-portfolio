# Evidence Inventory

## Dataset identity

- **Name:** Splunk Attack Data — Atomic Red Team T1136.001
- **Dataset ID:** `cc9b25e2-efc9-11eb-926b-550bf0943fbb`
- **Controlled test:** Create a new Windows admin user
- **Target slice:** `ATTACKRANGE\T1136.001_Admin`
- **Primary host:** `win-dc-7216619.attackrange.local`
- **Source date:** 2020-10-09
- **Licence:** Apache License 2.0

## Local-only source artifacts

| Artifact | Bytes | SHA-256 | Records | Time range | Handling |
| --- | ---: | --- | ---: | --- | --- |
| `atomic_red_team.yml` | 1,613 | `2fa07b9b0e4f12546affaff43b336e075337739a61e365e0fd70a9cc7831679b` | Metadata | 2020-10-09 | Local source metadata; may be regenerated/downloaded |
| `windows-security.log` | 6,433,943 | `c6f43003a4defb5bd31776d931de18c4576a8e22de486790fa519aa76a06b153` | 5,494 | 2020-10-09 09:33:26–10:47:22 | Raw; Git ignored |
| `windows-sysmon.log` | 11,560,462 | `334fff113e8d15026a7a1a0d3343643ce7e8a73552b1f33ee476eaa7826cbe42` | 6,386 | 2020-10-09T10:39:12.911642600Z–10:47:54.752898700Z | Raw; Git ignored |

`windows-security.log` does not label a time zone. Its key-event seconds align exactly with Sysmon `UtcTime`/`SystemTime`, so UTC is used as an analyst inference for the derived timeline. This inference is explicitly recorded rather than treated as source fact.

## Processed evidence

| File | Purpose | Sensitive-data handling |
| --- | --- | --- |
| `evidence/processed/dataset-profile.csv` | File-level profile, hashes, record counts, coverage, and limitations | No raw command lines |
| `evidence/processed/event-id-counts.csv` | Complete Event ID counts for the two selected telemetry files | Aggregated counts only |
| `evidence/processed/privilege-change-timeline.csv` | Ordered actor, account, group, process, and cleanup timeline | Static lab password redacted |
| `evidence/processed/key-events-sanitized.log` | Minimal filtered evidence excerpts used in the investigation | Static lab password redacted; unrelated records excluded |
| `evidence/processed/field-coverage.csv` | Available, missing, and searched-but-not-found evidence fields | No raw secrets |

## Field coverage summary

| Evidence category | Status | Notes |
| --- | --- | --- |
| Actor account/domain | Available | `ATTACKRANGE\Administrator` |
| Actor Logon ID | Available | Creation session `0x79779`; cleanup session `0x7FE66` |
| Target account | Available | `ATTACKRANGE\T1136.001_Admin` |
| Immutable numeric target SID | Not available | Rendered text resolves the Security ID to an account name |
| Privileged group | Available | `BUILTIN\Administrators` |
| Group type | Available/inferred from Event ID and DC context | Event 4732; built-in domain-local Administrators group on a DC |
| Command/process chain | Available | Sysmon Event 1 with `ProcessGuid`, PID, parent PID, user, Logon ID, image, and command line |
| Account create/enable/password/modify | Available | 4720, 4722, 4724, 4738 |
| Membership add | Available | 4732, supported by 4735 and `net localgroup` process evidence |
| Explicit member removal | Not observed | No 4733 for the target in selected Security telemetry |
| Account deletion | Available | 4726 plus Sysmon cleanup command |
| Target logon or target Event 4672 | Not observed | Searched Security 4624/4625/4648/4672 and Sysmon `User` fields |
| Source IP for actor session | Not observed | Field exists in 4624 but value is `-`; same-host service-mediated logon |
| Ticket/approval/change window | Not available | Not part of the public dataset |
| Full cross-host or network activity | Not available | Selected coverage is Windows Security and one host's Sysmon telemetry |

## Integrity and reproducibility

The SHA-256 values above identify the exact source artifacts used. The analysis script verifies those files, profiles the complete dataset, filters only the named target account, redacts the static test password, and regenerates all processed CSV/log evidence.
