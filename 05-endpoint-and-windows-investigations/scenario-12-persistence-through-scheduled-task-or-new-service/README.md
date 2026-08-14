# Scenario 12 — Persistence Through Scheduled Task or New Service

## Executive summary

This scenario investigates Windows persistence through a scheduled task. The selected OTRF Security Datasets sample represents a controlled Empire simulation and contains Windows Security, Task Scheduler, Sysmon, PowerShell, System, and network-filtering telemetry.

The investigation confirmed that a high-integrity PowerShell session created `\MordorElevated` on `LAB-WKS-05`. The task was configured through `schtasks.exe` to run at logon as `SYSTEM` and launch a hidden PowerShell registry-backed loader. After a confirmed reboot and remote interactive logon, Task Scheduler launched the task as PowerShell PID `620`. That process invoked `csc.exe` and established a TCP connection to the deactivated lab endpoint `10[.]10[.]10[.]5:80`.

Final disposition:

> **True Positive — confirmed simulated malicious scheduled-task persistence.**

The dataset attribution establishes that the activity was part of an Empire simulation. The telemetry independently confirms task creation, execution, elevated process activity, dynamic compilation, and network communication. It does not establish whether an equivalent action in a production environment would have been authorised.

## Investigation scope

- Primary host: `LAB-WKS-05`
- Primary account label: `LAB\user-a`
- Evidence window: `2020-09-21 17:58:04` to `2020-09-21 18:02:25`
- Raw records: `59,399`
- Hosts represented: `3`
- Main persistence object: `\MordorElevated`
- Related execution-only object: `\MordorElevatedTask`
- Primary ATT&CK technique: `T1053.005 — Scheduled Task/Job: Scheduled Task`

Lab hostnames, domain names, account names, source addresses, and controller addresses are sanitised or deactivated in public evidence. Raw files and working exports remain local and are excluded by `.gitignore`.

## Confirmed behaviour chain

1. PowerShell wrote encoded data to `HKLM\SOFTWARE\Microsoft\Network\debug`.
2. The same high-integrity account session launched `schtasks.exe /Create` for `\MordorElevated`.
3. Security Event ID `4698` and Task Scheduler Event ID `106` confirmed successful task creation and registration.
4. The operator requested a reboot with `shutdown.exe /r`; shutdown and startup events confirmed the reboot.
5. A remote interactive logon occurred for the same account label.
6. Task Scheduler Event ID `129` launched `\MordorElevated` as PowerShell PID `620`.
7. Security Event ID `4688` confirmed that PID `620` ran in the local `SYSTEM` logon session with system integrity.
8. PID `620` created `csc.exe`, and Windows Filtering Platform Event ID `5156` tied PID `620` to a TCP connection to `10[.]10[.]10[.]5:80`.

The related task `\MordorElevatedTask` followed a parallel PID `636` execution chain, but its creation was not observed in the collection window. It is therefore not attributed to the observed creation session.

## Key correlation

| Persistence object | Creation | Task start | PowerShell | Child process | Network |
|---|---|---|---|---|---|
| `\MordorElevated` | 4698 record `755562` | 129 record `7293` | PID `620` / `0x26c` | `csc.exe` PID `6780` / `0x1a7c` | 5156 record `773421` |
| `\MordorElevatedTask` | Not observed | 129 record `7290` | PID `636` / `0x27c` | `csc.exe` PID `5360` / `0x14f0` | 5156 record `773419` |

Task Scheduler recorded decimal PIDs, while Security Event ID `4688` recorded hexadecimal process IDs. Converting `0x26c` to `620` and `0x27c` to `636` was essential to establish the correlation.

## Repository contents

- `dataset-decision-record.md` — dataset selection, source, licence, and safety decision
- `evidence-inventory.md` — raw, working, processed, and missing evidence
- `triage-note.md` — concise SOC triage decision
- `investigation-notes.md` — analyst hypotheses and correlation notes
- `investigation-report.md` — full evidence-based investigation
- `detection-engineering.md` — detection logic, tuning, and coverage gaps
- `recommended-actions.md` — containment, eradication, recovery, and validation
- `detections/sigma/` — two process-creation detection rules
- `evidence/processed/` — sanitised timelines, correlations, status matrix, and validation results
- `scripts/extract-scenario12-evidence.sh` — core offline evidence-extraction script

## Evidence status vocabulary

- **Confirmed** — directly supported by the available event telemetry.
- **Inferred** — supported by correlated facts but not directly recorded.
- **Not observed** — the relevant data source was checked and no matching event was found.
- **Not available** — the dataset did not provide the required source or field.
- **Unable to confirm** — evidence exists but is insufficient for a reliable conclusion.
- **Detection gap** — collection or parsing prevented a security control from evaluating the behaviour reliably.

## Safety and publication notes

- Analysis was performed offline; no logged address or payload was contacted or executed.
- Full encoded PowerShell content is excluded from public files.
- Raw ZIP and JSON files remain in `evidence/raw/` and are ignored by Git.
- Working TSV exports remain in `evidence/working/` and are ignored by Git.
- Processed evidence retains only the minimum fields required to reproduce the conclusions.

## Source

- [OTRF dataset page — Empire Elevated Scheduled Tasks](https://securitydatasets.com/notebooks/atomic/windows/persistence/SDWIN-200921175806.html)
- [OTRF Security-Datasets repository](https://github.com/OTRF/Security-Datasets)
- [MIT licence](https://github.com/OTRF/Security-Datasets/blob/master/LICENSE)

