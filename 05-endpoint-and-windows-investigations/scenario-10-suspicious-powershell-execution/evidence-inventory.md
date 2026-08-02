# Evidence Inventory

## Raw evidence retained locally

| ID | File | Purpose | Size | SHA-256 | Publication status |
| --- | --- | --- | ---: | --- | --- |
| E01 | `evidence/raw/empire_launcher_vbs.zip` | Original downloaded dataset archive | 313,016 bytes | `812da270cf8cda6f1948fb6275410f15dc1794d0bd6b623c9c25b2518285019c` | Local only; Git-ignored |
| E02 | `evidence/raw/empire_launcher_vbs_2020-09-04160940.json` | Extracted Windows JSONL events | 5,625,164 bytes | `d569bc556907e23acf638b762c0acfbbecba016b6b2e07a86356151a799b661c` | Local only; Git-ignored |
| E03 | `evidence/raw/SDWIN-190518182022.yaml` | Upstream dataset metadata and emulation description | 4,139 bytes | `04f5d168d72ccf00cec9489e3d5951e9b87e893bf88af1f8e8553b5f926dede1` | Local only; Git-ignored |

## Processed evidence safe for publication

| ID | File | Purpose | Status |
| --- | --- | --- | --- |
| P01 | `evidence/processed/dataset-profile.csv` | Record, host, channel, time-range, and relevant event-ID counts | Created; contains aggregate data only |
| P02 | `evidence/processed/key-event-timeline.csv` | Normalised incident timeline with source timing basis and evidence status | Created |
| P03 | `evidence/processed/process-chain.csv` | PID, ProcessGuid, parent, Logon ID, and command-chain mapping | Created |
| P04 | `evidence/processed/network-activity.csv` | Correlated Sysmon and Security network event | Created |
| P05 | `evidence/processed/file-activity.csv` | Minimal file-create/delete evidence and analyst assessment | Created |
| P06 | `evidence/processed/powershell-behaviour-summary.csv` | PowerShell command, script-block, stage, discovery, and task evidence | Created |
| P07 | `evidence/processed/scope-and-gaps.csv` | Scope counts, negative findings, and telemetry limitations | Created |
| P08 | `evidence/processed/key-log-extracts.md` | Sanitised filtered log excerpts supporting the final chain | Created |
| P09 | `evidence/processed/public-file-manifest.sha256` | SHA-256 manifest for every publishable file except the manifest itself | Created |

Processed evidence is limited to aggregate data and minimal, attributable extracts. It excludes the complete Base64 command, full script body, cookie and key material, and repeated pipeline text.

## Available evidence

- Windows Security process creation and supporting logon/object-access events.
- PowerShell Operational module/pipeline events and one complete script-block event.
- Sysmon process, network, file creation, DNS query, file deletion, process access, registry, image-load, and related endpoint events.
- Hostname, user/SID, Logon ID, PID, ProcessGuid, parent identifiers, command line, ScriptBlockId, timestamps, file paths, process-image hashes, and network endpoints where logged.
- Source-provided metadata describing the controlled Empire VBS launcher emulation.

## Not available

- Original EVTX/XML records and digital signatures for the event logs.
- The actual `launcher.vbs` file and its content/hash.
- The bytes or hash of any downloaded PowerShell stage.
- Packet capture, HTTP request/response body, proxy log, or server-side C2 log in the downloaded evidence.
- EDR alert, prevention action, quarantine record, memory capture, or forensic disk image.
- Asset owner, business purpose, change ticket, and authorised-administration context.
- Long-term telemetry sufficient to evaluate delayed persistence or later impact.

## Correlation constraints

- Use `@timestamp` and embedded Sysmon `UtcTime` as the primary UTC fields. The unzoned `EventTime` field must not be treated as UTC without validation.
- Use `RecordNumber` as the dataset's event-record sequence field; do not rename it to `EventRecordID` without documenting the mapping.
- PID matching alone is insufficient. Prefer ProcessGuid, parent ProcessGuid, host, user, Logon ID, image, and command line together.
- PowerShell 4103 events should be joined by host, `ExecutionProcessID`, Runspace ID, Host Application, account, and time window.
- The author-provided emulation narrative is provenance/context, not a substitute for raw-event evidence.
