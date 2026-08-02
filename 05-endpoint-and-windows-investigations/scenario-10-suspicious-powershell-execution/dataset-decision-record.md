# Dataset Decision Record

## Scenario

Scenario 10 - Suspicious PowerShell Execution Investigation

## Investigation objective

Determine whether the observed PowerShell activity represents authorised administration, suspicious but unconfirmed use, or malicious execution. The investigation must independently verify:

1. the initiating user, host, logon session, and parent process;
2. the complete process chain and command line;
3. the content and purpose of the encoded or obfuscated PowerShell;
4. any associated script-block, module, file, DNS, and network telemetry;
5. whether downloaded content, follow-on execution, persistence, privilege escalation, or lateral movement can be confirmed;
6. the affected account and host scope; and
7. the evidence limitations that prevent stronger conclusions.

No attack stage is treated as successful until supported by the supplied telemetry.

## Candidate comparison

| Candidate | Provenance and data type | Relevant coverage | Licence | Safety | Decision |
| --- | --- | --- | --- | --- | --- |
| OTRF Security Datasets - **Empire VBS Execution** (`SDWIN-190518182022`) | Controlled Mordor lab emulation; newline-delimited Windows event JSON | Security 4688; PowerShell 4103/4104; Sysmon 1, 3, 11, 22 and 23; common host, user, PID, ProcessGuid and Logon ID fields | Repository `LICENSE` currently states MIT, but the README retains a conflicting GPL-3.0 label pointing to an obsolete path | Downloaded ZIP contains one JSON log only; no executable or script file | **Use with restrictions** |
| OTRF APT29 Day 1 | Controlled ATT&CK evaluation emulation; broad host and network telemetry | Very strong: Security 4688, PowerShell Operational, Sysmon 1/3/11 and additional sources | Same OTRF repository-level licence ambiguity | Log archives rather than a live payload, but the host archive is approximately 367 MB | Not selected: excellent but unnecessarily broad and slow for a focused PowerShell scenario |
| Splunk Attack Data - Empire PowerShell Script Block Logging | Simulated detection-test data | PowerShell 4104 only for the referenced unit dataset | Apache-2.0 | Static log data | Rejected as primary evidence: insufficient process, file, network, and scope telemetry |
| EVTX-ATTACK-SAMPLES | Community Windows EVTX samples mapped to individual ATT&CK techniques | Broad event-ID coverage across separate samples | GPL-3.0 | Static EVTX samples | Rejected as primary evidence: separate technique samples should not be combined into one incident chain without shared correlation evidence |

## Selected dataset

- **Title:** Empire VBS Execution
- **Dataset ID:** `SDWIN-190518182022`
- **Contributor:** Roberto Rodriguez (`@Cyb3rWard0g`)
- **Creation date:** 2019-05-18
- **Last metadata modification:** 2020-09-20
- **Environment:** Mordor `shire` controlled lab
- **Dataset type:** Atomic simulated attack telemetry
- **Source documentation:** https://securitydatasets.com/notebooks/atomic/windows/execution/SDWIN-190518182022.html
- **Dataset download:** https://raw.githubusercontent.com/OTRF/Security-Datasets/master/datasets/atomic/windows/execution/host/empire_launcher_vbs.zip
- **Metadata source:** https://raw.githubusercontent.com/OTRF/Security-Datasets/master/datasets/atomic/_metadata/SDWIN-190518182022.yaml
- **Repository:** https://github.com/OTRF/Security-Datasets
- **Repository licence file:** https://github.com/OTRF/Security-Datasets/blob/master/LICENSE
- **Accessed:** 2026-08-02

## Why this dataset was selected

The dataset is compact while preserving a coherent, single-window evidence chain. It contains both Windows Security and Sysmon process creation, PowerShell module and script-block logging, and follow-on file and network activity. This supports field-level correlation rather than relying on a malicious label or a single encoded command.

The selected archive is also substantially smaller than the APT29 Day 1 alternative and can be analysed offline with standard macOS tools (`jq`, `rg`, `sort`, and `shasum`).

## Integrity and format validation

| Item | Result |
| --- | --- |
| ZIP size | 313,016 bytes |
| ZIP SHA-256 | `812da270cf8cda6f1948fb6275410f15dc1794d0bd6b623c9c25b2518285019c` |
| ZIP integrity | Passed `unzip -t`; no archive errors |
| ZIP contents | One file: `empire_launcher_vbs_2020-09-04160940.json` |
| Extracted JSON size | 5,625,164 bytes |
| Extracted JSON SHA-256 | `d569bc556907e23acf638b762c0acfbbecba016b6b2e07a86356151a799b661c` |
| JSON format | Newline-delimited JSON (JSONL) |
| JSON records | 2,067 lines; all 2,067 parsed successfully |
| Normalised time range | `2020-09-04T20:09:40.845Z` to `2020-09-04T20:10:49.124Z` |

## Verified telemetry coverage

| Source | Event ID | Count | Key fields available |
| --- | ---: | ---: | --- |
| Windows Security | 4688 | 5 | Security ID, account, domain, Logon ID, new/creator PID, image, parent image, command line |
| PowerShell Operational | 4103 | 87 | Account, `ExecutionProcessID`, `ContextInfo`, `Host Application`, Runspace ID, Pipeline ID, command name, payload |
| PowerShell Operational | 4104 | 1 | Account, `ExecutionProcessID`, `ScriptBlockId`, `ScriptBlockText`, record number |
| Sysmon Operational | 1 | 5 | `UtcTime`, `ProcessGuid`, PID, image, command line, user, Logon ID, hashes, parent GUID/PID/image/command line |
| Sysmon Operational | 3 | 10 | `UtcTime`, ProcessGuid, PID, image, user, protocol, source/destination IP and port |
| Sysmon Operational | 11 | 22 | `UtcTime`, ProcessGuid, PID, image, target filename, creation time |
| Sysmon Operational | 22 | 2 | ProcessGuid, PID, image, query name and result |
| Sysmon Operational | 23 | 2 | ProcessGuid, PID, user, image, deleted path and hash |

Additional available sources include Windows PowerShell 400/600/800 events, Security logon and object-access events, and one WMI Activity event.

## Safety assessment

The archive contains telemetry only. It does not contain the referenced VBS launcher, a downloaded stage, an executable, a DLL, or a packet capture. The JSON does contain recorded encoded PowerShell and script text. That text must be treated as inert evidence: it will be decoded as text only, never executed, and no dataset-contained address will be contacted.

## Authenticity and realism

This is realistic Windows telemetry generated during a controlled adversary emulation, not an anonymised production incident. It preserves native event concepts and correlation identifiers, but it also includes author-provided emulation metadata. Final findings will distinguish what the raw events independently show from what the dataset author states occurred.

## Licence and publication decision

The repository's current root `LICENSE` file contains the MIT Licence. The current rendered README still contains a conflicting `License: GPL-3.0` heading whose link points to an obsolete repository path. Because that inconsistency creates avoidable redistribution uncertainty, the raw ZIP, full JSONL, metadata YAML, and complete encoded/script-block content will remain local and Git-ignored.

GitHub publication will be limited to attributed analysis, aggregate counts, defanged indicators, and minimal sanitised event excerpts needed to reproduce the conclusions. The raw dataset will not be redistributed in this portfolio.

## Known limitations before investigation

- No original EVTX files or original Windows XML records are provided.
- `RecordNumber` is the JSON equivalent used in place of an `EventRecordID` field.
- Many Sysmon fields are embedded in the `Message` string and must be parsed.
- No EDR alert record or vendor verdict is included.
- The VBS file, downloaded stage bytes, memory image, packet payload, and HTTP response are not included.
- The dataset covers approximately 68 seconds, so long-term persistence and later impact may be outside the collection window.
- Source metadata provides simulation ground truth, but it must not replace event-level verification.

## Final decision

**Use with restrictions.** The dataset is suitable for Scenario 10 because it provides coherent and sufficiently rich endpoint telemetry for a focused PowerShell investigation. Raw evidence remains local, and the final assessment must preserve the distinction between observed telemetry, inference, source-provided context, and unavailable evidence.

## Post-investigation fitness confirmation

The completed investigation confirmed that the selected dataset supports field-level correlation across Security 4688/5156, PowerShell 4103/4104/800, and Sysmon process/network/file telemetry. It was sufficient to distinguish successful staged execution from a mere encoded-command alert and to document negative findings for persistence, elevation, credential access, and lateral movement. Its principal remaining limitations are the absence of the original VBS, network content, Defender/AMSI outcome telemetry, memory evidence, and activity after the short capture window.
