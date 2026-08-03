# Dataset Decision Record

## Decision

Use the OTRF Security Datasets **Empire Elevated Scheduled Tasks** host dataset as the primary evidence source for Scenario 12. Follow the Scheduled Task investigation route rather than forcing a combined Scheduled Task and Windows Service scenario.

## Selected dataset

| Field | Value |
|---|---|
| Project | OTRF Security Datasets |
| Dataset | Empire Elevated Scheduled Tasks |
| Dataset type | Controlled adversary simulation / lab telemetry |
| Created | 2020-09-21 |
| Contributor | Roberto Rodriguez (`@Cyb3rWard0g`) |
| Primary tactic | Persistence (`TA0003`) |
| Primary technique | Scheduled Task (`T1053.005`) |
| Simulation tool | Empire, `schtasks` module |
| Format analysed | Line-delimited JSON in ZIP archive |
| Licence | MIT |
| Analysis mode | Offline, static log analysis only |

Source references:

- Dataset documentation: <https://securitydatasets.com/notebooks/atomic/windows/persistence/SDWIN-200921175806.html>
- Repository: <https://github.com/OTRF/Security-Datasets>
- Licence: <https://github.com/OTRF/Security-Datasets/blob/master/LICENSE>
- Upstream archive: <https://raw.githubusercontent.com/OTRF/Security-Datasets/master/datasets/atomic/windows/persistence/host/empire_schtasks_creation_execution_elevated_user.zip>

## Selection rationale

The scheduled-task route was selected because this dataset provides the strongest correlation across the required investigation questions:

- `schtasks.exe` process creation and command-line parameters;
- Security Event ID `4698` for task creation;
- Task Scheduler Event ID `106` for registration;
- Task Scheduler Event ID `129` for execution and process ID;
- Security Event ID `4688` for execution context and parent-child process relationships;
- Sysmon registry events for the registry-backed payload location;
- reboot and logon evidence supporting the `ONLOGON` trigger;
- Windows Filtering Platform events linking the resulting PowerShell PIDs to network activity.

The same collection contains a System Event ID `7045`, but the extracted record does not expose usable service name, image path, account, or start-type details. Treating it as a second persistence chain would create an unsupported conclusion. The service route was therefore excluded from the primary analysis.

## Alternatives considered

| Route | Strengths | Limitations | Decision |
|---|---|---|---|
| Scheduled Task | Creation, registration, execution, process, reboot, logon, registry, and network telemetry correlate within one short window | Task XML fields did not parse cleanly in the normalised export; file hash and signer fields are absent | Selected |
| Windows Service | Event ID `7045` is present | The available record lacks the configuration needed to attribute or assess the service | Not selected |
| Synthetic self-generated logs | Full control over schema and labels | Would provide weaker independent evidence and less realistic background noise | Not selected |

## Evidence quality and limitations

The dataset includes background Windows activity from three lab hosts. This provides realistic benign noise and prevents conclusions based only on a suspicious task name. The relevant behaviour is supported by multiple independent Windows channels.

Important limitations:

- The collection window is only 4 minutes and 21 seconds.
- The task XML parser used during analysis did not extract `UserId`, `LogonType`, `RunLevel`, trigger, command, or arguments into dedicated fields.
- Configuration claims therefore rely on the observed `schtasks.exe` command line and the task's later behaviour, not on successfully parsed task XML.
- The creation of `\MordorElevatedTask` is not present in the collection window.
- The original login event for creator Logon ID `0xa1d79` is not present.
- File creation, binary hash, and signer evidence for any payload are not available.
- Network evidence confirms TCP communication to destination port `80`; it does not independently confirm HTTP content.
- Change tickets, deployment records, and production authorisation context are not part of the dataset.

## Safety decision

The archive is treated as potentially sensitive security evidence even though it contains logs rather than an executable sample.

- Do not run or decode embedded PowerShell content as part of this scenario.
- Do not connect to addresses present in the logs.
- Keep the original ZIP, JSON, full messages, and working exports local.
- Publish only sanitised summaries, deactivated indicators, source metadata, hashes, and reproducible read-only queries.

## Integrity records

| Local raw object | SHA-256 |
|---|---|
| `empire_schtasks_creation_execution_elevated_user.zip` | `74662dc5c52f4ac2fc9dcb336bae7fb4e101217169c65adf5784b03015501d3b` |
| `empire_schtasks_creation_execution_elevated_user_2020-09-21175806.json` | `1e595a94305c7a2283fb9109ae79f52906aefc0c19e2064a27fad9da2d0e27e9` |

