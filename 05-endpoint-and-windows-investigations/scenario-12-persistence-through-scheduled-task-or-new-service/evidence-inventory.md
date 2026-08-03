# Evidence Inventory

## Collection summary

| Metric | Value |
|---|---:|
| Evidence start | `2020-09-21 17:58:04` |
| Evidence end | `2020-09-21 18:02:25` |
| Duration | 4 minutes 21 seconds |
| Parsed events | 59,399 |
| Hosts | 3 |
| Events from primary host | 52,708 (88.74%) |
| Events from secondary workstation | 3,388 (5.70%) |
| Events from domain controller | 3,303 (5.56%) |

Public labels replace lab host, domain, user, and source-address values. The task names, registry path, event identifiers, record identifiers, and process identifiers are retained because they are necessary for correlation.

## Raw evidence — local only

| File | Purpose | Integrity | Git status |
|---|---|---|---|
| `evidence/raw/.../empire_schtasks_creation_execution_elevated_user.zip` | Original upstream archive | SHA-256 recorded | Ignored |
| `evidence/raw/.../empire_schtasks_creation_execution_elevated_user_2020-09-21175806.json` | Extracted line-delimited Windows telemetry | SHA-256 recorded | Ignored |

The public hash list is stored in `evidence/source/raw-sha256.txt`. Local absolute paths are intentionally removed.

## Working evidence — local only

| Working file | Purpose | Result summary |
|---|---|---|
| `all-event-index.tsv` | Event-level time, host, channel, ID, and record index | 59,399 rows |
| `key-event-schemas.tsv` | Available fields for key event types | 34 rows |
| `task-lifecycle.tsv` | Task create, update, delete, register, and launch candidates | 48 rows |
| `task-xml-events.jsonl` | Task-related records retained for XML review | 13 rows |
| `task-definitions.tsv` | Normalised task configuration fields | 13 rows; relevant fields unresolved |
| `process-candidates.tsv` | `schtasks`, PowerShell, reboot, and child-process candidates | 19 rows |
| `powershell-candidates.tsv` | PowerShell-channel candidates | 308 rows |
| `network-candidates.tsv` | PowerShell network-filtering events | 4 rows |
| `logon-context.tsv` | Security 4624 and 4672 context | 202 rows |
| `mordor-task-events.tsv` | Focused lifecycle for the two related tasks | 4 rows |
| `registry-network-debug.tsv` | Registry payload and TaskCache records | 5 rows |
| `relevant-logon-context.tsv` | Focused account and Logon ID context | 18 rows |
| `reboot-logon-evidence.tsv` | Shutdown, startup, and subsequent logon sequence | 127 rows |

Working exports may contain full command lines and environment-specific identifiers, so they remain under `evidence/working/` and are ignored by Git.

## Published processed evidence

| File | Contents | Sanitisation |
|---|---|---|
| `evidence/processed/persistence-timeline.csv` | Chronological persistence and follow-on events | Host/user labels replaced; controller deactivated; payload omitted |
| `evidence/processed/key-events.csv` | Minimum fields required to reproduce the main correlations | No full messages, XML, or encoded content |
| `evidence/processed/task-execution-correlation.csv` | Task-to-PID-to-child-to-network mapping | Host/user labels replaced |
| `evidence/processed/evidence-status.csv` | Confirmed, inferred, unavailable, and gap decisions | No raw data |
| `evidence/processed/detection-validation.csv` | Rule match counts and validation limits | No raw messages |

## Evidence used in the final conclusion

| Source | Event IDs | Investigative use |
|---|---|---|
| Sysmon Operational | 1, 12, 13 | Creator process, reboot request, registry value, and TaskCache changes |
| Windows Security | 4624, 4672, 4688, 4698, 5156, 5158 | Account/session context, process creation, task creation, and network correlation |
| Task Scheduler Operational | 106, 129 | Task registration and task-to-process-ID mapping |
| System | 12, 13, 109, 6006 | Shutdown and restart confirmation |

## Evidence unavailable or insufficient

| Question | Status | Reason |
|---|---|---|
| Who created `\MordorElevatedTask`? | Not observed | No creation event for this task appears in the collection window |
| What login originated creator session `0xa1d79`? | Not observed | No matching 4624/4672 session event appears in the available window |
| Did parsed task XML independently confirm every task setting? | Detection gap | The normalisation query did not extract the task XML fields |
| What payload file hash or signer was involved? | Not available | No usable file metadata was supplied for the in-memory/registry-backed content |
| Was the destination communication HTTP? | Unable to confirm | TCP destination port `80` is confirmed; application-layer content is absent |
| Was there an authorised change or deployment? | Not available | No ticketing, software-deployment, or change-management source was included |
| Did the task execute repeatedly after the window? | Unable to confirm | The short dataset ends approximately one minute after the observed execution |
| Is System Event ID `7045` part of this chain? | Unable to confirm | The extracted event lacks service configuration and cannot be correlated safely |

