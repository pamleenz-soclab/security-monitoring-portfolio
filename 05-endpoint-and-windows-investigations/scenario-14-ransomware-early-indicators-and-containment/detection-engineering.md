# Detection Engineering

## Detection strategy

No single event is sufficient to confirm ransomware. The recommended detection model combines:

1. Suspicious process execution.
2. Process ancestry.
3. File-creation burst and filename repetition.
4. Authentication activity.
5. Remote-access context.
6. Trace-removal commands.
7. Recovery-mechanism telemetry.

## High-confidence analytic

### Recursive ransom-note placement by a non-standard process

Trigger when one process GUID:

- Creates the same README-like filename.
- Writes to at least 20 distinct directories.
- Completes the activity within five minutes.
- Is not a known backup, deployment, archiving, or indexing process.

This dataset produced:

- 183 note files.
- 183 distinct directories.
- One payload Process GUID.
- Approximately one minute of concentrated activity.

### Correlation analytic

```text
RDP or explicit-credential activity
→ Administrator desktop process
→ new executable from unusual path
→ repeated README creation
→ failed account attempts
```

This correlation is more reliable than any individual RDP, process, or file event.

## Rules included

| Rule | Purpose |
|---|---|
| `win_suspicious_ransomware_builder.yml` | Detect an unusual builder creating an encryption-oriented executable |
| `win_ransom_note_file_creation.yml` | Detect a README-like ransom-note file created by a non-standard process |
| `win_wevtutil_clear_windows_logs.yml` | Detect Windows log-clearing commands |
| `win_stop_terminal_services.yml` | Detect Terminal Services stop commands |
| `win_temp_binary_outbound_4444.yml` | Detect a temporary-directory executable connecting to TCP/4444 |
| `win_failed_logons_from_unusual_process.yml` | Detect failed logons initiated by a non-system executable |

The Sigma rules are event-level detections. Burst, sequence, and multi-log correlation must be implemented in the SIEM.

## False-positive controls

### Ransom-note filename

Exclude:

- Software documentation installation.
- Source-code extraction.
- Backup restore operations.
- Known deployment accounts and signed installers.

Require one or more of:

- Same filename in many directories.
- Unusual executable image.
- Explorer-launched binary.
- Ransomware hash or path intelligence.
- Concurrent failed logons or trace removal.

### Log clearing

Allow only documented maintenance identities and change windows. A three-log clear sequence should remain high severity even when initiated by an administrator.

### Service stop

`termservice` may be stopped during maintenance. Increase severity when followed by:

- RDP activity.
- Log clearing.
- Unusual process execution.
- File-impact indicators.

### TCP/4444

Do not classify all TCP/4444 traffic as malicious. Require:

- Temporary or user-writable executable path.
- Unexpected process signature or hash.
- Parent-child anomalies.
- Other incident context.

## Telemetry gaps

The environment should add:

- Windows System logs.
- VSS logs.
- Backup-product logs.
- EDR file rename and delete telemetry.
- File-server share auditing.
- Packet capture or network metadata for high-value services.
- Central immutable log retention.
