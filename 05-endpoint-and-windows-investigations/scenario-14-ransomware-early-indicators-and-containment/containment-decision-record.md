# Containment Decision Record

## Decision summary

**Primary decision:** Immediately isolate `EC2AMAZ-I41BETP`, retain power, perform rapid volatile capture, and terminate the payload.

## Decision factors

- Payload execution is confirmed.
- File-impact markers are active and process-linked.
- Administrative session involvement is confirmed.
- A temporary control executable and TCP/4444 connection are present.
- Log-clearing commands were executed.
- File encryption is not yet proven, but waiting for proof would create unacceptable impact risk.

## Option assessment

| Option | Use when | Benefit | Business impact | Forensic risk | Decision |
|---|---|---|---|---|---|
| Network-isolate host | Payload or control activity is active | Stops external control and remote spread | Host service interruption | Terminates network sessions | **Immediate** |
| Terminate payload | File impact is active | Stops local impact | Application interruption | May lose runtime keys/configuration | **After rapid volatile capture** |
| Disable/reset account | Admin session or credential use is involved | Stops account reuse | May affect maintenance and recovery access | May change authentication evidence | **Immediate, with break-glass validation** |
| Block SMB from affected host | Ransomware may access shares | Protects file servers | Removes share access for users/services | Low | **Immediate scoped block** |
| Block RDP/WinRM/WMI | Remote management path is involved | Stops remote operator access | Interrupts administration | Loses active session | **Immediate for affected host** |
| Isolate all shares | Share impact is confirmed or rapidly suspected | Protects enterprise files | High business outage | Low | **Not justified by current evidence** |
| Maintain power for memory | Isolation is effective | Preserves volatile evidence | Host remains running | Local process may continue | **Only for a short capture window** |
| Immediate power-off | Isolation or process termination fails | Stops all activity | Abrupt outage | Loses memory, sessions, and possible keys | **Fallback only** |

## Recommended sequence

```text
Confirm EDR visibility
→ isolate host
→ capture process/network/session state
→ terminate LB3.exe
→ terminate Administrator session
→ disable/reset credentials
→ block management and share access
→ acquire forensic image
→ rebuild and restore
```

## Rollback requirements

Network access must not be restored until:

- The asset has been rebuilt or independently validated.
- Administrative credentials have been rotated.
- Adjacent hosts have been investigated.
- Shared-resource access has been reviewed.
- EDR and central logging are functioning.
- Representative files and backups have been validated.
