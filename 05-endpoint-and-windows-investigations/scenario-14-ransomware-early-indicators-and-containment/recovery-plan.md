# Recovery Plan

## Recovery objective

Return business service without reintroducing the payload, control executable, compromised session, or unvalidated data.

## Phase 1 — Preserve and scope

1. Export the centralised Sysmon, Security, and PowerShell logs.
2. Capture memory or targeted volatile evidence when operationally feasible.
3. Acquire a forensic disk image or EDR collection.
4. Preserve the affected payload, builder, configuration, and note files in an isolated evidence store.
5. Search adjacent systems for the same hashes, paths, and network indicators.

## Phase 2 — Validate data impact

Because encryption was not confirmed by the supplied telemetry:

1. Select representative business files from each affected directory class.
2. Attempt safe read/open validation.
3. Compare hashes to backup or repository baselines.
4. Measure entropy where original or baseline files are available.
5. Check for changed extensions, missing files, sparse files, and zero-length files.
6. Review application-specific integrity checks.
7. Check file-server audit logs for writes from the affected host and account.

## Phase 3 — Validate recovery mechanisms

1. Enumerate VSS snapshots.
2. Check backup job state and most recent successful backup.
3. Validate backup immutability and separation.
4. Review backup-operator and backup-service logs.
5. Perform a test restore into an isolated location.
6. Do not rely on the absence of a `vssadmin` command as proof that recovery is healthy.

## Phase 4 — Eradicate

Preferred action: rebuild or reimage the affected host.

Remove or invalidate:

- `qSwUwejx.exe`
- `builder.exe`
- `LB3.exe`
- Associated configuration and key files
- Persistence mechanisms
- Unauthorised scheduled tasks or services
- Compromised local profiles and sessions

Rotate:

- Local Administrator credentials
- Related domain administrative credentials
- Service credentials used on the host
- Any secrets exposed to the affected session

## Phase 5 — Restore

1. Restore applications from trusted installation media.
2. Restore data from a validated clean point.
3. Reapply secure ActiveMQ configuration and patches.
4. Restrict management access to approved hosts.
5. Re-enrol EDR and confirm policy health.
6. Confirm central log forwarding before production use.

## Phase 6 — Monitor

For at least 72 hours after reconnection, monitor:

- TCP/4444.
- Unexpected RDP from `10.0.1.10` or other sources.
- Temporary-directory executable network connections.
- Ransom-note filename creation.
- Event-log clearing.
- Service-stop commands.
- Failed administrative logons.
- External PowerShell or CertUtil activity.
