# Recommended Actions

## Immediate — first 15 minutes

1. Isolate `EC2AMAZ-I41BETP` using EDR or a switch/firewall control.
2. Preserve power and capture:
   - Running processes.
   - Process tree.
   - Network connections.
   - Logged-on users and sessions.
   - Volatile command history where available.
3. Terminate `LB3.exe` after rapid volatile capture.
4. Terminate the affected Administrator desktop session.
5. Temporarily disable or reset the affected local/domain administrative credentials.
6. Block TCP/4444 for the affected asset.
7. Remove the host's access to SMB shares and administrative protocols.

## Short term — first hour

1. Investigate `10.0.1.10`:
   - Asset ownership.
   - RDP authorisation.
   - Credential use.
   - EDR timeline.
   - Related sessions.
2. Investigate `10.0.2.13`:
   - ActiveMQ role.
   - TCP/61616 and TCP/8080 activity.
   - TCP/4444 listener or process.
   - Application and web logs.
3. Search all endpoints for:
   - Payload SHA-256.
   - Builder SHA-256.
   - `qSwUwejx.exe`.
   - `7duXYi3SC.README.txt`.
   - TCP/4444.
   - Similar parent-child chains.
4. Preserve relevant event logs from central collection because local log-clearing commands were executed.
5. Check file servers for activity from:
   - `10.0.2.12`
   - `EC2AMAZ-I41BETP\Administrator`
   - Logon ID `0x11c15c`

## Recovery preparation

1. Validate representative pre-existing files by opening and hashing them.
2. Compare business files to backups or known-good baselines.
3. Check file extensions and content entropy.
4. Verify VSS and backup status independently.
5. Confirm the absence of persistence.
6. Rebuild or reimage the affected host rather than relying on file deletion alone.
7. Rotate administrative credentials before reconnecting the asset.
8. Restore only from validated clean backup points.

## Detection improvements

1. Alert on a non-standard executable producing many identically named README files across distinct directories.
2. Correlate Explorer-launched binaries with file-creation bursts.
3. Alert on temporary-directory executables connecting to TCP/4444.
4. Correlate RDP authentication with high-integrity payload execution.
5. Alert when multiple Windows logs are cleared within a short period.
6. Alert on service-stop commands followed by ransomware indicators.
7. Retain central logs to withstand local log clearing.
8. Enable file-server auditing for high-value shares.
9. Add VSS, backup-product, and Windows System telemetry.
10. Maintain endpoint telemetry for file rename, delete, and content-change detection.

## Threat hunting pivots

- SHA-256:
  - `8ADCB1AE01F295EBD4A50B6BB41F9FE05AE90FC7E655002A8C400F7F9D05A582`
  - `A736269F5F3A9F2E11DD776E352E1801BC28BB699E47876784B8EF761E0062DB`
  - `90D120880614E1E2A94067BAAD1454B09E2BE7A9DA51B71E33C247077D9F9538`
- Filename: `7duXYi3SC.README.txt`
- Temporary image: `qSwUwejx.exe`
- Destination port: `4444`
- Payload path: `C:\Intel\Build\LB3.exe`

These values come from a laboratory dataset and should be treated as dataset-specific pivots, not universal LockBit indicators.
