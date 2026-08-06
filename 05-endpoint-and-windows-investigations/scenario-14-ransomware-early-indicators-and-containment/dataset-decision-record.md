# Dataset Decision Record

## Decision

Use the Splunk Attack Data dataset **ActiveMQ Exploit LockBit Ransomware** as the sole event source for Scenario 14.

## Dataset identity

| Item | Value |
|---|---|
| Dataset title | ActiveMQ Exploit LockBit Ransomware |
| Dataset identifier | `1d5e15bc-7eaf-46a2-8a92-ad9e3eb5cbb4` |
| Source repository | Splunk Attack Data |
| Repository URL | `https://github.com/splunk/attack_data` |
| Dataset path | `datasets/apt_simulations/ActiveMQ_exploit_Lockbit_Ransomware` |
| Fixed source commit | `671041b0405d5d766378a34a82bae59c5c672d9f` |
| Source commit date | `2026-07-31T13:11:40-04:00` |
| Dataset test date | `2026-04-28` |
| Environment | Splunk Attack Range |
| Repository licence | Apache License 2.0 |

## Selected evidence

- `windows-sysmon.log`
- `windows-security.log`
- `windows-powershell.log`

These three files belong to the same simulated event and support process, authentication, PowerShell, file, and network correlation.

## Selection rationale

The dataset was selected because it:

- Provides at least two independent telemetry classes.
- Supports host, account, process, time, and file-impact correlation.
- Contains a ransomware build and execution sequence.
- Includes authentication and remote-access evidence.
- Is safe to analyse offline because no executable payload is required.
- Has a fixed repository commit and clear repository licence.
- Allows the investigation to distinguish confirmed ransom-note impact from unconfirmed content encryption.

## Alternatives considered

### EN2025 endpoint and network malware dataset

Not selected because it is primarily a large sandbox and machine-learning dataset. It does not provide a coherent enterprise incident with Windows authentication, logon IDs, administrative sessions, or containment context.

### SILRAD ransomware Sysmon dataset

Not selected because it is primarily Sysmon-only classification data and does not satisfy the preferred multi-source enterprise investigation requirement.

### Other single-source Splunk LockBit or Ryuk datasets

Not selected because they provide narrower Sysmon-only evidence and cannot support the same authentication and PowerShell correlation.

### MITRE ATT&CK Evaluations ransomware scenarios

Used only as a conceptual reference. They do not provide a single offline raw event package equivalent to the selected dataset.

## Safety assessment

The acquisition and analysis process:

- Downloaded log files only.
- Did not execute malware.
- Did not retrieve a malicious binary.
- Did not reconstruct or deploy an operational ransomware workflow.
- Stored raw evidence in a Git-ignored directory.
- Published only sanitised derived evidence.

## Decision constraints

The dataset does not contain:

- Windows System logs.
- Dedicated VSS or backup-product logs.
- File content or entropy.
- Dedicated file-rename telemetry.
- Packet capture or application-layer ActiveMQ request content.
- Complete file-server or shared-drive auditing.

Therefore, it cannot independently confirm:

- Successful content encryption.
- Successful deletion of shadow copies.
- Successful service termination or log clearing.
- Exact exploit request content.
- Enterprise-wide lateral movement.
- Data exfiltration.
