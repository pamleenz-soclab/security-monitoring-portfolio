# Dataset Decision Record

## Decision

Use the OTRF Security Datasets **Empire Invoke SMBExec** host and network archives pinned to commit `d9d40ef123d2c87d5d3df28c96bcab4f0faccc87`.

## Scenario acceptance criteria

The selected dataset had to support one attributable event chain containing:

- source host/IP and source-side process context;
- target host/IP;
- account and successful authentication context;
- remote protocol/service evidence;
- remote service creation;
- target-side execution and privilege context;
- an independent network or EDR confirmation source;
- a clear license and reproducible source record.

A dataset was not accepted merely because it contained Logon Type 3, TCP/445 or a service-install event.

## Rejected candidate

The first candidate was Splunk Attack Data under an Atomic Red Team `T1021.002` directory. Its files were individually valid, but the directory aggregated tests from different dates, hosts and execution methods. It did not provide one attributable chain containing a common authentication session, source address, target, service action and execution outcome.

The following artifacts were therefore not combined:

- SMBExec/WMIExec-style process and registry traces from one test;
- share/PsExec traces from other hosts and dates;
- a `PsExec \\localhost` test;
- a separate RDP configuration modification.

They are retained under ignored `evidence/raw/rejected-splunk-atomic-red-team/` for provenance and are not used as evidence for the selected incident.

## Selected candidate assessment

| Requirement | OTRF evidence | Result |
|---|---|---|
| Source | `WORKSTATION5`, `172.18.39.5`, source PowerShell ProcessGuid | Pass |
| Target | `WORKSTATION6`, `172.18.39.6` | Pass |
| Account | `THESHIRE\pgustavo` | Pass |
| Authentication | 4624 Type 3 NTLMv2, 4776 success, NTLMSSP packets | Pass |
| Cross-log key | Target Logon ID `0x2074186` | Pass |
| SMB/RPC | 5140 `IPC$`, 5145 `svcctl`, PCAP SVCCTL operations | Pass |
| Remote service | 4697, 7045 and Sysmon 12/13 | Pass |
| Execution | Security 4688 and Sysmon 1 process chain as SYSTEM | Pass |
| Network outcome | Target PowerShell to private lab address `10.10.10.5:80` | Pass |
| License/integrity | MIT license, pinned commit, archive hashes | Pass |

## What the dataset can answer

- Which source host, target host and account were involved.
- Whether the target accepted a Type 3 NTLM authentication.
- Whether `IPC$`, `svcctl` and remote SCM operations occurred.
- Which service was created and which command it contained.
- Whether target-side commands executed and under which identity.
- Whether the target process made a follow-on network connection.

## What the dataset cannot independently answer

- Whether the activity was authorized by a production change or deployment record.
- How the source endpoint was initially compromised.
- Where the credential material originally came from.
- Whether target/network telemetry alone represents password use or pass-the-hash.
- Whether activity outside the supplied capture affected additional hosts.

## Integrity controls

- Host archive SHA-256: `c0fc435c9ce0ecdc7cd57b4055977b949ac6b1cae9d7f4ce7aa0f0e5eae7d7f1`
- Network archive SHA-256: `d9879be3d5e93268d4ea1ca5c7f107f0f16624b5df4aee43b04aa48a14560eea`
- Downloads use an immutable upstream commit rather than the mutable branch head.
- `unzip -tq` validates both archives before extraction.
- The analysis script records extracted JSON/PCAP hashes in `analysed-file-inventory.csv`.
- Raw and working evidence remain excluded by `.gitignore`.

## Limitations

- Source PowerShell process creation predates the capture window.
- Source telemetry and simulation metadata reveal hash use; ordinary target telemetry cannot independently distinguish the credential representation.
- The temporary service is deleted shortly after execution.
- Cross-host timestamps differ by about two seconds, requiring correlation by identifiers, flow tuple and a narrow time window.
- This is controlled teaching data rather than an organic production incident.

## Sources

- [OTRF dataset documentation](https://securitydatasets.com/notebooks/atomic/windows/lateral_movement/SDWIN-190518210125.html)
- [OTRF Security-Datasets repository](https://github.com/OTRF/Security-Datasets)
- [MITRE ATT&CK T1021.002](https://attack.mitre.org/techniques/T1021/002/)
