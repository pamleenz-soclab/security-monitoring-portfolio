# Investigation Notes

## Working hypothesis

`WORKSTATION5` used `THESHIRE\pgustavo` over SMB to reach the remote Service Control Manager on `WORKSTATION6`, create a temporary service and run encoded PowerShell.

## Correlation ledger

| Evidence | Key fields | Relationship | Status |
|---|---|---|---|
| Security 4624 on target | `pgustavo`, Type 3, NTLM, `172.18.39.5:50504`, Logon ID `0x2074186` | Establishes successful remote authentication | Confirmed |
| Security 4776 on DC | `pgustavo`, workstation `WORKSTATION5`, status `0x0` | Confirms credential validation dependency | Confirmed |
| Security 4672 | Subject Logon ID `0x2074186` | Privileges assigned to the same target session | Confirmed |
| Security 5140/5145 | account, source IP/port, Logon ID, `IPC$`, `svcctl` | Links authentication to remote SCM named pipe | Confirmed |
| PCAP | `172.18.39.5:50504 → 172.18.39.6:445`, NTLMSSP, `IPC$`, SVCCTL | Independently confirms direction and protocol operations | Confirmed |
| Security 4697/System 7045 | service `PGUJLOAKFQFVOMHGFQPX`, encoded PowerShell command | Links session to temporary service creation | Confirmed |
| Sysmon 12/13 | service registry path/name | Confirms service lifecycle | Confirmed |
| Sysmon 1/Security 4688 | ProcessGuid and parent ProcessGuid | Proves `services.exe → cmd.exe → cmd.exe → powershell.exe` | Confirmed |
| Sysmon 3 | target PowerShell GUID, `10.10.10.5:80` | Links service-created process to network activity | Confirmed |
| PowerShell 4104 | script behaviour and retrieval URI | Confirms logging/AMSI impairment and staged execution logic | Confirmed |
| Sysmon 1/Security 4688 | `whoami.exe`, parent target PowerShell GUID, SYSTEM | Confirms post-exploitation command execution | Confirmed |

## Important analytical decisions

- Logon Type 3 was not treated as lateral movement by itself.
- TCP/445 was not treated as proof of PsExec or SMBExec by itself.
- Event 7045 was not treated as malicious by itself.
- The conclusion depends on the combined authentication, named-pipe, RPC, service, process and network sequence.
- `WERR_SERVICE_REQUEST_TIMEOUT` was not interpreted as execution failure because target process telemetry proves execution.
- `WmiPrvSE.exe` was excluded from the main chain because no ProcessGuid, Logon ID or network correlation joined it to the service execution.
- `MORDORDC` was classified as an authentication dependency, not a compromised target.
- The private IP `10.10.10.5` is described as a lab listener, not public malicious infrastructure.

## Evidence-status ledger

- **Confirmed:** `WORKSTATION5 → WORKSTATION6`, `THESHIRE\pgustavo`, NTLM Type 3, `IPC$`, `svcctl`, SVCCTL operations, service creation, SYSTEM PowerShell, HTTP activity, `whoami.exe`.
- **Inferred:** the source host was already under attacker control before the captured lateral action.
- **Not observed:** RDP, WinRM, durable service persistence, a third internal target, compromise of `MORDORDC`.
- **Not available:** authorization, change-ticket, deployment and asset-owner records.
- **Unable to confirm from target/network telemetry:** plaintext-versus-hash credential representation and WMI remote execution.
- **Detection gap:** missing 5145, 4697, process command lines, PowerShell 4104 or east-west network telemetry would materially reduce confidence.
