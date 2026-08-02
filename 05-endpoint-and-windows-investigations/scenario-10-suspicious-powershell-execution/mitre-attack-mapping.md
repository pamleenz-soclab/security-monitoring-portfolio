# MITRE ATT&CK Mapping

Mappings are based on observed event content and are separated by evidence status. Dataset metadata or framework labelling alone was not used to assert a technique.

## Confirmed techniques

| Technique | Name | Evidence in this investigation | Status boundary |
| --- | --- | --- | --- |
| [T1059.005](https://attack.mitre.org/techniques/T1059/005/) | Command and Scripting Interpreter: Visual Basic | WScript executed `launcher.vbs` | VBS execution confirmed; original script content unavailable |
| [T1059.001](https://attack.mitre.org/techniques/T1059/001/) | Command and Scripting Interpreter: PowerShell | PowerShell process, 4104 stager, 4103 commands, and Event 800 agent pipeline | Confirmed |
| [T1027](https://attack.mitre.org/techniques/T1027/) | Obfuscated Files or Information | 5,056-character encoded command, mixed case, string concatenation, and nested Base64 | Confirmed |
| [T1140](https://attack.mitre.org/techniques/T1140/) | Deobfuscate/Decode Files or Information | Runtime Base64 decoding and RC4-like transformation before `IEX` | Confirmed in executed code |
| [T1562.001](https://attack.mitre.org/techniques/T1562/001/) | Impair Defenses: Disable or Modify Tools | Code attempted to alter Script Block Logging policy state and set `amsiInitFailed` | Attempt confirmed; actual AMSI bypass success unable to confirm |
| [T1105](https://attack.mitre.org/techniques/T1105/) | Ingress Tool Transfer | Initial `DownloadData` logic, attributed network connection, and new second-stage code in the same runspace | Successful in-memory stage transfer confirmed; bytes unavailable |
| [T1071.001](https://attack.mitre.org/techniques/T1071/001/) | Application Layer Protocol: Web Protocols | HTTP server, port 80, WebClient download/POST methods, and web URI paths | Program flow confirmed; packet content unavailable |
| [T1573.001](https://attack.mitre.org/techniques/T1573/001/) | Encrypted Channel: Symmetric Cryptography | Executed stage includes RC4, AES-CBC, and HMAC-protected task/channel logic | Cryptographic channel implementation confirmed; exact transmitted bytes unavailable |
| [T1047](https://attack.mitre.org/techniques/T1047/) | Windows Management Instrumentation | `Get-WmiObject` queried local WMI classes | Local WMI only; no lateral movement mapping |
| [T1016](https://attack.mitre.org/techniques/T1016/) | System Network Configuration Discovery | `Win32_NetworkAdapterConfiguration` query | Confirmed |
| [T1082](https://attack.mitre.org/techniques/T1082/) | System Information Discovery | `Win32_OperatingSystem` query and agent host-information collection | Confirmed |
| [T1033](https://attack.mitre.org/techniques/T1033/) | System Owner/User Discovery | Agent executed `whoami` and logged `theshire\pgustavo` | Confirmed |

## Inferred technique

| Technique | Name | Evidence | Why not confirmed |
| --- | --- | --- | --- |
| [T1204.002](https://attack.mitre.org/techniques/T1204/002/) | User Execution: Malicious File | Explorer parent and Windows Recent item for `launcher.vbs` | Strongly suggests interactive access, but delivery, click action, and user intent are not directly recorded |

## Techniques not mapped

| Area | Decision |
| --- | --- |
| Persistence | Not mapped: no scheduled task, service, autorun value, startup item, WMI subscription, or profile persistence observed |
| Privilege escalation | Not mapped: PowerShell ran at Medium integrity with a limited token |
| Credential access | Not mapped: no supporting command or telemetry |
| Process injection | Not mapped: no injection evidence |
| Lateral movement | Not mapped: WMI queries were local; no remote service, WinRM, SMB, or remote WMI execution |
| Indicator removal | Not mapped: deleted `__PSScriptPolicyTest` files are normal PowerShell side effects, not attacker cleanup evidence |
| Impact | Not mapped: no encryption, destruction, or service disruption observed |

## Mapping principle

ATT&CK records adversary behaviour, not incident severity or certainty by itself. Each mapping above is constrained to the behaviour supported by the data. An impairment attempt is not reported as a successful bypass, local WMI discovery is not reported as lateral movement, and absence within this short capture is not treated as proof of global absence.
