# Indicators and Investigation Identifiers

## Reusable or huntable indicators

| Type | Observed value | Defanged / safe form | Confidence | Use and limitation |
| --- | --- | --- | --- | --- |
| Destination IP | `10.10.10.5` | `10[.]10[.]10[.]5` | High in this dataset | Confirmed PowerShell destination; private lab IP, not a globally malicious address |
| Destination service | TCP `80` | `10[.]10[.]10[.]5:80` | High | Confirmed by Sysmon 3 and Security 5156 |
| Initial launcher path | `C:\Users\pgustavo\Desktop\launcher.vbs` | Same local path | High | Execution confirmed; file bytes and hash not available |
| Staging path | `/news.php` | `/news[.]php` when sharing externally | High in code | Present in initial and agent code; HTTP request body/path not independently available from network telemetry |
| Negotiation path | `/login/process.php` | `/login/process[.]php` when sharing externally | High in code | Present in executed stage code; generic path should be correlated with other features |
| PowerShell command pattern | `wscript.exe -> powershell.exe -noP -sta -w 1 -enc` | Long Base64 omitted | High | Strong behavioural indicator when parentage and network activity are combined |
| Defence-impairment pattern | cached group-policy settings plus constructed `ScriptBlockLogging` and `AmsiUtils.amsiInitFailed` fields | N/A | High | Behavioural content in 4104; use case-insensitive and deobfuscated matching |
| Script-block content hash | `cca88ef46c983e164828873bdb2494227ba50fc16d8496553ea83c5129dfd974` | N/A | High | Analyst-derived SHA-256 of UTF-8 `ScriptBlockText`; not a file hash |

## Context-only artefacts

| Artefact | Value | Why it is not a standalone IOC |
| --- | --- | --- |
| User agent | `Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko` | Generic legacy browser string with high false-positive potential |
| Local source IP | `172.18.39.5` | Lab endpoint address, useful only within this incident |
| Account | `THESHIRE\pgustavo` | Affected identity, not intrinsically malicious |
| Host | `WORKSTATION5.theshire.local` | Affected lab asset, not reusable outside this dataset |
| `launcher.lnk` | `C:\Users\pgustavo\AppData\Roaming\Microsoft\Windows\Recent\launcher.lnk` | Windows Recent item created after access; not the original launcher |

## Incident-scoped correlation identifiers

| Identifier | Value |
| --- | --- |
| Logon ID | `0x2D5A4B` |
| WScript PID / ProcessGuid | `2440` / `{860ba2e3-9f13-5f52-2603-000000000400}` |
| PowerShell PID / ProcessGuid | `2316` / `{860ba2e3-9f13-5f52-2703-000000000400}` |
| `whoami.exe` PID / ProcessGuid | `9152` / `{860ba2e3-9f2e-5f52-2a03-000000000400}` |
| ScriptBlockId | `6e4c1b59-2eb8-4934-9e78-32cd88822dbb` |
| PowerShell HostId | `39315e7d-5bea-48aa-8ea8-21c983c954a8` |
| PowerShell RunspaceId | `2f526b39-34e5-4958-8786-a61c85685778` |

PIDs, ProcessGuids, Logon IDs, HostIds, and RunspaceIds are excellent evidence joins for this case but should not be deployed as durable IOC detections.

## Explicit exclusions

- The hashes of `wscript.exe`, `powershell.exe`, `conhost.exe`, and `whoami.exe` are Microsoft system-binary hashes in this dataset and are not treated as malicious IOCs.
- SHA-256 `96AD1146EB96877EAB5942AE0736B82D8B5E2039A80D3D6932665C1A4C87DCF7` belongs to PowerShell policy-test files and is not a malicious payload indicator.
- The complete Base64 command, cookie value, staging key, session key, and session identifier are intentionally not published.
- No domain name or downloaded-stage file hash is available.
