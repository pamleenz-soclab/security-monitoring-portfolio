# Investigation Report

## Executive summary

Windows Security, Sysmon, PowerShell Operational, and classic Windows PowerShell telemetry confirm that `WORKSTATION5.theshire.local` executed a VBS-launched, hidden, encoded PowerShell stager under `THESHIRE\pgustavo`. The process connected to `10.10.10.5:80`, loaded and executed an Empire-compatible second stage in memory, collected local host and network information, entered a command task loop, and executed `whoami` with the result `theshire\pgustavo`.

The incident is classified **True Positive**, severity **High**, confidence **High**. Successful malicious execution and command-and-control capability are confirmed. Persistence, privilege escalation, credential access, lateral movement, and destructive activity were not observed. The approximately 69-second dataset cannot prove that those behaviours never occurred outside the collection window.

## Investigation scope and questions

The investigation sought to establish:

1. the initiating host, user, session, parent, and full process chain;
2. the actual contents and purpose of the encoded PowerShell;
3. whether any download, second-stage execution, network activity, or task execution succeeded;
4. the associated file, registry, WMI, and account activity;
5. whether persistence, elevation, credential access, or lateral movement was present;
6. the affected host and account scope; and
7. the limitations preventing stronger conclusions.

No result was accepted solely from the dataset title, an encoded-command flag, an IOC, or a malicious framework label.

## Evidence examined

| Source | Relevant coverage |
| --- | --- |
| Windows Security | Event 4688 process creation; Event 5156 permitted network connection |
| PowerShell Operational | 87 Event 4103 module/pipeline events; one Event 4104 script block |
| Windows PowerShell | 126 Event 800 pipeline-detail events, plus engine/provider lifecycle records |
| Sysmon | Process, network, file, registry, DNS, pipe, and image-load telemetry |
| WMI Activity | Supporting local WMI-provider activity |

The raw JSONL contains 2,067 records across three hosts. Its SHA-256 is `d569bc556907e23acf638b762c0acfbbecba016b6b2e07a86356151a799b661c`.

## Time and record interpretation

- Sysmon embedded `UtcTime` is the preferred source-event time.
- Normalised `@timestamp` is used for sources without embedded UTC.
- Unzoned `EventTime` reflects local lab time and is not treated as UTC.
- `RecordNumber` represents the source channel's event sequence. It is not globally ordered across channels.
- Collection delay explains small differences between a process source time and its later PowerShell pipeline record.

## Finding 1 - Interactive shell launched the VBS

Sysmon Event 1 Record `251079` shows:

```text
UtcTime=2020-09-04 20:09:55.035
Image=C:\Windows\System32\wscript.exe
ProcessId=2440
CommandLine="C:\windows\System32\WScript.exe" "C:\Users\pgustavo\Desktop\launcher.vbs"
ParentImage=C:\Windows\explorer.exe
ParentProcessId=5728
User=THESHIRE\pgustavo
LogonId=0x2D5A4B
```

Security 4688 Record `66940` independently reports new PID `0x988` (2440), creator PID `0x1660` (5728), the same image, account, command, and logon session.

Explorer also created `C:\Users\pgustavo\AppData\Roaming\Microsoft\Windows\Recent\launcher.lnk` at `20:09:55.141Z`. This is a Windows Recent item, not the original malicious file. Together, the Explorer parent and Recent item support an interactive open, but they do not identify the delivery mechanism or prove the user's intent.

**Assessment:** VBS execution is Confirmed. User execution is Inferred. Initial delivery is Not available.

## Finding 2 - WScript launched hidden encoded PowerShell

Sysmon Event 1 Record `251258` shows PowerShell PID `2316` with:

```text
powershell.exe -noP -sta -w 1 -enc <5056-character Base64>
```

The parent is WScript PID `2440`, with exact ProcessGuid continuity. Security 4688 Record `66981` independently reports new PID `0x90c` (2316) and creator PID `0x988` (2440). The process ran as `THESHIRE\pgustavo`, Logon ID `0x2D5A4B`, Medium integrity, with a limited token.

Parameter meanings:

- `-noP`: do not load the PowerShell profile;
- `-sta`: single-threaded apartment mode;
- `-w 1`: hidden window style in this command;
- `-enc`: UTF-16LE Base64-encoded command.

These switches can appear in legitimate automation. Maliciousness was determined from the decoded code and follow-on evidence, not from the switches alone.

**Assessment:** Encoded hidden PowerShell and its parent/child relationship are Confirmed.

## Finding 3 - The initial stager performed malicious operations

PowerShell 4104 Record `1948` is tied to PID `2316` and ScriptBlockId `6e4c1b59-2eb8-4934-9e78-32cd88822dbb`. Its ScriptBlockText has analyst-derived UTF-8 SHA-256:

```text
cca88ef46c983e164828873bdb2494227ba50fc16d8496553ea83c5129dfd974
```

Offline text-only decoding and inspection identified four core behaviours:

1. accessing PowerShell's cached group-policy settings and assigning zero to constructed Script Block Logging values;
2. using reflection to target `AmsiUtils` and assign `true` to the constructed `amsiInitFailed` field;
3. decoding a nested UTF-16LE Base64 server value to `http://10.10.10.5`;
4. calling `DownloadData` for `/news.php`, applying an RC4-like transformation, and piping the result to `IEX`.

The evidence records execution of the impairment code, but no Defender or AMSI operational source establishes whether AMSI impairment actually succeeded. Only one 4104 record exists; later code appears in Event 800/4103 rather than additional 4104 events. This pattern is consistent with logging impairment but does not independently prove it caused the missing records.

**Assessment:** Malicious stager behaviour and impairment attempts are Confirmed. Bypass success is Unable to confirm.

## Finding 4 - The PowerShell process established outbound network activity

Sysmon Event 3 Record `251809` reports:

```text
UtcTime=2020-09-04 20:09:59.621
ProcessGuid={860ba2e3-9f13-5f52-2703-000000000400}
ProcessId=2316
Source=172.18.39.5:50699
Destination=10.10.10.5:80
Protocol=tcp
Initiated=true
```

The ProcessGuid is identical to the PowerShell creation event. Security 5156 Record `67323` independently records the same application, PID, direction, addresses, ports, and protocol.

No PCAP, proxy, or server log is present. Therefore, the TCP session is Confirmed, while exact HTTP requests and responses are Not available. A single TCP connection can carry several HTTP requests through connection reuse.

## Finding 5 - The downloaded second stage executed in memory

Windows PowerShell Event 800 Record `1364` records a new body of code after the initial stager. It is associated with:

- HostId `39315e7d-5bea-48aa-8ea8-21c983c954a8`;
- RunspaceId `2f526b39-34e5-4958-8786-a61c85685778`;
- PipelineId `1`;
- the same HostApplication and account.

The stage contains:

- `UploadData` POST operations for `/login/process.php` and `/news.php`;
- RSA negotiation;
- AES-CBC, HMAC-SHA256, and RC4 routines;
- collection of domain, user, host, IP, OS, process, and administrator-state information;
- task-URI selection, encrypted response processing, and `IEX` task execution;
- an `XC0SA` agent entry point with server, staging-key, session-key, and session-ID parameters.

Successful second-stage execution is supported by the combination of:

1. initial 4104 logic implementing `DownloadData -> decrypt -> IEX`;
2. a network connection from the exact PowerShell ProcessGuid to the decoded server;
3. new stage code logged as pipeline execution in the same PowerShell session; and
4. a later completed operating-system task through that agent loop.

This is materially stronger than observing only a download attempt. The downloaded response bytes and their hash remain Not available.

**Assessment:** Downloaded in-memory stage and agent execution are Confirmed. Exact HTTP content is Not available.

## Finding 6 - The agent performed local discovery

PowerShell 4103 Records `1962` and `1963` show PID `2316`, the same HostId/RunspaceId, and:

```text
Get-WmiObject -Class Win32_NetworkAdapterConfiguration
Get-WmiObject -Class Win32_OperatingSystem
```

WMI provider activity is present, but `WmiPrvSE.exe` PID `4864` was launched by `svchost.exe` as `NETWORK SERVICE`. It was not a direct PowerShell child. The WMI object paths reference `WORKSTATION5`, not a remote host.

**Assessment:** Local network and operating-system discovery are Confirmed. Remote WMI and lateral movement are Not observed.

## Finding 7 - The agent executed and returned a task

Three independent records close the task chain:

1. Event 800 Record `1417` shows `Invoke-Expression` receiving parameter value `whoami` in the agent RunspaceId.
2. Sysmon Event 1 Record `251944` and Security 4688 Record `67369` show PowerShell PID `2316` launching `whoami.exe` PID `9152`.
3. PowerShell 4103 Record `1999` records `theshire\pgustavo` followed by command completion.

The PowerShell parent ProcessGuid of `whoami.exe` exactly matches the stager/agent PowerShell. The C2 code and active network session make server tasking the most likely source of the command, but the packet body is unavailable and cannot be reconstructed byte-for-byte.

**Assessment:** Agent task execution and local result are Confirmed. Transport of that exact task/result through the C2 session is Inferred with high confidence.

## File and registry assessment

### Files

PowerShell created four Sysmon Event 11 objects:

- two `__PSScriptPolicyTest` files;
- the PowerShell local runtime directory;
- `ModuleAnalysisCache`.

It deleted the two policy-test files. Their shared SHA-256 is `96AD1146EB96877EAB5942AE0736B82D8B5E2039A80D3D6932665C1A4C87DCF7`. These are PowerShell runtime artefacts and are not classified as malicious payloads or evidence-clearing behaviour.

No on-disk downloaded stage was observed.

### Registry

The PowerShell ProcessGuid generated 328 Sysmon Event 12 `CreateKey` records, mainly involving certificate stores, PowerShell policy paths, Internet Settings, WinTrust, WMI, and TCP/IP configuration. No tied Sysmon Event 13 `SetValue` or Event 14 rename was found. No autorun, RunOnce, service, startup-folder, or scheduled-task persistence path matched.

Event 12 records alone do not prove that attacker-controlled persistent values were installed. Their concentration around runtime initialisation and local discovery, combined with the absence of Event 13, means they are not mapped to persistence.

## Affected scope

| Scope item | Result |
| --- | --- |
| Hosts with launcher, encoded command, server, runspace, and task evidence | 1 - `WORKSTATION5.theshire.local` |
| Accounts with matching malicious chain | 1 - `THESHIRE\pgustavo` |
| Other telemetry hosts | `WORKSTATION6.theshire.local`, `MORDORDC.theshire.local` |
| Matching malicious chain on other hosts | Not observed |

The result is limited to the supplied dataset. It is not an enterprise-wide absence claim.

## Alternative explanations

### Legitimate administrative automation

Rejected. Although encoded PowerShell can be legitimate, the combined logging impairment, AMSI impairment attempt, encrypted staged agent, Empire-compatible task protocol, and completed remote-capable task loop are incompatible with ordinary administration.

### Download attempted but failed

Rejected. New second-stage code executed in the same runspace and later completed `whoami` tasking.

### False process-chain join caused by PID reuse

Rejected. ProcessGuid/ParentProcessGuid continuity, Logon ID, account, image, and Security 4688 PID conversion independently agree.

### Remote WMI lateral movement

Rejected for the observed window. The WMI queries were local, and the provider process had the expected service parent.

### Persistence through registry activity

Not supported. Event 12 activity exists, but no persistence-specific value write, task, service, or autorun evidence was found.

## Final assessment

| Dimension | Assessment |
| --- | --- |
| Classification | **True Positive - successful malicious PowerShell / Empire-compatible agent execution** |
| Severity | **High** |
| Confidence | **High** |
| Confirmed effect | Code execution, active HTTP C2 capability, discovery, and arbitrary task execution |
| Confirmed affected scope | One host and one account in supplied telemetry |
| Escalation threshold | Met |

Severity is High because a staged agent executed and accepted a command, establishing active adversary capability on the host. Confidence is High because several independent event sources agree on all major relationships. Severity is not raised to Critical because no elevated execution, credential theft, lateral movement, persistence, destructive action, or broader host scope was confirmed.

## Evidence boundaries

| Status | Conclusion |
| --- | --- |
| **Confirmed** | VBS, encoded PowerShell, malicious stager, impairment attempts, network connection, in-memory second stage, discovery, task loop, `whoami`, and result |
| **Inferred** | Interactive user opening and C2 transport of the exact task/result |
| **Not observed** | Persistence, privilege escalation, credential access, lateral movement, on-disk payload, encryption, or destruction |
| **Not available** | VBS bytes, download bytes, packet/HTTP content, proxy/server logs, memory image, and post-window telemetry |
| **Unable to confirm** | AMSI impairment success, exact packet content, and actual Administrators-group membership |
| **Detection gap** | Only one 4104; no Defender/AMSI outcome, proxy, full DNS, PCAP, or long-term collection |

See `mitre-attack-mapping.md` for the evidence-based ATT&CK mapping.
