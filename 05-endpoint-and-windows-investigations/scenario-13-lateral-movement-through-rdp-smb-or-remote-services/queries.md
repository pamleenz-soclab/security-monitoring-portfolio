# Investigation and Hunting Queries

These queries document the concentrated investigation sequence. Field mappings differ across collectors; validate names before production use.

## Local OTRF JSON — dataset overview

```bash
jq -r '[.Hostname, .Channel, (.EventID|tostring)] | @tsv' \
  evidence/raw/otrf-host/empire_smbexec_dcerpc_smb_svcctl_2020-09-20025716.json \
  | sort | uniq -c | sort -nr
```

Purpose: count Event IDs by host and channel before selecting an attack window.

Important parameters:

- `jq -r` emits raw tab-separated text rather than quoted JSON.
- `@tsv` creates stable columns.
- `sort | uniq -c` groups and counts identical records.

## Local OTRF JSON — target authentication

```bash
jq -r '
  select(.Hostname=="WORKSTATION6.theshire.local" and .EventID==4624)
  | {
      EventTime, TargetDomainName, TargetUserName, LogonType,
      LogonProcessName, AuthenticationPackageName, LmPackageName,
      IpAddress, IpPort, WorkstationName, TargetLogonId
    }
' evidence/raw/otrf-host/empire_smbexec_dcerpc_smb_svcctl_2020-09-20025716.json
```

Purpose: identify who authenticated, from where, by which protocol and under which target Logon ID.

## Local OTRF JSON — follow the target Logon ID

```bash
jq -c '
  select(
    .Hostname=="WORKSTATION6.theshire.local"
    and ((.TargetLogonId // .SubjectLogonId // "") == "0x2074186")
  )
  | {
      EventTime, EventID, Channel, TargetUserName, SubjectUserName,
      IpAddress, ShareName, RelativeTargetName, ServiceName
    }
' evidence/raw/otrf-host/empire_smbexec_dcerpc_smb_svcctl_2020-09-20025716.json
```

Purpose: correlate authentication, privileges, share/named-pipe access and service creation without relying only on timestamp proximity.

The `//` operator chooses the first non-null Logon ID field because different Windows events use different field names.

## Local OTRF JSON — service registry lifecycle

```bash
jq -c '
  select(
    .Hostname=="WORKSTATION6.theshire.local"
    and (.EventID==12 or .EventID==13)
    and ((.TargetObject // "") | contains("PGUJLOAKFQFVOMHGFQPX"))
  )
  | {UtcTime, EventID, Image, TargetObject, Details}
' evidence/raw/otrf-host/empire_smbexec_dcerpc_smb_svcctl_2020-09-20025716.json
```

Purpose: verify that `services.exe` created, configured and then marked the transient service for deletion.

## Local OTRF JSON — target process chain

```bash
jq -r '
  select(
    .Hostname=="WORKSTATION6.theshire.local"
    and .EventID==1
    and .UtcTime>="2020-09-20 06:57:45.000"
    and .UtcTime<="2020-09-20 06:58:10.000"
  )
  | [
      .UtcTime, .User, .ProcessGuid, .Image,
      .ParentProcessGuid, .ParentImage, .CommandLine
    ] | @tsv
' evidence/raw/otrf-host/empire_smbexec_dcerpc_smb_svcctl_2020-09-20025716.json
```

Purpose: reconstruct `services.exe → cmd.exe → cmd.exe → powershell.exe → whoami.exe` by ProcessGuid/ParentProcessGuid.

Do not commit the raw output because it contains the full encoded command.

## Local OTRF JSON — target PowerShell network outcome

```bash
jq -r '
  select(
    .Hostname=="WORKSTATION6.theshire.local"
    and .EventID==3
    and .ProcessGuid=="{d273d0f0-fd6c-5f66-7605-000000000800}"
  )
  | [
      .UtcTime, .User, .Image, .SourceIp, .SourcePort,
      .DestinationIp, .DestinationPort
    ] | @tsv
' evidence/raw/otrf-host/empire_smbexec_dcerpc_smb_svcctl_2020-09-20025716.json
```

Purpose: prove that the service-created PowerShell process made the callback, rather than merely finding unrelated HTTP traffic.

## Wireshark display filters

```text
ip.addr == 172.18.39.5 && ip.addr == 172.18.39.6 && tcp.port == 445
```

Purpose: isolate the SMB flow between source and target.

```text
tcp.stream eq <stream-number>
```

Purpose: follow one TCP conversation after selecting a packet from the SMB flow. Replace `<stream-number>` with the value Wireshark assigns.

```text
tcp contains 73:00:76:00:63:00:63:00:74:00:6c:00
```

Purpose: locate UTF-16LE `svcctl` bytes even if dissector field names vary.

## TShark — compact SVCCTL operation sequence

```bash
tshark \
  -r evidence/raw/otrf-network/empire_smbexec_dcerpc_smb_svcctl_WORKSTATION6_2020-09-20025716.cap \
  -Y 'tcp.port == 445 && (smb2 || dcerpc)' \
  -T fields \
  -E header=y \
  -E separator=$'\t' \
  -e frame.number \
  -e frame.time_utc \
  -e ip.src \
  -e tcp.srcport \
  -e ip.dst \
  -e tcp.dstport \
  -e _ws.col.Protocol \
  -e _ws.col.Info
```

Purpose: verify the SMB Session Setup, `IPC$`, `svcctl`, `OpenSCManagerW`, `CreateServiceW`, `StartServiceW` and service deletion sequence. Review the `StartServiceW` response together with target process telemetry; a service-request timeout does not prove that the configured command failed.

## Splunk — target Logon ID correlation

```spl
index=windows (EventID=4624 OR EventID=4672 OR EventID=4697 OR EventID=5140 OR EventID=5145)
| eval CorrelationLogonId=coalesce(TargetLogonId, SubjectLogonId)
| where isnotnull(CorrelationLogonId)
| stats min(_time) as firstTime max(_time) as lastTime
    values(EventID) as EventIDs
    values(TargetUserName) as TargetUsers
    values(SubjectUserName) as SubjectUsers
    values(IpAddress) as SourceIPs
    values(ShareName) as Shares
    values(RelativeTargetName) as NamedPipes
    values(ServiceName) as Services
    by host CorrelationLogonId
| where mvfind(EventIDs, "4624")>=0
    AND mvfind(EventIDs, "5145")>=0
    AND mvfind(EventIDs, "4697")>=0
| convert ctime(firstTime) ctime(lastTime)
```

Purpose: identify target sessions that combine a logon, detailed share access and service creation.

## Microsoft Sentinel — behavioural sequence

See `detections/microsoft-sentinel/smbexec_lateral_movement_correlation.kql` for the complete correlation. The query uses target host, account and a two-minute time bin because Windows table mappings do not always preserve a common Logon ID across every event source.

