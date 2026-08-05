# Investigation Report — SMB Remote Service Lateral Movement

## 1. Investigation question

Did an account on one Windows endpoint use SMB or another remote service to move laterally and execute code on a second endpoint? Which source, target, account, authentication session, remote mechanism and target process chain are supported by the evidence?

## 2. Initial hypothesis

The first coherent cluster contained a Type 3 NTLM logon on `WORKSTATION6`, `IPC$\svcctl` access and an unexpected service command invoking encoded PowerShell. The initial hypothesis was:

> `WORKSTATION5` used `THESHIRE\pgustavo` over SMB to reach the Service Control Manager on `WORKSTATION6`, create a temporary service and execute a PowerShell payload.

Successful execution, privilege context and scope still required independent validation.

## 3. Investigation logic

### 3.1 Establish the network endpoints

Sysmon Event 3 records `172.18.39.5:50504 → 172.18.39.6:445` on both endpoints. The source-side event attributes the connection to PowerShell ProcessGuid `{b34bc01c-f6f9-5f66-b410-000000000400}` running as `THESHIRE\pgustavo`.

Both endpoint PCAPs independently contain the same flow. The SYN direction proves that `WORKSTATION5` initiated the connection to `WORKSTATION6`.

### 3.2 Establish the authentication session

On `WORKSTATION6`, Security Event 4624 records:

- Target account: `THESHIRE\pgustavo`
- Logon Type: `3` (network)
- Logon process: `NtLmSsp`
- Authentication package: `NTLM`
- LM package: `NTLM V2`
- Source: `WORKSTATION5`, `172.18.39.5:50504`
- Target Logon ID: `0x2074186`

On `MORDORDC`, Event 4776 records successful credential validation for `pgustavo` from `WORKSTATION5` with status `0x0`. Event 4672 on the target assigns sensitive privileges to the same Logon ID.

PCAP frame 10 independently records `NTLMSSP_AUTH` for `theshire\pgustavo`, followed by a successful SMB Session Setup response.

### 3.3 Link the session to remote Service Control Manager access

Security Event 5140 records access to `\\*\IPC$`; Event 5145 records relative target `svcctl`. Both events use account `pgustavo`, source `172.18.39.5:50504` and Subject Logon ID `0x2074186`.

The PCAP sequence independently shows:

1. Tree Connect to `\\WORKSTATION6.theshire.local\IPC$`;
2. creation/opening of named pipe `svcctl`;
3. DCE/RPC bind to SVCCTL;
4. `OpenSCManagerW`.

This excludes ordinary document-share access and identifies the remote mechanism as SMB2 plus Service Control Manager RPC.

### 3.4 Link the session to service creation

Security Event 4697 uses Subject Logon ID `0x2074186` and records service `PGUJLOAKFQFVOMHGFQPX`. System Event 7045 independently records the same service. Its command expands `%COMSPEC%` into nested command shells and encoded PowerShell.

Sysmon Events 12 and 13 show `services.exe` creating and populating:

```text
HKLM\System\CurrentControlSet\Services\PGUJLOAKFQFVOMHGFQPX
```

The registry and service events support a temporary demand-start service. The same service name and command are visible in the reassembled `CreateServiceW` request in both endpoint PCAPs.

### 3.5 Resolve the service-start timeout

The PCAP records a `StartServiceW` request followed by `WERR_SERVICE_REQUEST_TIMEOUT`. This response does not establish execution failure. The configured command launches shells rather than a conventional service binary that reports normal service status.

Within the same second, target process telemetry records the expected service-child chain. The defensible conclusion is:

> The Service Control Manager reported a start timeout, but the configured service command executed successfully.

### 3.6 Prove execution and privilege context

Sysmon Event 1 reconstructs:

```text
services.exe
  -> cmd.exe /C ...
     -> cmd.exe /C start /b ...
        -> powershell.exe -noP -sta -w 1 -enc <redacted>
```

The target processes run as `NT AUTHORITY\SYSTEM` with Logon ID `0x3e7`. Security Event 4688 provides parallel process-audit evidence. The execution identity is therefore confirmed from process telemetry rather than inferred only from the service configuration.

### 3.7 Validate the payload outcome

PowerShell Event 4104 exposes the decoded stage-one behaviour. It:

- attempts to disable Script Block Logging;
- sets the in-memory AMSI initialization-failed flag;
- creates a `System.Net.WebClient`;
- retrieves data from `http://10.10.10.5/login/process.php`;
- decrypts stage data with an RC4-style routine;
- invokes the result in memory with `IEX`.

The same target PowerShell ProcessGuid `{d273d0f0-fd6c-5f66-7605-000000000800}` connects to `10.10.10.5:80`. Target PCAP confirms bidirectional HTTP traffic. At `06:58:05.469Z`, that PowerShell process spawns `whoami.exe` as SYSTEM, demonstrating active target control.

`10.10.10.5` is a private lab address. The attribution of that endpoint as an Empire listener comes from the controlled simulation context; the network connection itself is directly observed.

## 4. Confirmed sequence

1. Source-side PowerShell on `WORKSTATION5` initiates TCP/445 to `WORKSTATION6`.
2. `THESHIRE\pgustavo` authenticates with NTLMv2 using Logon Type 3; `MORDORDC` validates the credential.
3. The target session receives special privileges under Logon ID `0x2074186`.
4. The same session accesses `IPC$` and `svcctl`.
5. SVCCTL performs `OpenSCManagerW`, `CreateServiceW` and `StartServiceW` for `PGUJLOAKFQFVOMHGFQPX`.
6. Although SVCCTL returns a start timeout, `services.exe` launches nested `cmd.exe` processes and encoded PowerShell as SYSTEM.
7. The script attempts logging/AMSI impairment and performs staged HTTP retrieval and in-memory execution.
8. The target PowerShell connects to the private lab listener at `10.10.10.5:80`.
9. The same PowerShell process starts `whoami.exe` as SYSTEM.
10. The temporary service is deleted shortly after use.

## 5. Verdict and scope

**True Positive — successful SMB remote-service lateral movement and remote execution.**

- Source: `WORKSTATION5` / `172.18.39.5`.
- Account: `THESHIRE\pgustavo`.
- Target: `WORKSTATION6` / `172.18.39.6`.
- Remote mechanism: SMB2, `IPC$`, `svcctl`, DCE/RPC SVCCTL.
- Target execution: encoded PowerShell as `NT AUTHORITY\SYSTEM`.
- Confirmed internal movement scope: `WORKSTATION5 → WORKSTATION6`.
- `MORDORDC` performed credential validation; compromise is not observed.
- The source host contains source-side attack activity and should be treated as compromised, but its initial-compromise path is outside the supplied capture.
- Authorization status is **Not available** because no change, deployment or administrator-approval records are included.

## 6. Pass-the-hash assessment

The source-side simulation command and dataset ground truth show that `Invoke-SMBExec` was supplied an NTLM hash. Pass-the-hash is therefore confirmed for the controlled simulation, not independently by the target and network telemetry.

A production analyst with only the target and network records should report successful NTLM authentication and suspected credential-material abuse, while marking the exact credential representation as **Unable to confirm**.

## 7. Competing explanations

- **Ordinary file-share access:** excluded by `IPC$`, `svcctl`, SVCCTL binding and remote SCM operations.
- **Local-only administrator activity:** excluded by the remote source tuple and target Type 3 session.
- **Authorized remote administration or deployment:** authorization records are not available. However, the random temporary service, encoded hidden PowerShell, AMSI/logging impairment, staged HTTP activity and SYSTEM `whoami.exe` make a benign explanation implausible in this controlled dataset.
- **WMI lateral movement:** `WmiPrvSE.exe` appears in the window, but its process and network identifiers do not join the confirmed SMB service chain. WMI remote execution is **Unable to confirm**.
- **Durable service persistence:** the service is transient and deleted after execution. Durable persistence is **Not observed**.

## 8. Evidence-status summary

| Status | Findings |
|---|---|
| Confirmed | Source, target, account, NTLM Type 3 logon, `IPC$`, `svcctl`, SCM RPC, service creation, SYSTEM process chain, HTTP activity, `whoami.exe` |
| Inferred | Source host was under attacker control before the lateral action; supported by source-side attack activity and simulation context |
| Not observed | RDP, WinRM, durable service persistence, movement to a third internal target, compromise of `MORDORDC` |
| Not available | Change ticket, software-deployment record, administrator approval, asset-owner validation |
| Unable to confirm from target/network telemetry | Whether plaintext or hash material was supplied; WMI remote execution |
| Detection gap | Environments without 5145, 4697, process command lines, PowerShell 4104 or east-west packet/EDR network telemetry would lose major correlation points |

## 9. Limitations

- Source PowerShell process creation is outside the collection window.
- Some Windows events have one-second resolution, and endpoint/collector times differ by up to about two seconds.
- The portable PCAP parser records flows and byte markers; full RPC operation details require Wireshark/TShark dissection.
- Controlled simulation ground truth must remain separate from what endpoint and network telemetry independently prove.
