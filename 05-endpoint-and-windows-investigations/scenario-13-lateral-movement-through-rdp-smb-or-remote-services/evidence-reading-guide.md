# Evidence Reading Guide

This guide follows the shortest defensible path from an initial SMB clue to a confirmed SYSTEM-level compromise.

## Step 1 — identify source and target

Open `evidence/processed/network-flow-summary.csv` and find:

```text
172.18.39.5:50504 -> 172.18.39.6:445
```

This establishes the direction of the candidate lateral connection. It does not yet identify the account or prove execution.

## Step 2 — identify the account and session

Open `authentication-remote-service-evidence.csv` and read the 4624 row:

- user: `pgustavo`;
- target: `WORKSTATION6`;
- source: `172.18.39.5` / `WORKSTATION5`;
- Logon Type: 3;
- authentication: NTLMv2;
- Logon ID: `0x2074186`.

The Logon ID is more important than timestamp alone because it identifies the Windows logon session.

## Step 3 — follow the Logon ID

In the same file, confirm that `0x2074186` appears with:

- 4672 — special privileges;
- 5140 — `IPC$` share access;
- 5145 — `svcctl` named-pipe access;
- 4697 — installation of `PGUJLOAKFQFVOMHGFQPX`.

The parameter relationship is:

```text
account + source IP/port + target Logon ID
    -> share/named pipe
    -> service creator
```

## Step 4 — verify that the service is the same object everywhere

Use service name `PGUJLOAKFQFVOMHGFQPX` across:

- Security 4697;
- System 7045;
- Sysmon 12/13 service registry events;
- both PCAPs in `pcap-marker-evidence.csv`.

This rules out an unrelated service event that happened near the same time.

## Step 5 — prove execution

Open `remote-process-chain.csv` and follow ProcessGuid/ParentProcessGuid:

```text
services.exe
  -> cmd.exe {d273d0f0-fd6b-5f66-7305-000000000800}
  -> cmd.exe {d273d0f0-fd6b-5f66-7405-000000000800}
  -> powershell.exe {d273d0f0-fd6c-5f66-7605-000000000800}
  -> whoami.exe
```

All target processes run as `NT AUTHORITY\SYSTEM`. The PowerShell ProcessGuid is then reused to locate its outbound network event.

## Step 6 — prove successful payload activity

Read `decoded-stager-findings.md`, then locate the `10.10.10.5:80` flow in `network-flow-summary.csv`.

The relationship is:

```text
service ImagePath
    -> target PowerShell ProcessGuid
    -> PowerShell 4104 behaviour
    -> outbound HTTP connection
    -> whoami child process
```

This proves more than attempted service creation: the configured command ran, established bidirectional HTTP activity and produced a post-exploitation `whoami.exe` child process.

## Step 7 — state what is not proven

- The domain controller authenticated `pgustavo`; it was not shown compromised.
- No additional target after `WORKSTATION6` appears in the capture.
- Target telemetry alone does not prove hash-versus-password use.
- The service is transient execution, not proven durable persistence.
- Authorization records are not included, so authorization status is Not available.
- The exact credential representation is Unable to confirm from target/network telemetry; pass-the-hash is supported by simulation ground truth.

