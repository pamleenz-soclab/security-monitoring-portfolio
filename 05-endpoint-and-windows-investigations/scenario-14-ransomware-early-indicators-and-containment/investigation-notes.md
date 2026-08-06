# Investigation Notes

## Method

The investigation followed an evidence-first sequence:

1. Validate source integrity and file format.
2. Parse all XML events into a normalised SQLite index.
3. Build broad candidate categories.
4. Remove keyword-only false positives.
5. Correlate by logical host, timestamp, Process GUID, Parent Process GUID, PID, account, Logon ID, IP address, and Event Record ID.
6. Separate direct evidence from inference and telemetry gaps.

## Step 1 — Identify the ransomware-related processes

### File reviewed

`verification-ransomware-processes.tsv`

### Key events

#### Builder process

- Timestamp: `2026-04-24T10:30:08.9092119Z`
- Source: Sysmon Event ID 1
- Record ID: `7765`
- Host: `EC2AMAZ-I41BETP.attackrange.local`
- Account: `NT AUTHORITY\SYSTEM`
- Logon ID: `0x3e7`
- Image: `C:\Intel\builder.exe`
- Process GUID: `{0741354c-4630-69eb-5d07-000000006702}`
- PID: `6832`
- Parent Process GUID: `{0741354c-45f2-69eb-5407-000000006702}`
- Parent image: `C:\Windows\System32\cmd.exe`

The public evidence records the command as:

> Builder invoked with an encryption-oriented build profile, public-key input, configuration input, and output path `Build\LB3.exe`.

The full command is intentionally not reproduced in the published portfolio.

#### Payload process

- Timestamp: `2026-04-24T10:32:10.1648399Z`
- Source: Sysmon Event ID 1
- Record ID: `7816`
- Host: `EC2AMAZ-I41BETP.attackrange.local`
- Account: `EC2AMAZ-I41BETP\Administrator`
- Logon ID: `0x11c15c`
- Image: `C:\Intel\Build\LB3.exe`
- Process GUID: `{0741354c-46aa-69eb-7f07-000000006702}`
- PID: `1844`
- Parent Process GUID: `{0741354c-1bf6-69eb-ee01-000000006702}`
- Parent image: `C:\Windows\explorer.exe`
- Integrity: `High`
- SHA-256: `8ADCB1AE01F295EBD4A50B6BB41F9FE05AE90FC7E655002A8C400F7F9D05A582`

Windows Security Event ID 4688, Record ID `325724`, independently confirms creation of the same payload image at the same time.

## Step 2 — Reconstruct the process relationships

### File reviewed

`verification-process-chain.tsv`

### Control path

At `10:29:06.9946114Z`, Sysmon Record ID `7756` recorded:

- Child: `C:\Windows\System32\cmd.exe`
- Child Process GUID: `{0741354c-45f2-69eb-5407-000000006702}`
- Parent: `qSwUwejx.exe`
- Parent Process GUID: `{0741354c-35c1-69eb-4e05-000000006702}`
- Account: `NT AUTHORITY\SYSTEM`

The child Process GUID is exactly the Parent Process GUID recorded in the later `builder.exe` event. This confirms:

```text
qSwUwejx.exe → cmd.exe → builder.exe
```

### Interactive execution path

At `07:29:58.4487578Z`, Explorer started under:

- Account: `EC2AMAZ-I41BETP\Administrator`
- Logon ID: `0x11c15c`
- Process GUID: `{0741354c-1bf6-69eb-ee01-000000006702}`

At `10:32:10.1648399Z`, the payload event recorded this same Explorer Process GUID as its Parent Process GUID. This confirms:

```text
explorer.exe → LB3.exe
```

The build and execution paths are related by the generated file, but they are separate process branches.

## Step 3 — Correlate network activity

### File reviewed

`verification-network.tsv`

### ActiveMQ-related activity

At `09:19:51Z–09:20:02Z`, Java process GUID `{0741354c-3142-69eb-e404-000000006702}` was associated with:

- `10.0.2.13 → 10.0.2.12:61616`
- `10.0.2.12 → 10.0.2.13:8080`

At `09:20:03.3092296Z`, temporary executable `qSwUwejx.exe` connected:

- Source: `10.0.2.12:50834`
- Destination: `10.0.2.13:4444`
- Sysmon Record ID: `7144`

This supports a sequence consistent with service exploitation and a reverse or control channel. Exact ActiveMQ exploit content cannot be confirmed because the dataset has no PCAP or application request log.

### RDP activity

At `10:30:53.7167867Z`, Sysmon Record ID `7781` recorded:

- Source: `10.0.1.10:55386`
- Destination: `10.0.2.12:3389`
- Image: `C:\Windows\System32\svchost.exe`

Security events then recorded:

- Event ID 4624, Record ID `325691`, Administrator, Logon Type 3, Source IP `10.0.1.10`
- Event ID 4648, Record ID `325702`, explicit credentials, Source IP `10.0.1.10`
- Event ID 4624, Record ID `325703`, Administrator, Logon Type 7, Source IP `10.0.1.10`

This supports a reconnect or unlock of an existing Administrator desktop session. A new Logon Type 10 event was not observed.

## Step 4 — Prove file impact

The relevant file records were selected by exact Process GUID correlation, not by filename alone.

The two ransomware-related process GUIDs produced:

- One output file: `C:\Intel\Build\LB3.exe`
- 183 files named `7duXYi3SC.README.txt`
- 184 unique paths
- 184 distinct directories in the combined builder-and-payload result set

The actual payload branch accounts for the 183 README files.

At `10:32:33.5558516Z`, Notepad opened:

`C:\Users\Administrator\Desktop\7duXYi3SC.README.txt`

This independently supports the existence and visibility of the ransom note.

### What this proves

- Recursive directory traversal or directory enumeration.
- Repeated creation of a ransom-note filename.
- Impact marker placement across a broad local directory tree.

### What this does not prove

- Existing files were encrypted.
- Existing files were renamed.
- Existing files were deleted.
- File entropy changed.
- Users could not open their files.
- A file share was affected.

## Step 5 — Review recovery inhibition and defence evasion

### Recovery inhibition

No command-bearing evidence was found for:

- `vssadmin`
- WMI shadow-copy deletion
- `wbadmin`
- `bcdedit`
- `reagentc`
- `diskshadow`
- Backup-service termination

The first-pass `Backup Operators` hits were keyword false positives.

### Defence and trace removal

The following command executions were retained:

- `net stop termservice /yes`
- `net1 stop termservice /yes`
- `wevtutil cl System`
- `wevtutil cl Application`
- `wevtutil cl Security`

The dataset confirms process creation for these commands. It does not independently confirm that the service stopped or all three logs were successfully cleared.

Ansible and Chocolatey PowerShell module source code was excluded as false-positive context. Audit policy commands that enabled Kerberos auditing were classified as benign telemetry preparation.

## Step 6 — Review credential activity

At `10:32:11Z`, immediately after payload execution, Security Event IDs 4625 recorded failed logons associated with:

- Process ID `0x734`
- Process name `C:\Intel\Build\LB3.exe`
- Logon ID `0x11c15c`

Accounts attempted:

- `attackrange.local\ad.lab`
- `attackrange.local\Administrator`
- `attackrange.local\Admin2`

All observed attempts failed. No successful authentication or remote target was established.

## Step 7 — Review exfiltration

Initial broad candidates were Ansible, Chocolatey, download helper functions, and software-installation code. No evidence established:

- Data collection.
- Staged archive creation.
- Upload command.
- External transfer of collected business data.
- Exfiltration volume.
- Exfiltration success.

The correct classification is **not observed**, rather than confirmed exfiltration.
