# Triage Note

## Alert context

A simulated enterprise dataset showed a Windows host executing a binary named `LB3.exe`, creating repeated README files, attempting authentication, and showing earlier remote-service and command-execution activity.

## Initial triage question

Determine whether the evidence supports:

1. Ransomware preparation only.
2. Recovery inhibition or defence evasion.
3. Confirmed file encryption.
4. Remote access or lateral movement.
5. Data collection or exfiltration.
6. Immediate containment.

## Initial severity

**Critical — confirmed ransomware payload execution with active file-impact markers**

Severity is based on payload execution and recursive ransom-note creation, not on an unsupported claim of successful encryption.

## Initial scope

- Primary host: `EC2AMAZ-I41BETP` / `10.0.2.12`
- Administrative account: `EC2AMAZ-I41BETP\Administrator`
- System context: `NT AUTHORITY\SYSTEM`
- Remote-management source requiring investigation: `10.0.1.10`
- Service-side peer requiring investigation: `10.0.2.13`

## Immediate high-signal observations

- Temporary executable connected to `10.0.2.13:4444`.
- The same process GUID later spawned `cmd.exe` as `SYSTEM`.
- `builder.exe` produced `C:\Intel\Build\LB3.exe`.
- `explorer.exe` launched `LB3.exe` in a high-integrity Administrator session.
- The payload created 183 identically named ransom-note files in 183 directories.
- The payload process ID was associated with seven failed logons.
- `wevtutil` commands targeted the System, Application, and Security logs.
- No command-bearing VSS or backup-destruction evidence was found.

## Triage decision

1. Isolate the affected host.
2. Capture rapid volatile evidence.
3. Terminate the payload.
4. Restrict administrative credentials and sessions.
5. Investigate the two adjacent private IP addresses.
6. Validate file content before declaring successful encryption.
