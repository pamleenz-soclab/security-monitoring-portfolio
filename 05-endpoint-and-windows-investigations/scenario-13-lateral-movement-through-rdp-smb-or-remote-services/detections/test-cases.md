# Detection Test Cases

## Positive case — OTRF Empire Invoke SMBExec

Expected base detections:

- Event 5145: `ShareName=\\*\IPC$`, `RelativeTargetName=svcctl`.
- Event 7045: ImagePath contains `%COMSPEC%`, PowerShell and `-enc`.
- Sysmon 1: `services.exe` spawns `cmd.exe` with nested PowerShell command.

Expected correlation:

- 4624, 5145 and 4697 occur on `WORKSTATION6` under Logon ID `0x2074186` within two seconds.
- Severity becomes High because the service command contains encoded PowerShell.

## Negative and tuning cases

1. Start an existing Windows service locally. Expect no service-install or lateral correlation.
2. From an approved deployment server, install a service whose ImagePath is a signed executable. The `svcctl` lead may fire, but the encoded-shell service rule should not.
3. Create a local test service using `cmd /c powershell -enc` with no remote logon or `svcctl`. Expect behavioural service/process detections but no lateral-movement correlation.
4. Run an authorised remote administrative service action from a normal workstation. Expect review/tuning unless the source, account and target are explicitly approved.
5. Replay the OTRF data after removing 4697. Expect lower-confidence `svcctl` and process alerts, not the complete authentication-to-service correlation.

All simulations must be authorised, isolated and documented.

