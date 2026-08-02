# Recommended Actions

These actions describe an appropriate live-enterprise response. No containment action was performed against the controlled training dataset.

## Priority 1 - Immediate containment and preservation

1. **Isolate the affected endpoint through EDR or network controls.** Preserve management access and avoid shutting the host down until volatile evidence decisions are made.
2. **Capture volatile evidence.** Acquire memory, active network connections, process details, loaded PowerShell assemblies/runspaces, and EDR process telemetry before terminating the process.
3. **Preserve logs and disk evidence.** Export original EVTX for Security, Sysmon, PowerShell Operational, Windows PowerShell, WMI Activity, Defender Operational, and Task Scheduler; collect the VBS and relevant user-profile artefacts.
4. **Protect the affected account.** Disable or restrict `THESHIRE\pgustavo` if operationally safe, revoke active sessions/tokens, reset credentials, and review MFA and identity sign-in activity.
5. **Block confirmed infrastructure with context.** Block `10.10.10.5:80` and the observed URI pattern in the affected environment if it is not authorised. This is an RFC1918 lab address and must not be treated as a universal public IOC.

## Priority 2 - Scope the incident

Hunt across the longest available retention period for:

- `wscript.exe` or `cscript.exe` launching PowerShell;
- PowerShell with combinations of `-enc`, `-nop`, hidden window, and unusual parentage;
- the decoded stager's ScriptBlockId or analyst-derived ScriptBlockText hash;
- `DownloadData`, `UploadData`, `/news.php`, and `/login/process.php` in PowerShell or proxy telemetry;
- attempts to access PowerShell cached policy settings or `AmsiUtils.amsiInitFailed` through reflection;
- endpoint connections to `10.10.10.5:80` or equivalent infrastructure from unexpected processes;
- PowerShell launching discovery utilities after network contact;
- the affected account on other hosts, including remote logon and token use;
- scheduled tasks, services, WMI subscriptions, Run/RunOnce values, startup folders, PowerShell profiles, and new local users after the observed window;
- credential access, LSASS access, browser credential stores, and directory-service discovery;
- lateral movement through WinRM, SMB, WMI, RDP, remote services, or PowerShell remoting.

Do not limit hunting to PIDs or ProcessGuids from this host; those identifiers are incident-specific.

## Priority 3 - Eradication and recovery

1. Remove and preserve `launcher.vbs` and any related files only after evidence acquisition.
2. Terminate the malicious PowerShell and associated processes after volatile capture.
3. Remove any persistence discovered during extended scoping.
4. Reimage the endpoint from a trusted baseline when arbitrary agent execution is confirmed and complete integrity cannot be established.
5. Rotate credentials and secrets accessible to the affected user and host according to exposure analysis.
6. Restore business access only after EDR health, logging configuration, endpoint hardening, and network controls are verified.
7. Monitor the host and account for recurrence after recovery.

## Priority 4 - Detection and prevention improvements

- Enable PowerShell Script Block Logging and Module Logging with protected central forwarding.
- Collect Security 4688 with command-line auditing, Sysmon process/network/file/DNS/registry events, and Defender Operational/AMSI detections.
- Alert on script-host-to-PowerShell parent/child sequences and encoded hidden PowerShell with uncommon parents.
- Correlate PowerShell ProcessGuid with subsequent network connections and discovery children.
- Baseline approved automation, code-sign administrative scripts, and use constrained administration controls where practical.
- Apply attack-surface-reduction and application-control policies to restrict risky script-host and PowerShell behaviour, testing against business workflows first.
- Ensure proxy and DNS telemetry retain process/user/host attribution where the platform supports it.
- Detect unexpected changes or attempted in-memory manipulation of logging and AMSI components.
- Maintain sufficient retention to investigate activity before and after short alert windows.

Detailed analytics and tuning guidance are in `detection-opportunities.md`.

## Validation before closure

Close the incident only after confirming:

- no active agent session or associated process remains;
- the original launcher and delivery path are understood;
- no persistence or additional payload is present;
- the account has been secured and its activity scoped;
- no second affected host or user exists in retained telemetry;
- required credentials and tokens have been rotated;
- endpoint and central PowerShell logging are functioning;
- recovery controls and detections have been tested.
