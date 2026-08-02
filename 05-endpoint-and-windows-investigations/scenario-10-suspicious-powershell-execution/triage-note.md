# Triage Note

## Alert summary

| Field | Value |
| --- | --- |
| Scenario | Suspicious PowerShell Execution Investigation |
| Initial signal | WScript-launched PowerShell with hidden window and encoded command |
| Host | `WORKSTATION5.theshire.local` |
| User | `THESHIRE\pgustavo` |
| PowerShell PID | `2316` (`0x90c`) |
| PowerShell ProcessGuid | `{860ba2e3-9f13-5f52-2703-000000000400}` |
| Logon ID | `0x2D5A4B` |
| First malicious-chain event | `2020-09-04T20:09:55.035Z` |
| Initial triage severity | High |
| Final triage disposition | True Positive - escalate for incident response |

## Triage question

Does the encoded PowerShell represent legitimate administration, suspicious but unconfirmed activity, or successful malicious execution?

## Initial hypotheses

| Hypothesis | Evidence required | Triage result |
| --- | --- | --- |
| H1 - authorised script or administrative automation | Approved change context, expected parent, readable command, known destination, and benign follow-on activity | Rejected by observed behaviour; business authorisation data was not available, but the decoded code and completed agent task are incompatible with routine administration |
| H2 - suspicious launcher that failed before payload execution | Encoded launch with no successful network/stage/task evidence | Rejected; network, second-stage code, and `whoami` completion were confirmed |
| H3 - successful malicious PowerShell agent execution | Coherent process chain, malicious script behaviour, process-attributed network activity, second-stage execution, and task result | Supported |

## Triage evidence

1. Sysmon Event 1 Record `251079` and Security 4688 Record `66940` show `explorer.exe -> wscript.exe` running `launcher.vbs`.
2. Sysmon Event 1 Record `251258` and Security 4688 Record `66981` show `wscript.exe -> powershell.exe` with `-noP -sta -w 1 -enc`.
3. PowerShell 4104 Record `1948` shows attempted logging and AMSI impairment, a decoded HTTP server, `/news.php`, `DownloadData`, decryption, and `IEX`.
4. Sysmon Event 3 Record `251809` and Security 5156 Record `67323` independently show outbound TCP to `10.10.10.5:80` from PowerShell PID `2316`.
5. Windows PowerShell Event 800 Record `1364` shows second-stage negotiation and agent code in the same HostId and RunspaceId.
6. Windows PowerShell Event 800 Record `1417`, Sysmon Event 1 Record `251944`, and PowerShell 4103 Record `1999` show `whoami` execution and the result `theshire\pgustavo`.

Minimal filtered source excerpts are retained in `evidence/processed/key-log-extracts.md`.

## Correlation check

The principal chain uses:

- host `WORKSTATION5.theshire.local`;
- account `THESHIRE\pgustavo` and consistent SID;
- logon session `0x2D5A4B`;
- decimal/hex PID equivalence: `2440=0x988`, `2316=0x90c`, and `9152=0x23c0`;
- Sysmon ProcessGuid/ParentProcessGuid continuity;
- PowerShell HostId `39315e7d-5bea-48aa-8ea8-21c983c954a8`;
- PowerShell RunspaceId `2f526b39-34e5-4958-8786-a61c85685778`.

Time proximity was used only to bound the search, not as the sole joining condition.

## Scope at triage

- Matching affected hosts: **1**
- Matching affected accounts: **1**
- Other hosts in dataset: `WORKSTATION6.theshire.local`, `MORDORDC.theshire.local`
- Matching malicious chain on other hosts: **Not observed**

## Immediate disposition

**Escalate as a High-severity True Positive.** In a live environment, isolate the host, preserve volatile evidence, block the destination with appropriate scoping, disable or protect the affected account, and start enterprise-wide hunting for the launcher path, encoded command pattern, ProcessGuid-independent command features, destination, URIs, and related account activity.

## Triage boundaries

- **Confirmed:** successful second-stage and task execution.
- **Not observed:** persistence, privilege escalation, credential access, lateral movement, or destructive impact.
- **Not available:** original VBS, HTTP content, EDR action, memory image, and post-window events.
- **Unable to confirm:** exact C2 bytes and whether AMSI impairment succeeded.
