# Incident Overview

The investigation begins on SCRANTON with execution of an unusual `.scr` from a user-writable ProgramData location. Stable process identifiers link that event to `cmd.exe`, `sdclt.exe`, `control.exe`, and hidden PowerShell. The PowerShell process extracts bytes from `monkey.png`, invokes reconstructed content in memory, and later accesses LSASS using the exact same ProcessGuid.

A follow-on PowerShell process produces process-attributed outbound communications and connects to NASHUA on TCP/5985. NASHUA records a same-time Kerberos network logon and `wsmprovhost.exe` under an exact target Logon ID. Later remote sessions from source address `10.0.1.4` use ADMIN$, write `PSEXESVC.exe`, access `IPC$\svcctl`, and install the PSEXESVC service.

PSEXESVC then launches `C:\Windows\Temp\python.exe` on NASHUA. A descendant Python process generates 348 Sysmon Event 3 records to `192.168.0.4:8443`. NASHUA also shows password-protected archive staging and SDelete cleanup.

On SCRANTON, an auto-start LocalSystem service pointing to `javamtsup.exe` is installed and later executes as `NT AUTHORITY\SYSTEM`, establishing successful persistence execution and an elevated outcome.

The evidence does not establish how the initial `.scr` arrived, whether LSASS access yielded credentials, whether collected data was exfiltrated, or whether a business-impact stage occurred.
