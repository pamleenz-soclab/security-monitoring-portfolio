# Interview Walkthrough

## 2-minute overview

I investigated a source-derived APT29 adversary-emulation dataset as an enterprise compromise case. I started from an unusual `.scr` execution on SCRANTON and used exact ProcessGuid lineage to reconstruct execution into hidden PowerShell. The same PowerShell accessed LSASS. A child PowerShell then initiated WinRM traffic toward NASHUA, where target authentication and `wsmprovhost` were linked through an exact Logon ID. A later SMB/PsExec sequence used network logons, ADMIN$, PSEXESVC, svcctl, and service execution. PSEXESVC launched a Python payload that made hundreds of process-attributed connections. I also confirmed persistence on SCRANTON through an auto-start LocalSystem service that later ran as SYSTEM, plus collection staging and cleanup on NASHUA. I refused to claim Initial Access, successful credential extraction, exfiltration, or business impact because the evidence did not prove those outcomes.

## 5-minute walkthrough

1. Start with `HOSTJSON:373`, the ProgramData `.scr`.
2. Show exact `.scr -> cmd -> sdclt -> control -> PowerShell` lineage.
3. Pivot from that PowerShell's exact SourceProcessGuid to LSASS Event 10.
4. Show child PowerShell network activity to NASHUA:5985.
5. Show target-side Kerberos logon + `wsmprovhost` under exact Logon ID.
6. Show the stronger PsExec sequence: source-IP network logon, ADMIN$ PSEXESVC write, IPC$ svcctl, 7045, PSEXESVC process, Python child.
7. Finish with exact Python ProcessGuid driving 348 connections, RAR staging/SDelete, and the SCRANTON persistence service later executing as SYSTEM.
8. Explain the boundaries: PFX export failed, two LSASS candidates were benign, `Temp\python.exe` 5145 was ReadAttributes only, Zeek did not overlap the host timeline, and no exfiltration/impact outcome exists.

## 10-minute technical walkthrough

Use the same sequence but explicitly state the correlation strength at each pivot:

- exact ProcessGuid / ParentProcessGuid = Strong,
- exact same-host Logon ID = Strong,
- source-to-target WinRM bridge = Moderate,
- service path/name + later SYSTEM execution = strong contextual correlation.

Explain timestamp normalization from 143,883 paired records. Distinguish process-attributed Sysmon Event 3 from the independent but temporally non-overlapping Zeek package. End with containment and the P1 detection-engineering backlog.

## Common interview questions

**Why did you believe these events were related?**
Because the strongest links used stable identifiers. Where no stable identifier crossed hosts, I downgraded the relationship.

**What evidence was strongest?**
The initial process lineage, the malicious PowerShell SourceProcessGuid accessing LSASS, NASHUA Logon IDs, PSEXESVC parent/child execution, and Python ProcessGuid-to-network correlation.

**What did you refuse to conclude?**
Initial delivery, successful credential extraction, certificate theft, successful exfiltration, and business impact.

**How did you determine scope?**
I required incident-correlated malicious activity on the entity. SCRANTON and NASHUA met that threshold; NEWYORK and UTICA did not.

**What was the most important telemetry gap?**
Initial-delivery telemetry, followed by the host/Zeek temporal-alignment gap.

**What would you contain first?**
Isolate SCRANTON/NASHUA and revoke `pbeesly`, while preserving evidence.

**How would you know containment worked?**
No recurrence of malicious services/processes/sessions/network activity, old credentials unusable, intended controls enforced, and legitimate operations restored.

**Which detection would you improve first?**
The cross-host WinRM/PsExec sequence because it detects propagation and combines source process-network evidence with strong target-side session identifiers.

**What would you do differently in a real SOC?**
Add CMDB/asset criticality, IdP/session telemetry, proxy/NDR/DLP evidence, EDR response/memory data, and service-owner validation before containment.
