# Master Timeline

The authoritative structured timeline is:

`evidence/processed/master-timeline.csv`

Key phases:

- **02:55:56Z — SCRANTON:** unusual ProgramData `.scr` executes under `pbeesly`.
- **02:57–02:58Z:** exact process lineage reaches hidden/steganographic PowerShell.
- **02:58–03:05Z:** process-attributed communications, SDelete cleanup, LocalSystem service creation, failed PFX export, and incident-correlated LSASS access.
- **03:09Z:** SCRANTON PowerShell connects to NASHUA WinRM; NASHUA records same-time Kerberos logon and `wsmprovhost`.
- **03:10–03:15Z:** additional network logons, ADMIN$/PSEXESVC write, svcctl, PSEXESVC execution, and Python payload launch.
- **03:15–03:17Z:** exact Python ProcessGuid generates 348 connections to `192.168.0.4:8443`; RAR staging and SDelete cleanup follow.
- **03:19Z — SCRANTON:** the earlier auto-start service executes as SYSTEM.
- **03:21Z:** hostui / registry-IEX / encoded PowerShell lineage executes and is followed by communication to `192.168.0.4:443`.

The timeline retains timestamp basis and uncertainty rather than pretending all sources had identical clock semantics.
