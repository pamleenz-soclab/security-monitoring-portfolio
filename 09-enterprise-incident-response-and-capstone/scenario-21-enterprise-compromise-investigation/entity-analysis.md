# Entity Analysis

## Identity

`DMEVALS\pbeesly` is the only identity promoted into affected scope. It appears in the malicious execution lineage on SCRANTON and in remote-access/payload activity on NASHUA. Telemetry proves misuse across hosts; it does not prove how the credential was obtained.

## Hosts

**SCRANTON** is the initial affected endpoint and source of lateral movement. It contains the selected lead, hidden PowerShell, LSASS access, persistence, SYSTEM execution, and incident-related network communication.

**NASHUA** is the correlated lateral-movement target. It records WinRM/wsmprovhost, SMB/PsExec activity, Python payload execution, repeated process-attributed communications, archive staging, and SDelete cleanup.

**NEWYORK** and **UTICA** remain observed-only. Presence in the dataset is not enough to label either compromised.

## Network and services

`192.168.0.4` and `192.168.0.5` are high-confidence incident observables inside the lab. Because they are RFC1918 addresses, they are not portable public malicious-IP intelligence.

The Java-named LocalSystem service is a persistence mechanism. PSEXESVC is a remote-execution mechanism; because PsExec is dual-use, context is essential.
