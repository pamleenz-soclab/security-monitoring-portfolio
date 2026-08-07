# Executive Incident Summary

## What happened?

A source-derived adversary-emulation investigation identified a multi-stage compromise affecting two Windows endpoints. Suspicious execution began on SCRANTON under the `pbeesly` account and progressed through hidden/in-memory PowerShell, credential-access behavior, persistence as a LocalSystem service, outbound communications, and lateral movement to NASHUA. NASHUA then showed WinRM/PsExec-style remote execution, a temporary Python payload, repeated outbound connections, archive staging, and cleanup activity.

## What was affected?

- `SCRANTON.dmevals.local` — affected/compromised.
- `NASHUA.dmevals.local` — affected/compromised.
- `DMEVALS\pbeesly` — affected/misused identity.
- `NEWYORK` and `UTICA` — observed in the dataset but not established as compromised.

## Business risk

Technical risk is high because the evidence includes persistence, SYSTEM execution, LSASS access, lateral movement, process-attributed C2-like communication, and collection/staging. The dataset does not demonstrate real business-service disruption or successful data theft, so those outcomes are not claimed.

## What should be contained first?

In a real incident:

1. Isolate SCRANTON and NASHUA while preserving evidence.
2. Disable/reset `pbeesly` and revoke sessions/tickets.
3. Stop and quarantine validated malicious services/processes after evidence capture.
4. Block validated incident communications and unauthorized east-west remote-service paths after business-impact checks.

## What remains uncertain?

Initial delivery is not available. LSASS access does not prove credential material was recovered. The reviewed PFX export explicitly failed. Collection does not prove exfiltration. Independent Zeek telemetry is not time-aligned with the host incident.

## What happens next?

Containment should be followed by credential/session validation, persistence removal, endpoint recovery, expanded hunting, and a defined monitoring window. Detection engineering should prioritize stable-ID correlations for process lineage, LSASS access, WinRM/PsExec movement, service persistence, and process-attributed C2.
