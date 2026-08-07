# Scenario 21 — Enterprise Compromise Investigation

**Priority:** Capstone
**Case type:** Source-Derived Enterprise Adversary-Emulation Investigation
**Primary dataset:** OTRF Detection Hackathon — APT29 ATT&CK Evaluations, Day 1
**Pinned upstream commit:** `b5989e17465753f46433e77f795f651453c01279`

This capstone demonstrates an evidence-led enterprise incident-response workflow across Windows authentication, endpoint/process, service, PowerShell, and network telemetry. It deliberately does **not** stitch unrelated Scenario 01–20 events into one fictional incident.

## Final investigation outcome

The selected lead was an unusual `.scr` executable launched from `C:\ProgramData\victim` on `SCRANTON.dmevals.local` by `DMEVALS\pbeesly`. Exact `ProcessGuid` / `ParentProcessGuid` relationships linked the lead through `cmd.exe`, `sdclt.exe`, `control.exe`, and hidden PowerShell. The same malicious PowerShell process later accessed LSASS.

The investigation established persistence through an auto-start LocalSystem service, lateral movement from SCRANTON to NASHUA through WinRM and SMB/PsExec-style remote service execution, launch of a temporary Python payload on NASHUA, repeated process-attributed network connections, and archive staging followed by SDelete cleanup.

The evidence **does not establish** the original delivery mechanism, successful credential extraction, successful certificate theft, successful exfiltration, or a destructive/business-impact outcome.

## Evidence discipline

- ATT&CK mapping does not substitute for telemetry.
- Exact stable identifiers are preferred over time proximity.
- Weak/time-only relationships are not promoted to a confirmed chain.
- `Not observed`, `Not available`, and `Unable to assess` remain distinct.
- Attempted behavior is separated from successful outcome.
- Raw evidence remains local, read-only, and Git-ignored.
- Source-associated Zeek evidence is not used as same-event corroboration because its capture window does not overlap the host incident window.

Start with `executive-summary.md`, `technical-investigation-report.md`, `master-timeline.md`, and `interview-walkthrough.md`.
