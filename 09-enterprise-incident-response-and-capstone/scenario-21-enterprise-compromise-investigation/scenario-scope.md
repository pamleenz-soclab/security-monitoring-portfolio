# Scenario Scope

## In scope

The primary evidence boundary is OTRF APT29 ATT&CK Evaluations **Day 1**, pinned to commit:

`b5989e17465753f46433e77f795f651453c01279`

Primary incident telemetry:

- Windows Security authentication and share events.
- Sysmon process, network, and process-access telemetry.
- PowerShell Operational / Windows PowerShell telemetry.
- Windows System service-installation telemetry.
- Source-associated Zeek/PCAP network artifacts, subject to the temporal limitation below.

## Out of scope

- Day 2.
- Scenario 01–20 as incident evidence.
- Cloud identity and mailbox telemetry.
- Real business-service outcome and recovery telemetry.

Scenario 01–20 may be referenced for methodology or detection-engineering patterns only.

## Time boundary

Host telemetry spans approximately `2020-05-02T02:55:23Z` through `2020-05-02T03:28:17Z`.

The source-associated Zeek artifacts are dated April 30. They therefore cannot be claimed as direct network-sensor corroboration of the May 2 host events. Sysmon Event 3 remains valid process-attributed endpoint network telemetry for the incident.

## Time normalization

For records lacking explicit `UtcTime`, the investigation uses `EventTime + 14,400 seconds`. This offset was derived from 143,883 paired `EventTime`/`UtcTime` observations, all of which agreed on the four-hour offset. Source timestamps and uncertainty are retained in the master timeline.
