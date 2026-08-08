# Scenario 02: Repeated SSH Invalid-User Authentication Attempts

## Overview

This scenario investigates repeated SSH (Secure Shell) invalid-user authentication attempts against a monitored Linux endpoint.

The activity was generated in an authorized lab environment to simulate a brute-force-style authentication pattern. The purpose of this scenario is to validate endpoint log collection, Wazuh SIEM / XDR (Security Information and Event Management / Extended Detection and Response) alert generation, MITRE ATT&CK mapping, and evidence-based SOC (Security Operations Center) alert triage.

## Environment

| Component | Details |
|---|---|
| SIEM / XDR Platform | Wazuh |
| Wazuh Manager | soc-lab-wazuh-server |
| Monitored Endpoint | soc-lab-ubuntu-target-01 |
| Endpoint Operating System | Ubuntu 22.04.5 LTS |
| Agent ID | 001 |
| Agent IP | 10.126.0.3 |
| Log Source | /var/log/auth.log and journald |
| Test Username | m2test0507 |
| Scenario Type | Authorized lab simulation |

## Objective

The objective was to determine whether repeated SSH invalid-user authentication attempts could be detected, validated, and documented using multiple evidence sources.

The investigation focused on:

- confirming raw Linux authentication logs;
- validating Wazuh alert generation;
- reviewing Wazuh Dashboard event fields;
- mapping the activity to MITRE ATT&CK;
- identifying any detection engineering issues, such as duplicate log ingestion.

## Test Activity

Three controlled SSH invalid-user authentication attempts were generated from a trusted test source against the Ubuntu target endpoint.

The target server rejected the attempts because the test username did not exist. Password authentication was not enabled for the test user path, and the observed behavior was an invalid-user SSH authentication attempt rather than a successful login.

## Evidence Summary

| Evidence Source | Finding |
|---|---|
| Ubuntu Target `/var/log/auth.log` | 3 core `Invalid user m2test0507` events were recorded |
| Wazuh `alerts.log` | Wazuh generated alerts for the invalid-user SSH attempts |
| Wazuh `alerts.json` | 6 Wazuh alert records were observed |
| Wazuh Dashboard | 6 hits were displayed for `m2test0507` |
| Wazuh Event Details | Rule ID 5710, rule level 5, and MITRE ATT&CK mapping were confirmed |

## Key Wazuh Rule Details

| Field | Value |
|---|---|
| rule.id | 5710 |
| rule.level | 5 |
| rule.description | sshd: Attempt to login using a non-existent user |
| rule.groups | syslog, sshd, authentication_failed, invalid_login |
| decoder.name | sshd |
| data.srcuser | m2test0507 |
| agent.name | soc-lab-ubuntu-target-01 |
| manager.name | soc-lab-wazuh-server |

## MITRE ATT&CK Mapping

| Tactic | Technique ID | Technique |
|---|---|---|
| Credential Access | T1110.001 | Password Guessing |
| Lateral Movement | T1021.004 | SSH |

## Detection Engineering Finding

The Ubuntu Target recorded 3 core SSH invalid-user events in `/var/log/auth.log`.

Wazuh displayed 6 alert records associated with the same test activity. Review of the Wazuh record locations showed:

- 3 records from `/var/log/auth.log`
- 3 records from `journald`

Together with the endpoint count of 3 core SSH invalid-user events, this strongly indicates duplicate ingestion of the authentication activity across the two Linux log sources.

The retained sanitized evidence does not preserve sufficient per-record fields, such as the original SSH process ID and source port, to reconstruct a one-to-one pairing of all six Wazuh records.

This is an important detection engineering finding because overlapping log collection can inflate SIEM alert counts and create unnecessary SOC noise. Future tuning should review whether both log sources are required for SSH authentication monitoring..

## Assessment

**True Positive — Authorized Lab Simulation**

The activity was a true authentication failure pattern from a detection perspective. Multiple invalid-user SSH authentication attempts were observed against the monitored Ubuntu endpoint.

However, the activity was intentionally generated in an authorized lab environment. No successful login or evidence of compromise was observed.

## Severity

| Context | Severity |
|---|---|
| Lab environment | Low |
| Internet-facing production server | Medium |

In a production environment, repeated SSH invalid-user authentication attempts may indicate password guessing, brute-force activity, internet scanning, or early-stage unauthorized access attempts.

## Screenshots

| Screenshot | Description |
|---|---|
| `screenshots/01-scenario-02-dashboard-filtered-events.png` | Wazuh Dashboard filtered event list showing 6 hits for `m2test0507` |
| `screenshots/02-scenario-02-event-detail-core-fields.png` | Event details showing agent, source user, decoder, full log, and location |
| `screenshots/03-scenario-02-event-detail-rule-mitre-fields.png` | Event details showing Wazuh rule and MITRE ATT&CK mapping |

## Related Files

| File | Purpose |
|---|---|
| `triage-note.md` | SOC-style alert triage note |
| `investigation-report.md` | Detailed technical investigation report |
| `recommended-actions.md` | Recommended containment, hardening, and detection improvement actions |
| `evidence/` | Sanitized supporting evidence files |

## Key Learning Points

- Raw endpoint logs should be used to validate SIEM alerts.
- Wazuh rule `5710` detects SSH login attempts using non-existent users.
- MITRE ATT&CK mapping helps translate raw technical activity into attacker behavior.
- Dashboard alert counts may differ from raw endpoint event counts due to duplicate log ingestion.
- Detection engineering should consider both detection coverage and alert noise.