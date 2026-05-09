# Security Monitoring and Incident Response Portfolio

This repository documents a hands-on security monitoring lab designed to simulate core SOC (Security Operations Center) and Security Engineering workflows.

The current focus is Linux SSH (Secure Shell) authentication monitoring, Wazuh SIEM / XDR (Security Information and Event Management / Extended Detection and Response) alert validation, raw log validation, network evidence validation, MITRE ATT&CK mapping, SOC-style triage notes, and detection engineering observations.

Public version note: real public IP addresses, credentials, private dashboard URLs, and sensitive screenshots must be sanitized before publishing.

## Lab Overview

The lab is hosted in DigitalOcean and uses a Wazuh SIEM / XDR server to monitor a Linux endpoint.

The lab currently validates the pipeline from controlled security activity to:

- Linux endpoint logging
- Wazuh Agent collection
- Wazuh alert generation
- Wazuh Dashboard investigation
- Raw log validation
- Network packet validation
- SOC-style alert triage reporting
- Detection engineering observations

## Current Lab Components

| Component | Role |
|---|---|
| MacBook Air | SSH administration client, browser access point, and controlled test source |
| Wazuh Server | SIEM / XDR server, Wazuh Manager, Wazuh Indexer, Wazuh Dashboard, and Filebeat |
| Ubuntu Target Endpoint | Monitored Linux endpoint and authorized test target |
| Wazuh Agent | Endpoint log collector installed on the Ubuntu Target |

## Core Skills Demonstrated

| Skill Area | Evidence in This Portfolio |
|---|---|
| Alert triage | SOC-style triage notes for SSH authentication and port scanning scenarios |
| Raw log validation | `/var/log/auth.log`, `journald`, Wazuh `alerts.json`, and tcpdump summaries |
| SIEM validation | Wazuh Rule 5710 validation and Wazuh alert review |
| Network evidence validation | tcpdump-based confirmation of TCP port probing activity |
| Detection engineering | Duplicate ingestion, keyword over-collection, and port-scan detection gap analysis |
| MITRE ATT&CK mapping | T1110.001 Password Guessing, T1021.004 SSH, T1595 Active Scanning, and T1046 Network Service Discovery |
| Reporting | Investigation reports, recommended actions, and sanitized evidence |
| Evidence handling | Sanitized logs, alert records, packet summaries, and screenshots organized by scenario |

## Completed Scenarios

| Scenario | Title | Assessment | Key Learning |
|---|---|---|---|
| Scenario 01 | SSH Invalid User Authentication Attempt Investigation | True Positive — Authorized Lab Simulation | Validated the Wazuh monitoring pipeline after enabling `/var/log/auth.log` collection |
| Scenario 02 | Repeated SSH Invalid-User Authentication Attempts | True Positive — Authorized Lab Simulation | Identified repeated invalid-user behavior and duplicate alert ingestion from `/var/log/auth.log` and `journald` |
| Scenario 03 | Benign Authentication Failure Case | Benign Positive | Demonstrated that a valid alert can be benign when the activity is isolated, controlled, and explainable |
| Scenario 04 | Port Scanning Investigation and Detection Gap Analysis | Detection Gap | Confirmed TCP port probing with tcpdump and identified that the current Wazuh host-log configuration did not clearly alert on port scanning |

## Month 1 Deliverables

| File | Purpose |
|---|---|
| `docs/lab-architecture.md` | Documents the cloud SOC lab architecture, including Wazuh Server, Ubuntu Target, MacBook admin client, and network communication paths |
| `docs/data-source-inventory.md` | Lists available log sources, key Wazuh fields, and monitoring coverage for SSH authentication investigation |
| `templates/alert-triage-template.md` | Reusable SOC alert triage template for future investigations |
| `scenarios/01-ssh-invalid-user/README.md` | Scenario 01 overview, objective, environment, detection result, and investigation summary |
| `scenarios/01-ssh-invalid-user/triage-note.md` | Completed SOC-style alert triage note |
| `scenarios/01-ssh-invalid-user/investigation-report.md` | Full investigation report for SSH invalid-user authentication attempts |
| `scenarios/01-ssh-invalid-user/recommended-actions.md` | Remediation and detection improvement actions |
| `evidence/sanitized-samples/scenario-01/` | Sanitized evidence files for Scenario 01 |
| `screenshots/scenario-01/` | Sanitized Wazuh Dashboard screenshots for Scenario 01 |

## Month 2 Deliverables

| File | Purpose |
|---|---|
| `scenarios/02-ssh-repeated-failure/README.md` | Scenario 02 overview for repeated SSH invalid-user authentication attempts |
| `scenarios/02-ssh-repeated-failure/triage-note.md` | SOC-style triage note for repeated invalid-user SSH activity |
| `scenarios/02-ssh-repeated-failure/investigation-report.md` | Investigation report comparing raw endpoint event count and Wazuh alert count |
| `scenarios/02-ssh-repeated-failure/recommended-actions.md` | Recommended actions for repeated invalid-user SSH activity |
| `scenarios/03-benign-authentication-failure/README.md` | Scenario 03 overview for a benign SSH authentication failure |
| `scenarios/03-benign-authentication-failure/triage-note.md` | SOC-style triage note classifying the alert as benign positive |
| `scenarios/03-benign-authentication-failure/investigation-report.md` | Investigation report with timeline, evidence, MITRE ATT&CK mapping, and comparison with Scenario 02 |
| `scenarios/03-benign-authentication-failure/recommended-actions.md` | Recommended actions, detection engineering notes, and production response guidance |
| `scenarios/04-port-scanning-investigation/README.md` | Scenario 04 overview for controlled TCP port probing and detection gap analysis |
| `scenarios/04-port-scanning-investigation/triage-note.md` | SOC-style triage note for port scanning visibility analysis |
| `scenarios/04-port-scanning-investigation/investigation-report.md` | Investigation report correlating scanner-side output, tcpdump evidence, auth.log, and Wazuh alert review |
| `scenarios/04-port-scanning-investigation/recommended-actions.md` | Recommended actions for improving port-scan detection coverage |
| `docs/month-02-summary.md` | Month 2 summary covering authentication investigation, benign positive analysis, and port scanning detection gap |
| `evidence/sanitized-samples/scenario-02/` | Sanitized evidence files for Scenario 02 |
| `evidence/sanitized-samples/scenario-03/` | Sanitized evidence files for Scenario 03 |
| `evidence/sanitized-samples/scenario-04/` | Sanitized evidence files for Scenario 04 |
| `screenshots/scenario-02/` | Sanitized Wazuh Dashboard screenshots for Scenario 02 |
| `screenshots/scenario-03/` | Sanitized Wazuh Dashboard screenshots for Scenario 03 |

## Scenario 01

**Title:** SSH Invalid User Authentication Attempt Investigation

**Goal:** Generate a controlled SSH invalid-user authentication attempt against a monitored Ubuntu endpoint, verify raw Linux authentication logs, confirm Wazuh alert generation, and write a SOC-style alert triage report.

**Assessment:** True Positive — Authorized Lab Simulation

**Key result:** The monitoring pipeline was validated after configuring the Wazuh Agent to collect `/var/log/auth.log`.

**Main lesson:** A SIEM alert must be validated against raw endpoint logs. If the endpoint log source is not collected, the SIEM may not alert even when the raw event exists.

## Scenario 02

**Title:** Repeated SSH Invalid-User Authentication Attempts

**Goal:** Simulate repeated SSH invalid-user authentication attempts and investigate them using raw Linux logs, Wazuh alerts, Wazuh Dashboard fields, and MITRE ATT&CK mapping.

**Assessment:** True Positive — Authorized Lab Simulation

**Key findings:**

- The Ubuntu endpoint recorded three core SSH invalid-user events.
- Wazuh displayed six relevant SSH Rule 5710 alert records.
- The difference was caused by duplicate ingestion from two Linux log sources:
  - `/var/log/auth.log`
  - `journald`
- The alert count did not equal the actual endpoint event count.
- The behavior was treated as suspicious brute-force-style activity in detection context, although it was generated as an authorized lab simulation.

**Main lesson:** SOC analysts should validate SIEM alert counts against raw endpoint logs because duplicate ingestion can inflate alert volume.

## Scenario 03

**Title:** Benign Authentication Failure Case

**Goal:** Simulate and investigate a single benign SSH authentication failure, then compare it against the repeated invalid-user pattern from Scenario 02.

**Assessment:** Benign Positive

**Key findings:**

- The Ubuntu endpoint recorded one core SSH invalid-user event.
- Wazuh generated two relevant SSH Rule 5710 alert records because the same event was collected from both `/var/log/auth.log` and `journald`.
- A broad keyword search returned extra sudo-related alerts, showing that SOC analysts should filter by `rule.id`, `rule.description`, `decoder.name`, and log source.
- The event was not a false positive because the activity really occurred and was correctly detected.
- The event was assessed as benign because it was isolated, controlled, and showed no evidence of compromise.

**Evidence note:** `pre-simulation-baseline.txt` is intentionally empty. It records that no matching core SSH invalid-user event existed for `m2benign0509` before the simulation.

**Main lesson:** A technically valid alert is not automatically malicious. Context, frequency, source, successful-login evidence, and follow-on behavior are required for correct triage.

## Scenario 04

**Title:** Port Scanning Investigation and Detection Gap Analysis

**Goal:** Generate controlled TCP port probing activity, validate it using target-side tcpdump evidence, and determine whether the current Wazuh configuration produces a clear port-scan alert.

**Assessment:** Detection Gap

**Key findings:**

- The MacBook used `nc` / Netcat to perform controlled TCP port probing against the Ubuntu Target.
- Scanner-side output showed that `22/tcp` was reachable, while most other tested ports were refused or timed out.
- Target-side tcpdump evidence confirmed TCP SYN packets from the same source IP to multiple destination ports.
- `/var/log/auth.log` only recorded an SSH connection closure for the `22/tcp` probe.
- Wazuh did not generate a clear port-scan alert during the scan time window.
- The current host-log-focused monitoring configuration is effective for SSH authentication investigation but insufficient for reliable network-layer port-scan detection.

**Evidence note:** `wazuh-alerts-scan-window-sourceip-sanitized.json` and `wazuh-portscan-keyword-check-sanitized.txt` are intentionally empty. They document that no clear Wazuh port-scan alert or keyword match was observed.

**Main lesson:** No alert does not mean no activity. Network-layer activity may require network telemetry such as firewall logs, Zeek, Suricata, Security Onion, or cloud flow logs.

## Scenario Comparison

| Item | Scenario 01 | Scenario 02 | Scenario 03 | Scenario 04 |
|---|---|---|---|---|
| Activity type | Single invalid-user SSH attempt | Repeated invalid-user SSH attempts | Single benign invalid-user SSH attempt | Controlled TCP port probing |
| Main tool | SSH client | SSH client | SSH client | `nc` / Netcat and tcpdump |
| Primary evidence | `/var/log/auth.log`, Wazuh Rule 5710 | `/var/log/auth.log`, Wazuh Rule 5710 | `/var/log/auth.log`, Wazuh Rule 5710 | tcpdump, `nc`, auth.log, Wazuh alert review |
| Main Wazuh rule | 5710 | 5710 | 5710 | No clear port-scan alert |
| Duplicate ingestion finding | Not primary focus | Yes | Yes | Not primary focus |
| Final assessment | True Positive — Authorized Lab Simulation | True Positive — Authorized Lab Simulation | Benign Positive | Detection Gap |
| Main learning point | Enable and validate log collection | Alert count may be inflated | Valid alert can still be benign | No alert does not mean no activity |

## Repository Structure

    security-monitoring-portfolio/
    ├── README.md
    ├── docs/
    │   ├── lab-architecture.md
    │   └── data-source-inventory.md
    ├── templates/
    │   └── alert-triage-template.md
    ├── scenarios/
    │   ├── 01-ssh-invalid-user/
    │   ├── 02-ssh-repeated-failure/
    │   ├── 03-benign-authentication-failure/
    │   └── 04-port-scanning-investigation/
    ├── evidence/
    │   └── sanitized-samples/
    │       ├── scenario-01/
    │       ├── scenario-02/
    │       ├── scenario-03/
    │       └── scenario-04/
    └── screenshots/
        ├── scenario-01/
        ├── scenario-02/
        └── scenario-03/

## Security and Privacy Rules

Do not publish:

- Real public IP addresses
- Credentials
- Private dashboard URLs
- Real company logs
- Real user data
- Unsanitized screenshots
- Cloud provider metadata that should remain private
- Raw PCAP files containing unsanitized traffic metadata

All public evidence must use placeholders such as:

    [SOURCE_IP_REDACTED]
    [TARGET_PUBLIC_IP_REDACTED]
    [WAZUH_SERVER_PUBLIC_IP_REDACTED]

## Portfolio Direction

This repository is part of a 12-month plan to build a cybersecurity portfolio approximating enterprise SOC and Security Engineering workflows.

The current phase focuses on authentication monitoring, alert validation, raw log correlation, network evidence validation, SOC-style reporting, and detection engineering observations.
