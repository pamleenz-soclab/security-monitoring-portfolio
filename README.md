# Security Monitoring and Incident Response Portfolio

This repository documents a hands-on security monitoring lab built to simulate core Security Operations Center (SOC) and Security Engineering workflows.

## Lab Overview

The lab is hosted in DigitalOcean and uses a Wazuh SIEM / XDR server to monitor a Linux endpoint. Scenario 01 validates the pipeline from SSH authentication activity to endpoint logging, Wazuh alerting, and SOC-style triage.

> Public version note: Real public IP addresses, credentials, and screenshots should be sanitized before publishing this repository.

## Current Lab Components

| Component | Role |
|-----------|------|
| MacBook Air | SSH administration client and controlled test source |
| Wazuh Server | SIEM / XDR server, dashboard, manager, indexer, Filebeat |
| Ubuntu Target Endpoint | Monitored Linux endpoint and authorized attack target |
| Wazuh Agent | Endpoint log collector installed on the Ubuntu Target |

## Month 1 Deliverables

| File | Purpose |
|------|---------|
| `docs/lab-architecture.md` | Documents the cloud SOC lab architecture, including Wazuh Server, Ubuntu Target, MacBook admin client, and network communication paths. |
| `docs/data-source-inventory.md` | Lists available log sources, key Wazuh fields, and monitoring coverage for SSH authentication investigation. |
| `templates/alert-triage-template.md` | Reusable SOC alert triage template for future investigations. |
| `scenarios/01-ssh-invalid-user/README.md` | Scenario 01 overview, including objective, environment, detection result, and investigation summary. |
| `scenarios/01-ssh-invalid-user/triage-note.md` | Completed SOC-style alert triage note based on the reusable alert triage template. |
| `scenarios/01-ssh-invalid-user/investigation-report.md` | Full investigation report for SSH invalid-user authentication attempts. |
| `scenarios/01-ssh-invalid-user/recommended-actions.md` | Detailed remediation and detection improvement actions with command explanations. |
| `evidence/sanitized-samples/` | Sanitized sample evidence for public portfolio use, including endpoint logs and Wazuh alert logs. |
| `screenshots/README.md` | Placeholder and guidance for storing sanitized screenshots from Wazuh Dashboard and lab validation steps. |

## Scenario 01

**Title:** SSH Invalid User Authentication Attempt Investigation

**Goal:** Generate controlled SSH invalid-user authentication attempts against a monitored Ubuntu endpoint, verify raw Linux authentication logs, confirm Wazuh alert generation, and write a SOC-style alert triage report.

**Key result:** The monitoring pipeline was validated after configuring the Wazuh Agent to collect `/var/log/auth.log`.

## Repository Structure

```text
security-monitoring-portfolio/
├── README.md
├── docs/
│   ├── lab-architecture.md
│   └── data-source-inventory.md
├── templates/
│   └── alert-triage-template.md
├── scenarios/
│   └── 01-ssh-invalid-user/
│       ├── README.md
│       ├── triage-note.md
│       ├── investigation-report.md
│       └── recommended-actions.md
├── evidence/
│   └── sanitized-samples/
│       ├── authlog-fake-admin-sanitized.txt
│       └── wazuh-alerts-fake-admin-sanitized.txt
└── screenshots/
├── 01-agent-active.png
├── 02-threat-hunting-filtered-events.png
├── 03a-event-detail-core-fields.png
└── 03b-event-detail-rule-mitre-fields.png
```

## Security and Privacy Rules

Do not publish real public IP addresses, credentials, real company logs, private dashboard screenshots, or cloud provider metadata that should remain private.

---

## Scenario 03

**Title:** Benign Authentication Failure Case

**Goal:** Simulate and investigate a single benign SSH authentication failure, then compare it against repeated invalid-user activity from Scenario 02.

**Assessment:** Benign Positive

**Key findings:**

- The Ubuntu endpoint recorded one core SSH invalid-user event.
- Wazuh generated two relevant SSH Rule 5710 alert records because the same event was collected from both `/var/log/auth.log` and `journald`.
- A broad keyword search returned extra sudo-related alerts, showing that SOC analysts should filter by `rule.id`, `rule.description`, `decoder.name`, and log source.
- The event was not a false positive because the activity really occurred and was correctly detected.
- The event was assessed as benign because it was isolated, controlled, and showed no evidence of compromise.

**Scenario files:**

| File | Description |
|---|---|
| `scenarios/03-benign-authentication-failure/README.md` | Scenario overview, objective, evidence summary, and learning outcome |
| `scenarios/03-benign-authentication-failure/triage-note.md` | SOC-style alert triage note |
| `scenarios/03-benign-authentication-failure/investigation-report.md` | Full investigation report with timeline, evidence, MITRE ATT&CK mapping, and comparison with Scenario 02 |
| `scenarios/03-benign-authentication-failure/recommended-actions.md` | Recommended actions, detection engineering notes, and production response guidance |
| `evidence/sanitized-samples/scenario-03/` | Sanitized evidence files for Scenario 03 |
| `screenshots/scenario-03/` | Sanitized Wazuh Dashboard screenshots |

**Evidence note:**

`pre-simulation-baseline.txt` is intentionally empty. It records that no matching core SSH invalid-user event existed for `m2benign0509` before the simulation.
