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
    └── README.md
```

## Security and Privacy Rules

Do not publish real public IP addresses, credentials, real company logs, private dashboard screenshots, or cloud provider metadata that should remain private.
