# Month 2 - SOC Alert Triage and Detection Validation

This folder contains SOC-style alert triage scenarios based on SSH authentication monitoring, benign-positive analysis, and port-scanning visibility validation.

## Scenarios

| Scenario | Title | Assessment | Focus |
|---|---|---|---|
| Scenario 02 | Repeated SSH Invalid-User Authentication Attempts | True Positive - Authorized Lab Simulation | Repeated authentication failure analysis and duplicate Wazuh ingestion validation |
| Scenario 03 | Benign Authentication Failure Case | Benign Positive | Distinguishing valid-but-benign alerts from malicious activity |
| Scenario 04 | Port Scanning Investigation and Detection Gap Analysis | Detection Gap | Comparing tcpdump network evidence against host-log-focused Wazuh visibility |

## Skills Demonstrated

- SSH authentication alert triage
- Raw log and SIEM alert count comparison
- Benign-positive classification
- Port scanning evidence validation
- Detection gap analysis
- SOC investigation report writing
