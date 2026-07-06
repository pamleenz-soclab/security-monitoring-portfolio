# Scenario 03: Benign Authentication Failure Case

## Overview

This scenario documents a benign SSH (Secure Shell) authentication failure observed through Linux authentication logs and Wazuh SIEM / XDR (Security Information and Event Management / Extended Detection and Response).

The purpose of this scenario is to compare a single, explainable authentication failure against the repeated invalid-user pattern investigated in Scenario 02.

## Scenario Goal

The goal is to practice distinguishing between:

- Malicious-looking true positive activity
- Benign positive activity
- False positive activity

In this case, the SSH authentication failure was real and correctly detected by Wazuh, but the context indicates that it was a controlled, isolated, benign test rather than malicious activity.

## Test Summary

| Field | Value |
|---|---|
| Scenario | Benign Authentication Failure Case |
| Test username | `m2benign0509` |
| Target endpoint | `soc-lab-ubuntu-target-01` |
| Source IP | `[SOURCE_IP_REDACTED]` |
| Detection platform | Wazuh SIEM / XDR |
| Raw log source | `/var/log/auth.log` |
| Additional log source | `journald` |
| Wazuh rule ID | `5710` |
| Wazuh rule level | `5` |
| Wazuh rule description | `sshd: Attempt to login using a non-existent user` |
| Assessment | Benign Positive |

## Evidence Summary

The Ubuntu target recorded one core SSH invalid-user event in `/var/log/auth.log`.

Wazuh displayed two SSH alert records for the same activity because the same event was collected from two Linux log sources:

- `/var/log/auth.log`
- `journald`

This means the Wazuh alert count was higher than the actual number of SSH invalid-user attempts.

## Key Finding

A broad keyword search for `m2benign0509` returned more events than the actual SSH authentication failure alerts because earlier investigation commands also produced sudo-related logs.

The relevant Wazuh SSH alerts were identified by filtering on:

- `rule.id: 5710`
- `rule.description: sshd: Attempt to login using a non-existent user`
- `decoder.name: sshd`

## Screenshots

| Screenshot | Description |
|---|---|
| `01-scenario-03-dashboard-filtered-rule5710-events.png` | Wazuh Dashboard filtered to `m2benign0509 AND rule.id:5710` |
| `02-scenario-03-event-detail-core-fields.png` | Event detail showing source user, source IP, decoder, location, and full log |
| `03-scenario-03-event-detail-rule-mitre-fields.png` | Rule and MITRE ATT&CK mapping fields |

## Evidence Files

| Evidence File | Description |
|---|---|
| `authlog-m2benign0509-sanitized.txt` | Sanitized Ubuntu authentication log evidence |
| `pre-simulation-baseline.txt` | Baseline check before simulation |
| `wazuh-ssh-alerts-m2benign0509-sanitized.json` | Sanitized Wazuh SSH alert records |
| `wazuh-ssh-alert-count.txt` | Count of Wazuh SSH Rule 5710 alert records |
| `wazuh-location-count.txt` | Count of Wazuh alert locations |

## Learning Outcome

This scenario demonstrates that a technically valid alert can still be benign after contextual investigation.

The event was not a false positive because the SSH invalid-user event really occurred and was correctly detected. However, the behavior was isolated, controlled, and consistent with an expected administrator mistake or lab simulation. Therefore, the final assessment is Benign Positive.
