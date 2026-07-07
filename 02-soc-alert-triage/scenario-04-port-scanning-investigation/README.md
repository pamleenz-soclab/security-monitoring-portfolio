# Scenario 04: Port Scanning Investigation and Detection Gap Analysis

## Overview

This scenario documents a controlled TCP (Transmission Control Protocol) port probing activity against the Ubuntu Target endpoint.

The activity was generated from the MacBook using `nc` / Netcat because Nmap was not available on the MacBook. The Ubuntu Target captured the network evidence using `tcpdump`.

The investigation compares scanner-side evidence, target-observed network evidence, Linux authentication logs, and Wazuh SIEM / XDR alerts.

## Scenario Goal

The goal is to investigate whether a controlled TCP port scan is visible through the current monitoring pipeline.

This scenario specifically tests whether the existing Wazuh host-log-based configuration can clearly detect network-layer port scanning activity.

## Assessment

Detection Gap.

The controlled TCP port probing activity was confirmed using `tcpdump` on the Ubuntu Target, but no clear Wazuh port-scan alert was observed for the scan time window.

## Test Summary

| Field | Value |
|---|---|
| Scenario | Port Scanning Investigation and Detection Gap Analysis |
| Test source | MacBook |
| Target endpoint | `soc-lab-ubuntu-target-01` |
| Source IP | `[SOURCE_IP_REDACTED]` |
| Target IP | `[TARGET_PUBLIC_IP_REDACTED]` |
| Scan tool | `nc` / Netcat |
| Network evidence tool | `tcpdump` |
| Detection platform | Wazuh SIEM / XDR |
| Final assessment | Detection Gap |

## Evidence Summary

The scanner-side `nc` output showed TCP connection attempts to multiple ports. Port `22/tcp` was reachable, while most other tested ports were refused or timed out.

The target-side `tcpdump` evidence confirmed that the Ubuntu Target observed TCP SYN packets from the same source IP to multiple destination ports.

The Linux authentication log only recorded an SSH connection closure for the `22/tcp` probe.

Wazuh did not generate a clear port-scan alert during the scan time window.

## Key Finding

The current lab configuration can detect and alert on SSH authentication events, but it does not reliably detect network-layer port scanning activity based only on host authentication logs.

This indicates a monitoring coverage gap. Detecting port scanning reliably would require additional telemetry such as firewall logs, Zeek, Suricata, Security Onion, or explicit network detection rules.

## Evidence Files

| Evidence File | Description |
|---|---|
| `listening-ports-before-scan-sanitized.txt` | Target listening-port baseline before the scan |
| `nc-portscan-scenario04-sanitized.txt` | Scanner-side TCP probing results from MacBook |
| `tcpdump-portscan-summary-sanitized.txt` | Target-side tcpdump packet summary |
| `tcpdump-portscan-syn-summary-sanitized.txt` | SYN-only target-side tcpdump summary |
| `tcpdump-dst-port-count-sanitized.txt` | Destination port count observed by tcpdump |
| `authlog-portscan-sourceip-sanitized.txt` | SSH-related authentication log evidence for the scan source IP |
| `wazuh-alerts-scan-window-sourceip-sanitized.json` | Wazuh scan-window alert check; contains an empty JSON array because no alert object was observed |
| `wazuh-portscan-keyword-check-sanitized.txt` | Wazuh keyword check for port-scan terms; documents that no matching alert keyword was observed |
| `wazuh-portscan-keyword-check-count.txt` | Count of Wazuh port-scan keyword matches |
| `wazuh-detection-gap-note-sanitized.txt` | Detection gap summary note |

## Learning Outcome

This scenario demonstrates that scanner-side activity, target-observed network traffic, application logs, and SIEM alerts are different evidence layers.

A SOC analyst should not assume that a port scan will always appear in authentication logs or SIEM alerts. Network-layer detection requires appropriate network telemetry.
