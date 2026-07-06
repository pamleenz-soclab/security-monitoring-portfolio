# Recommended Actions: Port Scanning Detection Gap

## Summary

Scenario 04 identified a detection gap. A controlled TCP port scan was visible in target-side tcpdump evidence, but no clear Wazuh port-scan alert was generated during the scan time window.

The current lab is effective for SSH authentication monitoring, but it does not yet provide reliable network-layer scan detection.

## Immediate Action

| Action | Required? | Reason |
|---|---|---|
| Block source IP | No | Activity was authorized lab testing |
| Isolate target host | No | No compromise evidence was observed |
| Reset credentials | No | No authentication compromise occurred |
| Escalate as incident | No | Controlled lab activity |
| Document detection gap | Yes | Monitoring coverage gap was confirmed |

## Detection Engineering Recommendations

### 1. Add network telemetry

To detect port scans more reliably, add one or more of the following data sources:

- Firewall logs
- UFW logs
- Cloud firewall logs
- VPC flow logs
- Zeek logs
- Suricata IDS alerts
- Security Onion telemetry

### 2. Distinguish host logs from network logs

Linux authentication logs are useful for SSH authentication events, but they do not capture most network-layer probing activity.

A port scan may only produce authentication logs if it touches an application such as SSH.

### 3. Build a detection rule for multi-port probing

A basic detection logic could be:

    If the same source IP attempts connections to more than N distinct destination ports on the same target within a short time window, classify as possible port scanning.

Example tuning parameters:

| Parameter | Example |
|---|---|
| Time window | 1 minute |
| Destination port threshold | 10 or more ports |
| Same source IP | Required |
| Same target host | Required |
| Known scanner allowlist | Optional |

### 4. Reduce false positives

Potential benign sources include:

- Vulnerability scanners
- Monitoring systems
- Load balancer health checks
- Security team testing
- Approved asset discovery tools

Recommended tuning:

- Allowlist approved scanner IPs
- Add asset criticality
- Use threshold-based logic
- Correlate with successful connections
- Correlate with firewall deny logs

## Production Response Guidance

In production, port scan alerts should be triaged by asking:

1. Is the source internal or external?
2. Is the source an approved scanner?
3. How many ports were contacted?
4. How many hosts were targeted?
5. Did any connection succeed?
6. Did the scan precede authentication attempts or exploitation attempts?
7. Was the target an internet-facing production system?

## Recommended Controls

| Control | Purpose |
|---|---|
| Restrict administrative ports | Reduce exposed attack surface |
| Use firewall allowlists | Limit access to SSH and management services |
| Enable firewall logging | Provide network-layer evidence |
| Deploy IDS sensors | Detect scans and exploit attempts |
| Monitor cloud flow logs | Identify scanning patterns at network level |
| Correlate SIEM alerts with network telemetry | Improve detection confidence |

## Portfolio Learning Point

This scenario demonstrates a key SOC and Security Engineering lesson:

    No alert does not mean no activity.

The scan was visible in packet capture, but not clearly alerted by Wazuh. This is a detection coverage issue, not proof that the activity did not occur.
