# Alert Triage Note: Controlled TCP Port Scan

## Alert Name

Controlled TCP port probing observed at the network layer

## Initial Question

Was the controlled TCP port scan detected by the current Wazuh monitoring pipeline?

## Assessment

Detection Gap.

The TCP port probing activity was confirmed through scanner-side output and target-side tcpdump evidence, but no clear Wazuh port-scan alert was observed during the scan time window.

## Activity Summary

| Field | Value |
|---|---|
| Activity type | Controlled TCP port probing |
| Source | MacBook |
| Target | `soc-lab-ubuntu-target-01` |
| Source IP | `[SOURCE_IP_REDACTED]` |
| Target IP | `[TARGET_PUBLIC_IP_REDACTED]` |
| Tool | `nc` / Netcat |
| Network evidence | `tcpdump` |
| Wazuh result | No clear port-scan alert observed |
| Final classification | Detection Gap |

## Data Sources Reviewed

| Data Source | Purpose |
|---|---|
| `nc` output | Confirm scanner-side attempted TCP connections |
| `ss -tulpen` | Establish target listening-port baseline |
| `tcpdump` PCAP summary | Confirm target-observed network traffic |
| `/var/log/auth.log` | Check whether SSH application logs recorded scan-related activity |
| Wazuh `alerts.json` | Check whether Wazuh generated scan-related alerts |

## Evidence

### Scanner-Side Evidence

The MacBook used `nc` / Netcat to test multiple TCP ports on the Ubuntu Target.

Port `22/tcp` succeeded, while most other ports returned connection refused or operation timed out.

### Target-Side Network Evidence

The Ubuntu Target observed TCP SYN packets from the same source IP to multiple destination ports.

Observed destination ports included:

    21
    22
    80
    110
    143
    443
    3389
    5601
    8080
    8443
    9200
    9300
    1514
    1515
    55000

This confirms that the target host saw a multi-port TCP probing pattern.

### Authentication Log Evidence

The authentication log recorded an SSH connection closure related to the `22/tcp` probe:

    sshd: Connection closed by [SOURCE_IP_REDACTED] port 38829

This is not an invalid-user event and not a password failure. It only shows that the SSH service received a connection that closed without normal authentication.

### Wazuh Evidence

The Wazuh scan-window check produced zero matching alerts:

    0

The port-scan keyword check also produced zero matching alerts:

    0

This supports the conclusion that no clear Wazuh port-scan alert was generated.

## Timeline

| Time | Source | Event |
|---|---|---|
| May 9 04:12 UTC | MacBook | TCP port probing started using `nc` |
| May 9 04:12 UTC | Ubuntu Target tcpdump | Multiple TCP SYN packets observed |
| May 9 04:12 UTC | `/var/log/auth.log` | SSH connection closed entry observed for `22/tcp` |
| May 9 04:12 UTC | Wazuh alerts | No clear port-scan alert observed |

## Impact

No compromise was observed.

| Impact Area | Assessment |
|---|---|
| Successful login | Not observed |
| Exploitation | Not observed |
| Service disruption | Not observed |
| Host compromise | Not observed |
| Confirmed reconnaissance | Yes, authorized lab activity |
| Detection coverage gap | Yes |

## Triage Decision

The correct classification is Detection Gap.

The activity occurred and was verified through target-side packet capture. However, the current Wazuh host-log configuration did not produce a clear port-scan alert.

This is not a false positive. It is a visibility and detection coverage issue.

## Detection Improvement

To detect this type of activity more reliably, the lab should add or integrate one or more of the following:

- Firewall logs
- UFW logs
- Zeek network logs
- Suricata IDS alerts
- Security Onion
- Cloud firewall or VPC flow logs
- Wazuh rules based on network telemetry
