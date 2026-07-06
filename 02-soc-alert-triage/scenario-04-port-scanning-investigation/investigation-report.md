# Investigation Report: Port Scanning Investigation and Detection Gap Analysis

## Executive Summary

A controlled TCP port probing activity was performed from the MacBook against the Ubuntu Target endpoint.

The scanner-side evidence showed attempted TCP connections to multiple ports. The Ubuntu Target confirmed the activity using `tcpdump`, which observed TCP SYN packets from the same source IP to multiple destination ports.

The Linux authentication log only recorded an SSH connection closure for the `22/tcp` probe. Wazuh did not generate a clear port-scan alert during the scan time window.

The final assessment is Detection Gap.

## Scope

| Field | Value |
|---|---|
| Scenario | Scenario 04: Port Scanning Investigation |
| Test source | MacBook |
| Target endpoint | `soc-lab-ubuntu-target-01` |
| Source IP | `[SOURCE_IP_REDACTED]` |
| Target IP | `[TARGET_PUBLIC_IP_REDACTED]` |
| Tool used | `nc` / Netcat |
| Network capture tool | `tcpdump` |
| Detection platform | Wazuh SIEM / XDR |
| Final assessment | Detection Gap |

## Initial Detection

This scenario was not triggered by an initial Wazuh alert.

Instead, it was a controlled lab test designed to determine whether a multi-port TCP probing pattern would be visible in the current monitoring pipeline.

## Target Listening-Port Baseline

Before the scan, the Ubuntu Target listening-port baseline showed SSH listening on `22/tcp`.

The target also had local resolver services on loopback, but these were not externally exposed services.

This baseline helped confirm that `22/tcp` was the expected reachable service.

## Scanner-Side Evidence

The MacBook used `nc` / Netcat to probe multiple TCP ports.

The scanner-side result showed:

- `22/tcp` succeeded
- Several ports returned connection refused
- Several ports timed out

This confirms that the source attempted to connect to multiple TCP ports on the target.

## Target-Side Network Evidence

The Ubuntu Target captured the activity using `tcpdump`.

The SYN-only summary showed connection attempts from the same source IP to multiple destination ports, including:

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

This confirms that the target observed multi-port TCP probing.

## Scanner-Side vs Target-Side Difference

The scanner attempted more ports than the target-side SYN summary observed.

This is an important investigation point: scanner-side attempted ports and target-observed traffic may differ because some packets can be filtered by upstream firewalls, cloud controls, routing behavior, or other network path conditions.

Therefore, SOC analysts should distinguish between:

    What the scanner attempted

and:

    What the target actually observed

## Authentication Log Review

The Ubuntu authentication log recorded an SSH connection closure related to the `22/tcp` probe:

    sshd: Connection closed by [SOURCE_IP_REDACTED] port 38829

This is not an authentication failure and not an invalid-user event. It only indicates that the SSH service received a connection that closed before normal SSH authentication.

No broad authentication evidence was generated for the non-SSH ports because most port probes do not interact with Linux authentication services.

## Wazuh Alert Review

The Wazuh scan-window file contained zero matching events.

The port-scan keyword check also returned zero matches.

This indicates that Wazuh did not generate a clear port-scan alert for the controlled scan activity in the current lab configuration.

## Detection Gap

The investigation identified a detection gap:

    The port scan was visible in tcpdump but not clearly alerted by Wazuh.

The current monitoring configuration is effective for SSH authentication events, but it is not sufficient for reliable network-layer port scan detection.

## MITRE ATT&CK Mapping

| Tactic | Technique ID | Technique |
|---|---|---|
| Reconnaissance | T1595 | Active Scanning |
| Discovery | T1046 | Network Service Discovery |

This lab activity most closely resembles active scanning and network service discovery, but it was performed in an authorized and controlled environment.

## Timeline

| Time | Source | Event |
|---|---|---|
| May 9 04:12 UTC | MacBook | Controlled TCP port probing performed with `nc` |
| May 9 04:12 UTC | Ubuntu Target tcpdump | TCP SYN packets observed across multiple destination ports |
| May 9 04:12 UTC | `/var/log/auth.log` | SSH connection closure recorded for `22/tcp` |
| May 9 04:12 UTC | Wazuh `alerts.json` | No clear port-scan alert observed |

## Impact Assessment

| Impact Area | Result |
|---|---|
| Successful login | Not observed |
| Service exploitation | Not observed |
| Host compromise | Not observed |
| Data access | Not observed |
| Service disruption | Not observed |
| Reconnaissance activity | Confirmed as authorized lab activity |
| Detection gap | Confirmed |

## Conclusion

Scenario 04 demonstrates that network-layer evidence and SIEM alert evidence are not the same.

The controlled TCP port scan was confirmed through tcpdump, but Wazuh did not generate a clear port-scan alert in the scan time window. This indicates that the current host-log-focused configuration has a coverage gap for network reconnaissance.

Future lab work should add network telemetry such as firewall logs, Zeek, Suricata, Security Onion, or cloud flow logs to improve detection coverage.
