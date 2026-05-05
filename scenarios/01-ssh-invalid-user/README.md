# Scenario 01: SSH Invalid User Authentication Attempt Investigation

## Objective

Generate controlled SSH invalid-user authentication attempts against a monitored Ubuntu endpoint, verify the raw Linux authentication logs, confirm Wazuh alert generation, and document the investigation as a SOC-style alert triage case.

## Environment

| Field | Value |
|---|---|
| Wazuh Server | `soc-lab-wazuh-server` |
| Target Endpoint | `soc-lab-ubuntu-target-01` |
| Target Private IP | `10.126.0.3` |
| Target OS | Ubuntu 22.04.5 LTS |
| Wazuh Agent ID | `001` |
| Wazuh Agent Version | `v4.14.5` |
| Log Source | `/var/log/auth.log` |

## Test Summary

A controlled SSH authentication test was performed from an administrator machine against the Ubuntu Target using a non-existent username.

Test username:

```text
fake-admin
```

## Key Finding

The first test generated logs in `/var/log/auth.log`, but Wazuh did not alert because the Wazuh Agent was not yet configured to collect `/var/log/auth.log`.

After adding the following agent configuration and restarting the Wazuh Agent, the same test activity was successfully collected and alerted by Wazuh:

```xml
<localfile>
  <log_format>syslog</log_format>
  <location>/var/log/auth.log</location>
</localfile>
```

## Confirmed Evidence

Representative sanitized log:

```text
Apr 30 06:47:11 soc-lab-ubuntu-target-01 sshd[50661]: Invalid user fake-admin from 203.0.113.10 port 63881
```

## Wazuh Dashboard Fields

| Field | Value |
|-------|-------|
| `@timestamp` | `Apr 30, 2026 @ 18:47:12.620` |
| `GeoLocation.country_name` | `New Zealand` |
| `GeoLocation.location` | `{ "lon": 174, "lat": -41 }` |
| `_index` | `wazuh-alerts-4.x-2026.04.30` |
| `agent.id` | `1` |
| `agent.ip` | `10.126.0.3` |
| `agent.name` | `soc-lab-ubuntu-target-01` |
| `data.srcip` | `49.227.160.67` |
| `data.srcport` | `63881` |
| `data.srcuser` | `fake-admin` |
| `decoder.name` | `sshd` |
| `decoder.parent` | `sshd` |
| `full_log` | `Apr 30 06:47:11 soc-lab-ubuntu-target-01 sshd[50661]: Invalid user fake-admin from 49.227.160.67 port 63881` |
| `id` | `1777531632.14135` |
| `input.type` | `log` |
| `location` | `/var/log/auth.log` |
| `manager.name` | `soc-lab-wazuh-server` |
| `predecoder.hostname` | `soc-lab-ubuntu-target-01` |
| `predecoder.program_name` | `sshd` |
| `predecoder.timestamp` | `11049.2827662037` |
| `rule.description` | `sshd: Attempt to login using a non-existent user` |
| `rule.firedtimes` | `95` |
| `rule.gdpr` | `IV_35.7.d, IV_32.2` |
| `rule.gpg13` | `7.1` |
| `rule.groups` | `syslog, sshd, authentication_failed, invalid_login` |
| `rule.hipaa` | `164.312.b` |
| `rule.id` | `5710` |
| `rule.level` | `5` |
| `rule.mail` | `FALSE` |
| `rule.mitre.id` | `T1110.001, T1021.004` |
| `rule.mitre.tactic` | `Credential Access, Lateral Movement` |
| `rule.mitre.technique` | `Password Guessing, SSH` |
| `rule.nist_800_53` | `AU.14, AC.7, AU.6` |
| `rule.pci_dss` | `10.2.4, 10.2.5, 10.6.1` |
| `rule.tsc` | `CC6.1, CC6.8, CC7.2, CC7.3` |
| `timestamp` | `Apr 30, 2026 @ 18:47:12.620` |

## Assessment

```text
True Positive — authorized lab simulation
```

## Recommended Improvements

- Ensure Linux authentication logs are collected from all Linux endpoints.
- Restrict SSH to trusted administrator IPs or VPN ranges.
- Use SSH key-based authentication.
- Disable direct root SSH login.
- Add Wazuh correlation logic for repeated rule `5710` events from the same source IP.
- Standardize investigation timestamps.
