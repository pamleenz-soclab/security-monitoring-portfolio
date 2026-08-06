# Source, Licence, and Integrity Record

## Source

- Dataset: Splunk Attack Data — ActiveMQ Exploit LockBit Ransomware
- Dataset ID: `1d5e15bc-7eaf-46a2-8a92-ad9e3eb5cbb4`
- Repository: `https://github.com/splunk/attack_data`
- Fixed commit: `671041b0405d5d766378a34a82bae59c5c672d9f`
- Repository path: `datasets/apt_simulations/ActiveMQ_exploit_Lockbit_Ransomware`
- Repository licence: Apache License 2.0
- Acquisition UTC record time: `2026-08-06T04:31:55Z`
- Acquisition Pacific/Auckland record time: `2026-08-06T16:31:55+1200`

The download used a sparse shallow clone and fixed-commit GitHub media URLs after `git lfs pull` stalled. Each resulting file was checked to ensure it contained log data rather than a Git LFS pointer.

## Raw evidence hashes

| File | SHA-256 |
|---|---|
| `windows-sysmon.log` | `6fb7acc46cae31504b1d8fc7b731cfcbbfc61ef9819574a72d684c8ea47e9360` |
| `windows-security.log` | `55555312391cf49c51fddbbd2c19aa09d7c1469205d0f3374bec68ad4df49a78` |
| `windows-powershell.log` | `405c2a15b183abd9f23e22eb18ddb65b562d9b80cca7a4338ffeddc26cbb6c4c` |

## Redistribution decision

Raw evidence is not redistributed in this portfolio package. The repository contains only:

- Attribution.
- Hash records.
- Sanitised derived evidence.
- Detection content.
- Reproducible analysis scripts.

Users who wish to reproduce the analysis should obtain the source dataset directly and verify the fixed commit and hashes.
