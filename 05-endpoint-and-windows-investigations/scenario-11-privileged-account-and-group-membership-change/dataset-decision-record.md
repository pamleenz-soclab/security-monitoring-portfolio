# Dataset Decision Record

## Decision

- **Scenario:** Scenario 11 — Privileged Account and Group Membership Change
- **Selected dataset:** Splunk Attack Data — Atomic Red Team, T1136.001
- **Dataset ID:** `cc9b25e2-efc9-11eb-926b-550bf0943fbb`
- **Test date:** 2020-10-09
- **Author:** Patrick Bareiss
- **Environment:** Splunk Attack Range (controlled simulation)
- **Selected artifacts:** `atomic_red_team.yml`, `windows-security.log`, and `windows-sysmon.log`
- **Scenario slice:** Account `ATTACKRANGE\T1136.001_Admin` on `win-dc-7216619.attackrange.local`
- **Publishing decision:** **Use with restrictions**

Official references:

- [Splunk dataset page](https://research.splunk.com/attack_data/cc9b25e2-efc9-11eb-926b-550bf0943fbb/)
- [Splunk Attack Data repository](https://github.com/splunk/attack_data)
- [Dataset directory](https://github.com/splunk/attack_data/tree/master/datasets/attack_techniques/T1136.001/atomic_red_team)
- [Apache License 2.0](https://github.com/splunk/attack_data/blob/master/LICENSE)
- [Atomic Red Team T1136.001 test definition](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1136.001/T1136.001.md)

## Why this dataset was selected

The selected slice forms one controlled event chain and does not require unrelated datasets to be joined. Windows Security auditing records the actor session, account lifecycle, password-setting activity, privileged group membership change, and account deletion. Sysmon records the causative `cmd.exe`/`net.exe`/`net1.exe` process chain and the Atomic Red Team execution and cleanup commands.

The following facts can be confirmed from the same test interval:

1. `ATTACKRANGE\Administrator` obtained logon session `0x79779` and Event 4672 special privileges.
2. The same account and Logon ID created, enabled, set a password for, and modified `ATTACKRANGE\T1136.001_Admin`.
3. The same session added the target principal to `BUILTIN\Administrators`.
4. Sysmon independently recorded the matching `net user` and `net localgroup` commands under the same user and Logon ID.
5. A cleanup session `0x7FE66` deleted the target about three seconds later.

No target-account logon, target-account Event 4672, explicit-credential use by the target, or process execution under the target identity was found within the selected Windows Security and Sysmon files.

## Important environment caveat

Splunk and Atomic Red Team label this dataset as MITRE ATT&CK `T1136.001 — Create Account: Local Account`. However, the test ran on a domain controller and the audit fields identify the target as `ATTACKRANGE\T1136.001_Admin` and the group as `BUILTIN\Administrators`.

Microsoft documents the built-in Administrators group on a domain controller as a domain-local group in the Active Directory Builtin container. Therefore this scenario must not describe the event as an ordinary workstation-local SAM account without qualification. The source mapping is retained for provenance, while the evidence-aware interpretation is an Active Directory principal added to the domain's built-in Administrators group. Current ATT&CK mapping should also consider `T1098.007 — Additional Local or Domain Groups`; `T1136.002 — Domain Account` may describe the observed account semantics more precisely than the source label.

## Candidate comparison

| Candidate | Source and licence | Evidence strengths | Material limitations | Decision |
| --- | --- | --- | --- | --- |
| Splunk Attack Data T1136.001 Atomic Red Team | Controlled Attack Range; Apache-2.0 | Windows Security plus Sysmon; 4720, 4722, 4724, 4738, 4732, 4624, 4672, 4726; process and cleanup evidence; same actor Logon ID | No tickets; numeric SIDs rendered as names; test ran on a DC; full files contain unrelated Atomic activity and a static lab password | **Selected** |
| EVTX-to-MITRE-Attack hidden user creation | Controlled lab EVTX; CC0-1.0 | Single EVTX with 4720, 4722, 4724, 4738, 4732, 4733, 4726 and process events | Final hidden-account persistence depends on registry/SAM artifacts not present; plaintext lab password; no target logon | Not selected |
| Splunk Attack Data DNSAdmins member added | Controlled Attack Range; Apache-2.0 | Clear high-risk group-add event and actor/target fields | No account lifecycle and no post-change login or cleanup chain | Not selected |
| OTRF Security Datasets | Open-source simulated security datasets; MIT | Broad host/network research corpus | No clearly documented single current artifact was identified that combined account creation, privileged membership, and subsequent use better than the selected dataset | Not selected |

## Licence and publication decision

The repository is Apache-2.0 licensed and redistribution is permitted subject to the licence conditions. This portfolio nevertheless applies stricter evidence minimisation:

- Full raw logs remain local and are ignored by Git.
- GitHub contains only hashes, profiles, sanitised key-event excerpts, derived CSV evidence, and original analysis.
- Source attribution and licence links are retained.
- Static lab credentials appearing in Sysmon command lines are replaced with `[REDACTED-LAB-PASSWORD]` in processed evidence.

The restriction is driven by evidence minimisation and accidental-secret prevention, not by a claim that the public teaching data contains live enterprise credentials.

## Safety review

| Check | Result |
| --- | --- |
| Real enterprise data | Not observed; host and domain names identify an Attack Range lab |
| Live credentials | Not observed |
| Static teaching credential | Observed in Sysmon command lines; redacted from processed evidence |
| Token, cookie, bearer credential, or session secret | Not observed by focused pattern review |
| Executable or malicious payload bytes | Not present in the selected log files |
| Potentially sensitive command lines and unrelated tests | Present in the full Sysmon file; raw file remains local |
| Safe offline analysis | Yes |
| Suitable for public GitHub | Yes, only under the stated processed-evidence restrictions |

## Evidence terminology

- **Not available:** the dataset does not contain that evidence category. This applies to change tickets, approvers, approved windows, immutable numeric SIDs, directory Object IDs/DNs, and full cross-host EDR or network coverage.
- **Not observed:** the selected files contain the relevant telemetry type and were searched, but the event was not found. This applies to a logon, Event 4672, explicit-credential use, or process execution by `T1136.001_Admin` during the available interval.
