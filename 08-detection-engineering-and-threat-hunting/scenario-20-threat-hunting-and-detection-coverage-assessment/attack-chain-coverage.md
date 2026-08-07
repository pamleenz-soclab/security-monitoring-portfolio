# Attack Chain Coverage

The chain matrix shows why a single alert should not be used as a proxy for complete incident coverage.

| hunt_id | step_order | behaviour | attack_step | attack_technique_or_subtechnique | telemetry_status | observed_status | detection_status | validation_status | coverage_reasoning |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| HC-01 | 1 | Repeated MFA denial/timeout | MFA pressure | T1621 | Available | Observed | Detected | Source validated | Validated MFA sequence primitive |
| HC-01 | 2 | Success after failures | Authentication | T1621 | Available | Observed | Detected | Source validated | Terminal event of R19-01 |
| HC-01 | 3 | Post-auth cloud activity | Follow-on |  | Available | Observed | Partially detected | Syntax reviewed | Scenario 17 already contains a follow-on correlation KQL joining successful sign-in to OfficeActivity on the same user/session within 2h for operations New-InboxRule, Set-InboxRule, FileDownloaded, Add-MailboxPermission, Set-Mailbox. Exact review: 4/5 observed follow-on row(s) match that analytic; 1 do not. |
| HC-03 | 1 | Suspicious PowerShell execution | Command interpreter | T1059.001 | Available | Observed | No detection | Not tested | Stage1 found no Scenario10 rule/query artifact, only detection opportunities |
| HC-03 | 2 | Parent-child/file/network follow-on | Execution/C2 context | T1059.001;T1071.001;T1105 | Available | Observed | No detection | Not tested | Correlated telemetry is visible without a dedicated inventoried detection |
| HC-03 | 3 | HTTP request/response content | Network-content validation | T1071.001 | Not available | Unable to assess | Unable to assess | Not tested | HTTP bodies/PCAP/proxy/server logs are explicitly unavailable |
| HC-05 | 1 | Remote authentication | Authentication | T1078 | Available | Observed | Partially detected | Syntax reviewed | Scenario 13 already contains Sentinel and Splunk multi-event correlation logic for 4624 Type 3 + 5145 IPC$\svcctl + 4697 within two minutes under correlated user/logon context. The remote child-process/follow-on stage is covered by separate behavioural artifacts rather than being joined into the same correlation, so the full expanded hunt chain is Partially detected. |
| HC-05 | 2 | TCP/445 SMB connection | Remote services | T1021.002 | Available | Observed | Partially detected | Syntax reviewed | Scenario 13 already contains Sentinel and Splunk multi-event correlation logic for 4624 Type 3 + 5145 IPC$\svcctl + 4697 within two minutes under correlated user/logon context. The remote child-process/follow-on stage is covered by separate behavioural artifacts rather than being joined into the same correlation, so the full expanded hunt chain is Partially detected. |
| HC-05 | 3 | SVCCTL/service-control | Service execution | T1569.002 | Available | Observed | Detected | Syntax reviewed | Scenario 13 already contains Sentinel and Splunk multi-event correlation logic for 4624 Type 3 + 5145 IPC$\svcctl + 4697 within two minutes under correlated user/logon context. The remote child-process/follow-on stage is covered by separate behavioural artifacts rather than being joined into the same correlation, so the full expanded hunt chain is Partially detected. |
| HC-05 | 4 | Remote service process | Remote execution | T1569.002 | Available | Observed | Partially detected | Syntax reviewed | Scenario 13 already contains Sentinel and Splunk multi-event correlation logic for 4624 Type 3 + 5145 IPC$\svcctl + 4697 within two minutes under correlated user/logon context. The remote child-process/follow-on stage is covered by separate behavioural artifacts rather than being joined into the same correlation, so the full expanded hunt chain is Partially detected. |
| HC-05 | 5 | End-to-end lateral-movement sequence | Lateral movement chain | T1021.002;T1569.002 | Available | Observed | Partially detected | Syntax reviewed | Scenario 13 already contains Sentinel and Splunk multi-event correlation logic for 4624 Type 3 + 5145 IPC$\svcctl + 4697 within two minutes under correlated user/logon context. The remote child-process/follow-on stage is covered by separate behavioural artifacts rather than being joined into the same correlation, so the full expanded hunt chain is Partially detected. |
| HC-07 | 1 | WAF-observed SQLi-family request | Exploit attempt | T1190 | Available | Observed | Partially detected | Not tested | Source detection artifacts exist but deployment is unknown |
| HC-07 | 2 | Burst/multi-rule high-confidence SQLi | Correlated exploit attempt | T1190 | Available | Observed | Detected | Source validated | Corrected R19-03 local semantic approximation: Branch A = >=2 distinct SQLi rule IDs in one transaction OR a specialist SQLi rule; Branch B = >=20 distinct SQLi transaction IDs for the same source_ip+host in a rolling 5-minute window. Because the specification states that single generic Rule 942100-only events are retained for review/logging, a single 942xxx rule other than 942100 is treated as the local specialist-rule approximation. |
| HC-07 | 3 | Lower-frequency/single-rule SQLi candidate | Low-and-slow hunt | T1190 | Available | Not observed | Hunt only | Not tested | No transaction remains outside corrected R19-03 high-confidence logic in the reviewed dataset. |
| HC-08 | 1 | WAF SQLi attempt | Exploit attempt | T1190 | Available | Observed | Detected | Source validated | Request-side attempt is visible |
| HC-08 | 2 | Application handling/SQL exception | Backend application outcome | T1190 | Not available | Unable to assess | Unable to assess | Not tested | Application log absent |
| HC-08 | 3 | SQL query execution/table access | Database outcome | T1190 | Not available | Unable to assess | Unable to assess | Not tested | Database audit absent |
| HC-08 | 4 | Web shell/child process follow-on | Endpoint impact | T1505.003 | Not available | Unable to assess | Unable to assess | Not tested | Endpoint follow-on telemetry absent |
| HC-09 | 1 | File collection/staging | Collection/staging | T1005 | Available | Observed | Hunt only | Not tested | Investigation/hunt coverage |
| HC-09 | 2 | Compression/encoding pipeline | Archive/transform | T1560.001 | Available | Observed | Partially detected | Not tested | Pipeline Sigma artifact covers a high-signal primitive |
| HC-09 | 3 | Structured DNS chunks | DNS exfiltration | T1048.003;T1071.004 | Available | Observed | Detected | Source validated | R19-06 covers structured DNS primitive |
| HC-09 | 4 | Transfer outcome/hash match | Exfiltration outcome | T1048.003 | Available | Observed | Hunt only | Not tested | Outcome verification is investigative evidence |
| HC-09 | 5 | Exact process-to-DNS-flow join | Cross-source join | T1048.003 | Partial | Unable to assess | Unable to assess | Not tested | No stable endpoint process-to-flow identifier |
| HC-10 | 1 | Credential added/changed | Application persistence | T1098.001 | Available | Observed | Detected | Source validated | First stage of R19-04 |
| HC-10 | 2 | SP sign-in after credential change | Application identity auth | T1078.004 | Available | Observed | Detected | Source validated | R19-04 terminal event |
| HC-10 | 3 | API/resource activity linked to sign-in token | Cloud resource use | T1078.004 | Available | Observed | Partially detected | Not tested | Source evidence confirms token-to-API links; deployment of API rules is not evidenced |
| HC-10 | 4 | Exact permission claim for API request | Permission attribution |  | Not available | Unable to assess | Unable to assess | Not tested | Specific permission claim is not logged per API request |
| HC-12 | 1 | Privileged membership addition | Account manipulation | T1098;T1098.007 | Available | Observed | Detected | Source validated | R19-05 covers the membership change |
| HC-12 | 2 | Target authentication after change | Post-change use | T1078 | Available | Not observed | Hunt only | Not tested | Target authentication was searched and recorded Not observed |
| HC-12 | 3 | Explicit credential/special privilege use | Post-change privilege use | T1078 | Available | Not observed | Hunt only | Not tested | Target-attributed use recorded Not observed |
| HC-12 | 4 | Target process execution | Post-change execution |  | Available | Not observed | Hunt only | Not tested | Target process use recorded Not observed |
| HC-12 | 5 | Cross-host follow-on | Environment-wide use |  | Not available | Unable to assess | Unable to assess | Not tested | Cross-host follow-on telemetry is explicitly unavailable |

## Representative examples

### HC-05 — SMB remote-service lateral movement

The core authentication + `svcctl` + service-install correlation is already represented by Scenario 13 Sentinel/Splunk logic. The hunt adds remote-process and follow-on context. The expanded chain is therefore **Partially detected**, not `Hunt only`.

### HC-09 — data exfiltration

R19-06 covers the structured DNS primitive, while staging, transformation, transfer outcome, and exact endpoint-to-flow linkage have different coverage states.

### HC-12 — privilege change

R19-05 detects the membership addition. Post-change target use was searched and not observed in the selected host telemetry; cross-host follow-on is not available.
