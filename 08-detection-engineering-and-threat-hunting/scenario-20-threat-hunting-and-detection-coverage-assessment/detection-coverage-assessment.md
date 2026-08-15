# Detection Coverage Assessment

## Assessment method

Detection coverage is assessed per behaviour/attack step using:

- required and available telemetry;
- observed status;
- applicable rule/query artifact;
- detection status;
- validation status;
- deployment-status boundary;
- evidence reference.

No percentage is calculated from ATT&CK mappings or rule counts.

## Final matrix

| hunt_id | behaviour | attack_step | telemetry_status | detection_status | validation_status | deployment_status | coverage_reasoning |
| --- | --- | --- | --- | --- | --- | --- | --- |
| HC-01 | Repeated MFA denial/timeout | MFA pressure | Available | Detected | Source validated | Not available — repository evidence does not prove live deployment | Validated MFA sequence primitive |
| HC-01 | Success after failures | Authentication | Available | Detected | Source validated | Not available — repository evidence does not prove live deployment | Terminal event of R19-01 |
| HC-01 | Post-auth cloud activity | Follow-on | Available | Partially detected | Syntax reviewed | Not available — repository evidence does not prove live deployment | Scenario 17 already contains a follow-on correlation KQL joining successful sign-in to OfficeActivity on the same user/session within 2h for operations New-InboxRule, Set-InboxRule, FileDownloaded, Add-MailboxPermission, Set-Mailbox. Exact review: 4/5 observed follow-on row(s) match that analytic; 1 do not. |
| HC-03 | Suspicious PowerShell execution | Command interpreter | Available | No detection | Not tested | Not available | Stage1 found no Scenario10 rule/query artifact, only detection opportunities |
| HC-03 | Parent-child/file/network follow-on | Execution/C2 context | Available | No detection | Not tested | Not available | Correlated telemetry is visible without a dedicated inventoried detection |
| HC-03 | HTTP request/response content | Network-content validation | Not available | Unable to assess | Not tested | Not available | HTTP bodies/PCAP/proxy/server logs are explicitly unavailable |
| HC-05 | Remote authentication | Authentication | Available | Partially detected | Syntax reviewed | Not available — repository evidence does not prove live deployment | Scenario 13 already contains Sentinel and Splunk multi-event correlation logic for 4624 Type 3 + 5145 IPC$\svcctl + 4697 within two minutes under correlated user/logon context. The remote child-process/follow-on stage is covered by separate behavioural artifacts rather than being joined into the same correlation, so the full expanded hunt chain is Partially detected. |
| HC-05 | TCP/445 SMB connection | Remote services | Available | Partially detected | Syntax reviewed | Not available — repository evidence does not prove live deployment | Scenario 13 already contains Sentinel and Splunk multi-event correlation logic for 4624 Type 3 + 5145 IPC$\svcctl + 4697 within two minutes under correlated user/logon context. The remote child-process/follow-on stage is covered by separate behavioural artifacts rather than being joined into the same correlation, so the full expanded hunt chain is Partially detected. |
| HC-05 | SVCCTL/service-control | Service execution | Available | Detected | Syntax reviewed | Not available — repository evidence does not prove live deployment | Scenario 13 already contains Sentinel and Splunk multi-event correlation logic for 4624 Type 3 + 5145 IPC$\svcctl + 4697 within two minutes under correlated user/logon context. The remote child-process/follow-on stage is covered by separate behavioural artifacts rather than being joined into the same correlation, so the full expanded hunt chain is Partially detected. |
| HC-05 | Remote service process | Remote execution | Available | Partially detected | Syntax reviewed | Not available — repository evidence does not prove live deployment | Scenario 13 already contains Sentinel and Splunk multi-event correlation logic for 4624 Type 3 + 5145 IPC$\svcctl + 4697 within two minutes under correlated user/logon context. The remote child-process/follow-on stage is covered by separate behavioural artifacts rather than being joined into the same correlation, so the full expanded hunt chain is Partially detected. |
| HC-05 | End-to-end lateral-movement sequence | Lateral movement chain | Available | Partially detected | Syntax reviewed | Not available — repository evidence does not prove live deployment | Scenario 13 already contains Sentinel and Splunk multi-event correlation logic for 4624 Type 3 + 5145 IPC$\svcctl + 4697 within two minutes under correlated user/logon context. The remote child-process/follow-on stage is covered by separate behavioural artifacts rather than being joined into the same correlation, so the full expanded hunt chain is Partially detected. |
| HC-07 | WAF-observed SQLi-family request | Exploit attempt | Available | Partially detected | Not tested | Not available — repository evidence does not prove live deployment | Source detection artifacts exist but deployment is unknown |
| HC-07 | Burst/multi-rule high-confidence SQLi | Correlated exploit attempt | Available | Detected | Source validated | Not available — repository evidence does not prove live deployment | Corrected R19-03 local semantic approximation: Branch A = >=2 distinct SQLi rule IDs in one transaction OR a specialist SQLi rule; Branch B = >=20 distinct SQLi transaction IDs for the same source_ip+host in a rolling 5-minute window. Because the specification states that single generic Rule 942100-only events are retained for review/logging, a single 942xxx rule other than 942100 is treated as the local specialist-rule approximation. |
| HC-07 | Lower-frequency/single-rule SQLi candidate | Low-and-slow hunt | Available | Hunt only | Not tested | Not available — repository evidence does not prove live deployment | No transaction remains outside corrected R19-03 high-confidence logic in the reviewed dataset. |
| HC-08 | WAF SQLi attempt | Exploit attempt | Available | Detected | Source validated | Not available — repository evidence does not prove live deployment | Request-side attempt is visible |
| HC-08 | Application handling/SQL exception | Backend application outcome | Not available | Unable to assess | Not tested | Not available | Application log absent |
| HC-08 | SQL query execution/table access | Database outcome | Not available | Unable to assess | Not tested | Not available | Database audit absent |
| HC-08 | Web shell/child process follow-on | Endpoint impact | Not available | Unable to assess | Not tested | Not available | Endpoint follow-on telemetry absent |
| HC-09 | File collection/staging | Collection/staging | Available | Hunt only | Not tested | Not available — repository evidence does not prove live deployment | Investigation/hunt coverage |
| HC-09 | Compression/encoding pipeline | Archive/transform | Available | Partially detected | Not tested | Not available — repository evidence does not prove live deployment | Pipeline Sigma artifact covers a high-signal primitive |
| HC-09 | Structured DNS chunks | DNS exfiltration | Available | Detected | Source validated | Not available — repository evidence does not prove live deployment | R19-06 covers structured DNS primitive |
| HC-09 | Transfer outcome/hash match | Exfiltration outcome | Available | Hunt only | Not tested | Not available | Outcome verification is investigative evidence |
| HC-09 | Exact process-to-DNS-flow join | Cross-source join | Partial | Unable to assess | Not tested | Not available | No stable endpoint process-to-flow identifier |
| HC-10 | Credential added/changed | Application persistence | Available | Detected | Source validated | Not available — repository evidence does not prove live deployment | First stage of R19-04 |
| HC-10 | SP sign-in after credential change | Application identity auth | Available | Detected | Source validated | Not available — repository evidence does not prove live deployment | R19-04 terminal event |
| HC-10 | API/resource activity linked to sign-in token | Cloud resource use | Available | Partially detected | Not tested | Not available — repository evidence does not prove live deployment | Source evidence confirms token-to-API links; deployment of API rules is not evidenced |
| HC-10 | Exact permission claim for API request | Permission attribution | Not available | Unable to assess | Not tested | Not available | Specific permission claim is not logged per API request |
| HC-12 | Privileged membership addition | Account manipulation | Available | Detected | Source validated | Not available — repository evidence does not prove live deployment | R19-05 covers the membership change |
| HC-12 | Target authentication after change | Post-change use | Available | Hunt only | Not tested | Not available | Target authentication was searched and recorded Not observed |
| HC-12 | Explicit credential/special privilege use | Post-change privilege use | Available | Hunt only | Not tested | Not available | Target-attributed use recorded Not observed |
| HC-12 | Target process execution | Post-change execution | Available | Hunt only | Not tested | Not available | Target process use recorded Not observed |
| HC-12 | Cross-host follow-on | Environment-wide use | Not available | Unable to assess | Not tested | Not available | Cross-host follow-on telemetry is explicitly unavailable |

## Important corrected conclusions

- **HC-01:** the MFA failure-to-success sequence is detected by R19-01. Scenario 17 also contains a follow-on correlation KQL; precision review found that 4 of 5 observed post-authentication activities matched its exact user/session/2-hour/operation semantics. This is partial coverage, not a confirmed missing detection.
- **HC-05:** Scenario 13 already has Sentinel and Splunk multi-event SMBExec correlation for the core 4624 Type 3 → 5145 `svcctl` → 4697 sequence within two minutes. The expanded hunt chain is partially detected because later process/follow-on context is not all joined into the same analytic.
- **HC-03:** suspicious PowerShell and correlated endpoint context are observable, but reviewed repository state `7f0f92b` contained no dedicated Scenario 10 detection-rule artifact. This remains the confirmed detection gap.
