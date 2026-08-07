# Telemetry Coverage Assessment

| hunt_id | behaviour | attack_step | data_source | entity | telemetry_status | evidence_reference | limitation |
| --- | --- | --- | --- | --- | --- | --- | --- |
| HC-01 | Repeated MFA denial/timeout | MFA pressure | Cloud sign-in/MFA | user | Available | scenario17:mfa-fatigue-assessment.csv |  |
| HC-01 | Success after failures | Authentication | Cloud sign-in | user | Available | scenario17:mfa-fatigue-assessment.csv |  |
| HC-01 | Post-auth cloud activity | Follow-on | Cloud audit/resource | user | Available | scenario17:follow-on-activity-analysis.csv |  |
| HC-03 | Suspicious PowerShell execution | Command interpreter | PowerShell/Security/Sysmon | process | Available | scenario10:process-chain.csv;powershell-behaviour-summary.csv |  |
| HC-03 | Parent-child/file/network follow-on | Execution/C2 context | Sysmon/process/network | ProcessGuid | Available | scenario10:process-chain.csv;file-activity.csv;network-activity.csv |  |
| HC-03 | HTTP request/response content | Network-content validation | PCAP/proxy/server logs | HTTP session | Not available | scenario10:scope-and-gaps.csv | HTTP bodies/PCAP/proxy/server logs are explicitly unavailable |
| HC-05 | Remote authentication | Authentication | Windows Security | account | Available | scenario13:authentication-remote-service-evidence.csv |  |
| HC-05 | TCP/445 SMB connection | Remote services | Network/PCAP | source-target | Available | scenario13:network-flow-summary.csv |  |
| HC-05 | SVCCTL/service-control | Service execution | SMB/Windows service telemetry | target | Available | scenario13:pcap-marker-evidence.csv |  |
| HC-05 | Remote service process | Remote execution | Endpoint process | target process | Available | scenario13:remote-process-chain.csv |  |
| HC-05 | End-to-end lateral-movement sequence | Lateral movement chain | Authentication+network+process | source/target/account | Available | scenario13:attack-timeline.csv |  |
| HC-07 | WAF-observed SQLi-family request | Exploit attempt | WAF transaction | source/tx | Available | scenario15:web-request-timeline.csv |  |
| HC-07 | Burst/multi-rule high-confidence SQLi | Correlated exploit attempt | WAF transaction | source/tx | Available | scenario15:web-request-timeline.csv |  |
| HC-07 | Lower-frequency/single-rule SQLi candidate | Low-and-slow hunt | WAF transaction | source/UA/path | Available | scenario15:web-request-timeline.csv |  |
| HC-08 | WAF SQLi attempt | Exploit attempt | WAF | transaction | Available | scenario15:web-request-timeline.csv |  |
| HC-08 | Application handling/SQL exception | Backend application outcome | Application request/exception log | request | Not available | scenario15:application-and-database-evidence.csv | Application log absent |
| HC-08 | SQL query execution/table access | Database outcome | Database/backend audit | DB session | Not available | scenario15:application-and-database-evidence.csv | Database audit absent |
| HC-08 | Web shell/child process follow-on | Endpoint impact | Endpoint file/process | web server | Not available | scenario15:follow-on-activity-analysis.csv | Endpoint follow-on telemetry absent |
| HC-09 | File collection/staging | Collection/staging | Endpoint file/process | source | Available | scenario16:file-collection-and-staging-analysis.csv |  |
| HC-09 | Compression/encoding pipeline | Archive/transform | Endpoint command/process | process | Available | scenario16:compression-and-encryption-analysis.csv |  |
| HC-09 | Structured DNS chunks | DNS exfiltration | DNS/query | domain/query | Available | scenario16:dns-tunnelling-analysis.csv |  |
| HC-09 | Transfer outcome/hash match | Exfiltration outcome | Transfer/hash evidence | file/object | Available | scenario16:transfer-outcome-assessment.csv |  |
| HC-09 | Exact process-to-DNS-flow join | Cross-source join | Endpoint socket + DNS/flow stable ID | process-flow | Partial | scenario16:process-to-network-correlation.csv | No stable endpoint process-to-flow identifier |
| HC-10 | Credential added/changed | Application persistence | Directory audit/credential metadata | app/SP | Available | scenario18:credential-change-analysis.csv |  |
| HC-10 | SP sign-in after credential change | Application identity auth | SP sign-in | service principal | Available | scenario18:service-principal-signin-analysis.csv |  |
| HC-10 | API/resource activity linked to sign-in token | Cloud resource use | API/resource + correlation | app/SP/token | Available | scenario18:precise-cloud-privilege-correlation.csv |  |
| HC-10 | Exact permission claim for API request | Permission attribution | Per-request token/app-role claim | API request | Not available | scenario18:detection-gap-analysis.csv | Specific permission claim is not logged per API request |
| HC-12 | Privileged membership addition | Account manipulation | Windows Security group events | ATTACKRANGE\T1136.001_Admin | Available | scenario11:privilege-change-timeline.csv |  |
| HC-12 | Target authentication after change | Post-change use | 4624/4625 | ATTACKRANGE\T1136.001_Admin | Available | scenario11:field-coverage.csv |  |
| HC-12 | Explicit credential/special privilege use | Post-change privilege use | 4648/4672 | ATTACKRANGE\T1136.001_Admin | Available | scenario11:field-coverage.csv |  |
| HC-12 | Target process execution | Post-change execution | Sysmon Event 1 | ATTACKRANGE\T1136.001_Admin | Available | scenario11:field-coverage.csv |  |
| HC-12 | Cross-host follow-on | Environment-wide use | Cross-host EDR/network | ATTACKRANGE\T1136.001_Admin | Not available | scenario11:field-coverage.csv | Cross-host follow-on telemetry is explicitly unavailable |

## Key visibility boundaries

- HC-03 lacks HTTP bodies, PCAP, proxy, or server-side logs for independent HTTP-content/outcome validation.
- HC-08 lacks application request/exception logs, database/backend audit, and an independent web access log.
- HC-09 has only partial endpoint-process-to-flow linkage because no stable process-to-flow/socket identifier is available; Zeek/session UID is also unavailable.
- HC-10 lacks per-request permission/app-role-claim telemetry.
- HC-12 lacks cross-host EDR/network follow-on coverage.

These gaps constrain what can be concluded even when suspicious behaviour is otherwise visible.
