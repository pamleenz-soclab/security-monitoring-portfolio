# Hunt Hypotheses

The final eight hypotheses were selected after repository inventory and telemetry-feasibility review.

| hunt_id | domain | hypothesis | source_scenarios | attack_mapping | outcome | evidence_boundary |
| --- | --- | --- | --- | --- | --- | --- |
| HC-01 | Identity / Cloud | MFA denial/timeout -> success may have follow-on cloud activity outside the terminal event of the existing MFA sequence detection. | 17;19 | T1621 | Supported | Human operator identity/token theft is not inferred from the sequence. |
| HC-03 | Endpoint / Process | Suspicious PowerShell may have adjacent parent-child, file and network behaviour not covered by a dedicated detection. | 10;19 | T1059.001;T1071.001;T1105 | Supported | No post-capture or HTTP-content claims are made. |
| HC-05 | Endpoint / Network / Lateral Movement | SMB remote-service lateral movement may be reconstructable across authentication, TCP/445, service control and remote process telemetry while detections cover only subsets. | 13 | T1021.002;T1569.002 | Supported | Authorization/change-control evidence is not available and is not inferred. |
| HC-07 | Network / Web | SQLi activity may exist outside high-confidence burst or multi-rule correlation and require broader source/IP/user-agent/path/time hunting. | 15;19 | T1190 | Negative hunt result | No result would mean no matching candidate in the reviewed WAF dataset only; WAF evidence cannot establish backend execution. |
| HC-08 | Web / Application / Database | WAF-observed SQLi may be impossible to confirm as backend SQL execution or impact because required backend telemetry is absent. | 15 | T1190 | Unable to assess | HTTP status and WAF match are not proof of SQL execution or impact. |
| HC-09 | Network / DNS / Endpoint | Staging/process/network behaviour may extend beyond the selected structured-DNS-chunk detection primitive. | 16;19 | T1005;T1560.001;T1048.003;T1071.004 | Supported | Base64/gzip are not described as encryption without independent encryption evidence. |
| HC-10 | Cloud Identity / Privilege | Service-principal credential change may be followed by sign-in and API/resource use beyond the terminal event of the credential-to-sign-in rule. | 18;19 | T1098.001;T1078.004 | Supported | Permission capability does not prove which permission claim authorised a specific API request. |
| HC-12 | Identity / Windows Privilege | A privileged-group membership addition may be followed by target authentication or privilege use even though the membership detection ends at the change event. | 11;19 | T1098;T1098.007 | Negative hunt result | Negative result is bounded to reviewed data, host and time scope. |

No hypothesis was assigned a positive or negative result before execution.
