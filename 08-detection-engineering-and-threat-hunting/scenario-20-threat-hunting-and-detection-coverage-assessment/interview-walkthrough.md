# Interview Walkthrough

## 90-second version

> Scenario 20 is my threat-hunting and detection-coverage assessment. Instead of starting from a known alert, I selected eight hypotheses across identity, endpoint, Web/network, and cloud data. I used only processed evidence from earlier scenarios and a local Python evaluator to perform entity pivots and sequence correlation. Then I assessed each attack step separately for telemetry availability, detection status, and validation quality.
>
> The key lesson was that a rule file is not automatically coverage, but the opposite is also true: a hunt-only-looking behaviour is not automatically a detection gap. During precision review I withdrew two initial gaps because Scenario 17 already had an MFA follow-on KQL correlation and Scenario 13 already had Sentinel/Splunk SMBExec sequence logic. The final confirmed detection gap was suspicious PowerShell activity in Scenario 10, where process, file and network telemetry existed but no dedicated rule artifact was inventoried.
>
> I also kept two negative hunts and one unable-to-assess result. For example, WAF data showed SQL injection attempts, but application and database telemetry were missing, so I would not claim successful backend exploitation. The result is a coverage matrix that separates detection gaps from logging gaps and proposes new detection opportunities without turning the scenario into another rule-development exercise.

## Technical follow-up points

### How did you avoid false coverage claims?

I required per-behaviour telemetry status, detection status, validation status, and evidence references. ATT&CK mappings and rule-file existence were not sufficient.

### What was the most important correction?

HC-05. The initial view treated the full SMB lateral-movement chain as hunt-only. Review of Scenario 13 showed an existing Sentinel/Splunk correlation for 4624 Type 3 + 5145 `svcctl` + 4697 within two minutes, so I changed the expanded chain to Partially detected.

### What was the clearest logging gap?

HC-08. WAF telemetry could show an attempted SQLi request, but without application/database evidence I could not establish SQL execution or business impact.

### What was the clearest detection gap?

HC-03. PowerShell plus child/file/network context was visible, but no dedicated Scenario 10 detection rule was found in the repository inventory.

### Why keep negative hunts?

Because a bounded "not observed in reviewed telemetry" result is useful and auditable; it is different from claiming the behaviour did not occur.
