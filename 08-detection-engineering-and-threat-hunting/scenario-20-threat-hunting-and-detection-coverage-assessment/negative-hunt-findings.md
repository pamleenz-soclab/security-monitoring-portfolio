# Negative Hunt Findings

Negative hunts are preserved because they constrain what the reviewed telemetry supports.

| hunt_id | hypothesis | search_scope | telemetry_basis | query_result | classification | boundary |
| --- | --- | --- | --- | --- | --- | --- |
| HC-12 | A privileged-group membership addition may be followed by target authentication or privilege use even though the membership detection ends at the change event. | Target auth/privilege/process use after membership change in selected Security/Sysmon telemetry | Scenario11 privilege-change-timeline + field-coverage | 4 relevant checks Not observed; 1 relevant checks Not available | Negative hunt result | No matching target use was observed in reviewed files; this is not evidence that use never occurred elsewhere/later. |
| HC-07 | SQLi activity may exist outside high-confidence burst or multi-rule correlation and require broader source/user-agent/path/time hunting. | All SQLi-family transactions compared with corrected R19-03 Branch A and Branch B semantics. | Scenario 15 web-request-timeline.csv | No transaction remained outside corrected R19-03 high-confidence approximation. | Negative hunt result | Does not prove low-and-slow SQLi was absent outside this WAF dataset. |

## Interpretation

HC-07 means no SQLi-family transaction remained outside the corrected local R19-03 high-confidence semantic approximation **within the reviewed WAF dataset**.

HC-12 means no matching post-membership-change target authentication, special-privilege use, explicit credential use, or process execution was observed in the selected telemetry. Cross-host follow-on telemetry was unavailable.

Neither result is evidence that the behaviour could not have occurred outside the retained data, time window, host scope, or telemetry sources.
