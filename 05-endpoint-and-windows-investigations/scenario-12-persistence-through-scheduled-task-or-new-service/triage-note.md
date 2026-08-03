# Triage Note

## Case summary

| Field | Value |
|---|---|
| Case | Scenario 12 — Scheduled Task Persistence |
| Detection source | Windows endpoint telemetry in an attributed Empire simulation dataset |
| First relevant event | `2020-09-21 17:58:17` |
| Primary asset | `LAB-WKS-05` |
| Primary identity | `LAB\user-a` |
| Persistence object | `\MordorElevated` |
| Severity | High |
| Disposition | True Positive — simulated malicious activity confirmed |
| Primary ATT&CK mapping | `T1053.005` |

## Trigger for investigation

A high-integrity PowerShell session launched `schtasks.exe` with a command line that combined the following characteristics:

- task creation with forced overwrite;
- execution as local `SYSTEM`;
- `ONLOGON` trigger;
- hidden, non-interactive PowerShell action;
- registry-backed Base64 decoding and in-memory execution.

Task creation alone can be legitimate. The case was escalated because Windows also recorded successful task registration, a subsequent reboot and logon, task execution as `SYSTEM`, dynamic compilation through `csc.exe`, and TCP communication from the task-launched PowerShell process.

## Initial assessment

| Observation | Triage assessment |
|---|---|
| `schtasks.exe /Create` by an elevated user session | Suspicious but not sufficient alone |
| `/RU system` and `/SC ONLOGON` | High-impact persistence configuration |
| Hidden PowerShell registry loader | Strong malicious indicator in this context |
| 4698 and 106 at the same second | Creation and registration confirmed |
| Task Scheduler 129 after logon | Execution confirmed |
| PowerShell PID correlated to 4688 and 5156 | Privileged execution and network activity confirmed |
| No change or deployment records | Authorisation cannot be assessed from the dataset |

## Scope at triage

The confirmed persistence chain is limited to `LAB-WKS-05` in the available telemetry. Activity on the two other hosts was reviewed as background context. Domain-controller authentication events support normal domain authentication associated with the workstation session but do not show scheduled-task execution on the domain controller.

The second task, `\MordorElevatedTask`, executed at the same time and launched a parallel PowerShell chain. Its creation is not present in the window, so its creator and creation time remain unconfirmed.

## Immediate production-equivalent actions

For an equivalent event in a live environment:

1. Isolate the affected endpoint while preserving active volatile evidence.
2. Suspend or constrain the implicated account after validating operational impact.
3. Export both task definitions and capture relevant registry values before removal.
4. Terminate confirmed malicious task-launched processes.
5. Block the destination indicator using deactivated values translated back through internal case records.
6. Hunt for the task names, registry loader pattern, creator command line, and destination across the environment.
7. Validate the event against change, deployment, and endpoint-management records before final production attribution.

## Triage decision

Escalate to full incident investigation. The combination of persistence creation, actual execution, system-level context, registry-backed decoding, dynamic compilation, and network communication exceeds the threshold for a benign administrative explanation in the attributed simulation.

