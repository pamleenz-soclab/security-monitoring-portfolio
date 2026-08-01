# Scenario 08 - Business Email Compromise and Mailbox Rule Investigation

## Status

Completed

## Scenario summary

This scenario analyses Microsoft 365 Exchange audit samples that contain successful mailbox permission, forwarding, and Inbox-rule changes associated with BEC-related techniques.

The parser processed nine source files in JSON and CSV format, extracted 14 raw records, and deduplicated them to 12 unique audit events.

## Final assessment

**True Positive - Successful suspicious mailbox configuration changes were confirmed in simulated Microsoft 365 audit data.**

The evidence confirms:

- two mailbox delegation changes: SendAs and FullAccess;
- four email-hiding rule changes;
- six mailbox or Inbox-rule forwarding changes;
- a three-mailbox external-forwarding sequence completed in 66 seconds;
- two accounts forwarding to the same destination from the same source IP within 2 minutes 30 seconds.

The evidence does **not** confirm:

- unauthorised account access or account compromise;
- successful delivery of forwarded messages;
- email collection or data exfiltration;
- fraudulent messages, recipient action, payment diversion, or financial loss;
- one continuous incident spanning all nine source files.

The source repository states that the logs were created through simulated Microsoft 365 activity. The records are therefore treated as independent detection-engineering samples, not as a complete real-world BEC case.

## Investigation objective

Determine whether the available Exchange audit records show mailbox changes that could:

1. provide additional access to mailboxes;
2. forward messages to other recipients;
3. hide selected or all incoming messages;
4. support a BEC investigation;
5. establish account compromise or business impact.

## Data sources

- Microsoft 365 ExchangeAdmin audit records
- Five JSON files
- Four CSV exports containing JSON in the AuditData field
- Processed timeline: evidence/processed/mailbox-activity-timeline.csv

The raw samples originated from the public [blueteam0ps/det-eng-samples](https://github.com/blueteam0ps/det-eng-samples) repository and are licensed under Apache-2.0.

## Key findings

| Behaviour | Unique events | Assessment |
| --- | ---: | --- |
| Mailbox delegation | 2 | Successful SendAs and FullAccess grants; authorisation not available |
| Email hiding | 4 | Rules deleted, marked as read, or moved messages to low-visibility folders |
| Email forwarding | 6 | Successful mailbox-level and Inbox-rule forwarding configuration |
| Total | 12 | Suspicious BEC-related configuration changes; malicious intent not confirmed |

## Evidence structure

~~~text
scenario-08-business-email-compromise-and-mailbox-rule-investigation/
├── README.md
├── dataset-decision-record.md
├── triage-note.md
├── investigation-report.md
├── mailbox-rule-analysis.md
├── recommended-actions.md
├── scripts/
│   └── build-mailbox-timeline.py
└── evidence/
    ├── raw/                         # local only; ignored by Git
    └── processed/
        └── mailbox-activity-timeline.csv
~~~

## Reproduce the timeline

From the repository root:

~~~bash
SCENARIO_DIR="04-email-and-identity-investigations/scenario-08-business-email-compromise-and-mailbox-rule-investigation"

python3 "$SCENARIO_DIR/scripts/build-mailbox-timeline.py" \
  "$SCENARIO_DIR/evidence/raw" \
  "$SCENARIO_DIR/evidence/processed"
~~~

Expected validation:

~~~text
Validation passed: expected 14 raw records and 12 unique events.
~~~

The script:

- reads JSON objects, JSON arrays, and line-delimited JSON;
- reads CSV files with csv.DictReader;
- parses the nested AuditData JSON value;
- deduplicates primarily by OrganizationId and event Id;
- writes a UTC-ordered CSV timeline.

## MITRE ATT&CK mapping

| Technique | Evidence |
| --- | --- |
| [T1098.002 - Additional Email Delegate Permissions](https://attack.mitre.org/techniques/T1098/002/) | Add-RecipientPermission and Add-MailboxPermission |
| [T1114.003 - Email Forwarding Rule](https://attack.mitre.org/techniques/T1114/003/) | Set-Mailbox and New-InboxRule forwarding changes |
| [T1564.008 - Email Hiding Rules](https://attack.mitre.org/techniques/T1564/008/) | DeleteMessage, MarkAsRead, MoveToFolder, and StopProcessingRules |

ATT&CK mappings describe the observed configuration behaviours. They do not prove that an adversary performed them.

## Documents

- [Dataset decision record](dataset-decision-record.md)
- [Triage note](triage-note.md)
- [Investigation report](investigation-report.md)
- [Mailbox rule analysis](mailbox-rule-analysis.md)
- [Recommended actions](recommended-actions.md)

## Portfolio talking point

Analysed nine Microsoft 365 audit samples, corrected a parser to handle nested CSV AuditData, deduplicated 14 records into 12 unique events, and identified mailbox delegation, email-hiding, and forwarding behaviours while clearly separating confirmed configuration changes from unproven account compromise, exfiltration, and financial impact.

