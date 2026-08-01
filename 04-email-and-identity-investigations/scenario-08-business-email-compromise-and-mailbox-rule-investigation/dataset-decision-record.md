# Dataset Decision Record

## Decision

**Use with restrictions**

The dataset is suitable for learning Microsoft 365 mailbox investigation and evidence-bound incident reporting. It is not suitable for reconstructing a single end-to-end BEC incident because it contains multiple independent simulated activities and does not include authentication, message-trace, mailbox-access, or financial evidence.

## Source

- Repository: [blueteam0ps/det-eng-samples](https://github.com/blueteam0ps/det-eng-samples)
- Dataset directory: [dataset](https://github.com/blueteam0ps/det-eng-samples/tree/main/dataset)
- Licence: Apache-2.0
- Source description: Microsoft 365 adversary simulations performed through PowerShell, Microsoft APIs, and the Microsoft 365 web portal, with logs extracted using Microsoft Extractor Suite

## Selected files

| # | File | Format | Primary behaviour |
| ---: | --- | --- | --- |
| 1 | t1098.002_Mail Account Delegation full access permissions.json | JSON | FullAccess mailbox delegation |
| 2 | t1098.002_Mail account delegation-SendAs permission.csv | CSV | SendAs recipient permission |
| 3 | t1114.003_Forward_Rule_Multi_Users_Same_Forward_dest.json | JSON | Three mailbox-level forwarding changes |
| 4 | t1114.003_rule_mail_forward_same_dest.json | JSON | Two Inbox rules forwarding to one recipient |
| 5 | t1114_Set-Mailbox-ForwardSMTPAddress.csv | CSV | Mailbox-level SMTP forwarding |
| 6 | t1564.008_New inbox rule to delete email.csv | CSV | Subject-based deletion rule |
| 7 | t1564.008_Update existing mailbox rule using Set-InboxRule.csv | CSV | Subject-based move-to-Deleted-Items rule |
| 8 | t1564.008_markasread_delete_all_email.json | JSON | Mark-as-read and deletion rule |
| 9 | t1564.008_rule_mark_as_read_move.json | JSON | Mark-as-read and Archive rule |

## Safety

- The selected files contain log records only.
- No executable, script payload, credential, or malicious attachment is required.
- Analysis is performed locally and offline after download.
- Addresses and identifiers are part of a public simulated dataset; external destinations are defanged in narrative documents where practical.

## Data type and authenticity

The records are simulated Microsoft 365 audit data produced for detection-engineering use. They contain realistic Exchange audit fields and successful configuration operations, but they do not represent one continuous production incident.

This distinction controls the investigation language:

- the logged operations can be described as confirmed;
- malicious intent and account compromise cannot be inferred solely from the operation names;
- separate files are not joined into one attack chain without shared evidence;
- BEC and financial impact remain unconfirmed.

## Coverage

Available fields include:

- CreationTime
- Operation
- ResultStatus
- UserId and UserType
- ClientIP
- OrganizationId and OrganizationName
- ObjectId
- Parameters
- SessionId and, in some JSON records, UniqueTokenId
- event Id

The dataset supports analysis of:

- mailbox delegation;
- SendAs and FullAccess permissions;
- mailbox-level forwarding;
- Inbox-rule forwarding;
- message deletion, marking as read, and movement to folders;
- limited correlation by time, tenant, actor, source IP, session, target, and forwarding destination.

## Limitations

The following evidence is not available:

- Entra ID sign-in and authentication details;
- MFA and Conditional Access results;
- user and administrator baselines;
- change tickets and permission approvals;
- current mailbox, rule, and delegation state;
- mailbox GUID-to-owner directory mapping for all targets;
- message trace and delivery status;
- MailItemsAccessed, send, delete, and mailbox-content records;
- recipient replies or payment activity;
- endpoint, proxy, DNS, and EDR telemetry.

These gaps prevent confirmation of:

- unauthorised access;
- compromised credentials or sessions;
- successful forwarding of actual messages;
- data exfiltration;
- fraudulent sending;
- financial impact.

## Parsing and validation

The five JSON files store audit events directly. The four CSV files store one audit record per row, with the full event encoded as JSON in the AuditData column.

The final parser handles both formats and deduplicates using:

~~~text
OrganizationId + event Id
~~~

If an event Id is absent, the script falls back to a SHA-256 hash of the canonical event payload.

Validation result:

~~~text
9 source files
14 raw event records
12 unique events
2 duplicate copies removed
~~~

## Evidence preservation and publication

- Keep the nine downloaded source files in evidence/raw.
- Record SHA-256 values locally.
- Keep evidence/raw excluded through .gitignore.
- Publish the parser, the processed timeline, and narrative findings only.
- Review processed output for addresses, tokens, tenant identifiers, and other fields before staging.
- Retain source attribution and Apache-2.0 licence information.

## Final suitability decision

The dataset is accepted for Scenario 08 because it provides verifiable Exchange audit evidence for mailbox-rule, forwarding, and delegation analysis. It must be presented as a multi-sample investigation of BEC-related behaviours, not as a confirmed compromise or a single real-world BEC incident.

