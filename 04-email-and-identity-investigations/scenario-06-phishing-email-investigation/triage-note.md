# Triage Note

## Case Identification

| Field | Value |
|---|---|
| Scenario | Scenario 06 – Phishing Email Investigation |
| Case type | Suspicious email and malicious-link investigation |
| Triage verdict | True Positive – Malicious phishing email |
| Initial severity | Medium |
| Confidence | High confidence in maliciousness; impact not established |
| Disposition | Escalate for recipient scoping and interaction investigation |

## Email Summary

| Field | Observed value |
|---|---|
| From | ERIKA JOHANA LOPEZ VALIENTE `<redacted-sender[@]uptc[.]edu[.]co>` |
| Return-Path | `<redacted-sender[@]uptc[.]edu[.]co>` |
| To | `undisclosed-recipients:;` |
| Subject | `COMMERCIAL PURCHASE RECEIPT ONLINE 27 NOV` |
| Date header | Thu, 9 Dec 2022 09:58:26 +0100 |
| Content type | `multipart/alternative` |
| Body formats | Plain text and HTML |
| Embedded attachment | None identified |
| Malicious link | `hxxp://107[.]175[.]247[.]199/loader/install[.]exe` |

## Triage Findings

The message is assessed as a malicious phishing email because it combines
purchase-themed social engineering with a direct link to a Windows executable.

The most significant indicators are:

- An unexpected commercial purchase or receipt theme.
- An undisclosed recipient list.
- A direct IPv4 address instead of a normal web domain.
- Unencrypted HTTP delivery.
- A URL path ending in `install.exe`.
- Consistent malicious-link targeting in both the plain-text and HTML bodies.
- Instructions intended to persuade the recipient to access the external content.

The message did not contain the executable as an email attachment. Instead, it
attempted to direct the recipient to an externally hosted payload.

The available routing headers show processing through Microsoft-hosted mail
infrastructure, but this does not establish that the visible sender was trustworthy.
The sender account could have been compromised, abused, or spoofed. Available
evidence is insufficient to determine the exact sender-abuse mechanism.

Timestamp and message-content inconsistencies were also identified. These reduce
confidence in the exact campaign and delivery timeline but do not change the
malicious-content verdict.

## Severity Rationale

The initial severity is assessed as **Medium** because:

- The email contains a link to an executable payload.
- Successful interaction could lead to endpoint compromise.
- No organisational recipient has been confirmed.
- No user click, payload download, execution, credential exposure, or compromise
  has been established.

Escalate severity if further evidence confirms:

- Delivery to an organisational mailbox.
- User interaction with the URL.
- Download or execution of `install.exe`.
- Malicious endpoint activity.
- Credential or session compromise.
- Persistence, command-and-control, or lateral movement.

## Confirmed Facts

- The analysed EML is a valid MIME email containing plain-text and HTML bodies.
- Both body formats reference the same suspicious resource.
- The link uses the literal IP address `107[.]175[.]247[.]199`.
- The path references `/loader/install.exe`.
- The original ZIP and extracted EML were preserved and hashed.
- The email content is malicious.

## Not Established

The available static sample does not establish:

- Authoritative organisational delivery.
- A confirmed recipient.
- User interaction.
- Payload download.
- Payload execution.
- Credential disclosure.
- Endpoint compromise.
- Account compromise.
- Persistence or lateral movement.

Missing telemetry must not be interpreted as evidence that no interaction occurred.

## Initial Response Priorities

1. Preserve the original ZIP, EML, hashes, and analysis records.
2. Search authoritative mail systems for the sender, subject, Message-ID, URL,
   hosting IP, and similar messages.
3. Identify actual recipients and delivery status.
4. Block the complete malicious URL where operationally appropriate.
5. Quarantine matching messages after preserving evidence.
6. Review proxy, firewall, browser, and EDR telemetry for access or download.
7. Isolate an endpoint only when execution or other compromise evidence is found.
8. Review identity telemetry if credential exposure or suspicious sign-ins are
   identified.

## MITRE ATT&CK Context

| Technique | Relevance |
|---|---|
| T1566.002 – Phishing: Spearphishing Link | The email contains a malicious external link |
| T1204.001 – User Execution: Malicious Link | Potential next step if a recipient follows the link; not observed |
| T1105 – Ingress Tool Transfer | Potential if the executable is downloaded; not observed |

Only the phishing-link technique is directly supported by the email artifact.
User execution and payload transfer remain possible follow-on behaviours rather
than confirmed events.

## Evidence References

- `evidence/sample-hashes.txt`
- `evidence/header-authentication.txt`
- `evidence/body-structure.txt`
- `evidence/body-link-comparison.txt`
- `evidence/html-link-details.txt`
- `evidence/email-timeline.txt`
- `evidence/timestamp-consistency.txt`
- `evidence/ioc-inventory.txt`
- `evidence/threat-intelligence-results.txt`
- `evidence/impact-assessment.txt`
- `evidence/incident-classification-and-mitre-attack.txt`
- `evidence/detection-opportunities.md`
- `evidence/recommended-actions.md`

## Final Triage Decision

This is a **True Positive malicious phishing email** containing an executable
download link. The maliciousness of the message is confirmed, but organisational
delivery and user impact remain undetermined. The case should proceed to recipient
scoping, retrospective search, and interaction investigation without claiming that
an endpoint or account was compromised.
