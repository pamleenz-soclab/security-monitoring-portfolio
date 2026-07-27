# Scenario 06 – Phishing Email Investigation

## Overview

This scenario documents a static and offline investigation of a phishing
email that used a commercial purchase receipt theme to deliver a link to a
Windows executable.

The investigation followed an enterprise SOC workflow covering email
triage, MIME analysis, header authentication, URL extraction, threat
intelligence, timestamp validation, impact assessment, MITRE ATT&CK
mapping, response recommendations, and detection improvement.

## Final Verdict

**True Positive – Malicious**

**Incident category:** Phishing / malicious link / malware-delivery attempt

The email and its malicious delivery intent were confirmed. However, the
available evidence does not confirm that a recipient clicked the link,
downloaded or executed the payload, or that an endpoint or account was
compromised.

## Key Findings

- The message impersonated a commercial purchase receipt.
- It claimed that an invoice was attached, but no MIME attachment existed.
- Both MIME body formats contained the following executable-delivery URL:

      hxxp://107[.]175[.]247[.]199/loader/install[.]exe

- The URL used:
  - A direct external IP address.
  - Unencrypted HTTP.
  - A Windows `.exe` path.
  - Infrastructure unrelated to the apparent sender domain.
- The HTML anchor was malformed, showing why raw MIME and decoded-body
  inspection may be necessary.
- Historical threat intelligence classified the URL as a malware-download
  location.
- The exact payload hash and malware family could not be confirmed because
  the executable was not downloaded.
- Authentication and timestamp metadata contained material inconsistencies.
- No authoritative mail-flow, user-click, proxy, DNS, EDR, or identity
  telemetry was available.

## Email Summary

| Field | Finding |
|---|---|
| Subject | `COMMERCIAL PURCHASE RECEIPT ONLINE 27 NOV` |
| Recipient field | `undisclosed-recipients:;` |
| Apparent sender domain | `uptc.edu.co` |
| MIME structure | `multipart/alternative` |
| Body formats | `text/plain` and `text/html` |
| MIME attachment | Not present |
| Purchase reference | `00034959` |
| Access code | `8657` |
| Payload host | `107[.]175[.]247[.]199` |
| Payload path | `/loader/install.exe` |
| Final classification | True Positive – Malicious |

The sender's complete email address is retained only in private evidence
and is not reproduced in this public portfolio summary.

## Header Authentication Findings

The final Microsoft authentication results recorded:

| Control | Result |
|---|---|
| SPF | Softfail |
| DKIM | Fail |
| DMARC | None |
| ARC | Fail |

An upstream security gateway separately recorded SPF and DMARC passes.

The differing results may reflect forwarding or gateway processing. They
do not prove legitimacy and do not establish whether the sender address
was spoofed, an authorised account was abused, or an account was
compromised.

## Timestamp Anomaly

The sample contains conflicting human-readable and machine-readable time
values.

Several human-readable fields refer to December 2022 and contain an
incorrect weekday. Multiple machine-readable values instead align around
27 November 2023.

The exact original sending and delivery time is therefore unable to be
confirmed. Enterprise hunting should cover both candidate periods:

- `2022-12-09` through `2022-12-12 UTC`.
- Around `2023-11-27 UTC`.

## Impact Assessment

| Question | Assessment |
|---|---|
| Malicious email present | Confirmed |
| Malicious URL present | Confirmed |
| Malware-delivery intent | Confirmed |
| MIME attachment present | No |
| Credential harvesting observed | Not observed |
| Tenant delivery confirmed | Unable to confirm |
| User clicked the link | Unable to confirm |
| Payload downloaded | Unable to confirm |
| Payload executed | Unable to confirm |
| Exact malware family | Unable to confirm |
| Endpoint compromise | Unable to confirm |
| Account compromise | Unable to confirm |
| Full affected scope | Unable to confirm |

This distinction prevents a confirmed phishing attempt from being
incorrectly reported as a confirmed compromise.

## MITRE ATT&CK Mapping

| Technique | Relevance | Status |
|---|---|---|
| T1566.002 – Phishing: Spearphishing Link | Email contained an external executable-delivery link | Observed |
| T1204.001 – User Execution: Malicious Link | Successful delivery would require link interaction | Required or attempted; interaction not observed |
| T1105 – Ingress Tool Transfer | Link could transfer an executable to the endpoint | Potential follow-on; transfer not observed |

No post-exploitation techniques are mapped as confirmed because endpoint
execution telemetry was unavailable.

## Investigation Workflow

1. Preserved and hashed the original ZIP and EML artefacts.
2. Identified the MIME structure without rendering the email.
3. Extracted and decoded the plain-text and HTML bodies.
4. Compared links across both MIME body formats.
5. Analysed From, Return-Path, Message-ID, Received, SPF, DKIM, DMARC,
   and ARC evidence.
6. Reviewed historical URL and IP reputation.
7. Validated inconsistent timestamp fields.
8. Assessed possible delivery, interaction, execution, and compromise.
9. Mapped evidence-supported MITRE ATT&CK techniques.
10. Developed response and detection recommendations.
11. Sanitised public evidence and verified cross-document consistency.

## Investigation Documents

- [Triage Note](triage-note.md)
- [Investigation Report](investigation-report.md)
- [Recommended Actions](evidence/recommended-actions.md)
- [Detection Opportunities](evidence/detection-opportunities.md)
- [IOC Inventory](evidence/ioc-inventory.txt)
- [Email Timeline](evidence/email-timeline.txt)
- [Impact Assessment](evidence/impact-assessment.txt)
- [Incident Classification and MITRE ATT&CK](evidence/incident-classification-and-mitre-attack.txt)
- [Threat-Intelligence Results](evidence/threat-intelligence-results.txt)
- [Timestamp Consistency Analysis](evidence/timestamp-consistency.txt)
- [Sample Hashes](evidence/sample-hashes.txt)

## Detection Opportunities

The investigation identified opportunities to:

- Inspect URLs in both plain-text and HTML MIME parts.
- Extract `href` values from malformed HTML.
- Detect invoice-themed messages that link directly to executables.
- Alert on HTTP executable links hosted on raw external IP addresses.
- Correlate file extensions with sender-to-link infrastructure mismatch.
- Use authentication inconsistencies as supporting context.
- Correlate email telemetry with proxy, DNS, firewall, and EDR events.
- Detect conflicts between human-readable and machine-readable timestamps.

## Recommended Response Direction

In a production environment, responders should:

1. Search mail-flow records for matching messages and recipients.
2. Quarantine or remove confirmed matching messages.
3. Search security telemetry for the complete URL, hosting IP, path, and
   filename.
4. Review proxy, DNS, firewall, browser, and EDR activity.
5. Isolate affected endpoints if download or execution evidence is found.
6. Perform identity containment only when exposure or compromise evidence
   supports it.
7. Avoid blocking the sender's entire domain or the hosting provider's
   entire network range based on this single message.

## Tools and Methods

- Python standard-library email and MIME parsing.
- Shell-based hashing and text inspection.
- Static header and decoded-body analysis.
- VirusTotal and URLhaus historical reputation results.
- MITRE ATT&CK mapping.
- Offline evidence preservation and sanitisation.
- Cross-document consistency checks.

## Safety and Evidence Handling

The investigation was conducted without opening the malicious URL,
connecting to the payload host, downloading the executable, or executing
malware.

The original ZIP, EML, complete raw headers, and other sensitive evidence
are retained locally and excluded from Git. Only sanitised reports,
defanged indicators, and derived evidence summaries are intended for the
public portfolio.

## Skills Demonstrated

- Phishing email triage.
- MIME and HTML analysis.
- Email-header and authentication analysis.
- IOC extraction and sanitisation.
- Threat-intelligence interpretation.
- Timeline validation.
- Evidence-based impact assessment.
- MITRE ATT&CK mapping.
- Incident-response recommendations.
- Detection-gap identification.
- Safe evidence handling and documentation.

## Evidence Limitations

This scenario used a public static sample rather than live organisational
telemetry. The investigation could not independently confirm tenant
delivery, additional recipients, user interaction, endpoint execution,
account compromise, or the exact payload family.

All conclusions are limited to the available evidence.
