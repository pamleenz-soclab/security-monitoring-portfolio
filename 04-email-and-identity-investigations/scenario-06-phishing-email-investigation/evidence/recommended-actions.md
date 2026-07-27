# Recommended Actions

## Case

**Scenario 06 – Phishing Email Investigation**

## Decision Basis

The available evidence confirms that the investigated message contained a
malicious link directing users to:

    hxxp://107[.]175[.]247[.]199/loader/install[.]exe

The investigation does not establish:

- Authoritative organisational delivery.
- A confirmed recipient.
- User interaction.
- Payload download.
- Payload execution.
- Credential disclosure.
- Endpoint or account compromise.

The actions below therefore distinguish between confirmed facts,
investigative priorities, and conditional response actions.

---

## 1. Response Objectives

The immediate objectives are to:

1. Preserve the available evidence.
2. Determine whether the message reached organisational mailboxes.
3. Identify all recipients and related campaign messages.
4. Prevent further access to the malicious URL.
5. Establish whether any user accessed, downloaded, or executed the file.
6. Contain affected endpoints or accounts only when supported by evidence.
7. Improve detection coverage for similar phishing campaigns.

---

## 2. Immediate Actions

### 2.1 Preserve Evidence

Retain the following evidence in its original form:

- The original EML file.
- The original ZIP archive.
- Cryptographic hashes of both files.
- Parsed email headers.
- Decoded plain-text and HTML bodies.
- Extracted and defanged indicators.
- Threat-intelligence results with collection timestamps.
- Analyst commands and investigation notes.

Do not edit the original EML or replace it with a forwarded copy.

Store analyst-generated output separately from raw evidence and document:

- Evidence source.
- Collection time.
- Analyst identity.
- File hash.
- Any transformation or decoding performed.

### 2.2 Determine Delivery and Recipient Scope

Search authoritative email-gateway and mailbox records for:

- Complete malicious URL.
- Hosting IP `107[.]175[.]247[.]199`.
- URL path `/loader/install.exe`.
- Sender `redacted-sender[@]uptc[.]edu[.]co`.
- Subject `COMMERCIAL PURCHASE RECEIPT ONLINE 27 NOV`.
- Message-ID.
- Similar purchase-related wording.
- Related access-code or reference-number text.

For each matching message, record:

- Intended and actual recipients.
- Delivery status.
- Delivery timestamp.
- Quarantine or rejection status.
- Mailbox location.
- Whether the message was forwarded.
- Whether the user reported the message.
- Whether automated security controls modified or removed it.

Because the sample contains conflicting date indicators, search both:

    2022-12-09 through 2022-12-12 UTC

and:

    Around 2023-11-27 UTC

Include a reasonable buffer around both periods.

### 2.3 Block Confirmed Indicators

Recommended blocking priority:

1. Block the complete URL at the email gateway and secure web gateway.
2. Block requests for the specific host-and-path combination.
3. Consider blocking the individual IP after checking business dependencies.
4. Add the indicators to retrospective threat hunting.

Do not block the entire `107.175.240.0/21` network based only on this case.

Do not block the entire `uptc.edu.co` sender domain based only on one message.
The sender account may have been compromised, spoofed, or abused without the
entire domain being malicious.

Record:

- Control where the block was applied.
- Exact indicator blocked.
- Date and time.
- Rule owner.
- Expiry or review date.
- Any approved exception.

The IOC is historical. Current availability should not be treated as proof
that the infrastructure remains active or inactive.

### 2.4 Quarantine or Remove Matching Messages

If matching messages are found:

1. Preserve at least one original copy for investigation.
2. Quarantine or remove remaining copies according to organisational policy.
3. Search inboxes, deleted items, junk folders, archives, and shared mailboxes.
4. Check whether the message was forwarded internally.
5. Record every mailbox-remediation action.

Do not delete all copies before evidence preservation and scope confirmation.

### 2.5 Contact Identified Recipients

If recipients are identified, contact them promptly and without blame.

Ask whether they:

- Opened the message.
- Clicked the link.
- Saw a browser warning or download prompt.
- Downloaded `install.exe`.
- Opened or executed the file.
- Entered credentials or other information.
- Observed unusual pop-ups, processes, or system behaviour.
- Used another device to access the link.

Record the user's answers, approximate times, device used, and location.

Instruct the user not to reopen the email, revisit the URL, or launch any
downloaded file.

---

## 3. Evidence-Based Escalation Actions

| Evidence state | Recommended action |
|---|---|
| Message rejected or quarantined before delivery | Record prevented delivery, confirm no related messages, and review detection coverage |
| Message delivered but no interaction found | Remove the message, notify the recipient, and continue retrospective searches |
| Link accessed but no download confirmed | Escalate investigation and review proxy, browser, firewall, and endpoint telemetry |
| File downloaded but not executed | Quarantine the file, collect endpoint evidence, calculate its hash, and verify no execution |
| File executed | Isolate the endpoint and activate the malware or endpoint incident-response process |
| Credentials entered or exposed | Reset affected credentials, revoke sessions, review MFA and account activity |
| Persistence, command-and-control, credential access, or lateral movement found | Escalate to a high-severity incident and expand containment scope |

The absence of evidence in unavailable telemetry must not be described as
proof that interaction did not occur.

---

## 4. Endpoint Investigation

Perform endpoint investigation if evidence indicates that a recipient clicked
the link, downloaded the file, or executed it.

### 4.1 Collect Endpoint Evidence

Collect or review:

- EDR alerts and event timelines.
- Browser history and download records.
- File-creation events.
- File path, size, and cryptographic hashes.
- Mark-of-the-Web or Zone Identifier data.
- Process-creation events.
- Parent and child process relationships.
- Command-line arguments.
- Network connections.
- DNS activity, while recognising the direct-IP limitation.
- Persistence mechanisms.
- Scheduled tasks.
- Services.
- Startup locations.
- Registry run keys.
- Security-control alerts or prevention events.
- User logon and privilege information.

Relevant candidate locations include:

- Downloads.
- Desktop.
- Temporary directories.
- Browser caches.
- AppData.
- Email-client caches.
- Public or shared folders.

### 4.2 Preserve Before Remediation

Where practical and consistent with incident-response policy:

1. Capture relevant volatile and endpoint evidence.
2. Preserve EDR event data.
3. Record active processes and network connections.
4. Record the file path and hash.
5. Preserve relevant logs.
6. Then remove or quarantine malicious artifacts.

Do not execute the file to determine what it does.

Any malware analysis must occur only in an authorised, isolated analysis
environment using an evidence-preserving procedure.

### 4.3 Endpoint Containment

Isolate the endpoint when:

- The executable was launched.
- Malicious process activity is detected.
- Persistence is identified.
- Suspicious outbound communication is observed.
- The endpoint's state cannot be trusted.

A click alone warrants urgent investigation but does not automatically prove
endpoint compromise.

Record the reason for isolation and the person who authorised it.

---

## 5. Identity and Account Actions

The investigated link appears to reference an executable rather than a
credential-harvesting page. Credential exposure is therefore not confirmed.

Do not automatically reset or disable accounts solely because the email
exists.

If credential entry, token theft, or suspicious account activity is identified:

1. Reset the affected password.
2. Revoke active sessions and refresh tokens.
3. Review recent sign-ins and authentication failures.
4. Review MFA-method changes.
5. Review mailbox forwarding rules.
6. Review inbox rules.
7. Review OAuth or application consent grants.
8. Check for account recovery-information changes.
9. Search for unusual email sending or internal phishing.
10. Apply temporary access restrictions where justified.

Coordinate disruptive identity actions with the incident owner and record the
business impact.

---

## 6. Network and Web Investigation

Search proxy, firewall, NetFlow, browser, and endpoint telemetry for:

    107[.]175[.]247[.]199

Where URL-level telemetry exists, search for:

    /loader/install.exe

For each matching connection, identify:

- Source IP.
- Source endpoint.
- Associated user.
- Timestamp.
- Destination port.
- HTTP method and response status.
- Bytes transferred.
- Browser or initiating process.
- Whether the file download completed.
- Subsequent endpoint activity.

Because the URL uses a literal IP address, a browser may connect without making
a DNS request. A negative DNS search does not exclude access.

A firewall connection to the IP supports possible interaction, but does not by
itself prove that the executable was downloaded or launched.

---

## 7. Eradication and Recovery

If malicious execution or persistence is confirmed:

1. Remove or quarantine malicious files.
2. Remove confirmed persistence mechanisms.
3. Terminate malicious processes.
4. Block associated network indicators.
5. Patch exploited software if a vulnerability was involved.
6. Reset exposed credentials and secrets.
7. Rebuild the endpoint when integrity cannot be confidently restored.
8. Restore required data from a known-good source.
9. Re-enable security controls.
10. Conduct a post-remediation EDR and vulnerability scan.

Return an isolated endpoint to service only when:

- Malicious processes are absent.
- Persistence has been removed.
- Required credentials have been rotated.
- Security controls are functioning.
- Follow-up monitoring is enabled.
- The incident owner approves reconnection.

Continue enhanced monitoring after recovery for:

- Repeated connections to malicious infrastructure.
- New persistence.
- Unusual authentication.
- Privilege escalation.
- Internal reconnaissance.
- Lateral movement.
- Further phishing messages from affected accounts.

---

## 8. Communication and Coordination

Assign an incident owner if delivery or interaction is confirmed.

Notify relevant teams according to organisational policy:

- SOC or security operations.
- Email administration.
- Endpoint or EDR team.
- Network security team.
- Identity team.
- Service desk.
- The affected user's manager, where appropriate.
- Privacy, legal, or compliance teams where required.

User communication should:

- Explain what was observed.
- State what the user should and should not do.
- Avoid blame.
- Provide a reporting contact.
- Explain any device or account restrictions.
- Give an expected next update.

Do not contact the apparent sender or suspected attacker directly unless
authorised by the incident owner.

External reporting to hosting providers, email providers, law enforcement, or
national cyber-security authorities should follow organisational policy.

---

## 9. Longer-Term Security Improvements

### 9.1 Email Security

Consider implementing or improving:

- URL extraction from plain-text and HTML email.
- Detection of direct-IP links.
- Detection of executable links over plain HTTP.
- URL reputation checks.
- Time-of-click URL protection.
- Attachment and URL sandboxing.
- Retrospective message search and removal.
- Campaign clustering.
- SPF, DKIM, and DMARC monitoring.
- External-sender labelling.

Email authentication results should be used as supporting evidence rather than
as the sole phishing verdict.

### 9.2 Endpoint Security

Improve:

- Browser-download telemetry.
- EDR visibility for file creation and execution.
- Mark-of-the-Web enforcement.
- Application control.
- Blocking execution from user-writable locations where practical.
- Detection of browser-to-executable process chains.
- Detection of suspicious child processes.
- Central log retention.

### 9.3 Network Security

Improve:

- Full URL logging at secure web gateways where permitted.
- Direct-IP HTTP download detection.
- File-type inspection.
- User-to-device attribution.
- Proxy, firewall, and endpoint timestamp consistency.
- Correlation between email, web, and endpoint telemetry.

DNS monitoring alone is insufficient for direct-IP URLs.

### 9.4 SIEM Correlation

Prioritise correlations for:

    malicious email delivered
        -> recipient accesses URL
        -> browser downloads executable
        -> executable launches
        -> suspicious follow-on activity

Validate field mappings and time synchronisation between:

- Email gateway.
- Identity provider.
- Proxy.
- Firewall.
- DNS.
- EDR.
- Asset inventory.
- User-directory data.

### 9.5 User Awareness

Use the case as a safe training example covering:

- Unexpected purchase or receipt messages.
- Links using raw IP addresses.
- Executable downloads from email.
- Urgent access-code instructions.
- Reporting suspicious email.
- Avoiding interaction with suspicious links.

Use defanged screenshots or reconstructed examples. Do not expose users to the
live historical URL or payload.

---

## 10. Action Priorities

| Priority | Action | Owner |
|---|---|---|
| P1 | Preserve the EML, archive, hashes, and analysis records | Incident analyst |
| P1 | Search authoritative mail records and identify recipients | Email security team |
| P1 | Block the complete malicious URL | Email / web security team |
| P1 | Determine whether the link was accessed or the file executed | SOC / EDR team |
| P2 | Quarantine matching messages after preservation | Email security team |
| P2 | Contact identified recipients | SOC / service desk |
| P2 | Isolate endpoints if execution or compromise is indicated | Endpoint team |
| P2 | Review identity activity if credential exposure is suspected | Identity team |
| P3 | Deploy direct-IP executable-link detection | Detection engineering |
| P3 | Implement cross-source SIEM correlations | Detection engineering |
| P3 | Conduct lessons learned and control-gap review | Incident owner |

Specific team names may be adjusted to the organisation's operating model.

---

## 11. Closure Criteria

The investigation may be closed when the incident owner confirms that:

- Available email records have been searched.
- Matching messages and recipients have been documented.
- Mailbox remediation is complete where required.
- Relevant web and network telemetry has been reviewed.
- Relevant endpoints have been investigated.
- No unresolved evidence of execution or compromise remains.
- Confirmed malicious artifacts have been removed.
- Exposed credentials have been remediated.
- Blocking and monitoring controls are active.
- Evidence and response actions are documented.
- Residual risks and telemetry gaps are recorded.

If telemetry is unavailable, close the case with an explicit statement that
impact could not be fully determined. Do not replace missing evidence with an
assumption of no compromise.

---

## 12. Safety and Scope Limitations

Do not:

- Request or download the historical payload merely to complete the portfolio.
- Execute the payload on a personal or production device.
- Browse directly to the malicious URL.
- Treat current URL availability as proof of historical behaviour.
- Claim user execution without endpoint or user-interaction evidence.
- Claim account compromise without identity evidence.
- Apply broad network or domain blocks without impact assessment.
- Delete original evidence before preservation.

These recommendations are based on a static public sample and passive
threat-intelligence research. Final production actions should follow the
organisation's incident-response, legal, privacy, and change-management
procedures.
