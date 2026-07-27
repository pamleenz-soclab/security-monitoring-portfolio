# Investigation Report

## Case

**Scenario 06 – Phishing Email Investigation**

## Investigation Title

Commercial Purchase Receipt Phishing and Malware-Delivery Attempt

## Final Classification

**True Positive – Malicious**

**Incident category:** Email security incident / phishing / malicious link /
malware-delivery attempt

## Executive Summary

Static and offline analysis confirmed that the investigated email was a
malicious phishing message designed to direct a recipient to a Windows
executable hosted on an external IP address.

The message presented itself as a commercial purchase receipt and claimed
that an invoice document was attached. No MIME attachment was present.
Instead, the email body contained a link to:

    hxxp://107[.]175[.]247[.]199/loader/install[.]exe

The use of a direct IP address, unencrypted HTTP, an executable filename,
an unrelated hosting location, misleading invoice language, and
independent threat-intelligence results support the malicious
classification.

The available EML establishes the content and intent of the message, but
it does not provide authoritative organisational telemetry. Delivery to a
specific production mailbox, user interaction, payload download,
execution, endpoint compromise, account compromise, and the full affected
scope are therefore unable to be confirmed.

The message also contains materially inconsistent timestamp metadata.
Several machine-readable timestamps align with 27 November 2023, while
human-readable Date and Received fields contain inconsistent December
2022 dates. The exact original sending and delivery time cannot be
confirmed from the available sample.

## Investigation Objectives

The investigation was conducted to determine:

1. Whether the email was malicious.
2. Whether the message contained a malicious URL or attachment.
3. The likely social-engineering and technical delivery method.
4. Whether the sender identity could be validated.
5. Whether the evidence established delivery, user interaction, payload
   execution, or compromise.
6. Which indicators and time periods should be used for enterprise
   hunting and containment.

## Scope and Safety Controls

The investigation used a static `.eml` sample and locally extracted
evidence.

The following safety controls were maintained:

- The malicious URL was not opened.
- No connection was made to the payload-hosting IP.
- No executable was downloaded or run.
- The message was not rendered in a normal mail client.
- All malicious indicators were defanged in investigation documents.
- Original ZIP and EML artefacts were preserved separately.
- Public reports contain evidence summaries rather than the raw email.

This investigation did not have access to production mail-flow,
Safe Links, proxy, DNS, EDR, identity, or endpoint telemetry.

## Evidence Examined

The investigation examined:

- The preserved `194-PhishStrike.zip` training sample.
- The extracted `194-PhishStrike.eml`.
- Parsed and sanitised email headers.
- Decoded `text/plain` and `text/html` MIME bodies.
- Authentication and Received-header evidence.
- Extracted URL and HTML-anchor evidence.
- File hashes recorded during evidence collection.
- Static threat-intelligence results.
- Timestamp consistency analysis.
- IOC, impact, classification, response, and detection notes.

The original EML was not modified.

## Email Characteristics

| Field | Observed value or finding |
|---|---|
| Subject | `COMMERCIAL PURCHASE RECEIPT ONLINE 27 NOV` |
| Visible recipient | `undisclosed-recipients:;` |
| Apparent sender domain | `uptc.edu.co` |
| Reply-To | Not present |
| Sender header | Not present |
| Return-Path | Aligned textually with the apparent sender address |
| Message-ID | Gmail-formatted identifier observed |
| MIME structure | `multipart/alternative` |
| Body parts | `text/plain` and `text/html` |
| MIME attachment | Not present |
| Purchase reference | `00034959` |
| Access code | `8657` |
| Claimed amount | `$625.000 pesos` |

Although the message claimed that an invoice document was attached, no
attachment existed in the MIME structure. The supposed invoice was
represented by an external executable link.

This mismatch is a strong malicious indicator.

## Message Content and Social Engineering

The message used a financial purchase theme and stated that a purchase
had been successfully completed. This was likely intended to create
concern and encourage the recipient to inspect the supposed invoice.

The email attempted to increase credibility through:

- A purchase reference number.
- A monetary value.
- An access code.
- An institutional-looking sender identity.
- A professional signature.
- Repeated confidentiality notices.
- A remotely hosted institutional logo.

The message did not contain an observed credential-submission form.
Its primary observable objective was executable delivery rather than
credential harvesting.

The remote Wikimedia logo is a branding resource and is not classified
as the primary malicious IOC.

## MIME and HTML Findings

Both the plain-text and HTML bodies contained the payload-delivery URL.

The HTML anchor was malformed and was not properly closed. As a result,
one normal link-extraction method returned no links, while direct
inspection of the decoded HTML still identified the `href` value.

This demonstrates an important detection limitation: security controls
that depend only on normal HTML rendering or well-formed anchor parsing
may miss malicious URLs embedded in malformed markup.

Raw MIME and decoded-body inspection were therefore necessary to
identify the link reliably.

## Malicious URL Analysis

The confirmed malicious indicator is:

    hxxp://107[.]175[.]247[.]199/loader/install[.]exe

| Attribute | Finding |
|---|---|
| Scheme | HTTP |
| Host | `107[.]175[.]247[.]199` |
| Path | `/loader/install.exe` |
| File type implied by name | Windows executable |
| Domain used | None; direct IP address |
| Relationship to sender domain | None observed |
| Redirect behaviour | Not tested |
| Payload retrieved | No |
| Payload executed | No |

The URL is suspicious independently of reputation because it combines:

- A direct IP address instead of an expected commercial domain.
- Unencrypted HTTP delivery.
- A Windows `.exe` path.
- A sender-to-link infrastructure mismatch.
- An executable presented as an invoice document.

## Threat-Intelligence Findings

Threat-intelligence results recorded during the investigation
corroborated the malicious classification:

- VirusTotal URL result: 13 of 92 vendors classified the URL as
  malicious and one classified it as suspicious.
- VirusTotal IP result: 9 of 91 vendors classified the IP as malicious,
  with additional suspicious classifications.
- URLhaus record: ID `2381718`.
- URLhaus threat type: `Malware download`.
- URLhaus date added: `2022-10-22 12:39:04 UTC`.
- URLhaus historical status: `Offline`.
- URLhaus last reported online date: `2022-12-12`.
- A related historical MalwareBazaar entry was associated with SHA-256
  `5ca468704e7ccb8e1b37c0f7595c54df4e2f4035345b6e442e8bd4e11c58f791`
  and the signature `AsyncRAT`.

These results establish historical malicious reputation for the
delivery location. They do not prove that the related MalwareBazaar
sample was the exact payload offered to this recipient.

Because the executable was not downloaded, its hash and exact malware
family are not available. AsyncRAT, BitRAT, CoinMiner, or other
historical associations must not be treated as the confirmed payload
for this message.

## Header and Authentication Analysis

The Received chain should be read from the bottom upward. The observed
path was broadly:

1. Google mail infrastructure.
2. Trend Micro Email Security.
3. Microsoft 365 / Exchange Online Protection.
4. The final mailbox environment represented in the sample.

The final Microsoft authentication results recorded:

| Control | Result |
|---|---|
| SPF | Softfail |
| DKIM | Fail |
| DMARC | None |
| ARC | Fail |

An upstream Trend Micro ARC record separately recorded SPF and DMARC
passes.

These differing results can occur when a message passes through
multiple forwarding or security gateways. Therefore:

- The final authentication results do not validate the sender.
- The upstream pass results do not prove the message was legitimate.
- The evidence does not establish whether the address was directly
  spoofed, an authorised account was abused, or an account was
  compromised.
- The exact sender-abuse mechanism is **Unable to confirm**.

The strongest malicious finding is the message content and executable
delivery URL, not the authentication inconsistency alone.

## Timestamp Analysis

The EML contains conflicting time evidence.

The human-readable Date header states:

    Thu, 9 Dec 2022 09:58:26 +0100

However, 9 December 2022 was a Friday. Several Received fields also use
the incorrect weekday `Thu` for that date.

An `X-Received` field contains a human-readable December 2022 date, but
its embedded numerical timestamp converts to November 2023.

Several machine-readable values align closely:

| Source | Converted UTC time |
|---|---|
| X-Received numerical timestamp | `2023-11-27 14:58:38.266 UTC` |
| DKIM `t=` value | `2023-11-27 14:58:39 UTC` |
| Trend Micro received time | `2023-11-27 14:58:40.129 UTC` |
| ARC timestamps | Approximately `2023-11-27 14:58:41 UTC` |

The available sample therefore does not support a single authoritative
sending or delivery timestamp.

Enterprise searches should cover both candidate periods:

- `2022-12-09` through `2022-12-12 UTC`.
- Around `2023-11-27 UTC`.

This anomaly does not change the malicious verdict, but it reduces
confidence in timeline reconstruction from the EML alone.

## Impact Assessment

| Question | Assessment |
|---|---|
| Is the message malicious? | Confirmed |
| Is a malicious URL present? | Confirmed |
| Is malware-delivery intent present? | Confirmed |
| Is a MIME attachment present? | No |
| Is credential harvesting observed? | Not observed |
| Was delivery confirmed using authoritative tenant logs? | Unable to confirm |
| Were additional recipients identified? | Unable to confirm |
| Did a user click the link? | Unable to confirm |
| Did a host connect to the payload IP? | Unable to confirm |
| Was the executable downloaded? | Unable to confirm |
| Was the executable run? | Unable to confirm |
| Is the payload hash available? | Not available |
| Is the exact malware family confirmed? | Unable to confirm |
| Was persistence or command-and-control observed? | Not observed |
| Was an endpoint compromised? | Unable to confirm |
| Was an account compromised? | Unable to confirm |
| Is the affected-user or affected-host scope known? | Unable to confirm |

The evidence supports a confirmed malicious email incident but does not
support declaring a successful compromise.

## MITRE ATT&CK Mapping

| Technique | Relevance | Evidence status |
|---|---|---|
| T1566.002 – Phishing: Spearphishing Link | The email contained a link to an externally hosted executable | Observed |
| T1204.001 – User Execution: Malicious Link | Successful infection would require a recipient to follow the link | Attempted or required; user execution not observed |
| T1105 – Ingress Tool Transfer | The link could be used to transfer an executable to a victim host | Potential follow-on activity; transfer not observed |

No post-exploitation techniques are mapped as confirmed because no
payload execution or endpoint telemetry is available.

## Hunting Priorities

An enterprise investigation should search for:

- The complete malicious URL.
- IP address `107[.]175[.]247[.]199`.
- Path `/loader/install.exe`.
- Filename `install.exe`.
- The message subject.
- Purchase reference `00034959`.
- Access code `8657`.
- The apparent sender address recorded in the private evidence.
- Matching message identifiers and mail-flow records.
- Proxy, DNS, firewall, and EDR events involving the payload IP.
- Browser or process activity associated with `install.exe`.

Searches should cover both candidate time periods because of the
timestamp inconsistencies.

## Recommended Response Direction

The malicious message and any matching messages should be located and
quarantined or removed through authorised email-administration
procedures.

The complete URL and payload-hosting IP are appropriate
high-confidence indicators for security-control review. The entire
`107.175.240.0/21` network range and the complete `uptc.edu.co` domain
should not be blocked solely on the basis of this single message.

If interaction is identified, responders should examine the affected
endpoint for download, process, persistence, and outbound-network
evidence. Account-reset or endpoint-containment actions should be based
on confirmed exposure or compromise evidence rather than the phishing
email alone.

## Detection Opportunities

Detection engineering should consider:

- Inspecting URLs in both plain-text and HTML MIME parts.
- Extracting `href` values even when HTML is malformed.
- Alerting on financial or invoice-themed email that links directly to
  an executable.
- Detecting HTTP links to raw external IP addresses.
- Correlating `.exe` URL paths with sender-to-link domain mismatch.
- Using authentication failure or inconsistency as supporting context,
  not as the sole malicious verdict.
- Correlating email telemetry with proxy, DNS, firewall, and EDR data.
- Flagging material disagreement between human-readable and
  machine-readable timestamp fields.
- Preserving both raw-header values and normalised timestamps during
  analysis.

## Evidence Limitations

The following limitations apply:

1. The investigation used a public static sample rather than a live
   organisational incident.
2. Authoritative mailbox and message-trace records were not available.
3. User click and endpoint telemetry were not available.
4. The executable was not retrieved or analysed.
5. Threat-intelligence findings were historical and cannot establish
   the exact payload present at delivery time.
6. Timestamp metadata was materially inconsistent.
7. The full recipient and affected-host scope could not be established.
8. Sender spoofing, sender-account abuse, and sender-account compromise
   could not be distinguished from the available evidence.

## Conclusion

The investigated message is a **True Positive – Malicious phishing
email**.

It used a commercial purchase receipt theme to direct the recipient to
a historically malicious Windows-executable delivery location. The
absence of a real attachment, presence of a direct HTTP executable URL,
sender-to-link mismatch, malformed HTML, and independent reputation
results establish malicious intent.

The evidence confirms the phishing message, malicious link, and
malware-delivery attempt. It does not confirm that a user clicked the
link, downloaded or executed the payload, or that any endpoint or
account was compromised.
