# Detection Opportunities

## Case

**Scenario 06 – Phishing Email Investigation**

## Detection Objective

Detect phishing emails that use financial or purchase-related social
engineering to direct recipients to externally hosted executable files.

The strongest case-specific indicator is:

    hxxp://107[.]175[.]247[.]199/loader/install[.]exe

The investigation confirmed the malicious email and malicious URL, but did
not establish delivery to a specific mailbox, user interaction, payload
execution, or compromise.

---

## 1. Available Detection Indicators

| Indicator | Detection value | Limitation |
|---|---|---|
| Complete malicious URL | High | Historical IOC; availability may change |
| Hosting IP `107[.]175[.]247[.]199` | Medium to high | IP may host unrelated content |
| URL path `/loader/install.exe` | High when combined with host | Path can change |
| Filename `install.exe` | Low by itself | Generic filename |
| Plain HTTP executable download | Medium to high | Requires proxy or endpoint visibility |
| Direct-IP URL | Contextually suspicious | Not independently malicious |
| Purchase-related pretext | Contextual | Also occurs in legitimate email |
| `undisclosed-recipients:` | Contextual | Not independently malicious |
| Sender and subject | Campaign-search value | Can be changed or reused |

The complete URL is more specific to this case than the IP address or
filename alone.

---

## 2. Email Gateway Detection

### 2.1 Exact IOC Matching

Search inbound and historical email telemetry for:

- The complete malicious URL.
- The hosting IP address.
- The URL path `/loader/install.exe`.
- The sender address.
- The message subject.
- The Message-ID.
- Purchase-reference and access-code text from the email body.

Suggested logic:

    IF an inbound email contains
       "107[.]175[.]247[.]199/loader/install.exe"
    THEN generate a high-confidence malicious-email alert
    AND quarantine or remove matching messages
    AND identify all recipients

This is the highest-confidence email-layer detection for this campaign.

An exact IOC rule will not detect later messages if the attacker changes the
IP address, URL path, or filename.

### 2.2 Direct-IP Executable Link

Detect inbound email containing a URL that:

1. Uses an IP address rather than a domain name.
2. Uses unencrypted HTTP.
3. References an executable or script file.
4. Appears in financial, purchase, invoice, receipt, delivery, or
   access-related content.

Vendor-neutral analytic:

    IF direction = inbound
    AND url_host is an IPv4 or IPv6 literal
    AND url_scheme = "http"
    AND url_path ends with a high-risk extension
    THEN alert

Relevant extensions may include:

    .exe, .msi, .scr, .hta, .js, .vbs, .ps1, .bat, .cmd

Suggested severity:

**Medium to High**, depending on delivery status, reputation, recipient
interaction, and affected-user context.

Tuning considerations:

- Allowlist documented internal or vendor systems only after validation.
- Do not allowlist an entire hosting provider or IP range because one
  legitimate system uses it.
- Increase confidence when visible link text differs from the real
  destination.
- Increase confidence when the message targets multiple unrelated recipients.

### 2.3 Authentication and Sender Analysis

Where authoritative email-gateway results are available, inspect:

- SPF result.
- DKIM result.
- DMARC result.
- Header From and envelope-sender alignment.
- Reply-To differences.
- Display-name impersonation.
- Newly observed or unusual external senders.

Authentication failure or misalignment may strengthen a phishing verdict,
but authentication success does not prove that a message is benign. An
attacker may use a compromised legitimate account or a domain they control.

The current EML must not be assigned a definitive organisational SPF, DKIM,
or DMARC verdict without the receiving gateway's authoritative results.

### 2.4 Campaign Clustering

Search for related messages using combinations of:

- Sender.
- Subject.
- Message-ID or related identifier patterns.
- Complete URL.
- Hosting IP.
- URL path.
- HTML structure.
- Repeated wording.
- Purchase reference.
- Access code.
- Similar financial lures.

This may identify additional recipients even when related messages contain
slightly different subjects or sender addresses.

---

## 3. Proxy and Secure Web Gateway Detection

### 3.1 Exact URL Access

Search proxy and browser telemetry for requests to:

    107[.]175[.]247[.]199/loader/install[.]exe

Suggested logic:

    IF destination_ip = "107[.]175[.]247[.]199"
    AND url_path = "/loader/install.exe"
    THEN generate a high-confidence malicious-download alert

A matching request would establish interaction with the delivery
infrastructure. It would not by itself prove that the download completed or
that the executable ran.

### 3.2 Executable Download over Plain HTTP

Detect outbound web requests where:

- The destination is an external IP address.
- The request uses HTTP rather than HTTPS.
- The requested path ends in an executable or script extension.
- The initiating application or preceding event relates to email or webmail.

Suggested logic:

    IF outbound_http_request = true
    AND destination is external
    AND host is an IP literal
    AND requested_file has a high-risk extension
    THEN alert

This behavioural rule is more resilient than an exact IOC rule because it
may detect similar campaigns using different infrastructure.

### 3.3 Important DNS Limitation

The malicious URL uses a literal IP address rather than a domain name. A
browser may therefore connect directly to the IP without performing a DNS
lookup.

Consequently:

- DNS logs alone may not record the activity.
- A negative DNS search does not exclude user interaction.
- Proxy, firewall, NetFlow, browser, and endpoint telemetry are required.

---

## 4. Firewall and Network Detection

Search firewall, NetFlow, network-security monitoring, and proxy logs for
connections to:

    107[.]175[.]247[.]199

A matching outbound connection may support evidence of interaction, but a
basic firewall record normally cannot prove:

- The complete requested URL.
- Which file was downloaded.
- Whether the download completed.
- Whether the file executed.
- Whether the connection originated from this email.

Where possible, correlate the connection with:

- Source user.
- Source host.
- Browser or process telemetry.
- Email delivery time.
- Proxy URL records.
- EDR file events.

Blocking considerations:

- Block the complete URL at the proxy or secure web gateway.
- Blocking the individual IP may be appropriate after checking business
  dependencies.
- Do not block the entire `107.175.240.0/21` prefix based only on this case.

---

## 5. Endpoint and EDR Detection

### 5.1 Suspicious File Creation

Search for creation of:

    install.exe

in locations such as:

- User Downloads folders.
- Browser download caches.
- Temporary directories.
- Email-client caches.
- Desktop folders.
- Public or shared user directories.

Filename-only detection has low precision because `install.exe` is generic.
Combine it with:

- Download-source URL.
- File hash.
- Creation time.
- Mark-of-the-Web or Zone Identifier information.
- Initiating browser or email client.
- Subsequent execution.

### 5.2 Browser-Initiated Execution

Alert when a browser or email client downloads and launches a newly created
executable.

Relevant process relationships may include:

    email client or webmail
        -> browser
        -> downloaded executable

Higher-risk follow-on relationships may include:

    browser
        -> install.exe
        -> powershell.exe, cmd.exe, rundll32.exe, regsvr32.exe,
           wscript.exe, cscript.exe, or another unusual child process

These child-process examples are detection opportunities. They were not
observed in the available evidence and must not be reported as events that
occurred in this case.

### 5.3 Execution from User-Writable Locations

Detect newly downloaded executables launched from:

- Downloads.
- AppData.
- Temporary directories.
- Browser cache paths.
- Other user-writable locations.

Increase severity when execution is followed by:

- Persistence creation.
- Security-control modification.
- Credential access.
- Unusual outbound connections.
- Scripting-engine or command-shell execution.
- Access to sensitive systems.

---

## 6. SIEM Correlation Opportunities

### 6.1 Email to Web Access

    Inbound email containing suspicious URL
        -> same recipient or device accesses the URL
        -> within a reasonable time window

Result:

**High-priority phishing interaction alert**

### 6.2 Email to Download

    Inbound email containing executable link
        -> proxy records executable download
        -> source maps to the recipient or recipient device

Result:

**High-priority potential malware download**

### 6.3 Email to Endpoint Execution

    Inbound phishing email
        -> recipient accesses malicious URL
        -> browser creates executable
        -> executable starts

Result:

**Potential endpoint compromise – immediate escalation**

### 6.4 Post-Execution Network Activity

    Executable launched
        -> persistence or suspicious child process
        -> connection to rare or malicious infrastructure

Result:

**High-confidence endpoint incident**

Severity must also consider asset criticality, user privilege, control
response, and the scope of subsequent activity.

---

## 7. Detection Priorities

| Priority | Detection | Primary data source |
|---|---|---|
| 1 | Exact malicious URL in email | Email gateway |
| 2 | Exact URL access or download | Proxy / secure web gateway |
| 3 | Connection to hosting IP | Firewall / NetFlow |
| 4 | Browser-created and executed `install.exe` | EDR |
| 5 | Direct-IP HTTP executable link in email | Email gateway |
| 6 | Email-to-click-to-execution correlation | SIEM |
| 7 | Similar-message campaign clustering | Email gateway / SIEM |

Exact IOC rules should be deployed first for immediate case response.
Behavioural and correlation rules provide broader and more durable coverage.

---

## 8. Alert Escalation Model

| Evidence | Suggested handling |
|---|---|
| Matching message quarantined before delivery | Record confirmed malicious email and prevented delivery |
| Matching message delivered without interaction evidence | Medium; investigate recipient and telemetry |
| URL accessed by recipient or device | High-priority investigation |
| Executable downloaded | High; begin endpoint triage |
| Executable launched | Escalate as potential endpoint compromise |
| Persistence, C2, credential access, or lateral movement | High or Critical according to organisational impact |

These are portfolio recommendations rather than a universal severity
standard. An organisation should apply its own severity matrix.

---

## 9. Telemetry Search Windows

Because the sample contains conflicting dates, retrospective searches should
cover both candidate periods.

Primary candidate window:

    2022-12-09 through 2022-12-12 UTC

Alternative candidate window:

    Around 2023-11-27 UTC

Include a reasonable buffer before and after each window for timezone
differences, processing delays, and clock inconsistencies.

---

## 10. Detection and Visibility Gaps

The portfolio evidence does not include:

- Authoritative email-gateway delivery records.
- Mailbox audit records.
- DNS telemetry.
- Proxy or secure web gateway logs.
- Firewall or NetFlow records.
- Endpoint or EDR telemetry.
- Identity-provider logs.
- Confirmed recipient information.
- The payload file or its hash.

These are telemetry gaps, not proof that organisational controls failed.

Because these sources were unavailable, the investigation cannot determine:

- Whether the message reached a real mailbox.
- Whether additional recipients received similar messages.
- Whether the link was clicked.
- Whether the executable was downloaded or launched.
- Whether an endpoint or account was compromised.

---

## 11. Validation and Tuning

Before production deployment:

1. Test exact-IOC rules using safe, defanged test data.
2. Confirm that URL extraction covers HTML links and redirects.
3. Confirm whether proxy logs retain the complete path or only the host.
4. Confirm that endpoint telemetry records browser download origin.
5. Validate user-to-device identity mapping.
6. Test direct-IP executable-link rules against legitimate business mail.
7. Document approved exceptions rather than broadly suppressing alerts.
8. Measure false-positive rate and detection latency.
9. Retest SIEM correlations after field or schema changes.
10. Review IOC rules regularly because infrastructure changes.

Do not request, download, or execute the historical payload merely to test
the detection.

---

## 12. MITRE ATT&CK Alignment

| Technique | Detection relevance |
|---|---|
| `T1566.002 – Phishing: Spearphishing Link` | Detect the malicious link in email and correlate it with web activity |
| `T1204.001 – User Execution: Malicious Link` | Investigate evidence that the recipient accessed the link |

The evidence confirms the phishing-link mechanism. It does not confirm
actual user execution.

---

## 13. References

- MITRE ATT&CK T1566.002 – Phishing: Spearphishing Link:
  https://attack.mitre.org/techniques/T1566/002/
- MITRE ATT&CK T1204.001 – User Execution: Malicious Link:
  https://attack.mitre.org/techniques/T1204/001/
- DMARC specification:
  https://www.rfc-editor.org/rfc/rfc7489.html
