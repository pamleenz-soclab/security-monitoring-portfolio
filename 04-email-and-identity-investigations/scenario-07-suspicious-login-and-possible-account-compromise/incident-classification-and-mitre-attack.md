# Incident Classification and MITRE ATT&CK Mapping

## 1. Purpose

This document classifies the identity activity observed in the supplied
Microsoft Entra sign-in dataset and maps the supported behaviour to MITRE
ATT&CK.

It distinguishes between:

- facts directly observable in the supplied sign-in telemetry;
- conclusions supported by the controlled-lab ground truth published with the
  dataset;
- reasonable investigative hypotheses; and
- behaviours that cannot be confirmed from the available evidence.

This distinction is important because concurrent successful access from
different IP addresses is a valuable detection signal, but it does not
independently prove how authenticated session material was obtained.

## 2. Incident Classification Summary

| Field | Classification |
|---|---|
| Security domain | Identity and cloud account security |
| Event type | Suspicious concurrent Microsoft Entra access |
| Incident category | Possible account takeover and browser-session hijacking |
| Telemetry-only verdict | True Positive — suspicious concurrent access |
| Ground-truth-informed verdict | True Positive — controlled browser-session hijacking simulation |
| Initial telemetry severity | Medium-high |
| Ground-truth-informed severity | High |
| Confidence in concurrent access | High |
| Confidence in cookie theft from logs alone | Low |
| Confidence in cookie theft from publisher ground truth | High |
| Affected identities | One pseudonymised Microsoft Entra user |
| Observed source IPs | `35.1.2.153` and `50.1.2.43` |
| Observed business impact | Not established |
| Investigation disposition | True Positive in a controlled simulation; production impact not demonstrated |

## 3. Directly Observed Evidence

The following findings are directly supported by the supplied Entra sign-in
records:

1. All supplied records relate to the same pseudonymised user account.

2. Successful identity-layer access occurred from two source IP addresses:
   `35.1.2.153` and `50.1.2.43`.

3. The two client environments differ in:

   - source IP address;
   - autonomous system number;
   - operating system;
   - browser; and
   - User-Agent.

4. The complete recorded activity spans approximately 107.3 seconds.

5. Successful events from the two IP addresses occur within a rolling
   five-minute interval.

6. Events `E04` and `E14` are approximately 79.6 seconds apart.

7. Nine unique records have result code `0`, indicating successful
   identity-layer access.

8. The activity includes access associated with multiple Microsoft cloud
   applications or resources, including:

   - Azure Portal;
   - OfficeHome;
   - Microsoft Graph;
   - Office365 Shell; and
   - Exchange Online.

9. Several successful events state that authentication requirements were
   satisfied through claims already present in a token.

10. The supplied Conditional Access result is `notApplied`.

11. The supplied risk-related fields contain `none`.

12. Session identifiers are not populated.

13. No identical unique token identifier is demonstrated across both source IP
    addresses.

14. Raw lines 9 and 10 contain an exact duplicate of event `E07`. This event has
    result code `50140` and is excluded from successful-event counting.

These observations establish suspicious concurrent or rapidly alternating
access. They do not directly expose the contents of a browser cookie or record
the cookie-acquisition process.

## 4. Publisher Ground Truth

Splunk describes the dataset as a controlled attack simulation in which
Evilginx2 was used to phish a Microsoft Entra user and steal session cookies.

The stolen cookies were then imported into another browser and used to access
Microsoft Entra resources from a different location and source IP address.

Tenant-specific identifiers, usernames and IP addresses were replaced before
publication.

This ground truth establishes that the dataset represents malicious
browser-session reuse in the controlled lab. It does not make every individual
technical detail visible in the supplied Entra records.

The final classification therefore uses two evidence levels:

| Evidence level | Supported conclusion |
|---|---|
| Supplied sign-in telemetry | Suspicious successful access from divergent client environments |
| Splunk controlled-lab ground truth | Session cookies were stolen and reused from another browser and location |

## 5. Verdict Rationale

### Telemetry-only verdict

The telemetry-only verdict is:

> **True Positive — suspicious concurrent access and possible account
> compromise.**

This verdict is supported by the same account successfully accessing cloud
resources from two materially different client environments within
approximately 80 seconds.

The divergence in IP address, ASN, operating system, browser and User-Agent
makes the activity more significant than an ordinary IP-address change.

However, the records do not contain a shared session identifier or another
direct artefact proving that the same browser cookie was used across both
environments.

### Ground-truth-informed verdict

When the publisher's controlled-lab description is included, the verdict is:

> **True Positive — simulated malicious browser-session hijacking involving
> stolen session-cookie reuse.**

This is stronger than the telemetry-only verdict because the ground truth
describes the attack method used to generate the records.

## 6. Severity Assessment

The recommended initial severity is **medium-high** because the sign-in
telemetry contains:

- successful access rather than failed attempts;
- two different source IP addresses;
- different autonomous systems;
- different operating systems and browsers;
- rapid access within a short rolling interval; and
- access associated with multiple Microsoft cloud resources.

The severity becomes **high** when the controlled-lab ground truth confirms
that stolen authenticated session material was used.

A critical severity is not assigned because the supplied evidence does not
demonstrate:

- privileged-account compromise;
- destructive administrative changes;
- persistence;
- data exfiltration;
- financial loss;
- service disruption; or
- confirmed impact on a production organisation.

## 7. MITRE ATT&CK Mapping

### Publisher analytic mapping

| ATT&CK ID | Technique | Tactic | Mapping basis |
|---|---|---|---|
| `T1185` | Browser Session Hijacking | Collection | Splunk's published mapping for the concurrent-session analytic and attack dataset |

Splunk maps **Azure AD Concurrent Sessions From Different IPs** to `T1185`.
That mapping is retained as publisher context. The supplied sign-in telemetry
shows the resulting divergent authenticated access, but it does not directly
record browser-process manipulation, browser pivoting, or cookie import.

### Controlled-lab ground-truth mapping

| ATT&CK ID | Technique | Tactic | Mapping basis |
|---|---|---|---|
| `T1539` | Steal Web Session Cookie | Credential Access | Publisher-stated Evilginx2 acquisition and reuse of authenticated session cookies |

`T1539` is the more direct mapping for the publisher's statement that Evilginx2
obtained authenticated web-session cookies and that the stolen cookies were
imported into another browser and reused.

The sign-in telemetry itself does not directly observe cookie theft. This
mapping is therefore supported by publisher ground truth rather than by
`azuread.log` alone.

### Why both mappings are retained

The two mappings describe different aspects of the scenario:

- `T1185` is retained because it is Splunk's published analytic/dataset mapping
  and provides the browser-session-hijacking context used by the source dataset.
- `T1539` more precisely describes the controlled-lab theft and reuse of an
  authenticated web-session cookie.

Neither technique should be represented as directly proven by the supplied
Microsoft Entra sign-in records alone.

## 8. Techniques Not Assigned from the Supplied Telemetry

The following techniques should not be presented as directly observed from this
dataset:

### Phishing

The publisher states that Evilginx2 was used to phish the user, but the supplied
evidence does not include:

- a phishing email;
- a malicious message;
- a delivery channel;
- a phishing URL;
- user-click telemetry; or
- credential-entry telemetry.

A specific `T1566` phishing sub-technique is therefore not assigned from the
sign-in records.

### Adversary-in-the-Middle

Evilginx2 is consistent with an adversary-in-the-middle authentication flow,
and MITRE describes malicious proxies such as Evilginx2 as one way session
cookies may be obtained. However, the dataset does not include proxy, DNS, TLS,
web or network evidence showing that flow.

The parent technique `T1557` may therefore be noted as attack-method context,
but it is not directly observed or assigned from the supplied Entra telemetry.
No specific `T1557` sub-technique is mapped because the available evidence does
not demonstrate one of the defined network-level sub-techniques.

### Valid Accounts: Cloud Accounts

The events show access in the security context of a valid cloud user, but they
do not establish that the attacker used the user's password or another ordinary
account credential.

Because session-cookie theft is the more precise documented mechanism,
`T1078.004` is not required as a primary mapping for this investigation.

### Exfiltration or Collection of Business Data

The logs identify applications and resources involved in access. They do not
show:

- emails being read;
- files being downloaded;
- Graph objects being enumerated;
- mailbox rules being created;
- data being staged; or
- information leaving the organisation.

No data-collection or exfiltration technique should be assigned solely because
Microsoft Graph or Exchange Online appears in the sign-in records.

## 9. Evidence Boundaries

The investigation can establish:

- rapid successful access by the same account from divergent client
  environments;
- access associated with multiple Microsoft cloud resources;
- absence of an applied Conditional Access result in the supplied records;
- absence of recorded Entra risk detections in the supplied fields; and
- a strong account-compromise hypothesis.

The investigation cannot independently establish from these records:

- which source IP belonged to the legitimate user;
- which source IP belonged to the simulated attacker;
- the exact browser cookie that was stolen;
- whether the same refresh token was used;
- whether an MFA notification was approved;
- how the user reached the phishing infrastructure;
- what actions occurred inside the accessed applications;
- whether information was viewed, changed or downloaded; or
- whether a production business impact occurred.

IP geolocation labels should not be used to resolve these questions because the
publisher pseudonymised tenant-specific details and the supplied location
values may be inconsistent.

## 10. Final Classification

The final classification is:

> **True Positive — controlled Microsoft Entra account-compromise simulation
> involving stolen browser-session material, detected through rapid successful
> access from different source IPs and divergent client environments.**

The Microsoft Entra records provide strong behavioural evidence of suspicious
concurrent access.

The publisher's controlled-lab ground truth confirms the browser-session
hijacking mechanism. Without that external ground truth, the appropriate
production conclusion would remain **possible account compromise requiring
corroboration**, rather than confirmed session-cookie theft.

No production data loss, persistence, privilege escalation or other business
impact is demonstrated by the supplied evidence.

## 11. References

- Splunk Security Content, “Azure AD Concurrent Sessions From Different IPs”:
  https://research.splunk.com/cloud/a9126f73-9a9b-493d-96ec-0dd06695490d/
- Splunk Attack Data, “Azure AD Concurrent Sessions From Different IPs”:
  https://research.splunk.com/attack_data/c56d67f4-95de-46ae-8fbe-7b41e49bf95e/
- MITRE ATT&CK, “Browser Session Hijacking — T1185”:
  https://attack.mitre.org/techniques/T1185/
- MITRE ATT&CK, “Steal Web Session Cookie — T1539”:
  https://attack.mitre.org/techniques/T1539/
- MITRE ATT&CK, “Adversary-in-the-Middle — T1557”:
  https://attack.mitre.org/techniques/T1557/
- MITRE ATT&CK, “Valid Accounts: Cloud Accounts — T1078.004”:
  https://attack.mitre.org/techniques/T1078/004/
