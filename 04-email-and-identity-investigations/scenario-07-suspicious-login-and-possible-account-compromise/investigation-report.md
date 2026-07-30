# Investigation Report

## 1. Executive Summary

This investigation examined Microsoft Entra sign-in telemetry associated with one
pseudonymised user account.

The supplied dataset contains 15 non-empty raw records. Exact canonical JSON
comparison identified one duplicate pair at source lines 9 and 10, leaving 14
unique events for analysis.

The unique activity occurred between
`2023-01-24T23:13:31.9430219+00:00` and
`2023-01-24T23:15:19.2289311+00:00`, a period of approximately 107.3 seconds.

Successful resource access was recorded from two materially different client
environments:

| Source IP | ASN | Operating system | Browser |
|---|---:|---|---|
| `35.1.2.153` | `16509` | Windows 10 | Firefox 108.0 |
| `50.1.2.43` | `12271` | macOS | Chrome 108.0.0 |

The events show rapid successful access by the same account from both
environments. The observed applications and resources include Azure Portal,
OfficeHome, Microsoft Graph, Office365 Shell and Exchange Online.

Based only on the supplied sign-in telemetry, the activity is classified as:

> **True Positive — suspicious concurrent access and possible account
> compromise.**

The sign-in records do not independently prove which environment was operated by
an unauthorised person or how authenticated session material was obtained.

Splunk's controlled-lab description states that Evilginx2 was used to obtain an
authenticated Azure AD session cookie and that the stolen cookie was imported
into another browser. When this publisher ground truth is included, the final
classification is:

> **True Positive — simulated malicious browser-session hijacking involving
> stolen session-cookie reuse.**

No production data loss, persistence, privilege escalation or other business
impact is demonstrated by the supplied evidence.

## 2. Investigation Scope

The investigation sought to determine:

1. whether the supplied detection represented genuine suspicious identity
   activity;
2. whether successful access occurred from more than one client environment;
3. how password, MFA, token-claim and sign-in-flow records related to one another;
4. which Microsoft cloud applications and resources were accessed;
5. whether the sign-in telemetry directly proved account takeover or
   browser-session hijacking;
6. the appropriate severity, disposition and escalation decision; and
7. which containment, recovery and detection actions would be appropriate in a
   production environment.

The investigation was limited to the supplied Microsoft Entra sign-in records
and the publisher's dataset description.

No endpoint, email, DNS, proxy, packet-capture, Microsoft Entra audit,
Microsoft 365 Unified Audit Log or application-content telemetry was supplied.

## 3. Evidence Sources

| Evidence | Purpose |
|---|---|
| `evidence/raw/azuread.log` | Original Microsoft Entra sign-in telemetry |
| `evidence/processed/deduplicated-events.jsonl` | Fourteen unique events with retained portfolio metadata |
| `evidence/processed/event-summary.csv` | Flattened event summary for comparison and review |
| Splunk Security Content analytic | Detection logic and ATT&CK context |
| Splunk Attack Data description | Controlled-lab ground truth and dataset provenance |

The raw evidence was preserved unchanged.

The source file contains 15 non-empty records. Raw lines 9 and 10 are exact
duplicates and are represented once as event `E07` in the deduplicated
investigation timeline.

## 4. Dataset and Attribution Limitations

The publisher states that usernames, IP addresses and tenant-specific values
were replaced before publication.

The geographic labels in the records must therefore not be treated as reliable
physical attribution. The Buffalo-labelled records also contain internally
inconsistent geographic coordinates.

For this reason, the two contexts are described as the Oregon-labelled and
Buffalo-labelled environments rather than as verified physical locations.

The browser, operating-system, ASN and User-Agent differences establish two
materially different client environments. They do not uniquely prove that two
physical devices were involved because device IDs, management fields and
session IDs are unpopulated.

## 5. Investigation Method

The investigation used the following process:

1. preserved the supplied raw sign-in evidence;
2. counted all non-empty source records;
3. assigned stable event labels `E01–E14`;
4. removed one exact duplicate through canonical JSON comparison;
5. normalised key fields into `event-summary.csv`;
6. ordered the unique events by UTC timestamp;
7. compared source IP, ASN, operating system, browser and User-Agent values;
8. reviewed result codes and authentication-step details;
9. grouped related activity by correlation ID;
10. compared sign-in IDs, correlation IDs and unique token identifiers;
11. reviewed MFA, Conditional Access and risk fields;
12. separated directly observed evidence from investigative hypotheses and
    publisher ground truth; and
13. mapped supported behaviour to MITRE ATT&CK.

Records sharing an identical timestamp were not assigned a causal order unless
the evidence independently established one.

## 6. Event Timeline

### 6.1 Oregon-labelled authentication flow

At `23:13:31.943`, events `E01` and `E02` recorded Azure Portal authentication
activity from `35.1.2.153` using Windows 10 and Firefox 108.0.

Both records used result code `50074`, indicating that strong authentication was
required. The authentication details recorded a correct cloud password and
Mobile app notification activity.

Because the events share the same timestamp and identifiers, their ordering
must not be interpreted as a guaranteed sequence of separate user actions.

At `23:13:41.569`, event `E03` recorded completed Mobile app MFA. Its result code
was `50140`, representing the Keep me signed in interruption.

This code does not mean that the password was incorrect or that MFA failed.

### 6.2 First Buffalo-labelled successes

At `23:13:59.633`, event `E04` recorded successful OfficeHome access from
`50.1.2.43` using macOS and Chrome 108.0.0.

The record states that the first-factor and MFA requirements were satisfied by
claims already present in the token.

At `23:14:02.358`, event `E05` recorded successful Azure Portal access from the
same Buffalo-labelled environment, again using existing authentication claims.

These events occurred shortly after the Oregon-labelled MFA completion record,
but the sign-in logs do not contain a shared session ID or identical unique
token identifier proving how the two flows were related.

### 6.3 Buffalo-labelled authentication flow

At `23:14:31.262`, events `E06` and `E07` documented Mobile app MFA completion
for Azure Portal in the Buffalo-labelled environment.

`E06` also contained a correct cloud-password step. `E07` represented a
distinct authentication record within the processed timeline, although its two
raw source copies at lines 9 and 10 were exact duplicates.

Both events used result code `50140`, representing the Keep me signed in
interruption rather than a failed password or rejected MFA challenge.

At `23:14:36.694`, event `E08` recorded successful Azure Portal access. Its MFA
requirement was satisfied by a claim in the token.

### 6.4 Multi-resource cloud access

Between `23:14:42.349` and `23:14:46.037`, the Buffalo-labelled environment
recorded successful access associated with:

- OfficeHome;
- Microsoft Graph;
- Office365 Shell WCSS-Server; and
- Exchange Online.

These records relied on first-factor and MFA claims already present in the
token.

They establish successful identity-layer authorisation to the named resources.
They do not prove that messages were read, files were downloaded, directory
objects were enumerated or data was exfiltrated.

### 6.5 Later Oregon-labelled success

At `23:15:19.229`, event `E14` recorded successful Azure Portal access from the
original Oregon-labelled Windows/Firefox environment.

The event remained associated with the original Oregon-labelled correlation
flow, and its MFA requirement was satisfied by a claim in the token.

Events `E04` and `E14`, representing successful activity from the two
environments, were approximately 79.6 seconds apart.

## 7. Authentication and Correlation Analysis

The 14 unique events contain:

- 11 unique sign-in IDs;
- 8 unique correlation IDs;
- 11 unique token identifiers; and
- no populated session IDs.

`CORR-01` groups events `E01–E03` and `E14` in the Oregon-labelled environment.
It contains the password and MFA flow, the Keep me signed in interruption and
later successful Azure Portal access.

`CORR-03` groups events `E05–E08` in the Buffalo-labelled environment. It
contains successful token-claim access, password and MFA records, a Keep me
signed in interruption and later successful Azure Portal access.

A correlation ID may group related client authentication activity, but it must
not be treated as an individual access token or a guaranteed physical-device
session.

No correlation ID or identical unique token identifier appears across both
source IP addresses.

Consequently, the logs support rapid access from divergent environments but do
not directly demonstrate the same session cookie or refresh token crossing
between those environments.

## 8. MFA and Conditional Access Findings

Every unique event records `multiFactorAuthentication` as the authentication
requirement.

Where a new challenge was shown, Mobile app notification was the recorded MFA
method. Several later successful requests state that the MFA requirement was
satisfied by a claim already present in the token.

This wording means that Microsoft Entra accepted an existing MFA claim for the
request. It does not independently prove either MFA bypass or authorisation by
the account owner.

The requirement-policy metadata refers to Per-user MFA, Security Defaults, or
both. However, every unique event records the top-level Conditional Access
status as `notApplied`.

The dataset therefore does not demonstrate that a custom Conditional Access
policy was applied to either client environment.

## 9. Risk and Detection Findings

Every unique record contains:

- `riskLevelDuringSignIn: none`;
- `riskLevelAggregated: none`;
- `riskState: none`;
- no populated risk-event entries; and
- `flaggedForReview: false`.

These fields establish that the supplied events contain no recorded Microsoft
Entra risk detection.

They do not establish that the activity was benign or authorised. The absence
of a native risk flag must not override the behavioural evidence of rapid
successful access from divergent client environments.

## 10. Analysis and Verdict

### 10.1 Telemetry-only assessment

The sign-in telemetry directly establishes that:

- the same pseudonymised account accessed cloud resources from two source IPs;
- the client environments differed by ASN, operating system, browser and
  User-Agent;
- successful access occurred from both environments within a short interval;
- nine unique records recorded result code `0`;
- the Buffalo-labelled environment obtained identity-layer access associated
  with multiple Microsoft cloud resources; and
- several successful requests relied on existing first-factor and MFA token
  claims.

These facts are sufficient to validate the detection as a true positive for
suspicious concurrent or rapidly alternating access.

They are not sufficient to identify the unauthorised operator or independently
confirm theft of browser-session material.

The telemetry-only verdict is therefore:

> **True Positive — suspicious concurrent access and possible account
> compromise.**

### 10.2 Ground-truth-informed assessment

Splunk states that the dataset was generated by:

1. using Evilginx2 to phish a Microsoft Entra user;
2. obtaining an authenticated Azure AD session cookie;
3. importing the stolen cookie into another browser; and
4. using the stolen session material from another location and source IP.

Within this controlled simulation, the activity represents confirmed malicious
browser-session reuse.

The ground-truth-informed verdict is therefore:

> **True Positive — simulated malicious browser-session hijacking involving
> stolen session-cookie reuse.**

The ground truth establishes the attack method used to generate the dataset,
but it does not make the cookie contents or acquisition process directly visible
inside `azuread.log`.

## 11. Severity and Escalation

The recommended telemetry-only severity is **medium-high** because the activity
includes:

- successful access rather than only failed authentication;
- materially different client environments;
- rapid access within a short rolling interval;
- multiple Microsoft cloud applications and resources; and
- successful requests relying on existing authentication claims.

The severity becomes **high** when the controlled-lab ground truth confirms
reuse of stolen authenticated session material.

The event should be escalated for identity-compromise investigation and
containment.

Critical severity is not assigned because the supplied evidence does not
demonstrate:

- compromise of a privileged account;
- destructive administrative changes;
- persistence;
- data collection or exfiltration;
- financial loss;
- service disruption; or
- impact on a production organisation.

## 12. MITRE ATT&CK Mapping

| ATT&CK ID | Technique | Tactic | Evidence basis |
|---|---|---|---|
| `T1185` | Browser Session Hijacking | Collection | Primary publisher mapping; supported by controlled-lab ground truth |
| `T1539` | Steal Web Session Cookie | Credential Access | Supported by publisher ground truth; cookie theft is not directly recorded in the supplied sign-in telemetry |

Phishing and Adversary-in-the-Middle are relevant attack-method context because
the publisher states that Evilginx2 was used. However, the supplied evidence
does not contain message, URL, proxy, DNS, TLS or network telemetry showing those
behaviours.

`T1078.004` Valid Accounts: Cloud Accounts is not required as a primary mapping
because stolen authenticated session material is the more precise documented
mechanism.

No collection or exfiltration technique is assigned solely because Microsoft
Graph or Exchange Online appears in a successful sign-in record.

## 13. Recommended Response

In a production environment, responders should:

1. contact the user through a trusted channel and validate the expected device,
   browser, network and recent activity;
2. revoke active sessions and refresh tokens if suspicious access cannot be
   promptly explained;
3. reset the password and require secure reauthentication;
4. review registered MFA methods, device registrations and recent
   authentication-method changes;
5. review Microsoft Entra audit logs for application consent, role assignment,
   device registration and policy changes;
6. examine Microsoft 365 Unified Audit Log and Exchange Online activity for
   mailbox access, inbox rules, forwarding, message operations and delegated
   permissions;
7. examine SharePoint, OneDrive and Microsoft Graph activity for object or file
   access;
8. review endpoint, proxy, DNS and email telemetry for the suspected phishing
   and session-theft path;
9. preserve relevant identity, endpoint, email and application evidence; and
10. block confirmed malicious infrastructure where operationally appropriate.

Detailed containment, eradication, recovery and hardening measures are
documented in `recommended-actions.md`.

## 14. Detection and Hardening Opportunities

Production detection should correlate successful sign-ins for the same user
within a short rolling interval and compare more than the source IP alone.

Useful contextual differences include:

- ASN;
- operating system;
- browser;
- User-Agent;
- device identity;
- managed or compliant-device status;
- authentication strength;
- MFA claim reuse;
- application and resource sensitivity; and
- impossible or improbable travel context.

Detection logic should suppress exact duplicates and should not count result
codes `50074` or `50140` as successful sign-ins.

Result code `50140` should be interpreted as a Keep me signed in interruption
rather than as proof of a failed authentication attempt.

High-confidence detections should trigger investigation even when Entra risk
fields are `none`.

Detailed detection engineering recommendations are documented in
`detection-opportunities.md`.

## 15. Evidence Boundaries

The investigation establishes:

- one pseudonymised account;
- two materially different client environments;
- successful identity-layer access from both environments;
- rapid interleaving of the recorded activity;
- access associated with multiple Microsoft cloud resources;
- successful requests using existing authentication claims;
- no applied custom Conditional Access result in the supplied events;
- no recorded Entra risk detection; and
- controlled-lab ground truth confirming session-cookie theft and reuse.

The investigation does not independently establish from the sign-in records:

- which environment belonged to the legitimate user;
- which environment belonged to the simulated attacker;
- which person operated either browser;
- the exact cookie or token that was stolen;
- whether the same refresh token was reused;
- whether the two environments were separate physical devices;
- whether an MFA notification was knowingly approved;
- how the user reached the phishing infrastructure;
- whether email messages or files were viewed;
- whether mailbox rules or forwarding were changed;
- whether data was downloaded or exfiltrated; or
- whether production business impact occurred.

A successful Exchange Online sign-in proves identity-layer authorisation to the
Exchange resource. It does not prove that any particular message was viewed,
sent, deleted or forwarded.

## 16. Final Conclusion

The detection is a true positive for suspicious successful access from divergent
Microsoft Entra client environments.

The sign-in telemetry alone supports possible account compromise requiring
corroboration. It does not directly expose session-cookie theft or identify the
unauthorised access context.

The publisher's controlled-lab ground truth confirms that the dataset represents
browser-session hijacking through stolen session-cookie reuse.

The final disposition is:

> **True Positive — controlled Microsoft Entra account-compromise simulation
> involving stolen browser-session material, detected through rapid successful
> access from different source IPs and divergent client environments.**

No production data loss, persistence, privilege escalation or other business
impact is demonstrated by the available evidence.

## 17. References

- Splunk Security Content, “Azure AD Concurrent Sessions From Different IPs”:
  https://research.splunk.com/cloud/a9126f73-9a9b-493d-96ec-0dd06695490d/
- Splunk Attack Data, “Azure AD Concurrent Sessions From Different IPs”:
  https://research.splunk.com/attack_data/c56d67f4-95de-46ae-8fbe-7b41e49bf95e/
- Microsoft, “Learn about the sign-in log activity details”:
  https://learn.microsoft.com/en-us/entra/identity/monitoring-health/concept-sign-in-log-activity-details
- Microsoft, “Microsoft Entra authentication and authorization error codes”:
  https://learn.microsoft.com/en-us/entra/identity-platform/reference-error-codes
- Microsoft, “Manage the Stay signed in prompt”:
  https://learn.microsoft.com/en-us/entra/fundamentals/how-to-manage-stay-signed-in-prompt
- Microsoft, “Azure Monitor Logs reference — SigninLogs”:
  https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/signinlogs
- MITRE ATT&CK, “Browser Session Hijacking — T1185”:
  https://attack.mitre.org/techniques/T1185/
- MITRE ATT&CK, “Steal Web Session Cookie — T1539”:
  https://attack.mitre.org/techniques/T1539/
