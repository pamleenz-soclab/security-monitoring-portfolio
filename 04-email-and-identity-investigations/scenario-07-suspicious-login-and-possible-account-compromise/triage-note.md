# Triage Note

## Alert Summary

| Field | Value |
|---|---|
| Alert type | Concurrent Microsoft Entra sessions from different IP addresses |
| Security domain | Identity and cloud account security |
| Affected identity | One pseudonymised Microsoft Entra user |
| First observed event | 2023-01-24 23:13:31.9430219 UTC |
| Last observed event | 2023-01-24 23:15:19.2289311 UTC |
| Observed duration | Approximately 107.3 seconds |
| Source IP addresses | `35.1.2.153`, `50.1.2.43` |
| Initial severity | Medium-high |
| Telemetry-only verdict | True Positive — suspicious concurrent access |
| Ground-truth-informed verdict | True Positive — controlled browser-session hijacking simulation |
| Escalation required | Yes |
| Production impact | Not established |

## Initial Observation

Microsoft Entra sign-in telemetry shows the same pseudonymised user accessing
cloud resources from two materially different client environments within a
short period.

The observed environments are:

| Source IP | Operating system | Browser |
|---|---|---|
| `35.1.2.153` | Windows 10 | Firefox 108.0 |
| `50.1.2.43` | macOS | Chrome 108.0.0 |

The two environments differ in source IP address, autonomous system number,
operating system, browser and User-Agent.

Events `E04` and `E14` are approximately 79.6 seconds apart, and successful
activity from both source IP addresses falls within a rolling five-minute
interval.

## Key Evidence

- All supplied events relate to the same pseudonymised user account.
- Nine unique records have result code `0`, indicating successful
  identity-layer access.
- Successful access occurred from both observed source IP addresses.
- The activity involved Azure Portal, OfficeHome, Microsoft Graph, Office365
  Shell and Exchange Online.
- Several successful records state that the MFA requirement was satisfied by
  a claim already present in the token.
- The supplied Conditional Access result is `notApplied`.
- The supplied risk-related fields contain `none`.
- Session identifiers are not populated.
- No identical unique token identifier is demonstrated across both source IP
  addresses.
- Raw lines 9 and 10 contain an exact duplicate of event `E07`. The duplicate
  does not increase the number of unique events or successful sign-ins.

## Initial Assessment

The rapid successful activity from two divergent client environments is
sufficient to classify the detection as a true positive for suspicious
concurrent access.

The telemetry supports possible account compromise but does not independently
prove that a browser cookie or another specific session artefact was stolen or
reused. The sign-in records do not expose cookie contents, the cookie-acquisition
process or a shared session identifier across both environments.

The publisher's controlled-lab ground truth states that Evilginx2 was used to
phish the user, steal session cookies and import them into another browser.
With this ground truth included, the activity is classified as simulated
malicious browser-session hijacking.

## Severity Rationale

The initial severity is **medium-high** because the activity includes:

- successful access rather than only failed authentication attempts;
- two source IP addresses and autonomous systems;
- different operating systems, browsers and User-Agents;
- rapidly alternating activity;
- access associated with multiple Microsoft cloud resources; and
- successful events relying on authentication claims already present in a
  token.

The ground-truth-informed severity is **high** because the controlled simulation
confirms that stolen authenticated session material was reused.

Critical severity is not assigned because the supplied evidence does not
demonstrate privileged-account compromise, destructive changes, persistence,
data exfiltration, financial loss or service disruption.

## Triage Decision

> **Escalate for identity-compromise investigation and immediate containment.**

In a production environment, the account should be treated as potentially
compromised until the two access contexts have been validated with the user and
corroborated through additional identity, endpoint and application telemetry.

## Immediate Actions

1. Confirm the legitimate user's expected device, browser, location and recent
   sign-in activity through a trusted communication channel.
2. Revoke active sessions and refresh tokens if the second access context
   cannot be promptly validated.
3. Reset the account password and require secure reauthentication.
4. Review MFA methods, device registrations and recent authentication-method
   changes.
5. Review Microsoft Entra audit logs and application-level activity associated
   with Azure Portal, Microsoft Graph and Exchange Online.
6. Search for mailbox access, inbox-rule changes, file access, privilege
   changes, application consent and other post-authentication activity.
7. Block confirmed malicious indicators where operationally appropriate.
8. Preserve relevant identity, endpoint, email, proxy and application logs.

## Evidence Gaps

The supplied sign-in records do not establish:

- which source IP belonged to the legitimate user;
- which source IP belonged to the simulated attacker;
- the exact session cookie or token that was stolen;
- whether the same refresh token was reused;
- whether an MFA notification was approved;
- how the user reached the phishing infrastructure;
- what actions occurred inside the accessed applications;
- whether information was viewed, modified or downloaded; or
- whether any production business impact occurred.

The published dataset uses pseudonymised infrastructure details. IP
geolocation should therefore not be used to identify the legitimate or
malicious access context.

## ATT&CK Context

| ATT&CK ID | Technique | Use in this investigation |
|---|---|---|
| `T1185` | Browser Session Hijacking | Primary publisher mapping supported by the controlled-lab scenario |
| `T1539` | Steal Web Session Cookie | Supported by publisher ground truth; not directly visible in the supplied sign-in records |

Phishing, Adversary-in-the-Middle, Valid Accounts and data-exfiltration
techniques are not assigned as directly observed behaviours from the supplied
sign-in telemetry.

## Disposition

**True Positive in a controlled simulation.**

The Microsoft Entra records provide strong behavioural evidence of suspicious
concurrent access. The publisher's ground truth confirms that the simulation
involved stolen browser-session material.

Without that external ground truth, the appropriate production conclusion
would remain possible account compromise requiring corroboration rather than
confirmed session-cookie theft.
