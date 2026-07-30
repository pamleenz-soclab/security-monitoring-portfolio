# Authentication Analysis

## 1. Purpose and Scope

This document analyses the authentication behaviour recorded in
`evidence/raw/azuread.log`.

It explains:

- how password and Mobile app MFA steps appear in the records;
- the difference between a fresh authentication challenge and an authentication
  requirement satisfied by an existing token claim;
- the meaning of result codes `0`, `50074` and `50140`;
- the relationship between Security Defaults, Per-user MFA and Conditional
  Access;
- whether the sign-in telemetry independently proves MFA bypass or browser
  session hijacking; and
- the authentication evidence that should guide further investigation and
  detection engineering.

The analysis uses the 14 exact unique events documented in
`identity-timeline.md`. The original 15 records remain unchanged in the raw
evidence.

## 2. Authentication Concepts Used in This Investigation

| Evidence | Meaning | What it does not prove |
|---|---|---|
| Correct cloud password | Entra accepted the password during that authentication step | Who entered the password or whether the account owner authorised the activity |
| Mobile app notification completed | Entra recorded successful completion of the Mobile app MFA step | Who approved the notification, why it was approved or whether the approval was socially engineered |
| First-factor requirement satisfied by claim in the token | An existing token claim satisfied the first-factor requirement without a new password prompt for that request | That the request was benign or operated by the legitimate user |
| MFA requirement satisfied by claim in the token | An existing MFA claim was accepted without a new MFA prompt for that request | That MFA was disabled, removed or technically broken |
| Result code `0` | The recorded sign-in or resource-access request succeeded | That the access was authorised by the account owner |
| Result code `50074` | Strong authentication was required and was not fully satisfied for that individual request record | A final failed login or failed MFA flow when related records show later completion |
| Result code `50140` | The sign-in encountered the expected Keep me signed in interruption | An attack failure or MFA rejection |
| Conditional Access `notApplied` | No Conditional Access policy is demonstrated as applying to that event | That no MFA requirement existed or that the tenant had no Conditional Access policies configured |
| Risk values `none` | No Entra risk detection was recorded in the supplied event | That the sign-in was safe or authorised |

Authentication steps, event-level result codes and resource-access records must
therefore be interpreted together at authentication-flow level.

## 3. Overall Authentication Pattern

All 14 unique records specify `multiFactorAuthentication` as the authentication
requirement.

The activity contains two main authentication patterns:

1. interactive records containing password and Mobile app notification steps; and
2. successful requests where first-factor, MFA or both were satisfied by claims
   already present in a token.

| Pattern | Events | Interpretation |
|---|---|---|
| Oregon-labelled password and MFA flow | `E01–E03` | Password acceptance, Mobile app notification activity and Keep me signed in interruption within one correlated flow |
| Buffalo-labelled access using existing claims | `E04–E05` | Successful OfficeHome and Azure Portal access without a newly recorded interactive challenge for those requests |
| Buffalo-labelled password and MFA records | `E06–E07` | Related authentication records containing password and Mobile app MFA evidence; raw lines 9 and 10 duplicate `E07` |
| Buffalo-labelled successful Azure access | `E08` | Successful Azure Portal access with MFA satisfied by an existing claim |
| Buffalo-labelled Microsoft 365 resource access | `E09–E13` | Successful requests for OfficeHome, Microsoft Graph, Office365 Shell and Exchange Online using existing claims |
| Later Oregon-labelled success | `E14` | Successful Azure Portal access with MFA satisfied by an existing claim |

This pattern shows that both client environments obtained successful access. It
does not establish which environment was legitimate.

## 4. Oregon-Labelled Authentication Flow

### Initial authentication records

Events `E01` and `E02` have the same timestamp, sign-in ID, correlation ID and
token identifier. They contain related password and Mobile app notification
evidence but record different MFA states.

They must not be counted as two independent login attempts.

Both events have result code `50074`. At event level, this means the request
required strong authentication and had not reached a fully satisfied outcome in
that record. However:

- the correct cloud password was recorded;
- one record describes the Mobile app notification as successful;
- another describes authentication as in progress; and
- later records in the same correlation flow show completed MFA and successful
  resource access.

The `50074` records therefore represent intermediate strong-authentication
requirements within the wider flow rather than sufficient evidence of a final
failed login.

### MFA completion and Keep me signed in

Event `E03` records:

- the correct cloud password;
- Mobile app MFA completed in Entra ID; and
- result code `50140`.

Code `50140` is the Keep me signed in interruption. It is an expected part of an
interactive browser sign-in flow and does not negate the recorded MFA
completion.

### Later successful access

Event `E14` occurs under `CORR-01` and records successful Azure Portal access.
Its MFA requirement was satisfied by a claim in the token.

`E14` uses a different sign-in ID and unique token identifier from `E01–E03`.
This means it is a distinct telemetry record within the correlated activity. It
does not prove that the same access token or browser cookie was reused.

## 5. Buffalo-Labelled Authentication Activity

### Access before the recorded Buffalo MFA sub-flow

Events `E04` and `E05` show successful access to OfficeHome and Azure Portal.
First-factor and MFA requirements were satisfied by claims already present in
the token.

The records therefore show that this browser environment already possessed
authentication state that Entra accepted. The sign-in telemetry does not show
where that state originated.

### Password and Mobile app MFA records

Events `E06` and `E07` share the same:

- timestamp;
- sign-in ID;
- correlation ID; and
- unique token identifier.

They are nevertheless distinct unique records because their authentication-step
content differs. `E06` includes a correct cloud-password step, while `E07`
contains the Mobile app MFA completion record.

Raw lines 9 and 10 are exact copies of `E07`; they are not additional MFA
approvals.

Both unique events have result code `50140`, indicating the Keep me signed in
interruption rather than a failed authentication attempt.

### Successful resource access

Event `E08` records successful Azure Portal access after the Buffalo-labelled
MFA records, with MFA satisfied by a token claim.

Events `E09–E13` then show successful requests involving:

- OfficeHome;
- Microsoft Graph;
- Office365 Shell WCSS-Server; and
- Exchange Online.

These events establish successful identity-layer access to multiple Microsoft
resources. They do not establish what the operator did after accessing those
resources.

In particular, the Exchange Online record does not prove that any email was
read, sent, deleted or forwarded.

## 6. Meaning of Authentication Satisfied by Token Claim

An authentication requirement satisfied by a token claim is a normal feature of
modern authentication and single sign-on.

After Entra accepts the required authentication, later requests can present
claims showing that the first-factor or MFA requirement was previously
satisfied. The user does not necessarily receive a new password or MFA prompt
for every application and resource request.

This field is therefore not inherently malicious.

However, the same behaviour is important in a session-hijacking investigation.
If an attacker obtains valid authenticated session material, requests made with
that material may also carry previously satisfied authentication claims.

Consequently:

- the field does not independently prove MFA bypass;
- it does not prove that a fresh MFA challenge occurred for the request;
- it does not identify the person presenting the authenticated state; and
- it must be interpreted with source IP, browser, operating system, application,
  timing and other investigation evidence.

The absence of an identical unique token identifier across the two source IPs
neither proves nor disproves browser-session replay. The supplied log does not
contain the browser cookie or sufficient session identifiers to make that
connection directly.

## 7. MFA, Security Defaults and Conditional Access

The authentication requirement-policy metadata identifies Per-user MFA,
Security Defaults, or both in the recorded events.

These mechanisms must not be treated as equivalent to a custom Conditional
Access policy.

### Security Defaults

Security Defaults provides Microsoft-managed baseline identity protections. It
can require MFA registration and MFA for selected sign-in circumstances without
an organisation defining its own Conditional Access rules.

### Per-user MFA

Per-user MFA is an account-level MFA enforcement mechanism. Its appearance in
the authentication requirement metadata indicates a source of the MFA
requirement, not a custom Conditional Access decision.

### Conditional Access

Every supplied event records the top-level Conditional Access status as
`notApplied`.

The evidence therefore does not demonstrate enforcement of a custom Conditional
Access policy for:

- source location;
- sign-in risk;
- device compliance;
- managed-device state;
- authentication strength;
- sign-in frequency; or
- access to the recorded cloud applications.

This does not mean that the tenant had no Conditional Access policies. It means
that the supplied events do not show a policy applying to these sign-ins.

It also does not mean that MFA was absent: the records separately identify MFA
requirements from Security Defaults and Per-user MFA.

## 8. Did the Activity Bypass MFA?

### Conclusion based only on the sign-in telemetry

The sign-in telemetry does not independently prove that MFA was bypassed.

It shows that:

- Mobile app MFA was completed in both recorded authentication flows;
- several later requests relied on existing MFA claims;
- both browser environments obtained successful resource access; and
- the identity system did not record a risk detection for the activity.

Possible explanations that cannot be distinguished using this log alone include:

| Hypothesis | Consistency with available log | Missing evidence |
|---|---|---|
| Legitimate use of two browser environments | Possible | User and device baseline, user confirmation and reliable device identifiers |
| Password use followed by legitimate MFA approval | Possible | Identity of the person entering the password and approving MFA |
| Password compromise followed by deceptive or accidental MFA approval | Possible | MFA prompt context, user interview and attack telemetry |
| Replay of authenticated browser-session material | Possible | Session cookie, Evilginx2 telemetry or another direct session link |
| Separate unauthorised login from the second environment | Possible | Reliable attribution showing which environment was unauthorised |

The most accurate sign-in-log conclusion remains:

**Suspicious successful sign-in activity / Possible account compromise**

### Controlled-lab ground truth

Splunk states that Evilginx2 was used to obtain an authenticated Azure AD
session cookie and that the stolen cookie was imported into another browser.

Within that controlled simulation, the activity is confirmed browser session
hijacking.

Technically, this attack does not demonstrate that the attacker defeated the
MFA algorithm itself. It demonstrates reuse of authenticated session material
after authentication requirements had been satisfied. This behaviour is often
described operationally as MFA bypass or MFA evasion, but browser session
hijacking is the more precise classification for this dataset.

## 9. Detection and Investigation Significance

The following combination is more significant than any individual field:

- one account;
- two different source IPs and ASNs;
- two different operating systems and browsers;
- activity interleaved within approximately 107 seconds;
- successful access from both environments;
- multiple requests relying on previously satisfied authentication claims;
- rapid access to several Microsoft cloud resources;
- no populated device or session identifiers; and
- no recorded Entra risk detection or applied Conditional Access policy.

A production investigation should seek:

- user confirmation of expected locations, devices and MFA prompts;
- Entra device-registration and directory audit records;
- Microsoft 365 Unified Audit Log events;
- Exchange mailbox access, send, forwarding and Inbox Rule events;
- Microsoft Graph activity;
- endpoint and browser telemetry;
- EDR detections;
- DNS, proxy and firewall evidence;
- Identity Protection detections;
- token and session-revocation history; and
- any phishing message or AiTM infrastructure evidence.

## 10. Authentication Findings

1. The raw evidence contains 15 records but only 14 exact unique authentication
   events.

2. All unique events specify a multifactor-authentication requirement.

3. Password and Mobile app MFA evidence appears in both recorded browser
   environments.

4. Result codes `50074` and `50140` must be interpreted within their correlated
   authentication flows rather than counted as independent failed logins.

5. Nine unique records show successful identity-layer access.

6. Several successful requests relied on authentication claims already present
   in tokens and therefore did not require a newly recorded interactive prompt.

7. Both environments obtained successful access, but the log cannot identify
   which environment was operated by the legitimate user.

8. No custom Conditional Access enforcement or Entra risk detection is
   demonstrated by the supplied events.

9. The sign-in telemetry supports suspicious successful activity and possible
   account compromise, but does not independently prove session-cookie theft.

10. Splunk's controlled-lab ground truth establishes the simulated incident as
    confirmed browser session hijacking.

## 11. References

- Microsoft, “Sign-in event details for Microsoft Entra multifactor
  authentication”:
  https://learn.microsoft.com/en-us/entra/identity/authentication/howto-mfa-reporting
- Microsoft, “Learn about the sign-in log activity details”:
  https://learn.microsoft.com/en-us/entra/identity/monitoring-health/concept-sign-in-log-activity-details
- Microsoft, “Microsoft Entra authentication and authorization error codes”:
  https://learn.microsoft.com/en-us/entra/identity-platform/reference-error-codes
- Microsoft, “Configure Security Defaults for Microsoft Entra ID”:
  https://learn.microsoft.com/en-us/entra/fundamentals/security-defaults
- Microsoft, “Enable per-user multifactor authentication”:
  https://learn.microsoft.com/en-us/entra/identity/authentication/howto-mfa-userstates
- Microsoft, “Token theft playbook”:
  https://learn.microsoft.com/en-us/security/operations/token-theft-playbook
- Splunk Security Content, “Azure AD Concurrent Sessions From Different IPs”:
  https://research.splunk.com/attack_data/c56d67f4-95de-46ae-8fbe-7b41e49bf95e/
