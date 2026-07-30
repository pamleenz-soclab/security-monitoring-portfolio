# Identity Timeline

## 1. Purpose and Scope

This timeline reconstructs the identity activity contained in
`evidence/raw/azuread.log`.

It documents:

- the two recorded browser environments;
- authentication and MFA state changes;
- successful resource-access token requests;
- sign-in, correlation and token relationships;
- the exact duplicate record;
- the order in which the two environments appear; and
- the limits of the available sign-in telemetry.

The timeline describes what the sign-in records show. It does not independently
prove which person operated either browser or what actions occurred inside the
accessed applications.

All timestamps are recorded in UTC.

## 2. Evidence Handling

| Property | Value |
|---|---|
| Raw non-empty records | 15 |
| Exact unique records | 14 |
| Exact duplicate | Source lines 9 and 10 |
| Timeline start | `2023-01-24T23:13:31.9430219+00:00` |
| Timeline end | `2023-01-24T23:15:19.2289311+00:00` |
| Total observed period | Approximately 107.3 seconds |
| Deduplication method | Exact canonical JSON comparison |
| User count | One pseudonymised Entra user |
| Unique sign-in IDs | 11 |
| Unique correlation IDs | 8 |
| Unique token identifiers | 11 |
| Populated session IDs | None |

The raw duplicate remains unchanged in the source file. It is represented once
in the timeline as event `E07`, with both source line numbers retained.

Records sharing the same timestamp are not assigned a causal order. In
particular, `E01` and `E02`, and separately `E06` and `E07`, must be interpreted
as related authentication records rather than a guaranteed sequence of
sub-events.

## 3. Recorded Client Environments

The geographic names below are labels present in the dataset. Splunk states that
IP addresses and tenant-specific values were replaced, and the Buffalo-labelled
records contain inconsistent coordinates. These values must therefore not be
treated as reliable physical attribution.

| Attribute | Oregon-labelled environment | Buffalo-labelled environment |
|---|---|---|
| Source IP | `35.1.2.153` | `50.1.2.43` |
| ASN | `16509` | `12271` |
| Operating system | Windows 10 | macOS |
| Browser | Firefox 108.0 | Chrome 108.0.0 |
| Client application | Browser | Browser |
| Applications observed | Azure Portal | OfficeHome, Azure Portal, Office365 Shell, Exchange Online |
| Resources observed | Windows Azure Service Management API | OfficeHome, Windows Azure Service Management API, Microsoft Graph, Office365 Shell WCSS-Server, Exchange Online |
| First event | `23:13:31.943` | `23:13:59.633` |
| Last event | `23:15:19.229` | `23:14:46.037` |

The browser, operating-system, ASN and User-Agent differences establish two
materially different client environments. They do not uniquely identify two
physical devices because all device IDs, management fields and session IDs are
unpopulated.

## 4. Deduplicated Event Timeline

| Event | Time (UTC) | Raw line(s) | Environment | Application / resource | Result | Authentication evidence | Identifiers |
|---|---|---:|---|---|---|---|---|
| `E01` | `23:13:31.943` | 14 | Oregon-labelled Windows/Firefox | Azure Portal / Windows Azure Service Management API | `50074` — strong authentication required | Correct cloud password; Mobile app notification recorded as successful | `SIGNIN-01`; `CORR-01`; `TOKEN-01` |
| `E02` | `23:13:31.943` | 15 | Oregon-labelled Windows/Firefox | Azure Portal / Windows Azure Service Management API | `50074` — strong authentication required | Correct cloud password; Mobile app notification recorded as in progress | `SIGNIN-01`; `CORR-01`; `TOKEN-01` |
| `E03` | `23:13:41.569` | 13 | Oregon-labelled Windows/Firefox | Azure Portal / Windows Azure Service Management API | `50140` — Keep me signed in interrupt | Correct cloud password; Mobile app MFA completed in Entra ID | `SIGNIN-01`; `CORR-01`; `TOKEN-01` |
| `E04` | `23:13:59.633` | 12 | Buffalo-labelled macOS/Chrome | OfficeHome / OfficeHome | `0` — success | First-factor and MFA requirements satisfied by claims already present in the token | `SIGNIN-02`; `CORR-02`; `TOKEN-02` |
| `E05` | `23:14:02.358` | 11 | Buffalo-labelled macOS/Chrome | Azure Portal / Windows Azure Service Management API | `0` — success | First-factor and MFA requirements satisfied by existing token claims | `SIGNIN-03`; `CORR-03`; `TOKEN-03` |
| `E06` | `23:14:31.262` | 8 | Buffalo-labelled macOS/Chrome | Azure Portal / Windows Azure Service Management API | `50140` — Keep me signed in interrupt | Correct cloud password; Mobile app MFA completed in Entra ID | `SIGNIN-04`; `CORR-03`; `TOKEN-04` |
| `E07` | `23:14:31.262` | 9, 10 | Buffalo-labelled macOS/Chrome | Azure Portal / Windows Azure Service Management API | `50140` — Keep me signed in interrupt | Mobile app MFA completion record; raw lines 9 and 10 are exact duplicates | `SIGNIN-04`; `CORR-03`; `TOKEN-04` |
| `E08` | `23:14:36.694` | 7 | Buffalo-labelled macOS/Chrome | Azure Portal / Windows Azure Service Management API | `0` — success | MFA requirement satisfied by a claim in the token | `SIGNIN-05`; `CORR-03`; `TOKEN-05` |
| `E09` | `23:14:42.349` | 6 | Buffalo-labelled macOS/Chrome | OfficeHome / OfficeHome | `0` — success | First-factor and MFA requirements satisfied by existing token claims | `SIGNIN-06`; `CORR-04`; `TOKEN-06` |
| `E10` | `23:14:44.552` | 5 | Buffalo-labelled macOS/Chrome | Office365 Shell / Microsoft Graph | `0` — success | First-factor and MFA requirements satisfied by existing token claims | `SIGNIN-07`; `CORR-05`; `TOKEN-07` |
| `E11` | `23:14:44.595` | 4 | Buffalo-labelled macOS/Chrome | Office365 Shell / Office365 Shell WCSS-Server | `0` — success | First-factor and MFA requirements satisfied by existing token claims | `SIGNIN-08`; `CORR-06`; `TOKEN-08` |
| `E12` | `23:14:44.634` | 3 | Buffalo-labelled macOS/Chrome | Office365 Shell / Microsoft Graph | `0` — success | First-factor and MFA requirements satisfied by existing token claims | `SIGNIN-09`; `CORR-07`; `TOKEN-09` |
| `E13` | `23:14:46.037` | 2 | Buffalo-labelled macOS/Chrome | Exchange Online / Exchange Online | `0` — success | First-factor and MFA requirements satisfied by existing token claims | `SIGNIN-10`; `CORR-08`; `TOKEN-10` |
| `E14` | `23:15:19.229` | 1 | Oregon-labelled Windows/Firefox | Azure Portal / Windows Azure Service Management API | `0` — success | MFA requirement satisfied by a claim in the token | `SIGNIN-11`; `CORR-01`; `TOKEN-11` |

There are nine telemetry records with result code `0` and five records describing
authentication requirements or sign-in-flow interrupts. These counts must not be
interpreted as nine successful user sessions and five failed login attempts
because several records belong to the same authentication flow.

## 5. Correlation Analysis

| Correlation label | Events | Environment | Interpretation |
|---|---|---|---|
| `CORR-01` | `E01–E03`, `E14` | Oregon-labelled | Azure Portal authentication flow containing password, MFA, Keep me signed in interruption and later successful access |
| `CORR-02` | `E04` | Buffalo-labelled | Successful OfficeHome access using existing first-factor and MFA token claims |
| `CORR-03` | `E05–E08` | Buffalo-labelled | Azure Portal activity containing successful token-claim access, password and MFA records, Keep me signed in interruption and later successful access |
| `CORR-04` | `E09` | Buffalo-labelled | Successful OfficeHome token request |
| `CORR-05` | `E10` | Buffalo-labelled | Successful Microsoft Graph token request |
| `CORR-06` | `E11` | Buffalo-labelled | Successful Office365 Shell server token request |
| `CORR-07` | `E12` | Buffalo-labelled | Successful Microsoft Graph token request |
| `CORR-08` | `E13` | Buffalo-labelled | Successful Exchange Online token request |

No correlation ID or unique token identifier appears across both source IPs.

`CORR-01` contains two sign-in IDs and two token identifiers, while `CORR-03`
contains three sign-in IDs and three token identifiers. A correlation ID therefore
groups related client authentication activity but must not be treated as an
individual access token or a guaranteed physical-device session.

## 6. Key Sequence

1. At `23:13:31`, the Oregon-labelled Firefox environment supplied the correct
   password and entered an MFA flow.

2. At `23:13:41`, the Oregon-labelled flow recorded successful Mobile app MFA.
   Result code `50140` represents the Keep me signed in interruption and does not
   by itself indicate an unsuccessful attack or failed MFA.

3. At `23:13:59`, approximately 18 seconds after the Oregon-labelled MFA
   completion record, the Buffalo-labelled Chrome environment successfully
   accessed OfficeHome. Both first-factor and MFA requirements were satisfied by
   claims already present in the token.

4. At `23:14:02`, the Buffalo-labelled environment successfully accessed Azure
   Portal using existing authentication claims.

5. At `23:14:31`, two distinct authentication records with the same identifiers
   documented Mobile app MFA completion in the Buffalo-labelled environment. One
   record also included a correct cloud-password step.

6. Between `23:14:36` and `23:14:46`, the Buffalo-labelled environment recorded
   successful access to Azure Portal, OfficeHome, Microsoft Graph, Office365
   Shell and Exchange Online using existing authentication claims.

7. At `23:15:19`, the Oregon-labelled Firefox environment recorded successful
   Azure Portal access under its original correlation flow.

Events from the two environments are therefore interleaved within the same
approximately 107-second period. Because no session IDs or reliable device IDs
are populated, the sign-in log cannot independently prove that two physical
devices maintained simultaneous active sessions.

## 7. MFA and Conditional Access Timeline Notes

Every event records `multiFactorAuthentication` as the authentication
requirement.

The requirement-policy fields identify Per-user MFA, Security Defaults, or both.
Mobile app notification is the recorded MFA method when a new challenge is
shown.

All events record the top-level Conditional Access status as `notApplied`.
Therefore, the dataset does not demonstrate that a custom Conditional Access
policy was applied to either environment. Security Defaults and Per-user MFA
metadata must not be described as proof of a custom Conditional Access policy.

The phrase `MFA requirement satisfied by claim in the token` means that Entra
accepted an existing MFA claim for that request. It does not, by itself, prove
that MFA was bypassed or that the request was authorised by the account owner.

## 8. Risk and Detection Fields

All unique records contain:

- `riskLevelDuringSignIn: none`;
- `riskLevelAggregated: none`;
- `riskState: none`;
- empty risk-event arrays; and
- `flaggedForReview: false`.

These values establish that no Entra risk detection was recorded in the supplied
events. They do not establish that the sign-ins were benign or authorised.

## 9. Evidence Boundaries

The timeline supports the following findings:

- one account was accessed through two materially different client environments;
- successful resource-access records occurred from both environments;
- activity from the environments appeared within the same short time window;
- several Buffalo-labelled successes relied on existing first-factor and MFA
  claims;
- the Buffalo-labelled environment obtained tokens for multiple Microsoft
  services;
- no identical unique token identifier was observed across the two IP addresses;
  and
- no custom Conditional Access enforcement is demonstrated.

The timeline does not independently establish:

- which environment belonged to the legitimate user;
- who approved either Mobile app notification;
- how credentials or session material were obtained;
- whether the same browser cookie or refresh token was used across the IPs;
- whether the two client environments represent two physical devices;
- whether email messages or files were viewed;
- whether mailbox rules, forwarding or directory settings were changed;
- whether data was exfiltrated; or
- whether business impact occurred.

A successful Exchange Online sign-in record proves that access to the Exchange
resource was authorised at the identity layer. It does not prove that any
specific message was read, sent, deleted or forwarded.

## 10. Investigative Assessment

### Assessment based only on the sign-in telemetry

**Suspicious successful sign-in activity / Possible account compromise**

Confidence is high that the account was accessed from two different client
environments during a tightly overlapping period. Confidence is also high that
both environments obtained successful resource access.

The sign-in telemetry alone cannot identify the unauthorised operator or
independently confirm theft of browser-session material. It is therefore
insufficient to classify the incident as confirmed account compromise without
external evidence or publisher ground truth.

### Controlled-lab ground truth

Splunk states that the dataset was generated by using Evilginx2 to obtain an
authenticated Azure AD session cookie and importing the stolen cookie into
another browser.

Within the controlled simulation, the activity represents **confirmed browser
session hijacking**. This ground-truth statement remains separate from the
conclusion derived exclusively from `azuread.log`.

## 11. References

- Splunk Security Content, “Azure AD Concurrent Sessions From Different IPs”:
  https://research.splunk.com/attack_data/c56d67f4-95de-46ae-8fbe-7b41e49bf95e/
- Microsoft, “Learn about the sign-in log activity details”:
  https://learn.microsoft.com/en-us/entra/identity/monitoring-health/concept-sign-in-log-activity-details
- Microsoft, “Microsoft Entra authentication and authorization error codes”:
  https://learn.microsoft.com/en-us/entra/identity-platform/reference-error-codes
- Microsoft, “Manage the Stay signed in prompt”:
  https://learn.microsoft.com/en-us/entra/fundamentals/how-to-manage-stay-signed-in-prompt
- Microsoft, “Azure Monitor Logs reference — SigninLogs”:
  https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/signinlogs
- Microsoft, “Plan a Conditional Access deployment”:
  https://learn.microsoft.com/en-us/entra/identity/conditional-access/plan-conditional-access
