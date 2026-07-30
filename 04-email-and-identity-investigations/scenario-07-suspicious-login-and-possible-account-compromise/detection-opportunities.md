# Detection Opportunities

## 1. Purpose and Scope

This document converts the identity findings in `identity-timeline.md` and
`authentication-analysis.md` into detection opportunities.

It defines:

- the core concurrent-access detection hypothesis;
- required and optional telemetry;
- a baseline Splunk analytic;
- an improved rolling-window SPL hunting query;
- a Microsoft Sentinel KQL hunting query;
- alert enrichment, scoring and tuning;
- expected false positives;
- validation against the supplied dataset; and
- limitations that prevent the detection from independently confirming browser
  session hijacking.

The detection objective is to identify suspicious successful access by one
account from materially different client environments within a short period.

An alert produced by this logic is an investigation lead. It is not, by itself,
proof that a session cookie was stolen.

## 2. Detection Hypothesis

The core hypothesis is:

> If the same cloud account successfully accesses Microsoft resources from more
> than one source IP within a short rolling window, especially when the IPs,
> ASNs, operating systems or browsers differ, the activity may represent
> concurrent legitimate use, credential compromise or reuse of stolen
> authenticated session material.

The primary analytic should require:

1. the same Entra user or user ID;
2. successful identity-layer access;
3. at least two different source IP addresses; and
4. events occurring within a rolling five-minute window.

The following conditions increase confidence but should not be mandatory for the
initial correlation:

- different ASNs;
- different operating systems;
- different browsers or User-Agent strings;
- access from an unmanaged or unregistered device;
- access to several cloud applications or resources;
- an unfamiliar source relative to the user's baseline;
- token-claim-based authentication without a fresh interactive prompt;
- impossible or implausible travel;
- privileged account activity;
- Exchange Online, Microsoft Graph or Azure management access; and
- related phishing, endpoint, proxy or Identity Protection evidence.

## 3. Detection-Relevant Evidence in This Dataset

| Signal | Dataset evidence | Detection value |
|---|---|---|
| Same account | All records relate to one pseudonymised Entra user | Core correlation key |
| Different source IPs | `35.1.2.153` and `50.1.2.43` | Core anomaly |
| Different ASNs | `16509` and `12271` | Strengthens network divergence |
| Different operating systems | Windows 10 and macOS | Strengthens client divergence |
| Different browsers | Firefox 108.0 and Chrome 108.0.0 | Strengthens client divergence |
| Short time interval | Full activity spans approximately 107.3 seconds | Supports concurrent or rapidly alternating access |
| Successful access | Nine unique records have result code `0` | Demonstrates accepted identity-layer access |
| Existing authentication claims | Several successes used first-factor or MFA claims already present in tokens | Relevant to SSO and possible session-material reuse |
| Multiple resources | Azure Portal, OfficeHome, Microsoft Graph, Office365 Shell and Exchange Online | Increases investigative significance |
| Conditional Access | All supplied events record `notApplied` | Indicates no applied custom policy is demonstrated |
| Entra risk detections | Supplied risk fields contain `none` | Shows the activity was not flagged by the available risk fields |
| Session identifiers | No populated session IDs | Prevents direct cross-IP session linkage |
| Token identifiers | No identical unique token identifier appears across both IPs | Prevents direct token linkage using this field |
| Exact duplicate | Raw lines 9 and 10 duplicate event `E07` | Must not inflate event or MFA counts |

No individual signal proves compromise. The significance comes from correlating
the account, timing, successful access and client-environment divergence.

## 4. Recommended Detection Layers

### Layer 1: Core concurrent successful access

Generate a finding when:

- one account has successful access from two or more distinct IP addresses;
- the events occur no more than five minutes apart; and
- the events are not already explained by trusted corporate egress
  infrastructure.

This layer should normally produce a medium-severity finding requiring
enrichment.

### Layer 2: Client-environment divergence

Increase the finding confidence when at least one of the following changes
between the two successful events:

- ASN;
- operating system;
- browser;
- User-Agent;
- device ID;
- device compliance state; or
- device management state.

A change in IP alone is weaker because mobile networks, VPNs, proxies and cloud
security services can change the externally observed source address.

### Layer 3: Sensitive or rapid resource access

Increase severity when the second environment rapidly requests access to:

- Azure management resources;
- Microsoft Graph;
- Exchange Online;
- SharePoint or OneDrive;
- privileged administration applications; or
- multiple distinct cloud resources.

The supplied dataset contains rapid Azure Portal, OfficeHome, Microsoft Graph,
Office365 Shell and Exchange Online access from the Buffalo-labelled
environment.

### Layer 4: Corroborating evidence

Escalate the finding when supported by:

- a reported or detected phishing message;
- AiTM infrastructure or suspicious-domain telemetry;
- unexpected MFA approval reported by the user;
- endpoint browser-cookie access or credential-stealing activity;
- suspicious Inbox Rule, forwarding or OAuth-consent changes;
- risky sign-in or unfamiliar-sign-in detections;
- impossible-travel evidence;
- privilege changes; or
- data-access activity inconsistent with the user's role.

These additional sources can change the assessment from suspicious access to
confirmed or highly probable compromise.

## 5. Splunk Detection Opportunities

### Publisher baseline

Splunk Security Content provides an analytic that searches successful
non-interactive Entra sign-ins and counts distinct source IPs for each user in a
five-minute bucket.

The essential logic is:

```spl
`azure_monitor_aad`
category=NonInteractiveUserSignInLogs
properties.authenticationDetails{}.succeeded=true
action=success
| rename properties.* as *
| bucket span=5m _time
| rename userAgent as user_agent
| stats count
        min(_time) as firstTime
        max(_time) as lastTime
        dc(src) as unique_ips
        values(dest) as dest
        values(src) as src
        values(user_agent) as user_agent
  by user _time vendor_account vendor_product category
| where unique_ips > 1
| `azure_ad_concurrent_sessions_from_different_ips_filter`
```

This is a useful baseline, but a fixed clock-aligned bucket can split two events
that are less than five minutes apart when they occur on opposite sides of a
bucket boundary.

### Rolling-window SPL hunting query

The following environment-adapted template compares each successful event with
the preceding successful event for the same user:

```spl
`azure_monitor_aad`
category IN (SignInLogs, NonInteractiveUserSignInLogs)
action=success
| rename properties.* as *
| dedup _raw
| sort 0 user _time
| streamstats current=f
    last(_time) as previous_time
    last(src) as previous_src
    last(userAgent) as previous_user_agent
    last(dest) as previous_dest
  by user
| eval elapsed_seconds=_time-previous_time
| where isnotnull(previous_src)
    AND src!=previous_src
    AND elapsed_seconds>=0
    AND elapsed_seconds<=300
| table _time user src previous_src elapsed_seconds
        userAgent previous_user_agent dest previous_dest
```

Important implementation notes:

- field mappings depend on the installed Splunk add-on and local data model;
- `dedup _raw` prevents exact duplicate source events from inflating results;
- `sort 0 user _time` establishes per-user event order;
- `current=f` compares the current record with a previous record;
- `elapsed_seconds<=300` implements a rolling five-minute comparison;
- both interactive and non-interactive records should be retained for
  investigation even if the production alert is based primarily on successful
  resource-access events; and
- production-scale deployment should use tested data-model or indexed-field
  optimisations rather than treating this hunting query as final performance
  engineering.

A more advanced production implementation should maintain all distinct IPs seen
for the account during the rolling interval rather than only comparing adjacent
events.

## 6. Microsoft Sentinel KQL Hunting Query

The following query is a hunting template for successful Entra access from
different IP addresses within a rolling five-minute interval:

```kusto
let Lookback = 1d;
let DetectionWindow = 5m;
let SuccessfulSignIns = materialize(
    union isfuzzy=true
        (
            SigninLogs
            | where TimeGenerated >= ago(Lookback)
            | where tostring(ResultType) == "0"
            | extend ParsedDeviceDetail =
                parse_json(tostring(DeviceDetail))
            | project
                SignInId = tostring(Id),
                AccountKey = iff(
                    isnotempty(UserId),
                    tostring(UserId),
                    tostring(UserPrincipalName)
                ),
                UserPrincipalName = tostring(UserPrincipalName),
                CreatedDateTime,
                IPAddress = tostring(IPAddress),
                AutonomousSystemNumber =
                    tostring(AutonomousSystemNumber),
                OperatingSystem =
                    tostring(ParsedDeviceDetail.operatingSystem),
                Browser = tostring(ParsedDeviceDetail.browser),
                UserAgent = tostring(UserAgent),
                AppDisplayName = tostring(AppDisplayName),
                ResourceDisplayName = tostring(ResourceDisplayName),
                CorrelationId = tostring(CorrelationId),
                UniqueTokenIdentifier =
                    tostring(UniqueTokenIdentifier),
                SessionId = tostring(SessionId)
        ),
        (
            AADNonInteractiveUserSignInLogs
            | where TimeGenerated >= ago(Lookback)
            | where tostring(ResultType) == "0"
            | extend ParsedDeviceDetail =
                parse_json(tostring(DeviceDetail))
            | project
                SignInId = tostring(Id),
                AccountKey = iff(
                    isnotempty(UserId),
                    tostring(UserId),
                    tostring(UserPrincipalName)
                ),
                UserPrincipalName = tostring(UserPrincipalName),
                CreatedDateTime,
                IPAddress = tostring(IPAddress),
                AutonomousSystemNumber =
                    tostring(AutonomousSystemNumber),
                OperatingSystem =
                    tostring(ParsedDeviceDetail.operatingSystem),
                Browser = tostring(ParsedDeviceDetail.browser),
                UserAgent = tostring(UserAgent),
                AppDisplayName = tostring(AppDisplayName),
                ResourceDisplayName = tostring(ResourceDisplayName),
                CorrelationId = tostring(CorrelationId),
                UniqueTokenIdentifier =
                    tostring(UniqueTokenIdentifier),
                SessionId = tostring(SessionId)
        )
    | distinct *
);
SuccessfulSignIns
| join kind=inner (
    SuccessfulSignIns
    | project
        AccountKey,
        SecondTime = CreatedDateTime,
        SecondIP = IPAddress,
        SecondASN = AutonomousSystemNumber,
        SecondOS = OperatingSystem,
        SecondBrowser = Browser,
        SecondUserAgent = UserAgent,
        SecondApplication = AppDisplayName,
        SecondResource = ResourceDisplayName,
        SecondCorrelationId = CorrelationId,
        SecondTokenId = UniqueTokenIdentifier,
        SecondSessionId = SessionId
) on AccountKey
| where CreatedDateTime < SecondTime
| where SecondTime - CreatedDateTime <= DetectionWindow
| where IPAddress != SecondIP
| extend
    ElapsedSeconds = datetime_diff(
        "second",
        SecondTime,
        CreatedDateTime
    ),
    ASNChanged = AutonomousSystemNumber != SecondASN,
    ClientChanged =
        OperatingSystem != SecondOS
        or Browser != SecondBrowser
        or UserAgent != SecondUserAgent
| project
    UserPrincipalName,
    FirstTime = CreatedDateTime,
    SecondTime,
    ElapsedSeconds,
    FirstIP = IPAddress,
    SecondIP,
    ASNChanged,
    FirstASN = AutonomousSystemNumber,
    SecondASN,
    ClientChanged,
    FirstOS = OperatingSystem,
    SecondOS,
    FirstBrowser = Browser,
    SecondBrowser,
    FirstApplication = AppDisplayName,
    SecondApplication,
    FirstResource = ResourceDisplayName,
    SecondResource,
    CorrelationId,
    SecondCorrelationId,
    UniqueTokenIdentifier,
    SecondTokenId,
    SessionId,
    SecondSessionId
| order by SecondTime desc
```

Each union leg filters and projects the same normalized schema before the
union. This prevents cross-table field-type differences, particularly the
different `DeviceDetail` types, from splitting the field into separate
type-suffixed columns.

`distinct *` removes fully duplicate projected records before the self-join. In
the supplied dataset, duplicated event `E07` has result code `50140`, so it is
already excluded by the successful-sign-in filter. The deduplication remains
defensive protection against duplicated successful records in other datasets.

This query uses a pairwise self-join so that a pair crossing a fixed five-minute
bucket boundary can still be found.

It is intended for hunting and validation. At high event volumes, the pairwise
join can be expensive. A production analytics rule should constrain the
lookback, use ingestion-time filtering, apply trusted-network exclusions and
test a scalable rolling-window implementation against tenant volume.

The query must also be adapted if the environment sends interactive and
non-interactive events to different workspaces or uses different normalized
field names.

## 7. Validation Against the Supplied Dataset

The expected result of the rolling-window analytic is a positive finding for the
pseudonymised user.

Relevant successful events include:

- `E04` from `50.1.2.43` at `23:13:59.633`;
- `E05` and `E08–E13` from the same Buffalo-labelled environment; and
- `E14` from `35.1.2.153` at `23:15:19.229`.

`E04` and `E14` are approximately 79.6 seconds apart. The later Buffalo-labelled
successes are even closer to `E14`.

The core rolling-window conditions are therefore satisfied:

| Condition | Result |
|---|---|
| Same account | Met |
| Successful identity-layer access | Met |
| At least two distinct IP addresses | Met |
| Events no more than five minutes apart | Met |
| Different ASNs | Met |
| Different operating systems | Met |
| Different browsers and User-Agents | Met |
| Sensitive or multiple resources | Met |
| Direct shared session or token identifier | Not demonstrated |

A local implementation that places these exact successful timestamps into fixed
clock-aligned five-minute buckets may put `E04–E13` in the bucket ending at
`23:15:00` and `E14` in the next bucket. That implementation could miss the
cross-IP relationship even though the events are only about 80 seconds apart.

This boundary case is why the rolling-window design is recommended.

## 8. Alert Enrichment and Severity

The initial alert should contain:

- user principal name and immutable user ID;
- first and last event times;
- both source IP addresses;
- ASN and network-owner information;
- operating system, browser and User-Agent;
- device ID, compliance and management state when populated;
- application and resource names;
- interactive or non-interactive event type;
- result code;
- authentication methods and token-claim information;
- Conditional Access result;
- risk detections;
- correlation, request, token and session identifiers; and
- trusted-location, VPN and corporate-egress classification.

Suggested severity model:

| Conditions | Suggested severity |
|---|---|
| Different IPs only, known trusted networks or expected multi-device use | Low or informational |
| Different IPs within five minutes with no established explanation | Medium |
| Different IPs plus ASN, OS, browser or device divergence | Medium-high |
| Client divergence plus privileged or multi-resource access | High |
| Supporting phishing, token theft, malicious endpoint or unauthorised change evidence | High or critical according to impact |

The absence of Entra risk detections should not automatically reduce severity.
The supplied simulation demonstrates that suspicious successful access can
exist while the recorded risk fields remain `none`.

## 9. False Positives and Tuning

Expected benign explanations include:

- simultaneous use of a laptop and mobile device;
- normal switching between office, home and mobile networks;
- corporate VPN or secure web gateway egress changes;
- cloud proxy or service-edge infrastructure;
- virtual desktop or jump-host use;
- shared operational accounts;
- mobile-carrier address changes;
- approved travel;
- automated application activity; and
- delayed or duplicated log ingestion.

Recommended tuning includes:

- exclude confirmed corporate egress and security-service IP ranges;
- maintain user, service-account and application baselines;
- distinguish human user accounts from service identities;
- compare device IDs and management state when available;
- enrich IPs with ASN, VPN, proxy and threat-intelligence data;
- require stronger supporting signals before automatic containment;
- suppress repeated alerts for the same reviewed pair during a controlled
  period; and
- retain the underlying events so analysts can investigate a suppressed alert
  if additional evidence later appears.

Geographic distance should be treated as supporting evidence rather than a
standalone conclusion because IP geolocation is approximate and the dataset's
location values are pseudonymised or inconsistent.

## 10. Detection Limitations

This analytic detects concurrent or rapidly alternating successful access from
different IPs. It does not directly detect the theft of a browser cookie.

The alert cannot independently determine:

- which environment was legitimate;
- whether the same session cookie was used;
- whether the same refresh token was used;
- who approved an MFA notification;
- whether the user intentionally used both environments;
- what actions occurred inside the accessed applications; or
- whether data loss or another business impact occurred.

Different IPs and client characteristics are behavioural indicators. Direct
confirmation requires corroborating identity, endpoint, browser, email, proxy,
audit or attack-infrastructure evidence.

## 11. Detection Findings

1. A same-account, different-IP, successful-access correlation is appropriate
   for this dataset.

2. A five-minute rolling interval captures the observed cross-IP activity.

3. Fixed clock-aligned time buckets can create boundary misses and should be
   tested carefully.

4. ASN, operating-system, browser and User-Agent divergence materially improve
   triage quality.

5. Exact duplicates should be removed for event counting without altering the
   raw evidence.

6. Interactive authentication records and non-interactive resource-access
   records should be investigated together.

7. Access to multiple Microsoft cloud resources increases the alert's
   significance but does not prove post-authentication actions.

8. Empty session IDs and different unique token identifiers prevent direct
   session-replay confirmation.

9. Conditional Access `notApplied` and risk values of `none` are useful context
   but are not proof that the activity was benign.

10. The detection should generate an investigation lead, not an automatic
    conclusion of browser session hijacking.

## 12. MITRE ATT&CK Context

Splunk maps the simulation and associated analytic to:

- `T1185` — Browser Session Hijacking, under the Collection tactic.

`T1539` — Steal Web Session Cookie describes acquisition and subsequent use of
session cookies. However, the supplied Entra sign-in log observes suspicious
cloud access and does not directly record the cookie-theft action.

The final incident classification should therefore distinguish:

- what the sign-in telemetry detects;
- what the publisher's controlled-lab ground truth establishes; and
- which ATT&CK behaviours are directly observed versus inferred.

## 13. References

- Splunk Security Content, “Azure AD Concurrent Sessions From Different IPs”:
  https://research.splunk.com/cloud/a9126f73-9a9b-493d-96ec-0dd06695490d/
- Splunk Attack Data, “Azure AD Concurrent Sessions From Different IPs”:
  https://research.splunk.com/attack_data/c56d67f4-95de-46ae-8fbe-7b41e49bf95e/
- Microsoft, “Azure Monitor Logs reference — SigninLogs”:
  https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/signinlogs
- Microsoft, “Learn about the sign-in log activity details”:
  https://learn.microsoft.com/en-us/entra/identity/monitoring-health/concept-sign-in-log-activity-details
- MITRE ATT&CK, “Browser Session Hijacking — T1185”:
  https://attack.mitre.org/techniques/T1185/
- MITRE ATT&CK, “Steal Web Session Cookie — T1539”:
  https://attack.mitre.org/techniques/T1539/
