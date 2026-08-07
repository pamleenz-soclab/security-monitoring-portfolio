# Investigation Notes

## Method

The investigation followed an evidence-first sequence:

1. validate source hashes and schema;
2. classify sign-in types;
3. inventory identities, applications, devices, and IPs;
4. separate primary authentication from MFA;
5. examine Conditional Access policy-level results;
6. separate platform risk from direct facts;
7. establish user baseline and approved-network context;
8. correlate stable identifiers;
9. analyze non-interactive token activity;
10. review directory and Microsoft 365 follow-on activity;
11. obtain user verification;
12. compare the independent conclusion with ground truth.

## Reliable parsing results

- 162 sign-ins;
- 237 authentication steps;
- 327 Conditional Access policy results;
- four directory-audit records;
- four Microsoft 365 audit records;
- five risk detections;
- no duplicate sign-in IDs;
- no orphan authentication or Conditional Access child records.

## Password spray

`ATTACK-IP-01` and `ATTACK-IP-02` each attempted the same five users within 36 seconds. Every initial attempt returned error 50126. This proves a distributed invalid-password pattern but not, by itself, possession of a correct password.

## Correct primary authentication

At 01:44, 01:45, 01:46, and 01:47 UTC, `USER-001` reached MFA evaluation from `ATTACK-IP-01`. Two attempts were denied and two timed out. Reaching the MFA step after primary authentication distinguishes these events from the earlier invalid-password failures.

## MFA success

At 01:49:10 UTC, Microsoft Authenticator number matching succeeded. The event created `SESSION-001`. Telemetry proves method completion; it does not identify the physical approver or prove the user's intent.

The incident ticket later confirmed that the legitimate user denied two prompts, ignored two, and then approved one while trying to stop repeated notifications.

## Conditional Access

- Global MFA policy: success.
- High sign-in-risk MFA policy: success.
- Finance compliant-device policy: `reportOnlyFailure`.
- Legacy-authentication block policy: failure for the separate IMAP/ROPC request.

The report-only failure did not block the successful sign-in. The legacy policy did block the separate request and issued no token.

## Network and location

The previous Sydney event used an approved corporate VPN exit and a known managed device. It is a benign location anomaly and invalidates any claim that the calculated Sydney-to-Bucharest speed proves physical impossible travel.

The Bucharest sign-in remained suspicious for independent reasons: unapproved proxy infrastructure, unfamiliar ASN, unknown unmanaged device, successful primary authentication, repeated MFA requests, session creation, and follow-on activity.

## Stable identifiers

- `SIGNIN-INCIDENT-001` identifies the successful interactive record.
- `REQUEST-001` links the exact successful request to risk records.
- `CORRELATION-001` links the successful transaction, risk detections, and security-information registration in this synthetic package.
- `SESSION-001` links the interactive sign-in, three non-interactive token events, the inbox rule, and three file downloads.
- Unique token identifiers differ across token events and are not substitutes for the session ID.

## Non-interactive activity

Three successful non-interactive records accessed Exchange, SharePoint, and Microsoft Graph. They shared `SESSION-001` but had distinct request, correlation, original-request, and token identifiers. They represent background token/resource activity, not three new user MFA approvals.

## Follow-on activity

The incident chain included:

- registration of additional security information;
- creation of an inbox rule forwarding messages externally and deleting matching mail;
- download of three confidential finance documents.

The same session or correlation identifiers linked these actions to the successful sign-in.

## Workload identities

The service principal and managed identity used expected Azure egress and expected credential flows. They were not user identities and were classified as benign workload activity.

## Final conclusion

`USER-001`: **Confirmed account compromise**
Four other targeted users: **Unsuccessful attack**
Approved Sydney VPN event: **Benign anomaly**
Blocked legacy IMAP/ROPC attempt: **Unsuccessful attack**
Service principal and managed identity: **Benign**
