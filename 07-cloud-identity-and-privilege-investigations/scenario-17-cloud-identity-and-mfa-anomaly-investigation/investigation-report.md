# Investigation Report

## 1. Incident overview

A deterministic synthetic Microsoft Entra and Microsoft 365 dataset was investigated for a cloud-identity anomaly involving password spray, MFA fatigue, Conditional Access evaluation, token/session continuation, and follow-on business activity.

The incident affected five user accounts. Four accounts were unsuccessfully targeted. `USER-001` was successfully authenticated after repeated Microsoft Authenticator prompts and was subsequently used to modify authentication information, create an external-forwarding inbox rule, and download confidential finance documents.

## 2. Final classification

**Confirmed account compromise**

## 3. Scope

### Identities

- `USER-001`: confirmed compromise.
- `USER-002`–`USER-005`: unsuccessful password-spray targets.
- `SP-001`: benign service-principal sign-in.
- `MI-001`: benign managed-identity sign-in.
- `ADMIN-001`: legitimate response administrator.

### Applications and resources

- Microsoft 365;
- Office 365 Exchange Online;
- SharePoint Online;
- Microsoft Graph;
- Exchange Online through IMAP/ROPC;
- Azure Key Vault and Azure Storage for benign workload identities.

### Infrastructure

- `ATTACK-IP-01` — synthetic anonymous-proxy/hosting source.
- `ATTACK-IP-02` — second synthetic hosting source.
- `CORP-VPN-01` — approved Sydney corporate VPN exit.
- `CORP-OFFICE-01` — approved Auckland administrative egress.

## 4. Timeline

| UTC time | Event | Assessment |
|---|---|---|
| 2026-06-17 23:55 | Successful sign-in through approved Sydney VPN using known managed device | Benign anomaly |
| 01:40–01:41 | Ten invalid-password failures from two IPs against five users | Distributed password spray |
| 01:44–01:47 | Correct primary authentication for `USER-001`; two MFA denials and two timeouts | MFA fatigue sequence |
| 01:49:10 | Microsoft Authenticator number matching succeeds; session created | Suspicious successful sign-in |
| 01:50–01:51 | Anonymous-IP, unfamiliar-properties, and authenticator-phishing risk events | Platform-risk corroboration |
| 01:52–02:02 | Exchange, SharePoint, and Graph non-interactive token activity | Same-session continuation |
| 02:08 | Separate IMAP/ROPC attempt blocked by Conditional Access | Unsuccessful legacy-auth attempt |
| 02:12 | Additional security information registered | Unauthorized identity modification |
| 02:16 | External-forwarding and delete-message inbox rule created | Unauthorized mailbox persistence |
| 02:20–02:22 | Three confidential finance files downloaded | Business impact |
| 02:55 | User confirms sign-in and actions were unauthorized | Authorization boundary established |
| 03:05–03:10 | Sessions revoked, password reset, unauthorized method deleted | Containment and remediation |
| 03:49 | Unlikely-travel risk generated offline | Platform-risk lead only |

## 5. Authentication analysis

The initial ten failures returned error 50126, indicating invalid username or password. These records alone did not prove that the actor possessed a valid password.

Four later attempts for `USER-001` passed primary authentication and reached MFA. This materially changed the assessment: correct credentials had been used successfully even though the overall sign-ins failed.

The sequence was:

```text
Denied → Timeout → Denied → Timeout → Success
```

The success used Microsoft Authenticator number matching. Authentication telemetry proved that the method completed successfully. User verification was required to establish that the approval was unauthorized.

## 6. Conditional Access analysis

The successful sign-in had an overall Conditional Access status of success.

- The enforced all-user MFA policy succeeded.
- The enforced high-risk MFA policy succeeded.
- The finance compliant-device policy returned `reportOnlyFailure`.

The report-only policy did not prevent access. It showed that the sign-in would have failed a compliant-device requirement had the policy been enabled for enforcement.

A separate IMAP/ROPC request was blocked by an enforced legacy-authentication policy and produced no session or token.

## 7. Device analysis

The suspicious sign-in used Windows 11 and Chrome with an unknown/unmanaged device context. Device ID, compliance, management, and trust information were absent or negative.

The previous Sydney VPN sign-in used a known, managed, compliant macOS device. Empty device fields elsewhere were treated as not available rather than automatically classified as unmanaged.

## 8. Location and network analysis

The Sydney location was explained by an approved corporate VPN. Consequently, the calculated Sydney-to-Bucharest travel speed was not used as proof.

The Bucharest event remained suspicious because of the combination of:

- unapproved infrastructure;
- anonymous-proxy classification;
- ASN and country deviation from baseline;
- unknown/unmanaged device context;
- correct password use;
- repeated MFA prompts;
- successful MFA;
- same-session follow-on activity;
- user confirmation of unauthorized access.

## 9. Session and token analysis

`SESSION-001` was the strongest cross-source identifier. It linked:

- the successful interactive sign-in;
- three non-interactive user sign-ins;
- one Exchange inbox-rule event;
- three SharePoint file-download events.

Each non-interactive token event had its own request, correlation, original-request, and unique-token identifier. These records were interpreted as separate token/resource operations within the same session, not repeated interactive logins or repeated MFA approvals.

The evidence did not include raw token material and did not prove token theft or replay.

## 10. Risk analysis

Four risk detections linked to the successful request:

- anonymized IP address;
- unfamiliar sign-in properties;
- authenticator phishing;
- unlikely travel.

A password-spray risk event also existed for the attack pattern.

These signals strengthened prioritization but were not used as the primary proof of compromise. The conclusion remained supported without relying on a platform-generated score.

## 11. Follow-on activity and impact

The actor registered additional security information, created an inbox rule that forwarded mail externally and deleted matching messages, and downloaded three confidential finance files.

Potential impact included:

- unauthorized persistence through an added authentication method;
- covert mailbox forwarding;
- loss of confidentiality of finance planning, payroll, and supplier banking information;
- risk of fraud or business email compromise;
- exposure of additional correspondents and document metadata.

The dataset did not model downstream misuse, external delivery confirmation, or regulatory impact.

## 12. Containment

The response administrator:

1. revoked all refresh tokens;
2. reset the user's password;
3. deleted the unauthorized authentication method.

The recommended complete response also includes disabling the account if session termination cannot be verified, removing the inbox rule, reviewing OAuth grants and role assignments, checking endpoints, notifying data owners, and searching for related activity across the tenant.

## 13. Evidence basis

### Telemetry-confirmed

- password failures;
- successful primary authentication;
- MFA outcomes;
- Conditional Access results;
- session creation;
- non-interactive token events;
- authentication-method registration;
- inbox rule;
- file downloads;
- response actions.

### Platform-generated risk

- password spray;
- anonymous IP;
- unfamiliar properties;
- authenticator phishing;
- unlikely travel.

### Business verification

The user confirmed the sign-in, approval, authentication-method change, inbox rule, and file downloads were unauthorized.

### Ground truth

The synthetic ground truth aligned with the independent assessment and was checked only afterward.

## 14. Evidence gaps

- No approving-device identity or GPS.
- No raw tokens, cookies, secrets, or MFA seed.
- No Conditional Access internal condition traces.
- No cross-tenant or federation activity.
- No byte-for-byte portal-export fidelity.
- No evidence of downstream use of downloaded files.

## 15. Final assessment

The evidence supports **Confirmed account compromise** because unauthorized successful authentication led to a session and business-impacting actions, and the user verified that the activity was not authorized.

The result would have remained only `Suspicious successful sign-in` or `Possible account compromise` without the same-session follow-on activity and user verification.
