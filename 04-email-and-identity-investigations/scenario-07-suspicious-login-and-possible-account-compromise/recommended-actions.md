# Recommended Actions

## 1. Purpose and Response Status

This document describes the recommended response to the suspicious Microsoft
Entra access identified in Scenario 07.

The supplied dataset is public, pseudonymised and disconnected from a live
tenant. No account was disabled, no session was revoked and no user was
contacted during this investigation.

The actions below therefore represent a production incident-response plan,
rather than actions performed against the training environment.

## 2. Response Decision

The response should be based on both the available telemetry and the result of
user or asset-owner validation.

| Situation | Recommended decision |
|---|---|
| User confirms both environments and supporting evidence is consistent | Document the explanation, tune relevant trusted-network context and close as a benign anomaly if no contradictory evidence exists |
| User denies one environment | Treat as probable unauthorised access and begin immediate containment |
| User cannot be reached promptly and suspicious access appears active | Temporarily contain the account while continuing verification |
| Publisher ground truth is considered | Treat as confirmed controlled session-cookie theft and browser-session hijacking |
| Logs remain the only evidence | Retain the production conclusion of possible account compromise requiring corroboration |

For this controlled dataset, the publisher ground truth supports the
high-priority response path.

## 3. Immediate Containment

### 3.1 Open or escalate the identity incident

Create or escalate an incident containing:

- affected user principal name and immutable user identifier;
- first and last observed timestamps in UTC;
- both source IP addresses;
- client operating systems, browsers and User-Agents;
- applications and resources accessed;
- relevant correlation and unique token identifiers;
- Conditional Access and identity-risk results;
- the current evidence-based classification; and
- the analyst, incident owner and containment decision.

The initial scope should not claim mailbox compromise, data loss or malicious
administrative changes unless supporting service-level telemetry is found.

### 3.2 Preserve volatile evidence

Before making account changes where operationally practical, preserve:

- interactive and non-interactive Entra sign-in records;
- Entra audit records;
- Identity Protection detections and risk history;
- Conditional Access evaluation details;
- authentication-method and device-registration changes;
- OAuth consent and application-assignment activity;
- Microsoft 365 Unified Audit Log records;
- relevant Defender alerts and investigation results; and
- EDR telemetry from the user's known endpoints.

Record the time at which evidence was collected and the time at which each
containment action was performed.

Preservation must not delay urgent containment when unauthorised access appears
active.

### 3.3 Validate the activity through a trusted channel

Contact the user or responsible manager through a known telephone number,
in-person process or another independently verified channel.

Do not rely only on the potentially compromised email or collaboration account.

Ask whether the user:

- initiated the relevant access;
- used either observed device environment;
- used a corporate VPN, proxy or remote desktop service;
- travelled or worked remotely at the relevant time;
- recently changed browsers or devices;
- received an unexpected authentication prompt;
- entered credentials into an unfamiliar page; or
- noticed unexpected mailbox, file or account activity.

The publisher has pseudonymised the IP and location data, so those fields cannot
be used here to identify which environment belonged to the simulated attacker.

### 3.4 Temporarily block new sign-ins when warranted

If the user denies the activity, cannot be contacted promptly or the evidence
indicates continuing unauthorised access:

1. disable or block sign-in for the affected account;
2. record the administrator and exact containment time;
3. confirm that the change is effective; and
4. assess operational consequences with the service owner.

For privileged, emergency, service or synchronised identities, follow the
organisation's specialised recovery procedure and verify that another
authorised administrator can maintain tenant access.

### 3.5 Revoke existing sign-in sessions

Revoke the affected user's Microsoft Entra sign-in sessions after the account
has been contained.

Session revocation is important in this scenario because changing a password
alone must not be treated as sufficient containment for stolen authenticated
session material.

Revoking sessions resets the user's Microsoft Entra sign-in-session validity
time. This invalidates refresh tokens and Entra-managed browser sign-in cookies
issued before the revocation point, although propagation can take a few
minutes.

For supported Continuous Access Evaluation resource and client combinations,
the revocation event can be enforced in near real time. Non-CAE access tokens
may remain usable until they expire, and a session cookie issued independently
by an application remains governed by that application's own authorisation and
revocation controls. Use application-specific revocation or deprovisioning
controls where necessary.

Confirm revocation through follow-up sign-in and application telemetry rather
than assuming that every application session ended immediately.

## 4. Credential and Authentication Recovery

### 4.1 Reset the account password

Reset the password using the authoritative identity source:

- Microsoft Entra ID for a cloud-only identity;
- on-premises Active Directory for a synchronised identity; or
- the relevant identity provider for a federated identity.

Use a unique password that is delivered through a trusted channel. Do not send
the replacement password to the potentially compromised mailbox.

A password reset should accompany session revocation; it should not replace it.

If the organisation confirms that credentials were entered into phishing
infrastructure, check whether the user reused the same password on other
corporate services and apply the relevant credential-exposure procedure.

### 4.2 Review authentication methods

Preserve and review the account's registered authentication methods and related
audit events.

Investigate:

- newly registered passkeys or security keys;
- unfamiliar Microsoft Authenticator registrations;
- unexpected telephone numbers or email methods;
- Temporary Access Pass creation;
- changes to default authentication methods; and
- MFA registration or deletion events near the incident window.

Remove an authentication method only when it is unauthorised or cannot be
trusted.

Require MFA re-registration when compromise of the registered methods cannot
be excluded. Perform recovery from a known-clean device and through a verified
identity-proofing process.

### 4.3 Review devices and identity associations

Review devices registered, joined or associated with the account.

Compare device identifiers and compliance information with the observed
sign-in activity. The browser and operating-system strings in this dataset do
not prove that either environment was an Entra-registered device.

Disable or remove a device only after establishing that it is unauthorised or
compromised.

### 4.4 Review application consent and delegated access

Review Entra audit logs and application-consent records for:

- newly consented applications;
- newly granted delegated permissions;
- high-privilege Microsoft Graph permissions;
- unfamiliar enterprise applications;
- newly created app registrations or credentials; and
- consent activity initiated by the affected identity.

Revoke unauthorised grants and investigate the associated application or
service principal.

No malicious application consent is demonstrated in the supplied evidence.
This is a required scoping check, not an observed finding.

## 5. Scope the Post-Authentication Activity

### 5.1 Expand the identity timeline

Review a wider period before and after the observed activity using:

- interactive sign-in logs;
- non-interactive sign-in logs;
- service-principal sign-in logs where relevant;
- Entra audit logs;
- Identity Protection risk events; and
- Defender XDR incidents and alerts.

Search for:

- additional source IP addresses or autonomous systems;
- unfamiliar applications and resources;
- repeated access after containment;
- new authentication or recovery methods;
- role or group membership changes;
- device registration or ownership changes;
- password-reset activity;
- Conditional Access modifications; and
- similar activity affecting other users.

The investigation window should be widened if earlier initial access or later
persistence is discovered.

### 5.2 Review Microsoft 365 activity

Because the records include Exchange Online, Microsoft Graph and other
Microsoft cloud resources, review the corresponding service audit data for:

- mailbox rules, including hidden rules;
- external forwarding configuration;
- sent, deleted or moved messages;
- unusual mailbox searches or access;
- SharePoint and OneDrive file access or downloads;
- sharing-link creation;
- Teams or collaboration activity; and
- Microsoft Graph operations.

Do not infer any of these actions merely because a resource appears in a
sign-in record.

Any mailbox-rule or forwarding findings should be documented separately and
may support escalation to the Scenario 08 BEC and mailbox-rule investigation.
Scenario 07 and Scenario 08 must not be described as the same incident unless
shared evidence establishes that relationship.

### 5.3 Check for related identities

Hunt for other accounts showing:

- successful access from either observed IP address;
- the same unusual User-Agent or client combination;
- closely timed access from divergent environments;
- related Identity Protection detections; or
- similar consent, authentication-method or device changes.

This determines whether the event is isolated or part of a broader identity
attack.

## 6. Endpoint Investigation

Identify the legitimate user's devices through asset and identity records
rather than relying only on the sign-in User-Agent.

On relevant endpoints:

- collect EDR alerts and telemetry;
- review browser and credential-phishing indicators;
- check for malicious extensions or browser-profile changes;
- examine suspicious downloads and processes;
- review token, credential or browser-data access alerts;
- run an approved malware and vulnerability scan; and
- isolate the endpoint if active compromise is found.

Do not erase browser data or rebuild the endpoint before necessary forensic
evidence has been preserved.

The supplied Entra logs do not establish endpoint compromise. Endpoint
containment must therefore depend on endpoint evidence or confirmed attack
ground truth.

## 7. Recovery and Monitoring

Re-enable the identity only after:

- the account owner has been verified;
- unauthorised sessions have been revoked;
- credentials have been recovered;
- authentication methods have been reviewed;
- known persistence has been removed;
- required endpoint checks have been completed; and
- the incident owner accepts the remaining risk.

After restoration:

- require a fresh authenticated session;
- confirm access from the expected user and device;
- monitor interactive and non-interactive sign-ins;
- watch for reappearance of the suspicious IP or client pattern;
- review further authentication-method, consent and device changes;
- monitor relevant mailbox, file and administrative activity; and
- document the recovery time and validation evidence.

The monitoring period should follow organisational risk and retention
requirements and should be extended if additional suspicious activity appears.

## 8. Preventive Improvements

### 8.1 Investigate the Conditional Access result

The supplied records show `ConditionalAccessStatus = notApplied`.

Determine whether this resulted from:

- no applicable policy;
- an excluded user, group, application or location;
- a policy configuration gap;
- licensing or telemetry limitations; or
- the way the public dataset was generated.

Do not describe `notApplied` as proof that Conditional Access was globally
disabled.

### 8.2 Strengthen Conditional Access

Evaluate policies that:

- require MFA for organisational resources;
- require phishing-resistant authentication for privileged and high-risk use;
- block legacy authentication;
- require compliant or managed devices for sensitive access;
- use sign-in and user risk where licensing permits;
- restrict persistent browser sessions on unmanaged devices; and
- require reauthentication at a frequency appropriate to resource risk.

Test Conditional Access changes in report-only mode and assess policy impact
before enforcement.

Exclude and separately protect tested emergency-access accounts to prevent
tenant lockout.

### 8.3 Adopt phishing-resistant authentication

Prioritise phishing-resistant authentication methods, particularly for
administrators and users with access to sensitive resources.

Examples supported by Microsoft Entra authentication strengths include
passkeys or FIDO2 security keys, Windows Hello for Business and
certificate-based authentication where appropriate.

Phishing-resistant MFA reduces exposure to adversary-in-the-middle credential
phishing, but it does not remove the need for secure endpoints, session
protection and token-theft monitoring.

### 8.4 Improve identity-risk response

Where available, configure risk-based policies and operational procedures to:

- challenge or block high-risk sign-ins;
- require secure remediation for risky users;
- generate incidents for suspicious browser or token activity;
- revoke sessions during confirmed compromise; and
- record analyst feedback on safe or compromised sign-ins.

The `none` values in the supplied risk fields do not prove that the access was
benign. The custom concurrent-access analytic should remain an independent
detection layer.

### 8.5 Operationalise the concurrent-access detection

Use the rolling-window detection developed for this scenario to alert on the
same account successfully accessing resources from different IP addresses
within five minutes.

Enrich the alert with:

- autonomous-system changes;
- operating-system, browser and User-Agent differences;
- Conditional Access results;
- identity-risk information;
- device compliance;
- application sensitivity;
- known VPN, proxy and cloud-egress ranges; and
- user travel or remote-work context.

Test the rule against tenant volume and tune known benign infrastructure
without broadly suppressing divergent successful access.

## 9. Prioritised Action Register

| Priority | Recommended action | Reason |
|---|---|---|
| P1 | Preserve identity and audit evidence | Prevent loss of time-sensitive investigation data |
| P1 | Validate the activity through a trusted channel | Distinguish legitimate access from unauthorised use |
| P1 | Block sign-in if compromise is likely or access is continuing | Prevent acquisition of new tokens |
| P1 | Revoke all sign-in sessions | Invalidate Entra refresh tokens and prior Entra-managed browser sign-in cookies |
| P1 | Reset credentials and review authentication methods | Restore control of the identity |
| P1 | Review post-authentication and persistence activity | Identify impact and attacker footholds |
| P2 | Investigate associated endpoints | Identify the source of credential or session theft |
| P2 | Review related identities and infrastructure | Determine whether the attack is broader |
| P2 | Restore access from a known-clean environment | Return the user to service safely |
| P2 | Conduct heightened monitoring after recovery | Detect continued or repeated access |
| P3 | Strengthen Conditional Access and authentication | Reduce recurrence and improve containment |
| P3 | Operationalise and tune the rolling-window analytic | Improve future detection coverage |

## 10. Scenario Evidence Boundary

The supplied records directly support suspicious successful access from two
divergent client environments.

They do not independently demonstrate:

- which environment belonged to the attacker;
- the exact browser cookie or token used;
- credential entry into a phishing page;
- malicious MFA registration;
- unauthorised OAuth consent;
- endpoint compromise;
- mailbox-rule creation;
- file or email collection;
- privilege escalation; or
- data exfiltration.

The publisher's controlled-lab ground truth confirms stolen session-cookie
reuse. All other downstream actions remain investigative checks unless
additional evidence is obtained.

## 11. References

- Microsoft, “Revoke user access in an emergency in Microsoft Entra ID”:
  https://learn.microsoft.com/en-us/entra/identity/users/users-revoke-access
- Microsoft Graph, “user: revokeSignInSessions”:
  https://learn.microsoft.com/en-us/graph/api/user-revokesigninsessions?view=graph-rest-1.0
- Microsoft, “Investigate risk with Microsoft Entra ID Protection”:
  https://learn.microsoft.com/en-us/entra/id-protection/howto-identity-protection-investigate-risk
- Microsoft, “Token theft playbook”:
  https://learn.microsoft.com/en-us/security/operations/token-theft-playbook
- Microsoft, “Respond to a compromised cloud email account”:
  https://learn.microsoft.com/en-us/defender-office-365/responding-to-a-compromised-email-account
- Microsoft, “Continuous access evaluation in Microsoft Entra”:
  https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-continuous-access-evaluation
- Microsoft, “Require phishing-resistant multifactor authentication for
  Microsoft Entra administrator roles”:
  https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-admin-phish-resistant-mfa
- Microsoft, “Require reauthentication and disable browser persistence”:
  https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-all-users-persistent-browser
