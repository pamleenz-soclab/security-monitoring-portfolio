# Executive Summary

## Incident

A cloud identity was compromised after a distributed password spray and repeated Microsoft Authenticator prompts. The attacker successfully completed number-matching MFA, obtained a session, registered additional security information, created an external-forwarding mailbox rule, and downloaded three confidential finance files.

## Outcome

**Confirmed account compromise**

## Why the conclusion is reliable

The conclusion is supported by multiple independent evidence sources:

- correct primary authentication;
- repeated MFA denials and timeouts followed by success;
- enforced MFA Conditional Access policies satisfied;
- session creation;
- same-session non-interactive token activity;
- same-session mailbox and file activity;
- correlated authentication-method registration;
- user verification that the activity was unauthorized.

Risk labels and unusual location were treated as supporting leads, not proof.

## Scope

- Five users were targeted by password spray.
- One user was compromised.
- Four users had no successful authentication or follow-on activity.
- A separate legacy IMAP attempt was blocked.
- Service-principal and managed-identity sign-ins were benign.
- Three confidential finance files were accessed.
- An external-forwarding inbox rule was created.

## Response

Sessions were revoked, the password was reset, and the unauthorized authentication method was removed. Additional recommended actions include mailbox-rule removal, tenant-wide hunting, OAuth and role review, endpoint validation, data-owner notification, and strengthened Conditional Access controls.

## Strategic improvements

1. Enforce phishing-resistant authentication for sensitive roles.
2. Enable number matching and user education against MFA fatigue.
3. Enforce compliant or managed devices for finance access.
4. Block legacy authentication.
5. Alert on repeated MFA denial/timeout followed by success.
6. Correlate suspicious successful sign-ins with authentication-method changes, mailbox rules, and file downloads.
7. Maintain approved VPN, proxy, mobile-carrier, and cloud-egress inventories.
