# Recommended Actions

## Immediate containment

- Revoke all active sessions and refresh tokens for the compromised user.
- Temporarily disable the account if revocation cannot be confirmed.
- Reset the password through a trusted administrative channel.
- Remove unauthorized authentication methods.
- Require MFA re-registration from a trusted device.
- Remove the external-forwarding inbox rule.
- Review mailbox delegates, forwarding settings, transport rules, and inbox rules.
- Review OAuth applications and consent grants.
- Isolate and inspect any endpoint associated with the unauthorized sign-in.
- Block or monitor the attack IPs and related infrastructure with awareness that IP blocks alone are temporary controls.

## Investigation expansion

- Search both attack IPs across all sign-in types.
- Search all targeted usernames for later success.
- Review authentication-method registration events.
- Review device registration and join events.
- Review role assignments and privileged group changes.
- Review Azure Activity and Microsoft 365 audit.
- Review file downloads, sharing, and external links.
- Review mailbox access, search, message deletion, and forwarding.
- Review service-principal and managed-identity sign-ins separately from users.
- Check whether additional sessions continued after revocation.

## Recovery

- Confirm the user can sign in only from known devices and approved networks.
- Require secure password change and MFA re-registration.
- Validate that no unauthorized methods remain.
- Confirm inbox and transport rules are clean.
- Confirm no unauthorized OAuth grants or app credentials remain.
- Confirm downloaded data scope with finance and privacy owners.
- Monitor the account for at least one full token/session lifetime after containment.

## Preventive controls

- Enforce phishing-resistant authentication for finance and privileged users.
- Apply authentication strength policies.
- Enforce compliant or managed devices for sensitive applications.
- Move report-only device policies to enforcement after impact validation.
- Block legacy authentication tenant-wide with controlled exceptions.
- Use Smart Lockout and password-protection controls.
- Alert on MFA fatigue patterns.
- Alert on new authentication methods after risky sign-ins.
- Alert on forwarding rules after suspicious sign-ins.
- Correlate high-volume downloads with sign-in anomalies.
- Maintain an approved VPN/proxy/mobile/cloud-egress inventory.
- Ensure sufficient sign-in, audit, and Identity Protection retention.
