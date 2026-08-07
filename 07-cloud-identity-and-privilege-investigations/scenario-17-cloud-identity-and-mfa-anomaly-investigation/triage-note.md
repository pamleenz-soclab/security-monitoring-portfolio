# Triage Note

## Alert summary

Multiple users experienced invalid-password failures from two unfamiliar hosting-provider IP addresses. One targeted user then generated repeated Microsoft Authenticator denials and timeouts followed by a successful number-matching sign-in from an unapproved anonymous-proxy IP and an unknown unmanaged device.

## Initial severity

**High**

## Initial scope

- Five targeted user identities.
- Two source IP addresses.
- One successful suspicious user session.
- Microsoft 365, Exchange Online, SharePoint Online, and Microsoft Graph.
- One separate legacy IMAP/ROPC attempt.
- One service principal and one managed identity reviewed as possible noise.

## Immediate triage facts

- Ten error-50126 failures across five users indicate password-spray behavior.
- Four later attempts for `USER-001` passed primary authentication and failed at MFA.
- The fifth MFA-challenged attempt succeeded using number matching.
- Enforced MFA policies succeeded.
- A compliant-device policy returned `reportOnlyFailure` and did not block.
- A session was created and reused for non-interactive token activity and Microsoft 365 actions.
- User verification established that the successful sign-in and follow-on activity were unauthorized.

## Triage disposition

**Escalate as confirmed cloud-account compromise.**

## Immediate actions

1. Revoke active sessions and refresh tokens.
2. Reset the password using a clean administrative workflow.
3. Remove unauthorized authentication methods and require secure re-registration.
4. Disable the account temporarily if containment cannot be confirmed.
5. Remove the forwarding inbox rule and inspect mailbox permissions.
6. Review downloaded files and downstream exposure.
7. Search the two attack IPs, ASN patterns, device characteristics, and targeted usernames across the tenant.
8. Review OAuth consent, role assignment, device registration, and administrative actions.
