# Containment Decision Record

## Decision

Contain `USER-001` as a confirmed compromised identity.

## Decision time

2026-06-18 02:55 UTC, after user verification.

## Triggering evidence

- Correct primary authentication from unapproved infrastructure.
- Repeated MFA denials and timeouts followed by successful number matching.
- Session creation.
- Security-information registration.
- External-forwarding inbox rule.
- Confidential file downloads.
- User confirmation that all activity was unauthorized.

## Selected actions

| Action | Decision | Reason |
|---|---|---|
| Revoke sessions and refresh tokens | Execute immediately | Stop continued token use |
| Reset password | Execute immediately | Correct password was used |
| Remove unauthorized authentication method | Execute immediately | Prevent persistent access |
| Require MFA re-registration | Execute | Re-establish trusted methods |
| Disable account | Conditional | Use if session revocation cannot be verified or activity continues |
| Block source IPs | Temporary supplemental control | Infrastructure is synthetic/replaceable; not sufficient alone |
| Isolate device | Conditional | No corporate endpoint was tied to the attacker device |
| Remove inbox rule | Execute | Stop external forwarding and concealment |
| Review OAuth applications | Execute | Rule out consent-based persistence |
| Review data exposure | Execute | Three confidential files were downloaded |

## Actions observed in telemetry

- Refresh tokens revoked at 03:05 UTC.
- Password reset at 03:07 UTC.
- Unauthorized authentication method deleted at 03:10 UTC.

## Residual risk

- Existing application sessions can persist depending on token and service behavior.
- Downloaded data cannot be recalled solely through identity containment.
- No approving-device telemetry was available.
- No downstream use of the files was modeled.
