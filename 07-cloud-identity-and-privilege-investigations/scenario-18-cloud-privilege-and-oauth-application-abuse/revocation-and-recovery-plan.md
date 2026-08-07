# Revocation and Recovery Plan

## Why multiple actions are required

Cloud application access is represented by several independent objects and authorisation paths. Removing one element does not automatically remove all others.

| Action | Primary effect | What it does not automatically do |
|---|---|---|
| Revoke user sign-in sessions | Invalidates user refresh tokens and browser sessions | Remove application permissions or service-principal credentials |
| Delete delegated OAuth grant | Prevents new delegated tokens for that grant | Delete the service principal, application, or app-only permissions |
| Remove app-role assignment | Revokes an application permission | Delete credentials or delegated grants |
| Remove client secret | Prevents future authentication using that secret | Revoke every already-issued access token immediately |
| Remove certificate | Prevents future authentication using that key | Remove other credentials or grants |
| Remove federated credential | Prevents future token exchange through that issuer/subject trust | Revoke every token already issued through the trust |
| Disable service principal | Blocks new token issuance or use according to platform enforcement | Delete the application definition or preserve business configuration automatically |
| Delete enterprise application | Deletes the tenant-local service principal | Necessarily delete an app registration owned in another tenant |
| Delete app registration | Deletes the application definition in its home tenant | Automatically remediate every downstream resource or external tenant relationship |

## Ordered recovery plan

1. Preserve logs and object snapshots.
2. Disable the affected service principal.
3. Remove all unapproved credentials and federated trusts.
4. Remove delegated grants and app-role assignments.
5. Remove directory and Azure resource role assignments independently.
6. Revoke affected user sessions and reset user credentials where justified.
7. Review tokens, sessions, and resource-level authorisation caches.
8. Search downstream resources and rotate exposed credentials.
9. Recreate only owner-approved, least-privilege configuration.
10. Validate sign-ins and resource access before re-enabling.
11. Monitor closely for recurrent app ID, service-principal ID, source IP, issuer, subject, and credential changes.

## Rollback and evidence considerations

Do not delete the application object before preserving owners, reply URLs, required permissions, credentials, federated identities, grants, assignments, and audit records. Where business continuity requires rollback, use a documented clean configuration rather than restoring unverified credentials.
