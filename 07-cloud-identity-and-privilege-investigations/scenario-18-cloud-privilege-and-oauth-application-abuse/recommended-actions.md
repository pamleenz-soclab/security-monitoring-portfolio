# Recommended Actions

## Immediate containment

1. Disable the affected service principal to block new token issuance where supported.
2. Remove unapproved client secrets, certificates, and federated identity credentials.
3. Delete delegated OAuth grants and remove application app-role assignments separately.
4. Remove Entra directory roles and review any Azure RBAC assignments independently.
5. Revoke affected user refresh tokens and reset credentials when a user session may be compromised.
6. Review already-issued access-token exposure and resource-specific session controls.
7. Preserve directory audit, sign-in, Graph activity, Microsoft 365 audit, and resource logs before retention expires.

## Investigation expansion

- Search all service-principal sign-ins for the App ID, service-principal ID, credential key IDs, and federated credential IDs.
- Search Microsoft Graph, SharePoint, OneDrive, Exchange, Azure Resource Manager, Key Vault, and Storage telemetry.
- Identify all users, mailboxes, sites, files, subscriptions, and resources accessed by the application.
- Review whether the same administrator changed permissions or credentials on other applications.
- Check whether the same source IP, ASN, issuer, subject, or automation repository appears elsewhere.
- Validate application owners, publisher status, deployment pipelines, and change tickets.

## Recovery

- Re-create only the minimum approved permissions.
- Rotate legitimate downstream secrets the application could access.
- Restore application credentials through an approved pipeline.
- Validate owners, reply URLs, requiredResourceAccess, permission grants, role assignments, and federated trust subjects.
- Test business workflows before re-enabling the service principal.

## Strategic controls

- Require approval for admin consent and high-risk application permissions.
- Alert on credential additions to existing or dormant applications.
- Baseline service-principal source networks, resources, credential types, and activity volume.
- Prefer managed identity or narrowly scoped workload federation over long-lived secrets.
- Apply PIM and time-bound role controls where supported.
- Schedule periodic application-owner attestation and unused-permission removal.
- Export service-principal sign-ins and Microsoft Graph activity logs with sufficient retention.
