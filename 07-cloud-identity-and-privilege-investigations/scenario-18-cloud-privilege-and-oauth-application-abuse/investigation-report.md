# Investigation Report

## Executive finding

The investigation confirms an unapproved cloud privilege-abuse sequence involving administrator-initiated consent and privilege changes, service-principal credential creation, successful application-only authentication, Microsoft Graph resource activity, business-data access, and creation and use of a second persistence credential.

The correct event label is **Confirmed cloud privilege abuse**. The application identity assessment remains **Possible application identity compromise** because telemetry confirms credential use but does not directly identify the human operator or expose credential material.

## Scope

- Tenant: synthetic single-tenant environment.
- Primary application: `Northstar Data Operations Connector [SYNTHETIC]`.
- Incident interval: 2026-06-15 00:59–03:30 UTC.
- Baseline period represented: 2026-04-30 through 2026-06-14.
- Telemetry types: directory audit, object snapshots, OAuth grants, app-role assignments, directory role assignment, credential metadata, user sign-ins, service-principal sign-ins, API activity, platform risk, and business context.

## Object model

| Object | Stable identifier | Meaning |
|---|---|---|
| Application object | `e59726d4-d5cb-5b2d-9884-cd8788d3a59a` | Application definition / app registration object |
| App ID | `7e826e1b-2861-5d4f-866a-6366dd986a64` | Client identifier connecting the application definition and service principal |
| Service principal | `13b2b610-6000-5b59-a4c3-66994834a818` | Tenant-local enterprise application and security principal |
| Microsoft Graph resource service principal | `fba658c4-6949-5c14-b34c-cdfc6f08a125` | Resource service principal defining Graph permissions |

Deleting, disabling, or modifying one object is not automatically equivalent to taking the same action on the others.

## Initiating principal

The incident sequence began after an interactive sign-in by `Cloud Administrator Two` from `203.0.113.77` in `SG`. The administrator baseline expected New Zealand sources and normal user/group administration, not application consent, service-principal credential changes, or privileged application role assignment.

The sign-in risk label is treated only as a supporting platform signal. The investigation conclusion instead relies on audit changes, stable credential IDs, token IDs, resource operations, and owner verification.

## Permission and role changes

### Delegated permission grant

The service principal received a tenant-wide `AllPrincipals` OAuth grant with `offline_access Mail.ReadWrite`. This is delegated permission, meaning the application would act on behalf of a user. The grant's existence is confirmed, but use is not observed.

### Application permissions

The service principal received four app-role assignments:

- `Application.ReadWrite.All`;
- `AppRoleAssignment.ReadWrite.All`;
- `Sites.Read.All`;
- `Files.Read.All`.

Because the assigned principal is a service principal, these are application permissions and support app-only access. Assignment success does not prove use. Later application-only API activity confirms access by the service principal, while the exact permission claim used for each request remains unlogged.

### Directory role

An active permanent Entra directory role, `Cloud Application Administrator [SYNTHETIC ROLE]`, was assigned to the service principal. The assignment was not PIM eligible, time-bound, or activated through PIM. It was not an Azure RBAC assignment.

## Credential change and use

### Client secret

At `2026-06-15T01:18:00Z`, client-secret metadata named `backup-rotation` was added without an approved ticket. Secret material was not logged.

At `2026-06-15T01:24:00Z`, the exact key ID `39acbc69-455e-5b9d-adb1-dcd57a386a7b` appeared in a successful service-principal sign-in using `clientSecret` and `oauth2ClientCredentials`. This confirms use of the credential metadata, but it does not identify who possessed the secret.

### Federated identity credential

At `2026-06-15T01:36:00Z`, the primary application identity created `emergency-build`. The API operation and directory audit share request/operation context plus the same service-principal ID. Audit and API correlation IDs are intentionally not treated as equivalent.

At `2026-06-15T02:05:00Z`, the exact federated credential ID `20cc77c2-49cf-537d-9db9-b7d166018d7f` appeared in a successful application sign-in. This confirms that the new trust relationship was used.

## API activity and impact

The client-secret sign-in issued token identifier `bac69792-442c-5c36-9054-1a99f48152f3`. The same token identifier was recorded in successful operations that:

- listed applications;
- listed service principals;
- listed SharePoint sites;
- listed OneDrive drive items;
- downloaded `FY26-Forecast-Synthetic.xlsx`;
- created the additional federated identity credential.

The file-download record states `file_content_returned`, directly supporting confirmed business-data access in the synthetic event.

The federated-credential sign-in issued token identifier `52f99e92-bb8b-5678-8990-0a5caffcaffd`, which was used for a further application-listing operation.

## Governance verification

The application owner reported that no deployment, consent, role assignment, secret rotation, or federated identity change was approved for the incident date. No change ticket was found.

Approved baseline records were separately identified and excluded:

- legacy production certificate `prod-cert-2025`;
- approved rotation certificate `prod-cert-2026`;
- approved GitHub CI/CD federated credential `github-prod-deploy`;
- approved survey application user consent for `User.Read`.

## Containment

The responder disabled the service principal, deleted the delegated grant, removed app-role assignments, removed the directory role, removed the client secret, deleted the federated credential, and revoked the administrator user's refresh tokens.

These actions have different scopes. Revoking the user's sessions addresses user and delegated access but does not independently remove application-only credentials or app-role assignments. Deleting a grant does not delete credentials. Deleting a credential does not guarantee immediate invalidation of every already-issued access token.

## Final classification

### Confirmed cloud privilege abuse

Supported by unapproved privilege changes, credential use, application-only API activity, business-data access, persistence creation and use, and owner denial.

### Possible application identity compromise

Supported by successful use of unapproved credentials and off-baseline application activity. It remains possible rather than confirmed because credential material and direct operator attribution are unavailable.

## Detection gaps and limitations

- Exact app-role permission claims were not logged per API request.
- Delegated permission use was not observed.
- Cross-product correlation IDs cannot be assumed equivalent.
- Real environments may lack service-principal sign-ins or Microsoft Graph activity logs because of licensing, configuration, export, or retention.
- A successful sign-in or API response alone does not identify the person controlling an application identity.
