# Investigation Notes

## Analytical method

1. Validate source integrity and synthetic safety markers.
2. Map application object, application/client ID, and tenant-local service principal object.
3. Separate delegated grants from application permissions.
4. Classify directory roles separately from API app roles and Azure RBAC.
5. Validate credential start/end times before linking sign-ins.
6. Link credentials to sign-ins using key or federated credential IDs.
7. Link sign-ins to API operations using service-principal ID and unique token identifier.
8. Link API-created directory changes using request ID, operation ID, and service-principal ID.
9. Compare activity with owner, administrator, CI/CD, publisher, and change-window baselines.
10. Assign Confirmed, Inferred, Not observed, Not available, and Detection gap labels.

## Key timeline

| UTC time | Source | Event | Evidence label |
| --- | --- | --- | --- |
| 2026-06-15T00:59:00Z | UserSignIn | Interactive user sign-in | Confirmed |
| 2026-06-15T01:14:00Z | DirectoryAudit | Consent to application | Confirmed |
| 2026-06-15T01:15:00Z | DirectoryAudit | Add app role assignment to service principal | Confirmed |
| 2026-06-15T01:17:00Z | DirectoryAudit | Add member to role | Confirmed |
| 2026-06-15T01:18:00Z | DirectoryAudit | Add service principal credentials | Confirmed |
| 2026-06-15T01:24:00Z | ServicePrincipalSignIn | Application sign-in using clientSecret | Confirmed |
| 2026-06-15T01:33:00Z | APIActivity | Download driveItem content | Confirmed |
| 2026-06-15T01:36:00Z | APIActivity | Create federatedIdentityCredential | Confirmed |
| 2026-06-15T01:36:00Z | DirectoryAudit | Add federated identity credential | Confirmed |
| 2026-06-15T02:05:00Z | ServicePrincipalSignIn | Application sign-in using federatedIdentityCredential | Confirmed |
| 2026-06-15T02:08:00Z | APIActivity | List applications | Confirmed |
| 2026-06-15T03:05:00Z | Business context | Application owner reported no approved change ticket or deployment | Confirmed |
| 2026-06-15T03:18:00Z | DirectoryAudit | Disable service principal | Confirmed |
| 2026-06-15T03:30:00Z | DirectoryAudit | Revoke all refresh tokens for user | Confirmed |

## Stable-ID findings

### Client-secret path

- Credential key ID: `39acbc69-455e-5b9d-adb1-dcd57a386a7b`.
- Added: `2026-06-15T01:18:00Z`.
- Successful sign-in: `2026-06-15T01:24:00Z`.
- Sign-in ID: `510e1852-cb7d-57a5-8a9e-18670b119f66`.
- Token identifier: `bac69792-442c-5c36-9054-1a99f48152f3`.
- API operations with the same token: 6.

### Federated-credential path

- Federated credential ID: `20cc77c2-49cf-537d-9db9-b7d166018d7f`.
- Created: `2026-06-15T01:36:00Z`.
- Successful sign-in: `2026-06-15T02:05:00Z`.
- Sign-in ID: `2b54ad03-75d1-56c5-86c8-1a75073da7a3`.
- Token identifier: `52f99e92-bb8b-5678-8990-0a5caffcaffd`.

## Important negative findings

- No delegated user token was observed.
- No mailbox read, mail send, or inbox-rule activity was observed.
- No credential material was present.
- No PIM eligible assignment or activation was present.
- No Azure RBAC role assignment was present.
- No direct human attribution for application credential control was present.
