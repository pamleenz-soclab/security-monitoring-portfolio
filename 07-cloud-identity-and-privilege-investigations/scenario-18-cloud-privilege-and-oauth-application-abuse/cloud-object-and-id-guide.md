# Cloud Object and Identifier Guide

## Core relationship

```text
Application object (app registration definition)
  id = e59726d4-d5cb-5b2d-9884-cd8788d3a59a
  appId = 7e826e1b-2861-5d4f-866a-6366dd986a64
       │
       └── maps to tenant-local service principal
             id = 13b2b610-6000-5b59-a4c3-66994834a818
             appId = 7e826e1b-2861-5d4f-866a-6366dd986a64
```

## Identifier meanings

| Field | Meaning | Use in this investigation |
|---|---|---|
| Application object `id` | Object ID of the application definition | Application updates and federated identity credential target |
| `appId` | Application/client ID | Maps app definition, service principal, sign-ins, and API client activity |
| Service principal `id` | Tenant-local object ID | OAuth grant clientId, app-role principalId, directory role principal, and sign-ins |
| OAuth grant `id` | Delegated permission grant object | Revocation and audit tracking |
| App-role assignment `id` | Application permission assignment object | Revocation and permission inventory |
| Credential `keyId` | Password or certificate metadata ID | Credential-to-sign-in correlation |
| `FederatedCredentialId` | Federated identity credential ID used for sign-in | Persistence credential-to-sign-in correlation |
| `UniqueTokenIdentifier` | Token identifier recorded in sign-in and activity data | Sign-in-to-API correlation in the synthetic package |
| `RequestId` / `OperationId` | Request or operation identifier within a telemetry boundary | API-to-audit change correlation when semantics match |
| `CorrelationId` | Product-specific troubleshooting or flow identifier | Never assumed to have identical cross-product scope |

## Common mistakes avoided

- Treating app ID as an object ID.
- Treating app registration and enterprise application as the same object.
- Treating delegated scopes and application app roles as interchangeable.
- Treating Entra directory roles and Azure RBAC roles as the same system.
- Treating PIM eligibility as an active role assignment.
- Treating time proximity as proof when a stable identifier is available.
