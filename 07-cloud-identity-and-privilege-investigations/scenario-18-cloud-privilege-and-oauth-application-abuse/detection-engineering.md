# Detection Engineering

## Detection objectives

The detection set focuses on changes and follow-on use rather than treating any single consent or credential event as automatically malicious.

| Detection | Primary telemetry | Key correlation |
|---|---|---|
| Suspicious admin consent | Entra `AuditLogs` | Initiator, client service principal, consent type, scopes |
| High-risk application permission grant | `AuditLogs` / app-role inventory | Principal service-principal ID, resource ID, app-role ID/value |
| New credential on existing application identity | `AuditLogs` / object snapshot | Application or service-principal object ID, newly added credential ID |
| Credential followed by service-principal sign-in | `AuditLogs` + `AADServicePrincipalSignInLogs` | Added credential ID, sign-in credential ID, time window |
| Application permission followed by sensitive Graph use | `AuditLogs` + service-principal sign-in + `MicrosoftGraphActivityLogs` | Service-principal ID plus sign-in UTI / Graph sign-in-activity ID |
| Suspicious directory-role assignment | `AuditLogs` / role management | Principal ID, role definition, assignment type |
| Privileged role assigned to service principal | `AuditLogs` | Service-principal target plus privileged role |
| New federated identity credential | `AuditLogs` | Application object ID, issuer, subject, audience, credential ID |
| Dormant or no-recent-history application becomes active | `AADServicePrincipalSignInLogs` | Service-principal ID and historical last-sign-in baseline |
| Unusual administrator permission change | `AuditLogs` + administrator baseline | Initiator ID, operation family, source IP/country, change window |

## Correlation hierarchy

Use the strongest available evidence in this order:

1. Newly added credential key ID or federated credential ID.
2. Sign-in unique-token identifier joined to the workload's documented linkable identifier.
3. Service-principal object ID and App ID.
4. Request ID or operation ID when the source products document compatible semantics.
5. Correlation ID only inside a verified semantic boundary.
6. Time proximity as supporting context, never as the only join.

## Microsoft Sentinel production mapping

The synthetic dataset uses deliberately convenient normalised field names. Production queries must map to the actual connected tables.

- `AADServicePrincipalSignInLogs` exposes fields including `ServicePrincipalCredentialKeyId`, `FederatedCredentialId`, `ClientCredentialType`, `ServicePrincipalId`, `AppId`, and `UniqueTokenIdentifier`.
- `MicrosoftGraphActivityLogs` exposes `ServicePrincipalId`, `AppId`, `SignInActivityId`, `SessionId`, `RequestId`, `OperationId`, `Roles`, `Scopes`, request URI/method, and response fields.
- Microsoft documents `MicrosoftGraphActivityLogs.SignInActivityId` as the workload-side link to a sign-in log's `UniqueTokenIdentifier`. Prefer that documented link over same-name assumptions.
- The Scenario 18 synthetic API evidence does **not** contain `Roles` or `Scopes`, so exact permission-claim attribution remains **Not available** for the incident conclusion even though a production Graph activity table may provide those fields.

## Detection boundaries

- Admin consent is not automatically malicious.
- High-risk permissions require owner, change, publisher, baseline, and use context.
- A credential-addition alert does not prove the secret was obtained.
- A credential-addition-to-sign-in correlation is strong authentication evidence but can still represent approved rotation.
- A role-assignment alert does not prove role use.
- A successful sign-in does not identify the human operator.
- A successful Graph request does not always prove content return; inspect endpoint and response semantics.
- A service principal with no history in the chosen lookback is not automatically a dormant application; it can be newly deployed or outside retention.

## Tuning data

Maintain:

- approved application and service-principal inventory;
- owners and verified publishers;
- normal permission sets;
- approved administrator list;
- change windows and tickets;
- CI/CD issuers, subjects, audiences, and repositories;
- expected credential types and rotation schedule;
- expected source IPs, ASNs, countries, and target resources;
- application creation dates, inactivity baselines, and reactivation thresholds.

## Query status

The Sentinel examples use current Microsoft table/field semantics where those fields are available, but audit-event `TargetResources` / `modifiedProperties` shapes still require validation against the tenant's exported records. Splunk and Elastic examples use normalised placeholders and require mapping to the local add-on, index, data stream, or ECS implementation before production use. All rules are portfolio detection-engineering starting points, not turnkey production detections.
