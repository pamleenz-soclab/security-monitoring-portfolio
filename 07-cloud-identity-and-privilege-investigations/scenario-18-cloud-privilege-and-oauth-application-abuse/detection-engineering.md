# Detection Engineering

## Detection objectives

The detection set focuses on changes and follow-on use rather than treating any single consent or credential event as automatically malicious.

| Detection | Primary telemetry | Key correlation |
|---|---|---|
| Suspicious admin consent | Entra AuditLogs | Initiator, client service principal, consent type, scopes |
| High-risk application permission grant | AuditLogs / appRoleAssignment inventory | Principal service-principal ID, resource ID, appRoleId/value |
| New credential on existing service principal | AuditLogs / object snapshot | Service-principal or application object ID, credential key ID |
| Credential followed by service-principal sign-in | AuditLogs + AADServicePrincipalSignInLogs | Credential key ID or federated credential ID |
| Application permission followed by sensitive Graph use | AuditLogs + MicrosoftGraphActivityLogs | App ID, service-principal ID, time window, request URI |
| Suspicious directory role assignment | AuditLogs / role management | Principal ID, role definition, assignment type |
| Privileged role assigned to service principal | AuditLogs | Target resource type ServicePrincipal plus role |
| New federated identity credential | AuditLogs | Application object ID, issuer, subject, audience, credential ID |
| Dormant application becomes active | AADServicePrincipalSignInLogs | Service-principal ID and historical last-sign-in baseline |
| Unusual administrator permission change | AuditLogs + administrator baseline | Initiator ID, operation family, source IP/country, change window |

## Correlation hierarchy

Use the strongest available evidence in this order:

1. Credential key ID or federated credential ID.
2. Service-principal object ID.
3. App ID plus resource ID.
4. Unique token identifier.
5. Request ID or operation ID with compatible product semantics.
6. Correlation ID only inside a verified semantic boundary.
7. Time proximity as supporting context, never as the only join.

## Detection boundaries

- Admin consent is not automatically malicious.
- High-risk permissions require owner, change, publisher, baseline, and use context.
- A credential-addition alert does not prove the secret was obtained.
- A role-assignment alert does not prove use.
- A successful sign-in does not identify the human operator.
- Graph request success does not always prove data content was returned; inspect endpoint and response telemetry.

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
- application inactivity and reactivation thresholds.

## Query status

The Sentinel examples use Microsoft table and field names where available. Splunk and Elastic examples use documented normalised placeholders and require field mapping to the local add-on, index, data stream, or ECS implementation before production use.
