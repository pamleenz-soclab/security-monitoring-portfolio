# Triage Note

## Alert context

A service principal that had been dormant for more than 30 days became active after a sequence of consent, permission, role, and credential changes. The initiating administrator session originated from an off-baseline country and IP address and performed operations outside the administrator's normal activity profile.

## Initial severity

**High**

## Initial assessment

**Possible application identity compromise**

## Immediate observations

- User sign-in: `Cloud Administrator Two`, 2026-06-15 00:59 UTC, source `203.0.113.77`, country `SG`.
- Tenant-wide delegated grant: `offline_access Mail.ReadWrite`.
- Application permissions: `Application.ReadWrite.All`, `AppRoleAssignment.ReadWrite.All`, `Sites.Read.All`, and `Files.Read.All`.
- Entra directory role: active permanent `Cloud Application Administrator [SYNTHETIC ROLE]` assigned to a service principal.
- New client-secret key ID: `39acbc69-455e-5b9d-adb1-dcd57a386a7b`.
- Matching successful service-principal sign-in at `2026-06-15T01:24:00Z`.
- Matching token identifier used for Graph and resource operations.
- Additional federated identity credential created and later used.

## Benign alternatives checked

- Approved certificate rotation: present and excluded.
- Approved CI/CD federated identity: present and excluded.
- Low-risk user consent for `User.Read`: present and excluded.
- Normal application resource, source country, and credential baseline: inconsistent with the incident activity.
- Change ticket or owner approval: not found.

## Escalation decision

Escalate to cloud identity incident response. The event is not explained by the approved baseline and includes successful application-only access and business-content retrieval.

## Final triage disposition

**Confirmed cloud privilege abuse**
**Possible application identity compromise**
