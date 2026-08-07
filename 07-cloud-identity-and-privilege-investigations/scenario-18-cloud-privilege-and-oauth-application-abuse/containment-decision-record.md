# Containment Decision Record

## Decision

Contain the application identity and the initiating administrator identity as separate security principals.

## Actions selected

| Action | Selected | Reason |
|---|---:|---|
| Disable service principal | Yes | Stops or strongly restricts new application authentication while scope is assessed |
| Remove delegated OAuth grant | Yes | Removes delegated authorization; separate from app-only permissions |
| Remove app-role assignments | Yes | Revokes application permissions |
| Remove Entra directory role | Yes | Removes directory-administration capability |
| Remove client secret | Yes | Prevents future authentication with that secret |
| Remove federated identity credential | Yes | Prevents future token exchange through that trust |
| Revoke administrator refresh tokens | Yes | Addresses possible user-session compromise |
| Delete application object immediately | No | Preserve evidence and avoid unnecessary business destruction before owner and dependency review |
| Reset every user password | No | Application-only access is not terminated by indiscriminate user resets |

## Decision principles

- Grant, credential, service principal, and application object are distinct containment scopes.
- User-session revocation does not substitute for application containment.
- Credential deletion does not prove that already-issued tokens are immediately invalid.
- Destructive deletion is deferred until evidence preservation and business-owner review are complete.

## Re-enable criteria

- Owner validates the application business need.
- All unapproved grants, assignments, and credentials are removed.
- Approved credentials are rotated through a controlled process.
- Resource access logs show no unexplained follow-on activity.
- Least-privilege permissions are documented and approved.
- Monitoring is enabled before reactivation.
