# Validation Checklist

## Evidence integrity

- [x] Raw evidence generated deterministically.
- [x] Source SHA-256 records created.
- [x] 10/10 source hashes verified.
- [x] 162 sign-in IDs unique.
- [x] No orphan authentication steps.
- [x] No orphan Conditional Access records.
- [x] Raw and working directories excluded from Git.
- [x] Final package manifest generated after files were closed.

## Investigation logic

- [x] Interactive and non-interactive sign-ins separated.
- [x] Service principal and managed identity separated.
- [x] Primary authentication separated from MFA.
- [x] MFA success not equated with user authorization.
- [x] Report-only CA result not described as enforcement.
- [x] Risk scores not used as compromise proof.
- [x] Approved VPN context considered.
- [x] GeoIP not treated as physical location proof.
- [x] Session, correlation, request, and token identifier scopes documented.
- [x] Token refresh not counted as repeated user action.
- [x] Follow-on activity correlated.
- [x] User verification documented.
- [x] Ground truth checked only after independent assessment.

## Publication safety

- [x] No real UPN, tenant, user ID, device ID, session ID, or token ID.
- [x] No access token, refresh token, cookie, Authorization header, MFA seed, or secret.
- [x] Only synthetic RFC 5737 IP addresses retained.
- [x] Conditional Access policy names replaced with aliases in processed evidence.
- [x] Processed evidence contains identity aliases.
- [x] Raw and working files absent from standalone package.
- [x] Scripts remain publishable.
- [x] No trailing whitespace.
- [x] No conflict markers.
- [x] Git-aware and standalone validator modes supported.
