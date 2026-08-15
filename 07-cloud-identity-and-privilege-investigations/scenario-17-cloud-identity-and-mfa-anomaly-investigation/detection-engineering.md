# Detection Engineering

## Objectives

Detect and correlate:

1. distributed password spray;
2. repeated MFA denial/timeout followed by success;
3. unusual successful sign-in from unfamiliar infrastructure or device;
4. legacy authentication;
5. Conditional Access failure, not-applied, and report-only outcomes;
6. risky sign-in signals;
7. authentication-method changes after suspicious sign-in;
8. mailbox-rule creation and high-value file access;
9. deviations from the user's own baseline;
10. service-principal and managed-identity anomalies without mixing them with user detections.

## Detection principles

- Separate primary-authentication failure from MFA failure.
- Avoid treating all error codes as incorrect passwords.
- Require a time-bounded sequence for MFA-fatigue detection.
- Treat MFA success as method completion, not authorization.
- Treat `reportOnlyFailure` as evaluation only.
- Use `SessionId` where the log source actually exposes it; do not assume Microsoft 365 `OfficeActivity` carries the Entra session identifier.
- Treat user/IP/time correlation across Office audit as contextual linkage unless a stronger shared identifier is available.
- Keep service principals and managed identities in dedicated analytic rules.
- Use per-user baseline and approved-network inventories.
- Correlate identity events with audit and business activity.
- Preserve raw error code, failure reason, and additional details.

## Deployment mapping

- Microsoft Sentinel interactive sign-ins use `SigninLogs`; non-interactive user sign-ins use `AADNonInteractiveUserSignInLogs`.
- Identity Protection user risk events use `AADUserRiskEvents` rather than a synthetic table name.
- `OfficeActivity` follow-on correlation uses supported fields such as `UserId`, `ClientIP`, `Operation`, `ResultStatus`, `OfficeObjectId`, and time. It is not treated as a direct Entra `SessionId` join.
- SPL and ES|QL examples require field mapping to the organization's ingestion schema before deployment.

## Core rules

### MFA fatigue

Alert when the same user and source produce multiple denied or timeout MFA steps within 10–15 minutes and are followed by a successful MFA sign-in. Raise severity when:

- source is unapproved;
- device is unfamiliar or unmanaged;
- sign-in risk is medium/high;
- a new method is registered;
- a mailbox rule or file download follows.

### Password spray

Detect one source or infrastructure cluster producing invalid-password failures across many distinct users with low attempts per account. Consider distributed sources by grouping by ASN, provider, device fingerprint, user agent, and time.

### Legacy authentication

Detect IMAP, POP, SMTP AUTH, Exchange ActiveSync, or ROPC. Prioritize successful events and Conditional Access `notApplied`.

### Unusual successful sign-in

Score deviations from each user's network, country, device, application, protocol, and working-hour baseline. Suppress approved VPN, proxy, mobile-carrier, cloud-egress, and travel contexts.

### Follow-on correlation

Correlate suspicious successful sign-ins with:

- authentication-method registration;
- password reset;
- device registration;
- OAuth consent;
- role assignment;
- external forwarding;
- mailbox rules;
- file downloads;
- session revocation.

## Validation results

The included synthetic event should trigger:

- two password-spray source candidates;
- one MFA-fatigue sequence;
- one suspicious successful interactive sign-in;
- one blocked legacy-auth attempt;
- one authentication-method change;
- one forwarding rule;
- three confidential file downloads.

It should not incorrectly classify:

- the approved Sydney VPN sign-in as malicious;
- the three non-interactive token events as new MFA approvals;
- the report-only device result as an enforced block;
- the workload identities as user compromise.
