# Generic Detection Catalogue

## MFA fatigue

**Required data:** user, source IP, authentication-step time, method, result detail, overall sign-in result, session ID.

**Logic:** at least three denied or timeout Authenticator steps for the same user and source within 15 minutes followed by a successful MFA step.

**Severity upgrades:** unknown device, unapproved network, high risk, new security method, mailbox rule, file downloads.

## Password spray

**Required data:** timestamp, user, source IP, error code, application.

**Logic:** invalid-password failures from one source or related infrastructure against at least five distinct users within ten minutes, with low attempts per account.

## Legacy authentication

**Required data:** client application and authentication protocol.

**Logic:** IMAP, POP, SMTP AUTH, Exchange ActiveSync, or ROPC. Prioritize success or Conditional Access not applied.

## Unusual successful sign-in

**Required data:** user baseline, source network, ASN, country, device, application, protocol, risk, Conditional Access.

**Logic:** successful sign-in deviating from the user's normal combinations. Suppress approved VPN, proxy, travel, mobile, and cloud-egress contexts.

## Conditional Access coverage

**Logic:** identify failed, not-applied, and report-only policy results. Never treat report-only as enforcement. Do not infer exact not-applied reasons without policy condition detail.

## Follow-on correlation

**Logic:** correlate suspicious successful sign-ins with security-information changes, device registration, OAuth consent, role changes, mailbox forwarding, file downloads, and session revocation.
