# False-Positive Tuning

## MFA fatigue

Potential benign causes:

- repeated user mistakes;
- delayed push notifications;
- authenticator connectivity problems;
- multiple legitimate application prompts;
- device migration or re-registration;
- helpdesk-guided authentication.

Tuning:

- require denied/timeout outcomes followed by success;
- correlate source IP, ASN, device, session, and application;
- use a short time window;
- suppress known enrollment and migration windows;
- increase severity only with suspicious follow-on activity or user verification.

## Password spray

Potential benign causes:

- shared proxy or VPN egress;
- misconfigured applications;
- password-expiry events;
- automated health checks;
- large identity migrations.

Tuning:

- use distinct-user count and attempts-per-user;
- group related distributed IPs by ASN/provider and fingerprint;
- exclude approved scanners and identity-test systems;
- differentiate 50126 from CA and MFA errors;
- look for later success.

## Unusual location

Potential benign causes:

- corporate VPN;
- mobile carriers;
- cloud proxy/SASE;
- travel;
- GeoIP error;
- non-interactive logs preserving an earlier IP.

Tuning:

- compare with approved-network inventory;
- verify device and application;
- use user baseline;
- avoid using travel speed as proof;
- treat non-interactive source IP carefully.

## Unknown device

Potential benign causes:

- missing device fields;
- browser privacy features;
- unmanaged but approved BYOD;
- service limitations;
- legacy clients.

Tuning:

- distinguish `false` from empty;
- combine device data with protocol, source, and user baseline;
- do not alert solely on missing compliance data.

## Conditional Access

Potential benign causes:

- report-only evaluation;
- policy not targeting the user or resource;
- excluded account;
- unsupported client;
- existing MFA claim satisfying control.

Tuning:

- expand policy-level results;
- keep report-only separate;
- do not infer exact `notApplied` reason without condition data;
- correlate CA result with overall sign-in result.

## Workload identities

Potential benign causes:

- scheduled automation;
- Azure-managed token acquisition;
- certificate rollover;
- infrastructure scaling.

Tuning:

- maintain owner, credential type, resource, and egress baseline;
- use separate service-principal and managed-identity analytics;
- alert on new credentials, new resources, unfamiliar tenants, or unusual volume.
