# Containment Decision Record

## Decision

Contain `internal_share` promptly using host isolation or equivalent DNS/egress controls appropriate to business criticality; block `email-19.kennedy-mendoza.info` and `192.168.230.122`; restrict DNS egress to approved resolvers; and preserve then disable the suspicious `put` service. In the lab ground truth this service implements the exfiltration mechanism; production authorization would still need to be verified.

## Rationale

- Receiver-side hash equality proves completed data loss.
- The service runs with root context in the lab configuration.
- Activity persisted over multiple days and affected multiple data categories.
- A final object was still in progress when the simulation stopped.
- DNS is an infrastructure service; blocking only a single source process would be insufficient without resolver and egress controls.

## Alternatives rejected

- **Monitor only:** rejected because exfiltration was already confirmed.
- **Block only the domain:** insufficient because the mechanism can rotate domains or use direct authoritative DNS infrastructure.
- **Delete the service/script immediately:** rejected before evidence preservation because it could destroy forensic context.
- **Reimage without collection:** rejected because it would lose process, filesystem, and persistence evidence.

## Evidence-preservation prerequisite

Capture service files, unit definitions, hashes, process/socket state, audit logs, resolver logs, packet telemetry, and relevant share metadata before destructive remediation.
