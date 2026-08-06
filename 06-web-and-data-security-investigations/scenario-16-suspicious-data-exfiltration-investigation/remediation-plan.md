# Remediation Plan

## Phase 1 — Stabilise

- Isolate the affected server.
- Block known indicators and direct DNS egress.
- Preserve endpoint, resolver, firewall, and packet evidence.
- Rotate privileged and service credentials.

## Phase 2 — Scope

- Hunt for the domain, receiver IP, `3x6`/`3x7` grammar, long unique DNS queries, and similar systemd units.
- Identify all shares and datasets accessible to the service account.
- Review adjacent hosts for the same deployment artefacts or service configuration.

## Phase 3 — Eradicate

- Remove unauthorised unit files, scripts, binaries, and persistence mechanisms after preservation.
- Patch and harden the host.
- Rebuild from a trusted baseline where integrity is uncertain.
- Apply least privilege to file shares and service accounts.

## Phase 4 — Recover

- Restore the host behind enforced DNS and egress controls.
- Validate expected business services and approved data-transfer paths.
- Monitor for recurrence using the supplied detections and queries.

## Phase 5 — Improve

- Add Linux process-to-socket telemetry.
- Centralise recursive resolver logs with client identity.
- Implement DNS RPZ/sinkholing and rare-domain analytics.
- Integrate data catalogue, owner, and sensitivity fields into SOC alerts.
- Test low-and-slow exfiltration detections against approved backup, update, telemetry, and security products.
