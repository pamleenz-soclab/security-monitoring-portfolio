# Containment Strategy

Containment is designed rather than executed because the source is a historical emulation dataset.

## P1

- Isolate SCRANTON and NASHUA while preserving forensic visibility.
- Disable/reset `pbeesly` and revoke active sessions/tickets.
- Stop/quarantine validated malicious persistence and remote payloads after evidence capture.

## P2

- Block validated incident communications.
- Restrict unauthorized WinRM/SMB paths.
- Remove persistence after verifying service/binary ownership.

## P3

- Expand hunting for the same process, service, session, and network behavior across the estate.

Every action in `evidence/processed/containment-decision-register.csv` includes expected effect, business risk, and verification. Isolation, account revocation, service removal, and WinRM/SMB controls can all affect legitimate operations and must be validated before execution.
