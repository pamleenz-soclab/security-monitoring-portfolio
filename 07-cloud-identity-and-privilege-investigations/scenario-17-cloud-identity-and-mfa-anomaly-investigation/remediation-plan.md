# Remediation Plan

## Phase 1 — Stabilize

1. Revoke sessions and refresh tokens.
2. Disable the user if suspicious activity continues.
3. Reset password and invalidate remembered authentication.
4. Remove unauthorized authentication methods.
5. Remove forwarding and deletion rules.
6. Notify SOC, identity, messaging, finance, privacy, and incident-management owners.

## Phase 2 — Eradicate persistence

1. Inspect all registered authentication methods.
2. Review device registrations and join events.
3. Review OAuth consent and application grants.
4. Review delegated mailbox access.
5. Review role and group changes.
6. Review app passwords and legacy protocol access.
7. Confirm no attacker-created automation or service principals.

## Phase 3 — Assess impact

1. Validate file names, sensitivity labels, and access times.
2. Determine whether files were subsequently shared or modified.
3. Review mailbox content accessed around the incident.
4. Identify affected customers, suppliers, or employees.
5. Perform legal, privacy, and regulatory assessment.
6. Record confirmed and unconfirmed impact separately.

## Phase 4 — Restore

1. Re-enable the account only after trusted-device validation.
2. Require MFA re-registration.
3. Prefer phishing-resistant methods.
4. Confirm mailbox and SharePoint state.
5. Confirm user baseline after restoration.
6. Monitor closely for recurrence.

## Phase 5 — Improve controls

- Enforce compliant devices for finance.
- Block legacy authentication.
- Apply authentication strengths.
- Tune password-spray and MFA-fatigue detections.
- Correlate sign-in anomalies with audit activity.
- Expand retention and licensing where justified.
- Test incident playbooks quarterly.
