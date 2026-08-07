# Scenario 18 — Cloud Privilege and OAuth Application Abuse

**Priority:** Flagship
**Portfolio domain:** Cloud identity and privilege investigations
**Primary incident label:** **Confirmed cloud privilege abuse**
**Application identity assessment:** **Possible application identity compromise**

## Investigation objective

This scenario reconstructs an enterprise cloud-security investigation across directory audit, OAuth grants, application permissions, service-principal credentials, service-principal sign-ins, Microsoft Graph activity, resource access, persistence, and containment.

The evidence chain is:

```text
Initiating administrator session
→ tenant-wide delegated consent
→ high-risk application permissions
→ permanent Entra directory role
→ client-secret addition
→ service-principal sign-in using the exact key ID
→ application-only Microsoft Graph activity
→ business file content returned
→ federated identity credential creation
→ sign-in using the exact federated credential ID
→ additional API activity
→ containment and revocation
```

## Data status

The event package is **deterministic and explicitly synthetic**. It is based on Microsoft-published schema structures but is not exported from a real tenant. The repository contains no real tenant identifiers, UPNs, application IDs, service-principal IDs, credential values, private keys, cookies, or tokens.

The raw package and working files are regenerated locally and are Git ignored. Only sanitised processed evidence, original analysis code, queries, and detection examples are publishable.

## Key findings

- A cloud administrator session from an off-baseline source initiated tenant-wide delegated consent for `offline_access Mail.ReadWrite`.
- The same administrator assigned four Microsoft Graph application permissions and an active permanent Entra directory role to the application service principal.
- A client secret was added with no approved change ticket. Six minutes later, the exact credential key ID appeared in a successful service-principal sign-in.
- The resulting application-only token identifier appeared in successful directory, SharePoint, OneDrive, and file-download activity.
- The application identity created a federated identity credential. Request ID, operation ID, service-principal ID, and the resulting credential ID connect the API operation, audit event, later sign-in, and follow-on API use.
- The application owner confirmed that none of the incident-date consent, role, credential, or deployment changes were approved.
- Use of the delegated `Mail.ReadWrite` grant was **not observed**. No delegated user token, mailbox access, mail send, or inbox-rule activity appears in the evidence.
- A specific application permission claim for each API request is not logged; permission-to-operation attribution remains an inference.

## Primary synthetic identifiers

| Object | Identifier |
|---|---|
| Application object ID | `e59726d4-d5cb-5b2d-9884-cd8788d3a59a` |
| Application / client ID | `7e826e1b-2861-5d4f-866a-6366dd986a64` |
| Service principal object ID | `13b2b610-6000-5b59-a4c3-66994834a818` |
| Microsoft Graph resource service principal ID | `fba658c4-6949-5c14-b34c-cdfc6f08a125` |
| Incident client-secret key ID | `39acbc69-455e-5b9d-adb1-dcd57a386a7b` |
| Incident federated credential ID | `20cc77c2-49cf-537d-9db9-b7d166018d7f` |

These identifiers are synthetic. Application object ID, application/client ID, and service-principal object ID are deliberately distinct.

## Repository contents

```text
.
├── evidence/
│   ├── raw/                 # Local only; Git ignored
│   ├── working/             # Local only; Git ignored
│   └── processed/           # Sanitised, publishable evidence
├── detections/
│   ├── sentinel/
│   ├── splunk/
│   ├── elastic/
│   └── generic/
├── queries/
├── scripts/
├── screenshots/
├── investigation-report.md
├── detection-engineering.md
└── PACKAGE-MANIFEST.tsv
```

## Reproduce the analysis safely

From the repository root:

```bash
export REPO_ROOT="/Users/pamlee/Documents/GitHub/security-monitoring-portfolio"
export SCENARIO_DIR="$REPO_ROOT/07-cloud-identity-and-privilege-investigations/scenario-18-cloud-privilege-and-oauth-application-abuse"

"$SCENARIO_DIR/scripts/safe-reproducibility-wrapper.sh" \
  --repo-root "$REPO_ROOT"
```

The wrapper generates only synthetic raw evidence, validates it, produces working outputs, and runs stable-ID correlation. It does not connect to Microsoft Entra, Azure, Microsoft Graph, or any real tenant.

## Evidence-boundary summary

| Question | Conclusion |
|---|---|
| Were privilege and permission changes made? | Confirmed |
| Was a new client secret used? | Confirmed by exact credential key ID |
| Was a new federated credential used? | Confirmed by exact federated credential ID |
| Was application-only API activity performed? | Confirmed by token and service-principal IDs |
| Was business content returned? | Confirmed in synthetic API telemetry |
| Was delegated mailbox access used? | Not observed |
| Which exact app-role claim authorised each API request? | Not available; inferred from assignments and operation capability |
| Who controlled the application credentials? | Inferred; direct human attribution unavailable |

## Important documentation

- [Executive summary](executive-summary.md)
- [Triage note](triage-note.md)
- [Investigation report](investigation-report.md)
- [Containment decision record](containment-decision-record.md)
- [Revocation and recovery plan](revocation-and-recovery-plan.md)
- [Detection engineering](detection-engineering.md)
- [False-positive tuning](false-positive-tuning.md)
- [GitHub publishing guide](github-publishing-guide.md)

## References

- [Microsoft Graph directoryAudit resource](https://learn.microsoft.com/en-us/graph/api/resources/directoryaudit?view=graph-rest-1.0) — accessed 2026-08-07.
- [Microsoft Graph targetResource resource](https://learn.microsoft.com/en-us/graph/api/resources/targetresource?view=graph-rest-1.0) — accessed 2026-08-07.
- [Microsoft Graph oAuth2PermissionGrant resource](https://learn.microsoft.com/en-us/graph/api/resources/oauth2permissiongrant?view=graph-rest-1.0) — accessed 2026-08-07.
- [Microsoft Graph appRoleAssignment resource](https://learn.microsoft.com/en-us/graph/api/resources/approleassignment?view=graph-rest-1.0) — accessed 2026-08-07.
- [Apps and service principals in Microsoft Entra ID](https://learn.microsoft.com/en-us/entra/identity-platform/app-objects-and-service-principals) — accessed 2026-08-07.
- [AADServicePrincipalSignInLogs table](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/aadserviceprincipalsigninlogs) — accessed 2026-08-07.
- [Microsoft Graph activity logs overview](https://learn.microsoft.com/en-us/graph/microsoft-graph-activity-logs-overview) — accessed 2026-08-07.
- [Review permissions granted to enterprise applications](https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/manage-application-permissions) — accessed 2026-08-07.
- [Delete oAuth2PermissionGrant](https://learn.microsoft.com/en-us/graph/api/oauth2permissiongrant-delete?view=graph-rest-1.0) — accessed 2026-08-07.
- [Delete appRoleAssignment](https://learn.microsoft.com/en-us/graph/api/serviceprincipal-delete-approleassignments?view=graph-rest-1.0) — accessed 2026-08-07.
- [Revoke user sign-in sessions](https://learn.microsoft.com/en-us/graph/api/user-revokesigninsessions?view=graph-rest-1.0) — accessed 2026-08-07.
- [PIM role assignment overview](https://learn.microsoft.com/en-us/graph/api/resources/privilegedidentitymanagementv3-overview?view=graph-rest-1.0) — accessed 2026-08-07.
