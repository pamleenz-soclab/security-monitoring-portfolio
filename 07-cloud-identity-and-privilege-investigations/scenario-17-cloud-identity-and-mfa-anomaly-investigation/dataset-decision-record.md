# Dataset Decision Record

## Decision

Use a deterministic synthetic Microsoft Entra and Microsoft 365 identity-event package for Scenario 17.

## Initial preferred candidate

**CyberDefenders AzureSpray**

The lab was technically attractive because it described Azure AD sign-in logs, Identity Protection, password spray investigation, Conditional Access, Microsoft Sentinel, and follow-on activity.

## Acquisition-gate result

**Rejected**

The authenticated free account could access only the retired lab description. The page displayed `Unlock Full Lab Access` and required a Premium subscription. No downloadable evidence files were exposed. The dataset therefore failed the accessibility requirement before acquisition.

No CyberDefenders files were downloaded, copied, hashed, or used in this investigation.

## Other public-source findings

Microsoft official repositories and documentation provide authoritative schemas, sample records, and detection content, but no verified single public event package was located that combined:

- interactive and non-interactive user sign-ins;
- service-principal and managed-identity sign-ins;
- authentication-step details;
- Conditional Access policy evaluation;
- Identity Protection risk fields;
- stable request, correlation, session, and token identifiers;
- directory and Microsoft 365 follow-on audit;
- clear ground truth;
- unrestricted public redistribution.

Combining unrelated datasets was rejected because it would create an artificial attack chain without common identities, sessions, or event provenance.

## Selected approach

The selected dataset is generated locally from a deterministic Python generator. It models one tenant and one coherent incident and includes:

- 162 sign-in records;
- 87 interactive user sign-ins;
- 73 non-interactive user sign-ins;
- one service-principal sign-in;
- one managed-identity sign-in;
- authentication details;
- Conditional Access policy results;
- Identity Protection-style risk detections;
- Entra directory audit;
- Microsoft 365 unified audit;
- business context;
- incident-ticket verification;
- separate ground truth.

All identities, identifiers, applications, IP addresses, organisations, and activities are synthetic. Public IP addresses use documentation ranges.

## Strengths

- Complete and reproducible stable-ID correlation.
- Safe offline analysis.
- Clear separation of telemetry, platform risk, business verification, ground truth, and inference.
- No real tenant, user, token, credential, or MFA secret.
- Supports all four principal sign-in types.
- Supports detection-engineering validation and false-positive tuning.
- Can be published under a clear licence.

## Limitations

- Not a byte-for-byte portal, Graph, or Sentinel export.
- No Authenticator approving-device or GPS telemetry.
- No raw access token, refresh token, cookie, or token replay artifact.
- Conditional Access internal condition traces are not modeled.
- P2-equivalent risk visibility is synthetic; actual tenants can show hidden or delayed fields.
- Cross-tenant and federation behaviors are not modeled.

## Final suitability decision

**Accepted for Scenario 17**

The dataset is suitable for demonstrating investigation methodology, evidence discipline, stable-ID correlation, detection engineering, and portfolio reproducibility. It is not suitable for validating portal-export quirks or claiming experience with a live production tenant.
