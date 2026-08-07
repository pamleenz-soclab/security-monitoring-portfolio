# Dataset Decision Record

## Decision

Use a deterministic, Microsoft-schema-aligned synthetic event package as the primary Scenario 18 evidence source. Use public vendor samples only as independent detection fixtures; do not combine unrelated public events into a single claimed attack chain.

## Rationale

No publicly available event package identified during Stage 1 simultaneously provided directory audit, OAuth grants, application and service-principal snapshots, credential changes, service-principal sign-ins, API activity, stable identifiers, ground truth, offline availability, and clear redistribution terms.

The synthetic design makes the following controls explicit:

- one tenant and one primary incident;
- stable but fictitious identifiers;
- separate application and service-principal object IDs;
- credential metadata without secret material;
- benign baseline and approved change controls;
- a ground-truth file isolated from first-pass analysis;
- multiple independent telemetry types;
- deterministic regeneration and SHA-256 verification.

## Candidate comparison

| Candidate | Strength | Decision |
|---|---|---|
| Splunk Attack Data cloud identity fixtures | Open, reproducible atomic events | Detection fixture only; events are not one chain |
| Microsoft Sentinel and Entra samples | Authoritative schema and KQL reference | Schema and detection reference only |
| CyberDefenders cloud cases | Rich investigation narratives | Not selected because redistribution and raw-data access boundaries were unclear |
| OTRF / training-lab content | Strong training infrastructure | No matching complete event package identified |
| Synthetic event package | Complete same-event telemetry with stable IDs and explicit safety controls | Selected primary evidence |

## Dataset limitations

- It is not production telemetry and cannot demonstrate product-specific ingestion defects.
- It does not model every Entra, Microsoft 365, Azure, or SaaS log variant.
- Permission claims are intentionally absent from normalised API records, preserving the distinction between assignment and proven claim use.
- Secret values, access tokens, private keys, cookies, and real tenant identifiers are unavailable by design.

## Publication decision

Publish only scripts, queries, detection content, documentation, and sanitised processed evidence. Keep generated raw and working evidence local and ignored by Git.
