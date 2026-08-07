# Validation Checklist

## Evidence integrity

- [ ] Synthetic marker present in package metadata.
- [ ] No real tenant, UPN, App ID, object ID, credential ID, token, cookie, or private key.
- [ ] SHA-256 records generated after evidence creation.
- [ ] Parser does not read `ground-truth/`.
- [ ] Raw evidence is not modified after acquisition/generation.
- [ ] All credential-linked sign-ins occur within credential validity intervals.

## Object mapping

- [ ] Application object ID is distinct from service-principal object ID.
- [ ] Mapping uses App ID.
- [ ] OAuth grant clientId is treated as the client service-principal object ID.
- [ ] App-role principalId and resourceId are service-principal object IDs.
- [ ] Permission IDs are resolved against the resource service principal.

## Investigation

- [ ] Delegated and application permissions are separated.
- [ ] Entra directory roles and Azure RBAC are separated.
- [ ] Eligible, active, time-bound, and PIM activation states are separated.
- [ ] Credential metadata is not described as credential material.
- [ ] Credential use is linked by key ID or federated credential ID.
- [ ] API use is linked by service-principal ID and token/request context.
- [ ] Cross-product correlation IDs are not assumed equivalent.
- [ ] Benign administrators, CI/CD, approved changes, and low-risk consent are excluded.

## Conclusion quality

- [ ] Permission change is not automatically classified as abuse.
- [ ] Sign-in success is not automatically classified as attacker control.
- [ ] Platform risk is separated from telemetry-confirmed facts.
- [ ] Delegated mailbox use is marked Not observed when absent.
- [ ] Exact permission claim is marked Inferred/Not available when not logged.
- [ ] Final incident label is supported by business impact and owner verification.

## Publication

- [ ] `evidence/raw/` contains only `.gitkeep` in the standalone package.
- [ ] `evidence/working/` contains only `.gitkeep` in the standalone package.
- [ ] Processed evidence is sanitised.
- [ ] Scripts, queries, and detections are not accidentally ignored.
- [ ] `git diff --cached --check` passes.
- [ ] No pager blocks the terminal output.
- [ ] `PACKAGE-MANIFEST.tsv` matches the package contents.
