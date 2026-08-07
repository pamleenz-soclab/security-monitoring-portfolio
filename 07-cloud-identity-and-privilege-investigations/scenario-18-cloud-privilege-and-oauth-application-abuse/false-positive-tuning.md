# False-Positive Tuning

## Common benign patterns

### Approved application deployment

Expected indicators:

- change ticket and owner approval;
- known administrator or automation principal;
- normal change window;
- expected publisher and owner;
- documented permission set;
- predictable source network;
- immediate deployment-pipeline records.

### Credential rotation

Expected indicators:

- overlap with the old credential during a documented migration period;
- planned start and expiry dates;
- approved display name and key type;
- use from the application's established network and resource baseline;
- removal of the old credential after validation.

### CI/CD workload federation

Expected indicators:

- approved issuer;
- exact repository, environment, branch, or subject pattern;
- narrow audience;
- deployment record and owner;
- target resource consistent with the pipeline.

### Low-risk user consent

Expected indicators:

- `consentType=Principal`;
- low-impact delegated scopes;
- verified or approved publisher;
- user-initiated application use;
- no tenant-wide grant or app-only permissions.

### PIM activity

Expected indicators:

- eligible assignment existed before activation;
- request, approval, justification, MFA, and time-bound active schedule;
- activity performed during the activation period.

## High-value tuning conditions

Do not suppress solely by display name. Use stable IDs plus governance context.

A strong allow-list record should contain:

- app ID;
- service-principal object ID;
- application object ID where tenant-owned;
- owner;
- approved permissions;
- allowed credential types;
- allowed federation issuer and subject;
- allowed source networks and resources;
- expiry or review date;
- change-ticket reference.

## Conditions that should override an allow list

- new high-risk permission outside the approved set;
- new credential ID followed by off-baseline sign-in;
- dormant application reactivation;
- credential creation by the application itself;
- new issuer or repository subject;
- access to a new workload or sensitive endpoint;
- role assignment to the service principal;
- multiple applications changed by the same administrator in a short period.
