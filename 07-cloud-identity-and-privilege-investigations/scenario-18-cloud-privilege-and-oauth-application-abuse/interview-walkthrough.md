# Interview Walkthrough

## One-minute explanation

This scenario investigates an existing Entra application that received unapproved delegated consent, four application permissions, a permanent directory role, and a new client secret. I did not classify those changes as compromise by themselves. I mapped the application object to its tenant service principal using the App ID, then linked the new secret to a service-principal sign-in using the exact credential key ID. The resulting token ID appeared in Graph activity that enumerated directory and file resources, returned a finance file, and created a federated identity credential. That exact federated credential ID was then used for another sign-in. Owner verification confirmed there was no approved change. I classified the event as confirmed cloud privilege abuse, while keeping application identity compromise at possible because the logs did not identify the person controlling the credentials.

## Questions to expect

### Why is the OAuth grant not enough to call it malicious?

Consent may be legitimate. The decision also used administrator baseline, owner verification, permission scope, credential addition, credential use, API activity, and business impact.

### Why is the application identity only possibly compromised?

The telemetry proves that unapproved credential metadata was used, but it does not expose the secret value or directly identify the human operator.

### Why does revoking the administrator's sessions not solve the incident?

The service principal can authenticate as itself through application credentials. User-session revocation addresses user and delegated access, not independent application-only access.

### What is the strongest correlation?

The strongest chain is credential key ID → service-principal sign-in → unique token identifier → API activity. The federated persistence chain additionally uses request ID, operation ID, service-principal ID, and federated credential ID.

### Why not join everything on correlation ID?

Correlation ID semantics can differ across products. This investigation uses it only inside verified boundaries and relies on object, credential, token, request, and operation IDs for cross-source joins.
