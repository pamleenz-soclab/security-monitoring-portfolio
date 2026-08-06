# False-Positive Tuning

## Common benign sources

- DNS security, filtering, and endpoint-protection products
- CDNs and content-addressed distribution systems
- Service discovery and Kubernetes environments
- Anti-malware update systems
- Telemetry platforms using encoded identifiers
- Backup, deployment, or monitoring agents
- Browser prefetching and advertising ecosystems

## Required tuning dimensions

- Approved client host and business role
- Approved process and signed binary
- Approved resolver path
- Domain age, ownership, prevalence, and enterprise allowlist status
- Query grammar and filename-like components
- Unique-query ratio and chunk-index sequence
- Duration and cadence
- DNS response behaviour
- Direct DNS versus approved recursive resolver use
- Correlated file access, compression, or shell activity

## Suppression guidance

Suppress only after documenting the approved application, owner, destination, expected query structure, expected volume, and review expiry. Avoid permanent wildcard allowlists for broad cloud or CDN domains. Continue to alert when an approved binary is launched from an unusual path, parent, account, or host role.

## Threshold guidance

Use adaptive baselines per host/process/domain rather than a universal byte threshold. Low-and-slow transfer can average only tens of bytes per second. A high unique-query ratio plus stable chunk grammar is more discriminating than volume alone.
