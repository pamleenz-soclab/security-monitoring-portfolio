# Detection Engineering

## Detection objective

Detect sustained structured DNS file transfer while avoiding the assumption that long or high-entropy DNS names are automatically malicious.

## High-value features

- Client repeatedly queries one rare domain.
- Query names are unusually long and highly unique.
- A stable grammar contains a transfer marker, chunk index, encoded labels, and filename-like suffix.
- Sequential chunk indexes persist over minutes or days.
- Per-file completion markers occur.
- The endpoint process tree includes shell, compression, encoding, and DNS utilities.
- The source is a file server or privileged service account with no approved reason for custom DNS traffic.
- Resolver forwarding reaches a newly observed or attacker-controlled authoritative server.

## Detection layers

1. **Endpoint:** detect `gzip`/Base64/`dig` pipelines and unusual systemd services executing DNS tools.
2. **Resolver:** detect grammar, long labels, uniqueness, and sustained per-client cadence.
3. **Network:** detect large numbers of outbound DNS requests to a rare domain and direct DNS bypass.
4. **Correlation:** join recent file access/enumeration or compression events to DNS anomalies on the same host.
5. **Outcome:** when available, use DLP, receiver, cloud, or controlled sinkhole evidence to determine completion.

## ATT&CK-oriented mapping

- T1005 — Data from Local System
- T1083 — File and Directory Discovery
- T1560.001 — Archive via Utility / streamed compression
- T1048.003 — Exfiltration Over Unencrypted Non-C2 Protocol
- T1071.004 — DNS

## Tuning principles

Do not alert solely on query length, entropy, UDP/53 volume, or a compression utility. Require multiple independent features and use allowlists for approved DNS security agents, content-distribution telemetry, service discovery, backup products, and enterprise resolvers.

See `false-positive-tuning.md` and the platform-specific query directories.

## Rule-role and outcome boundaries

- The `3x6`/`3x7` grammar rule is intentionally **scenario-specific** and high confidence for this lab protocol; it should not be presented as a generic DNS-tunnelling signature.
- Burst and byte-volume analytics are **supplemental**. This case averaged about 17.5 seconds between requests, so a short-window burst threshold can miss the observed low-and-slow behaviour.
- Process-to-network correlation must use a stable process identifier when the platform provides one. Host-plus-time correlation is supportive, not direct process attribution.
- A DNS alert, `NOERROR` response, or completion-like marker is not proof of completed data loss. Completion requires independent receiver, DLP, application, or reconstruction evidence.
