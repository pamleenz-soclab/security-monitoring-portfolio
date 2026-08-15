# Scenario 16 — Suspicious Data Exfiltration Investigation

**Priority:** Flagship
**Final result:** **Confirmed exfiltration**
**Primary technique:** Low-and-slow DNS tunnelling
**Dataset:** AIT Log Data Set v2.1, `russellmitchell` scenario
**Canonical timeline:** UTC

## Executive finding

A pre-existing service named `put` on `internal_share` (`10.143.0.103`) enumerated synthetic Samba-share files, compressed each file with `gzip`, encoded the stream with Base64, split it into fixed-size DNS labels, and transmitted it through `email-19.kennedy-mendoza.info`. The traffic crossed the internal resolver and firewall path to an attacker-controlled authoritative DNS receiver.

The investigation confirmed successful exfiltration of **31 files totaling 2,042,802 bytes**. Every receiver-side file had the same filename, size, and SHA-256 hash as its unique source object. One additional object, `Vaughn-mcdaniel.docx`, generated 128 data-chunk requests but had no completion marker and no receiver file; it is classified separately as **Attempted exfiltration**.

## Why the result is confirmed

The conclusion does not rely on DNS volume, connection establishment, query entropy, or dataset labels alone. It is based on the combined evidence chain:

```text
Source host and file
→ deterministic DNS chunk sequence
→ completion marker
→ attacker receiver reconstruction
→ exact source/receiver SHA-256 equality
```

## Key metrics

| Metric | Result |
|---|---:|
| Completed objects | 31 |
| Confirmed object bytes | 2,042,802 |
| Additional attempted object | 1 |
| Exact-deduplicated DNS requests | 19,985 |
| DNS data requests (`3x6`) | 19,954 |
| Completion requests (`3x7`) | 31 |
| Outbound request wire bytes | 5,266,713 |
| Observation period | 2022-01-20T12:48:27.530508+00:00 to 2022-01-24T13:50:03.248663+00:00 |
| Mean outbound wire rate | 15.08 bytes/second |

`5,266,713` request wire bytes are not equivalent to application data lost. They include headers, DNS grammar, filename/index metadata, Base64 expansion, and protocol overhead. The confirmed loss-volume figure is the 2,042,802 bytes represented by hash-matched source objects.

## Evidence classification

- **Telemetry-confirmed:** DNS packet structure, network path, chunk sequences, completion markers, receiver objects, hash matches, and service lifecycle audit records.
- **Ground truth:** service configuration, `/usr/bin/put`, root execution context, `gzip`/Base64/`dig` pipeline, block size, delay, and receiver configuration.
- **Inferred:** the exact `/usr/bin/put` process instance responsible for each individual packet because no stable endpoint process-to-flow identifier was present.
- **Not observed:** separate staging directory, archive file creation, encryption, log deletion, shell-history clearing, or security-tool impairment.
- **Not available:** Process GUID, Windows Logon ID, Zeek UID, DLP/CASB result, formal sensitivity labels, and real data ownership metadata.

## Repository map

- `evidence/processed/` — sanitised, publishable analysis outputs
- `detections/` — Sigma-style detection content
- `queries/` — Microsoft Sentinel KQL, Splunk SPL, and Elastic/generic queries
- `scripts/` — safe parsing, correlation, validation, and sanitisation utilities
- `evidence/raw/` and `evidence/working/` — local-only and Git-ignored

## Safe use

This package contains no raw PCAP, full logs, DNS payload labels, document contents, credentials, tokens, or receiver files. It does not contain code that performs data exfiltration. Detection queries and reproducibility scripts are defensive and read-only.

See `investigation-report.md` for the complete reasoning. The repository intentionally excludes local publication checklists, packaging manifests, and raw/working evidence.
