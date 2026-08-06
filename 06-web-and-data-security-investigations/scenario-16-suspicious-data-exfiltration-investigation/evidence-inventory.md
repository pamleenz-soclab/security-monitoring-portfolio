# Evidence Inventory

## Local-only primary evidence

| Evidence | Approximate role | Publication |
|---|---|---|
| `russellmitchell.zip` | Original AIT scenario archive | Excluded; retained locally under `evidence/raw/` |
| Linux audit and host logs | Service lifecycle and host context | Excluded |
| DNS resolver logs | Query, forwarding, and reply chain | Excluded except sanitised counts |
| Suricata telemetry | Directional flow counters and protocol context | Excluded except derived summaries |
| Two targeted PCAP files | Packet-level DNS structure and completion analysis | Excluded |
| Receiver logs and reconstructed files | Receiver-side completion evidence | Excluded; only hashes and metadata retained |
| Environment configuration and scripts | Ground-truth service and protocol definition | Excluded except minimal sanitised excerpts |

## Publishable processed evidence

The `evidence/processed/` directory contains the event timeline, host/process summary, destination chain, exact-deduplicated network metrics, object-level transfer outcome, hash-based data-scope assessment, cleanup analysis, detection gaps, and sanitised evidence references.

## Integrity

The original archive was verified against its expected MD5 and assigned a local SHA-256. Source and receiver objects were hashed independently. Exact equality was observed for all 31 completed object pairs.

## Time handling

- Structured logs primarily used UTC (`+0000`).
- PCAP display output on the analysis workstation could show local `+1300` timestamps.
- All processed timelines use UTC and preserve original representations where materially useful.

## Evidence boundary

Ground-truth files identify the configured service, user, script, protocol, and schedule. They are not treated as independent proof of runtime behaviour. Packet captures, resolver logs, Linux audit, receiver files, and hashes provide the telemetry-confirmed portions of the chain.
