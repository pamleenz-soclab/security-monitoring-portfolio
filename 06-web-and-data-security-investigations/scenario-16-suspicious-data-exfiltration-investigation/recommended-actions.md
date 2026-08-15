# Recommended Actions

## Immediate containment

1. Isolate `internal_share` while preserving volatile state and active network connections.
2. Block `email-19.kennedy-mendoza.info` and `192.168.230.122` at DNS, firewall, proxy, and threat-intelligence controls.
3. Restrict endpoint DNS to approved recursive resolvers; block direct external UDP/TCP 53.
4. Disable and preserve the `put` service and `/usr/bin/put` for forensic examination rather than deleting them immediately.
5. Review privileged/service credentials and keys exposed to or used by the host; rotate those with confirmed or plausible exposure, rather than assuming credential theft from DNS exfiltration alone.
6. Search all hosts and resolvers for the `3x6`/`3x7` grammar, the domain, and the receiver infrastructure.

## Evidence preservation

- Preserve raw PCAP, resolver logs, Linux audit, journal logs, service files, shell history, filesystem metadata, and receiver-side artefacts.
- Record original hashes before analysis.
- Export process, cgroup, socket, and network-namespace state when available.
- Maintain UTC-normalised copies while retaining original timestamps.

## Eradication and recovery

- Remove unauthorised service units only after evidence capture.
- Rebuild the source host from a trusted image when integrity cannot be established.
- Review share permissions and root service access.
- Validate that no similar service, cron job, timer, container, or startup script remains.
- Confirm DNS egress controls and monitoring before restoring production access.

## Long-term improvement

- Centralise DNS queries, responses, client identity, and resolver forwarding telemetry.
- Enrich DNS events with endpoint process and socket data.
- Deploy anomaly detections based on query grammar, uniqueness, label length, cadence, and rare domains.
- Integrate DLP and data-classification metadata into DNS and endpoint alerts.
- Baseline service accounts, file servers, backup agents, and approved DNS security products to reduce false positives.
