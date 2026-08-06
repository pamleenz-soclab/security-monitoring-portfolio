# Validation Checklist

## Evidence integrity

- [x] Original archive MD5 matched the expected value.
- [x] Local SHA-256 was recorded.
- [x] Raw evidence is excluded from the publishable package.
- [x] Source and receiver files were independently hashed.

## Time and direction

- [x] UTC is the canonical timeline.
- [x] Original timestamp representations are retained where needed.
- [x] Suricata directional fields were not renamed without validation.
- [x] Request and response bytes are reported separately.

## Packet accounting

- [x] Overlapping PCAP perspectives were identified.
- [x] Exact duplicate rows were removed before final counts.
- [x] Wire bytes are not described as application data volume.

## Outcome

- [x] Completed objects have receiver-side SHA-256 equality.
- [x] Completion markers were checked per object.
- [x] Missing chunk indexes were checked.
- [x] The interrupted object is labelled Attempted exfiltration.
- [x] Successful DNS responses are not used alone as completion proof.

## Evidence classification

- [x] Telemetry-confirmed facts are separated from ground truth.
- [x] Process-to-network linkage is marked Inferred.
- [x] Not observed and Not available are used distinctly.
- [x] No real-world business impact or sensitive-data owner is invented.

## Publication

- [x] No raw PCAP or full logs are included.
- [x] No Office document content is included.
- [x] No full encoded DNS payload is included.
- [x] No credentials, tokens, cookies, API keys, or sessions are included.
- [x] Scripts are defensive and do not perform exfiltration.
- [x] Standalone validation mode requires raw/working placeholders only.

## Git-aware local-evidence handling

The Git-aware validator and sanitisation tests deliberately exclude `evidence/raw/` and `evidence/working/` from publishable-content scans. They separately confirm that local files in those directories are ignored and untracked. Standalone mode still requires those directories to contain only `.gitkeep`.
