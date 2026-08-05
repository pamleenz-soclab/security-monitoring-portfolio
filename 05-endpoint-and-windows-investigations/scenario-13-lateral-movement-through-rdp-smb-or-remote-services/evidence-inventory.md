# Evidence Inventory

## Handling model

- Original archives, extracted JSON, PCAPs and rejected-candidate files remain under `evidence/raw/` and are ignored by Git.
- Intermediate queries and verification bundles remain under `evidence/working/` and are ignored by Git.
- Only sanitised, minimal processed evidence is tracked.
- Full encoded payloads and the demonstration NTLM hash are excluded from tracked content.

## Source archives

| Evidence | Size | SHA-256 | Publication status |
|---|---:|---|---|
| OTRF host archive | 753,172 bytes | `c0fc435c9ce0ecdc7cd57b4055977b949ac6b1cae9d7f4ce7aa0f0e5eae7d7f1` | Raw, ignored |
| OTRF network archive | 248,603 bytes | `d9879be3d5e93268d4ea1ca5c7f107f0f16624b5df4aee43b04aa48a14560eea` | Raw, ignored |

The fixed source URLs, acquisition time, license and upstream commit are recorded in `evidence/source-records.tsv`.

## Analysed raw files

`evidence/processed/analysed-file-inventory.csv` records the extracted host JSON and both PCAP names, sizes and SHA-256 values. These raw files are not published in the repository.

## Processed evidence

| File | Purpose |
|---|---|
| `analysis-summary.json` | Verdict, scope, correlation keys and evidence boundaries |
| `attack-timeline.csv` | UTC-normalised event sequence |
| `authentication-remote-service-evidence.csv` | 4624/4776/4672/5140/5145/4697/7045 correlation |
| `remote-process-chain.csv` | Sanitised target process ancestry |
| `host-to-host-scope.csv` | Source, target, DC dependency and lab-listener scope |
| `network-flow-summary.csv` | Selected PCAP flow summaries |
| `pcap-capture-summary.csv` | Capture size, packet count and time range |
| `pcap-marker-evidence.csv` | NTLMSSP, `svcctl` and service-name byte markers |
| `decoded-stager-findings.md` | Sanitised stage-one behaviour summary |
| `indicator-summary.csv` | Scenario-specific identifiers and their roles |
| `key-event-id-counts.csv` | Relevant event-count inventory by host/channel |

## Independent telemetry classes

1. Windows Security/System authentication, share and service events.
2. Sysmon/EDR process, registry and network events.
3. PowerShell Script Block Logging.
4. Endpoint packet captures.

The lateral-movement conclusion is supported by multiple independent telemetry classes rather than a single event or port.

## Publication limitations

- Private laboratory addresses are retained for reproducibility and clearly labelled as lab infrastructure.
- No credentials, tokens or full dangerous payloads are published.
- The dataset does not include production authorization or change-management records.
- Source initial compromise and activity outside the capture window remain out of scope.
