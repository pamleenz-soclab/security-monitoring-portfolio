# Dataset Decision Record

## Decision

Use the **AIT Log Data Set v2.1 `russellmitchell` full package**, including PCAP, as the sole primary event source for Scenario 16.

## Selection criteria

The selected scenario provides multiple telemetry types from the same simulated environment:

- Linux audit and host logs
- DNS resolver logs
- Suricata network telemetry
- Two PCAP capture perspectives
- Attack orchestration records and labels
- Receiver-side DNSteal logs and reconstructed objects
- Environment configuration describing hosts, services, and protocol parameters

This combination supports source-host identification, transport reconstruction, file-level outcome verification, and explicit separation of telemetry from ground truth.

## Alternatives considered

| Candidate | Strength | Limitation for this scenario |
|---|---|---|
| DARPA OpTC corrected dataset | Rich enterprise endpoint/network telemetry and clear public distribution status | Very large and operationally expensive; receiver-side object completion was not guaranteed |
| Splunk BOTS v3 | Diverse logs and clear CC0 status | Older pre-indexed format; weaker raw PCAP and receiver reconstruction path |
| CIC Bell DNS-EXF 2021 | Clear DNS exfiltration experiment and manageable size | No endpoint account/process or enterprise investigation chain |
| Splunk Attack Data | Current, detection-focused samples with clear repository licence | Individual samples generally expose one telemetry type and cannot be combined into one event |

## Why the full package was retained

The full package was required to identify and correct cross-capture duplication, inspect packet-level DNS grammar, validate request/response pairs, quantify wire-level bytes, and distinguish 31 completed objects from one interrupted object. The no-PCAP package would have left these outcome and counting questions unresolved.

## Constraints

- The reviewed v2.1 source record did not provide a sufficiently explicit licence statement for safe raw-data redistribution.
- Raw logs, PCAP, labels, receiver objects, and long excerpts are therefore excluded from this GitHub package.
- The package publishes original analysis, defensive queries, sanitised metadata, and minimal non-sensitive excerpts only.
- The synthetic event must not be presented as a real enterprise breach.
