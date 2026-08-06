# Investigation Notes

## 1. Acquisition and validation

The 7.13 GB archive passed the publisher-provided MD5 check. It was safely extracted without path traversal or symlink acceptance. The investigation retained the archive under Git-ignored raw storage and generated acquisition and SHA-256 records under working storage.

## 2. First-pass limitations

The first-pass parser correctly inventoried the event but produced several broad keyword candidate sets containing configuration, rules, binary Office data, and unrelated telemetry. Those candidate sets were not treated as findings. The first-pass DNS entropy calculation also measured the `3x6` control label rather than the encoded payload; that metric was excluded from the final conclusion.

## 3. PCAP overlap

The two targeted captures represented overlapping network perspectives. Exact deduplication reduced 75,756 rows to 39,970 rows. Final counts and byte estimates use only the deduplicated set.

## 4. Source and execution context

The validated source was `internal_share` (`10.143.0.103`). Linux audit recorded the `put` systemd unit lifecycle. Deployment variables defined `/usr/bin/put`, user `root`, and the configured share directories. Because endpoint telemetry did not include a stable process-to-socket identifier, exact per-packet process attribution remains inferred.

## 5. Collection and transformation

The configured script changed into each share directory and enumerated regular files with `find`. Each file was streamed through `gzip -c`, Base64 encoded, split into fixed-size labels, and sent with `dig`. No separate staging directory, archive file, archive volume, or encryption step was validated.

## 6. Network transport

The DNS path was:

```text
10.143.0.103 → 10.143.0.1 → 192.168.230.4 → 192.168.231.254 → 192.168.230.122
```

Data queries used marker `3x6`; completion queries used `3x7`. Query names included the object filename and dedicated domain `email-19.kennedy-mendoza.info`.

## 7. Transfer outcome

Thirty-one files had continuous observed chunk indexes, a completion marker, a receiver object, and exact source/receiver SHA-256 equality. These meet the threshold for **Confirmed exfiltration**.

`Vaughn-mcdaniel.docx` had chunks 0–127 and DNS replies but no completion marker or receiver file. It is classified as **Attempted exfiltration**. Successful DNS responses alone were not treated as proof of reconstruction.

## 8. Volume

- Confirmed source-object bytes: 2,042,802
- Outbound request wire bytes: 5,266,713
- Inbound response wire bytes: 5,646,428
- Bidirectional network footprint: 10,913,141

Only the first figure is used as confirmed data-loss volume. Wire bytes include protocol, filename, chunk index, encoding, compression effects, and link-layer overhead.

## 9. Causality boundary

The broader simulated VPN/Web attack began on 24 January, while DNS exfiltration was already active on 20 January. The investigation therefore does not claim that the Web compromise installed or triggered this exfiltration service. The defensible narrative is a pre-existing persistent exfiltration mechanism operating in the same environment.
