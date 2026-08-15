# Investigation Report

## Incident classification

**Confirmed exfiltration via low-and-slow DNS tunnelling**

## Scope and objective

This investigation reconstructed the source host, execution context, data objects, collection method, transformation pipeline, network path, transfer volume, completion state, cleanup observations, and business-impact boundary for suspicious outbound DNS activity in the AIT `russellmitchell` scenario.

## Findings

### Source host, account, and process

The source was `internal_share` at `10.143.0.103`. Ground-truth deployment configuration defined a service named `put`, running as `root`, with script path `/usr/bin/put`. Linux audit independently recorded the `put` unit lifecycle under systemd. The dataset did not provide a Windows Process GUID, Logon ID, or stable Linux process-to-flow identifier, so exact process-to-packet linkage is inferred from host, time, protocol grammar, and configuration rather than directly joined.

### Data collection and staging

The service iterated configured Samba share directories and enumerated files in each directory. It did not create a validated central staging directory or archive file. Files were transformed and sent one at a time in a streaming pipeline.

### Compression, encoding, and protocol

The script applied `gzip -c`, Base64 encoding, fixed-length splitting, and `dig`. Data requests used `3x6`, a chunk index, encoded labels, the source filename, and `email-19.kennedy-mendoza.info`. A `3x7` request marked file completion. Compression and Base64 are not encryption; no encryption was observed.

### Network path

```text
internal_share (10.143.0.103)
  → internal resolver (10.143.0.1)
  → firewall/NAT perspective (192.168.230.4)
  → upstream DNS (192.168.231.254)
  → attacker-controlled authoritative receiver (192.168.230.122)
```

### Packet and flow accounting

Two overlapping PCAPs initially produced 75,756 targeted rows. Exact cross-capture deduplication left 39,970 rows: 19,985 requests and 19,985 responses. Of the requests, 19,954 were data chunks and 31 were completion markers.

Outbound request frames totaled 5,266,713 bytes. This is not the application data-loss volume. The confirmed data-loss volume is 2,042,802 bytes across 31 source objects with receiver-side SHA-256 equality.

### Transfer outcome

Thirty-one files met all completion criteria:

1. The object was identified in the source share.
2. Packet telemetry exposed a continuous observed chunk sequence.
3. A `3x7` completion request was observed.
4. A receiver-side reconstructed object existed.
5. Source and receiver SHA-256 hashes were identical.

`Vaughn-mcdaniel.docx` did not meet the threshold. It had 128 data chunks and successful DNS responses but no completion request and no receiver object. It is classified as **Attempted exfiltration**.

### Data scope

Confirmed synthetic data included billing invoices, customer-record spreadsheets, payroll/management spreadsheets, and two business-report documents. Formal owners, enterprise sensitivity labels, retention rules, and real business impact were not available. Receiver-side hash equality confirms technical data loss, but does not by itself establish a Critical business severity.

### Baseline and anomaly context

The activity was not a burst or a conventional large upload. It continued for approximately 4.04 days with an average request interval of 17.48 seconds and an average outbound wire rate of 15.08 bytes/second. Its distinguishing features were structured query grammar, high uniqueness, long queries, file names, sequential chunk indexes, repeated use of a dedicated domain, and receiver reconstruction—not absolute volume.

### Cleanup and follow-on activity

The simulation stopped the DNSteal activity, and audit telemetry recorded the `put` unit lifecycle event. No validated deletion of source files, logs, shell history, receiver files, or security tools was observed. Service termination is not described as anti-forensic cleanup.

## Evidence assessment

| Question | Assessment |
|---|---|
| Did data leave the source host? | Yes, packet telemetry shows structured chunk transmission |
| Did the receiver obtain complete objects? | Yes, 31 exact source/receiver SHA-256 matches |
| Was every attempted object completed? | No, one object lacked a completion marker and receiver file |
| Can exact process-to-flow identity be proven? | No; strongly inferred due missing stable identifier |
| Was encryption used? | Not observed |
| Was a staging archive created? | Not observed |
| Was DLP/CASB blocking recorded? | Not available |
| Is the business impact real-world? | No; this is synthetic lab data |

## Final determination

**Overall result: Confirmed exfiltration.**

- 31 objects: **Confirmed exfiltration**
- `Vaughn-mcdaniel.docx`: **Attempted exfiltration**
- Process-to-network join: **Inferred**
- Receiver reconstruction and object integrity: **Confirmed**
