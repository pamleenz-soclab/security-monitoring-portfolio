# Validation Checklist

## Evidence integrity

- [x] Source commit fixed.
- [x] Raw file sizes recorded.
- [x] Raw SHA-256 hashes recorded.
- [x] Raw evidence read-only.
- [x] Raw and working directories ignored by Git.
- [x] Parser errors reviewed.
- [x] Host aliases normalised.
- [x] PID correlation supplemented with host, time, and Process GUID.

## Investigation quality

- [x] Process creation and file impact proved separately.
- [x] Builder and payload execution paths distinguished.
- [x] Ransom-note creation correlated to a process GUID.
- [x] Authentication events correlated to process PID and Logon ID.
- [x] Remote-access evidence separated from confirmed lateral movement.
- [x] Keyword false positives removed.
- [x] Recovery inhibition not asserted without command evidence.
- [x] Exfiltration not asserted from external connections alone.
- [x] File encryption not asserted without content-impact evidence.

## Publication safety

- [x] No raw logs included.
- [x] No executable or malware sample included.
- [x] No credential or token included.
- [x] Full operational ransomware command not reproduced in public evidence.
- [x] Private lab IPs labelled as private dataset addresses.
- [x] Large temporary files excluded.
- [x] Python cache excluded.
- [x] ZIP, PCAP, EVTX, and binaries excluded from Git.
- [x] Detection content is defensive.
- [x] Source and licence attribution included.

## Final repository checks

Run before commit:

```bash
git status --short -- "$SCENARIO_DIR"
git check-ignore -v "$RAW_DIR/windows-sysmon.log" "$WORKING_DIR/scenario14-events.sqlite"
git diff --cached --check
git diff --cached --name-only -- "$SCENARIO_DIR"
find "$SCENARIO_DIR" -type f \( -name '*.exe' -o -name '*.dll' -o -name '*.evtx' -o -name '*.pcap' -o -name '*.zip' \)
```

Expected result:

- Raw and working evidence remains ignored.
- No executable, EVTX, PCAP, ZIP, or cache file is staged.
- Only Markdown, CSV/TSV, YAML, query, Mermaid, JSON, and safe analysis scripts are committed.
