# Validation Checklist

## Dataset

- [ ] Preparation script reports both archive hashes as expected.
- [ ] One host JSON file and two PCAPs exist under ignored raw directories.
- [ ] Rejected Splunk candidate is retained, not deleted.
- [ ] `OTRF-Security-Datasets-LICENSE` was downloaded from the same fixed commit.

## Analysis

- [ ] `bash scripts/run_analysis.sh` exits successfully.
- [ ] Script reports `Validated 7504 host events and 2 PCAPs`.
- [ ] Script reports `True Positive - successful SMB remote service execution as SYSTEM`.
- [ ] Twelve processed evidence files are regenerated.
- [ ] `analysis-summary.json` is valid JSON.
- [ ] Full demo hash and full encoded payload do not appear in tracked files.
- [ ] `analysis-summary.json` separates observed facts, ground truth, not-observed items and unavailable authorization context.

## Detection content

- [ ] All three Sigma files parse as YAML.
- [ ] Sigma IDs are unique UUIDs.
- [ ] Rules include log source, condition, false positives, severity and ATT&CK mapping.
- [ ] Splunk and Sentinel correlation queries are labelled as schema-adaptation examples.

## Git protection

- [ ] `git check-ignore -v evidence/raw/*` shows every raw path is ignored.
- [ ] `git status --short --untracked-files=all .` shows documentation, scripts, detections and processed evidence only.
- [ ] `git diff --check` reports no whitespace errors.
- [ ] No `__pycache__`, `.pyc`, PCAP, raw JSON or archive file is staged.

## Portfolio completeness

- [ ] Verdict, severity, source, target, account and path are explicit.
- [ ] At least two independent telemetry types support lateral movement.
- [ ] Observed facts and simulation ground truth are separated.
- [ ] Containment, detection engineering and false-positive conditions are documented.
- [ ] ATT&CK mappings include SMB remote services and Service Execution.
- [ ] `evidence-inventory.md`, `investigation-notes.md` and `recommended-actions.md` are present.

