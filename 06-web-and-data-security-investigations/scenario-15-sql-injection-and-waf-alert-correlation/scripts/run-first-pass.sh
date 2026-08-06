#!/usr/bin/env bash
set -euo pipefail

SCENARIO_DIR="${1:?Usage: run-first-pass.sh SCENARIO_DIR}"
RAW_DIR="$SCENARIO_DIR/evidence/raw"
WORK_DIR="$SCENARIO_DIR/evidence/working"
EXTRACT_DIR="$WORK_DIR/extracted"
OUTPUT_DIR="$WORK_DIR/first-pass"
ZIP_PATH="$RAW_DIR/owasp.zip"
SCRIPT_DIR="$SCENARIO_DIR/scripts"

[[ -f "$ZIP_PATH" ]] || { printf 'ERROR: missing %s\n' "$ZIP_PATH" >&2; exit 20; }
[[ -x "$SCRIPT_DIR/safe_extract_zip.py" ]] || { printf 'ERROR: missing safe_extract_zip.py\n' >&2; exit 21; }
[[ -x "$SCRIPT_DIR/parse_modsec_audit.py" ]] || { printf 'ERROR: missing parse_modsec_audit.py\n' >&2; exit 22; }

rm -rf "$EXTRACT_DIR" "$OUTPUT_DIR"
mkdir -p "$EXTRACT_DIR" "$OUTPUT_DIR"

python3 "$SCRIPT_DIR/safe_extract_zip.py" "$ZIP_PATH" "$EXTRACT_DIR" \
  > "$WORK_DIR/extraction-log.txt" 2>&1

find "$EXTRACT_DIR" -type f -print0 \
  | xargs -0 file \
  > "$WORK_DIR/extracted-file-types.txt"

find "$EXTRACT_DIR" -type f -exec shasum -a 256 {} + \
  > "$WORK_DIR/extracted-file-sha256.txt"

python3 "$SCRIPT_DIR/parse_modsec_audit.py" \
  --input "$EXTRACT_DIR" \
  --output "$OUTPUT_DIR" \
  | tee "$WORK_DIR/first-pass-terminal-summary.txt"

cp "$WORK_DIR/evidence-source-record.tsv" "$OUTPUT_DIR/" 2>/dev/null || true
cp "$WORK_DIR/acquisition-manifest.tsv" "$OUTPUT_DIR/" 2>/dev/null || true
cp "$WORK_DIR/source-sha256-records.tsv" "$OUTPUT_DIR/" 2>/dev/null || true
cp "$WORK_DIR/archive-file-type.txt" "$OUTPUT_DIR/" 2>/dev/null || true
cp "$WORK_DIR/archive-integrity-test.txt" "$OUTPUT_DIR/" 2>/dev/null || true
cp "$WORK_DIR/archive-member-list.txt" "$OUTPUT_DIR/" 2>/dev/null || true
cp "$WORK_DIR/extracted-file-types.txt" "$OUTPUT_DIR/" 2>/dev/null || true

UPLOAD_ZIP="$WORK_DIR/scenario-15-first-pass-results.zip"
rm -f "$UPLOAD_ZIP"
(
  cd "$OUTPUT_DIR"
  zip -q -r "$UPLOAD_ZIP" . \
    -x 'analysis.sqlite'
)

printf '\nUpload package created:\n  %s\n' "$UPLOAD_ZIP"
printf '\nCompact summary:\n'
cat "$OUTPUT_DIR/compact-first-pass-summary.txt"
