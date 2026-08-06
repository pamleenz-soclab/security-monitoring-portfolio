#!/usr/bin/env bash
set -euo pipefail

SCENARIO_DIR="${1:?Usage: acquire-dataset.sh SCENARIO_DIR}"
RAW_DIR="$SCENARIO_DIR/evidence/raw"
WORK_DIR="$SCENARIO_DIR/evidence/working"
ZIP_PATH="$RAW_DIR/owasp.zip"
PART_PATH="$RAW_DIR/owasp.zip.part"
META_PATH="$RAW_DIR/zenodo-record-17178461.json"
DATASET_URL="https://zenodo.org/records/17178461/files/owasp.zip?download=1"
METADATA_URL="https://zenodo.org/api/records/17178461"
EXPECTED_MD5="95b7a8237abc163d8ca31e49f7318efd"

mkdir -p "$RAW_DIR" "$WORK_DIR"

printf 'Retrieving Zenodo metadata...\n'
if ! curl --fail --silent --show-error --location --retry 3 --retry-delay 2 \
  "$METADATA_URL" -o "$META_PATH"; then
  printf 'WARNING: metadata API retrieval failed; dataset download will continue.\n' >&2
  rm -f "$META_PATH"
fi

printf 'Downloading dataset archive...\n'
curl --fail --show-error --location --retry 5 --retry-delay 3 \
  --continue-at - --output "$PART_PATH" "$DATASET_URL"
mv "$PART_PATH" "$ZIP_PATH"

ACTUAL_MD5="$(md5 -q "$ZIP_PATH")"
if [[ "$ACTUAL_MD5" != "$EXPECTED_MD5" ]]; then
  printf 'ERROR: MD5 mismatch. Expected %s but got %s\n' "$EXPECTED_MD5" "$ACTUAL_MD5" >&2
  exit 10
fi

SHA256="$(shasum -a 256 "$ZIP_PATH" | awk '{print $1}')"
SIZE="$(stat -f '%z' "$ZIP_PATH")"
ACQUIRED_UTC="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

cat > "$WORK_DIR/evidence-source-record.tsv" <<EOF
field	value
title	A Thirty-Day Dataset of Malicious HTTP Requests Blocked by OWASP ModSecurity on a Production Web Server
record_id	17178461
doi	10.5281/zenodo.17178461
publisher	Zenodo
dataset_url	$DATASET_URL
file_name	owasp.zip
expected_md5	$EXPECTED_MD5
observed_md5	$ACTUAL_MD5
observed_sha256	$SHA256
observed_size_bytes	$SIZE
acquired_utc	$ACQUIRED_UTC
license	CC BY 4.0 as stated by the publication/record metadata; preserve attribution
local_path	evidence/raw/owasp.zip
EOF

cat > "$WORK_DIR/acquisition-manifest.tsv" <<EOF
acquired_utc	file_name	size_bytes	md5	sha256	source_url	storage_class	git_policy
$ACQUIRED_UTC	owasp.zip	$SIZE	$ACTUAL_MD5	$SHA256	$DATASET_URL	raw	local only; Git ignored
EOF

cat > "$WORK_DIR/source-sha256-records.tsv" <<EOF
relative_path	sha256	size_bytes
raw/owasp.zip	$SHA256	$SIZE
EOF

file "$ZIP_PATH" > "$WORK_DIR/archive-file-type.txt"
unzip -t "$ZIP_PATH" > "$WORK_DIR/archive-integrity-test.txt"
zipinfo -1 "$ZIP_PATH" > "$WORK_DIR/archive-member-list.txt"

printf '\nAcquisition complete\n'
printf '  file: %s\n' "$ZIP_PATH"
printf '  size: %s bytes\n' "$SIZE"
printf '  MD5:  %s (matches Zenodo)\n' "$ACTUAL_MD5"
printf '  SHA256: %s\n' "$SHA256"
