#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SCENARIO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
RAW_DIR="$SCENARIO_DIR/evidence/raw"
WORKING_DIR="$SCENARIO_DIR/evidence/working"
ARCHIVE_DIR="$RAW_DIR/otrf-archives"
HOST_DIR="$RAW_DIR/otrf-host"
NETWORK_DIR="$RAW_DIR/otrf-network"
REJECTED_DIR="$RAW_DIR/rejected-splunk-atomic-red-team"

UPSTREAM_REPOSITORY="https://github.com/OTRF/Security-Datasets.git"
UPSTREAM_COMMIT="d9d40ef123d2c87d5d3df28c96bcab4f0faccc87"
UPSTREAM_BASE="https://raw.githubusercontent.com/OTRF/Security-Datasets/$UPSTREAM_COMMIT"
HOST_ARCHIVE="empire_smbexec_dcerpc_smb_svcctl-host.zip"
NETWORK_ARCHIVE="empire_smbexec_dcerpc_smb_svcctl-network.zip"
HOST_SHA256="c0fc435c9ce0ecdc7cd57b4055977b949ac6b1cae9d7f4ce7aa0f0e5eae7d7f1"
NETWORK_SHA256="d9879be3d5e93268d4ea1ca5c7f107f0f16624b5df4aee43b04aa48a14560eea"

mkdir -p "$ARCHIVE_DIR" "$HOST_DIR" "$NETWORK_DIR" "$REJECTED_DIR" "$WORKING_DIR"

# Preserve the rejected candidate dataset. Only the explicitly known files are moved.
REJECTED_FILES=(
  "4688_smbexec_windows-security.log"
  "4688_wmiexec_windows-security.log"
  "atomic_red_team.yml"
  "firewall-powershell.log"
  "smbexec_windows-sysmon.log"
  "splunk-attack-data-LICENSE"
  "windows-powershell.log"
  "windows-security-xml.log"
  "windows-security.log"
  "windows-sysmon.log"
  "windows-system.log"
  "wmiexec_windows-sysmon.log"
)

for filename in "${REJECTED_FILES[@]}"; do
  if [[ -f "$RAW_DIR/$filename" ]]; then
    mv "$RAW_DIR/$filename" "$REJECTED_DIR/$filename"
  fi
done

curl --fail --location --retry 3 --retry-delay 2 \
  --output "$ARCHIVE_DIR/$HOST_ARCHIVE" \
  "$UPSTREAM_BASE/datasets/atomic/windows/lateral_movement/host/empire_smbexec_dcerpc_smb_svcctl.zip"

curl --fail --location --retry 3 --retry-delay 2 \
  --output "$ARCHIVE_DIR/$NETWORK_ARCHIVE" \
  "$UPSTREAM_BASE/datasets/atomic/windows/lateral_movement/network/empire_smbexec_dcerpc_smb_svcctl.zip"

curl --fail --location --retry 3 --retry-delay 2 \
  --output "$RAW_DIR/OTRF-Security-Datasets-LICENSE" \
  "$UPSTREAM_BASE/LICENSE"

actual_host_sha="$(shasum -a 256 "$ARCHIVE_DIR/$HOST_ARCHIVE" | awk '{print $1}')"
actual_network_sha="$(shasum -a 256 "$ARCHIVE_DIR/$NETWORK_ARCHIVE" | awk '{print $1}')"

if [[ "$actual_host_sha" != "$HOST_SHA256" ]]; then
  printf 'Host archive hash mismatch: %s\n' "$actual_host_sha" >&2
  exit 1
fi

if [[ "$actual_network_sha" != "$NETWORK_SHA256" ]]; then
  printf 'Network archive hash mismatch: %s\n' "$actual_network_sha" >&2
  exit 1
fi

unzip -tq "$ARCHIVE_DIR/$HOST_ARCHIVE"
unzip -tq "$ARCHIVE_DIR/$NETWORK_ARCHIVE"
unzip -o "$ARCHIVE_DIR/$HOST_ARCHIVE" -d "$HOST_DIR" >/dev/null
unzip -o "$ARCHIVE_DIR/$NETWORK_ARCHIVE" -d "$NETWORK_DIR" >/dev/null

SOURCE_RECORD="$WORKING_DIR/otrf-source-record.tsv"
printf 'field\tvalue\n' > "$SOURCE_RECORD"
printf 'repository\t%s\n' "$UPSTREAM_REPOSITORY" >> "$SOURCE_RECORD"
printf 'commit\t%s\n' "$UPSTREAM_COMMIT" >> "$SOURCE_RECORD"
printf 'dataset\tEmpire Invoke SMBExec\n' >> "$SOURCE_RECORD"
printf 'host_archive_sha256\t%s\n' "$HOST_SHA256" >> "$SOURCE_RECORD"
printf 'network_archive_sha256\t%s\n' "$NETWORK_SHA256" >> "$SOURCE_RECORD"
printf 'retrieval_date_utc\t%s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" >> "$SOURCE_RECORD"
printf 'documentation\thttps://securitydatasets.com/notebooks/atomic/windows/lateral_movement/SDWIN-190518210125.html\n' >> "$SOURCE_RECORD"

printf 'Dataset prepared successfully.\n'
printf 'Rejected candidate retained at: %s\n' "$REJECTED_DIR"
printf 'Host JSON: %s\n' "$HOST_DIR/empire_smbexec_dcerpc_smb_svcctl_2020-09-20025716.json"
printf 'Network PCAP directory: %s\n' "$NETWORK_DIR"

