#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SCENARIO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
HOST_JSON="$SCENARIO_DIR/evidence/raw/otrf-host/empire_smbexec_dcerpc_smb_svcctl_2020-09-20025716.json"
NETWORK_DIR="$SCENARIO_DIR/evidence/raw/otrf-network"
OUTPUT_DIR="$SCENARIO_DIR/evidence/processed"

python3 "$SCRIPT_DIR/analyze_otrf_smbexec.py" \
  --host-json "$HOST_JSON" \
  --network-dir "$NETWORK_DIR" \
  --output-dir "$OUTPUT_DIR"

