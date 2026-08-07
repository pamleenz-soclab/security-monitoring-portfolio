#!/bin/bash
set -euo pipefail
INPUT="${1:?Usage: extract-audit-operations.sh /path/to/01-directory-audit.jsonl}"
jq -r '[.activityDateTime, .activityDisplayName, .operationType, .result,
        (.initiatedBy.user.id // .initiatedBy.app.servicePrincipalId // "unknown"),
        (.correlationId // "") ] | @tsv' "$INPUT"
