#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "Usage: $0 <raw-json-lines-file> <working-output-directory>" >&2
  exit 64
fi

RAW_JSON=$1
OUTPUT_DIR=$2

if [[ ! -f "$RAW_JSON" ]]; then
  echo "Input file not found: $RAW_JSON" >&2
  exit 66
fi

if ! command -v jq >/dev/null 2>&1; then
  echo "jq is required but was not found." >&2
  exit 69
fi

mkdir -p "$OUTPUT_DIR"

# Validate that every input record is a JSON object. The script only reads logs;
# it never executes command lines or decodes payload content found in events.
jq -e 'type == "object"' "$RAW_JSON" >/dev/null

jq -r '
  [
    (.EventTime // .UtcTime // "<missing>"),
    (.Hostname // .Computer // "<missing>"),
    (.Channel // "<missing>"),
    ((.EventID // "<missing>") | tostring),
    ((.RecordNumber // .EventRecordID // "<missing>") | tostring)
  ] | @tsv
' "$RAW_JSON" | LC_ALL=C sort > "$OUTPUT_DIR/all-event-index.tsv"

jq -r '
  (.Channel // "") as $channel
  | ((.EventID // "") | tostring) as $id
  | select(
      (
        ((($channel | ascii_downcase) == "security")
          and (["4698","4699","4700","4701","4702"] | index($id)))
        or
        ($channel == "Microsoft-Windows-TaskScheduler/Operational"
          and (["106","129","141","200","201"] | index($id)))
      )
    )
  | [
      (.EventTime // .UtcTime // "<missing>"),
      ((.RecordNumber // .EventRecordID // "<missing>") | tostring),
      $channel,
      $id,
      (.Hostname // .Computer // "<missing>"),
      (.TaskName // "<missing>"),
      (.SubjectUserName // .UserContext // "<missing>"),
      (.SubjectLogonId // "<missing>")
    ] | @tsv
' "$RAW_JSON" | LC_ALL=C sort > "$OUTPUT_DIR/task-lifecycle.tsv"

jq -r '
  ((.EventID // "") | tostring) as $id
  | (
      (.Image // .NewProcessName // "") + " "
      + (.CommandLine // .ProcessCommandLine // "") + " "
      + (.ParentImage // .ParentProcessName // "")
    ) as $search
  | select(
      (($id == "1") or ($id == "4688"))
      and ($search | test("schtasks|powershell|shutdown|csc\\.exe"; "i"))
    )
  | [
      (.EventTime // .UtcTime // "<missing>"),
      ((.RecordNumber // .EventRecordID // "<missing>") | tostring),
      (.Channel // "<missing>"),
      $id,
      (.Hostname // .Computer // "<missing>"),
      (.User // .SubjectUserName // "<missing>"),
      (.SubjectLogonId // .LogonId // "<missing>"),
      ((.ProcessId // .ProcessID // .NewProcessId // "<missing>") | tostring),
      (.ProcessGuid // "<missing>"),
      (.Image // .NewProcessName // "<missing>"),
      ((.CommandLine // .ProcessCommandLine // "") | gsub("[\\r\\n\\t]+"; " ")),
      ((.ParentProcessId // .ParentProcessID // "<missing>") | tostring),
      (.ParentProcessGuid // "<missing>"),
      (.ParentImage // .ParentProcessName // "<missing>"),
      (.IntegrityLevel // .MandatoryLabel // "<missing>")
    ] | @tsv
' "$RAW_JSON" | LC_ALL=C sort > "$OUTPUT_DIR/process-candidates.tsv"

jq -r '
  ((.EventID // "") | tostring) as $id
  | (.Channel // "") as $channel
  | (.Image // .Application // "") as $application
  | select(
      (
        ($channel == "Microsoft-Windows-Sysmon/Operational" and $id == "3")
        or ((($channel | ascii_downcase) == "security")
          and (["5156","5158"] | index($id)))
      )
      and ($application | test("powershell|pwsh"; "i"))
    )
  | [
      (.EventTime // .UtcTime // "<missing>"),
      ((.RecordNumber // .EventRecordID // "<missing>") | tostring),
      $channel,
      $id,
      (.Hostname // .Computer // "<missing>"),
      ((.ProcessId // .ProcessID // "<missing>") | tostring),
      $application,
      (.SourceIp // .SourceAddress // "<missing>"),
      ((.SourcePort // "<missing>") | tostring),
      (.DestinationIp // .DestAddress // .RemoteAddress // "<missing>"),
      ((.DestinationPort // .DestPort // .RemotePort // "<missing>") | tostring)
    ] | @tsv
' "$RAW_JSON" | LC_ALL=C sort > "$OUTPUT_DIR/network-candidates.tsv"

jq -r '
  ((.EventID // "") | tostring) as $id
  | select(
      (.Channel // "") == "Microsoft-Windows-Sysmon/Operational"
      and (["12","13","14"] | index($id))
      and (((.TargetObject // "") + " " + (.Message // ""))
        | test("Software\\\\Microsoft\\\\Network|MordorElevated"; "i"))
    )
  | [
      (.EventTime // .UtcTime // "<missing>"),
      ((.RecordNumber // .EventRecordID // "<missing>") | tostring),
      $id,
      (.Hostname // .Computer // "<missing>"),
      (.Image // "<missing>"),
      (.ProcessGuid // "<missing>"),
      (.TargetObject // "<missing>"),
      (if ((.Details // "") | length) > 0 then "data-present" else "data-not-recorded" end)
    ] | @tsv
' "$RAW_JSON" | LC_ALL=C sort > "$OUTPUT_DIR/registry-candidates.tsv"

jq -r '
  (.Channel // "") as $channel
  | ((.EventID // "") | tostring) as $id
  | select(
      ($channel == "System" and (["12","13","109","6006"] | index($id)))
      or ((($channel | ascii_downcase) == "security")
        and (["4608","4624","4672"] | index($id)))
    )
  | [
      (.EventTime // .UtcTime // "<missing>"),
      ((.RecordNumber // .EventRecordID // "<missing>") | tostring),
      $channel,
      $id,
      (.Hostname // .Computer // "<missing>"),
      (.TargetUserName // .SubjectUserName // "<missing>"),
      (.TargetLogonId // .SubjectLogonId // "<missing>"),
      ((.LogonType // "<missing>") | tostring)
    ] | @tsv
' "$RAW_JSON" | LC_ALL=C sort > "$OUTPUT_DIR/reboot-logon-evidence.tsv"

wc -l \
  "$OUTPUT_DIR/all-event-index.tsv" \
  "$OUTPUT_DIR/task-lifecycle.tsv" \
  "$OUTPUT_DIR/process-candidates.tsv" \
  "$OUTPUT_DIR/network-candidates.tsv" \
  "$OUTPUT_DIR/registry-candidates.tsv" \
  "$OUTPUT_DIR/reboot-logon-evidence.tsv"

