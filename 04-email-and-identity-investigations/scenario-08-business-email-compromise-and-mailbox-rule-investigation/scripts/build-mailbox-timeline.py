#!/usr/bin/env python3
import csv
import hashlib
import json
import sys
from collections import Counter
from pathlib import Path


EXPECTED_FILES = [
    "t1098.002_Mail Account Delegation full access permissions.json",
    "t1098.002_Mail account delegation-SendAs permission.csv",
    "t1114.003_Forward_Rule_Multi_Users_Same_Forward_dest.json",
    "t1114.003_rule_mail_forward_same_dest.json",
    "t1114_Set-Mailbox-ForwardSMTPAddress.csv",
    "t1564.008_New inbox rule to delete email.csv",
    "t1564.008_Update existing mailbox rule using Set-InboxRule.csv",
    "t1564.008_markasread_delete_all_email.json",
    "t1564.008_rule_mark_as_read_move.json",
]


def decode_json(text):
    text = text.strip()
    if not text:
        return []
    try:
        return [json.loads(text)]
    except json.JSONDecodeError:
        values = []
        for line in text.splitlines():
            if not line.strip():
                continue
            values.append(json.loads(line))
        return values


def extract_events(value):
    if isinstance(value, list):
        for item in value:
            yield from extract_events(item)
        return
    if isinstance(value, str):
        for item in decode_json(value):
            yield from extract_events(item)
        return
    if not isinstance(value, dict):
        return
    if value.get("Operation"):
        yield value
        return
    if value.get("AuditData"):
        yield from extract_events(value["AuditData"])


def load_file(path):
    if path.suffix.lower() == ".csv":
        with path.open("r", encoding="utf-8-sig", newline="") as handle:
            for row in csv.DictReader(handle):
                yield from extract_events(row)
        return
    text = path.read_text(encoding="utf-8-sig", errors="replace")
    for value in decode_json(text):
        yield from extract_events(value)


def parameter_pairs(event):
    pairs = []
    for item in event.get("Parameters", []):
        if isinstance(item, dict):
            pairs.append((str(item.get("Name", "")), str(item.get("Value", ""))))
    return pairs


def clean(value):
    return "" if value is None else str(value)


def main():
    if len(sys.argv) != 3:
        raise SystemExit("Usage: scenario08_build_timeline.py RAW_DIR PROCESSED_DIR")

    raw_dir = Path(sys.argv[1])
    processed_dir = Path(sys.argv[2])
    missing = [name for name in EXPECTED_FILES if not (raw_dir / name).is_file()]
    if missing:
        raise SystemExit("Missing expected files:\n- " + "\n- ".join(missing))

    raw_records = []
    per_file = {}
    for name in EXPECTED_FILES:
        path = raw_dir / name
        events = list(load_file(path))
        per_file[name] = len(events)
        raw_records.extend((event, name) for event in events)

    groups = {}
    for event, source in raw_records:
        event_id = clean(event.get("Id"))
        organization_id = clean(event.get("OrganizationId"))
        if event_id:
            key = ("event_id", organization_id, event_id)
        else:
            payload = json.dumps(event, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
            key = ("payload_hash", hashlib.sha256(payload.encode("utf-8")).hexdigest())
        group = groups.setdefault(key, {"event": event, "sources": set(), "copies": 0})
        group["sources"].add(source)
        group["copies"] += 1

    ordered = sorted(
        groups.values(),
        key=lambda group: (
            clean(group["event"].get("CreationTime")),
            clean(group["event"].get("Id")),
        ),
    )

    processed_dir.mkdir(parents=True, exist_ok=True)
    timeline_path = processed_dir / "mailbox-activity-timeline.csv"
    fields = [
        "event_number",
        "creation_time_utc",
        "operation",
        "result_status",
        "actor",
        "client_ip",
        "organization_name",
        "organization_id",
        "target_object",
        "parameters",
        "event_id",
        "source_files",
        "raw_copies",
    ]
    with timeline_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for number, group in enumerate(ordered, start=1):
            event = group["event"]
            params = parameter_pairs(event)
            param_map = dict(params)
            writer.writerow(
                {
                    "event_number": number,
                    "creation_time_utc": clean(event.get("CreationTime")),
                    "operation": clean(event.get("Operation")),
                    "result_status": clean(event.get("ResultStatus")),
                    "actor": clean(event.get("UserId")),
                    "client_ip": clean(event.get("ClientIP")),
                    "organization_name": clean(event.get("OrganizationName")),
                    "organization_id": clean(event.get("OrganizationId")),
                    "target_object": param_map.get("Identity") or clean(event.get("ObjectId")),
                    "parameters": "; ".join(f"{name}={value}" for name, value in params),
                    "event_id": clean(event.get("Id")),
                    "source_files": "; ".join(sorted(group["sources"])),
                    "raw_copies": group["copies"],
                }
            )

    json_count = sum(name.endswith(".json") for name in EXPECTED_FILES)
    csv_count = sum(name.endswith(".csv") for name in EXPECTED_FILES)
    print("VALIDATION SUMMARY")
    print(f"Files processed: {len(EXPECTED_FILES)} ({json_count} JSON, {csv_count} CSV)")
    print(f"Raw event records: {len(raw_records)}")
    print(f"Unique events: {len(ordered)}")
    print(f"Duplicate copies removed: {len(raw_records) - len(ordered)}")
    print(f"Timeline written: {timeline_path}")
    print("Per-file raw records:")
    for name in EXPECTED_FILES:
        print(f"  {per_file[name]:>2}  {name}")
    print("Operations:")
    for operation, count in sorted(Counter(clean(g["event"].get("Operation")) for g in ordered).items()):
        print(f"  {count:>2}  {operation}")

    print("\nUNIQUE EVENT SUMMARY")
    for number, group in enumerate(ordered, start=1):
        event = group["event"]
        params = "; ".join(f"{name}={value}" for name, value in parameter_pairs(event)) or "-"
        print(f"[{number:02d}] {clean(event.get('CreationTime'))}Z | {clean(event.get('Operation'))} | Result={clean(event.get('ResultStatus'))}")
        print(f"     Actor={clean(event.get('UserId'))} | ClientIP={clean(event.get('ClientIP'))}")
        print(f"     Parameters: {params}")
        print(f"     Source={'; '.join(sorted(group['sources']))} | RawCopies={group['copies']}")

    if (len(raw_records), len(ordered)) != (14, 12):
        raise SystemExit("\nValidation failed: expected 14 raw records and 12 unique events.")
    print("\nValidation passed: expected 14 raw records and 12 unique events.")


if __name__ == "__main__":
    main()
