#!/usr/bin/env python3
"""Build a per-user sign-in baseline from Scenario 17 raw JSONL evidence."""
from __future__ import annotations

import argparse
import csv
import json
from collections import defaultdict
from pathlib import Path


def load_jsonl(path: Path):
    with path.open("r", encoding="utf-8") as fh:
        for line_number, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"Invalid JSONL at {path}:{line_number}: {exc}") from exc


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--raw-dir", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    source = args.raw_dir.expanduser().resolve() / "entra-signins.jsonl"
    if not source.is_file():
        print(f"ERROR: missing {source}")
        return 2

    state = defaultdict(lambda: {
        "events": 0, "successes": 0, "failures": 0,
        "first": None, "last": None, "countries": set(), "cities": set(),
        "asns": set(), "ips": set(), "devices": set(), "apps": set(),
        "client_apps": set(), "protocols": set(),
    })

    for event in load_jsonl(source):
        sign_in_type = event.get("signInLogType") or event.get("signInEventType")
        if not sign_in_type:
            values = event.get("signInEventTypes") or []
            sign_in_type = values[0] if values else None
        if sign_in_type not in ("interactiveUser", "nonInteractiveUser"):
            continue
        user = event.get("userPrincipalName")
        if not user:
            continue
        row = state[user]
        timestamp = event.get("createdDateTime")
        row["events"] += 1
        if event.get("status", {}).get("errorCode") == 0:
            row["successes"] += 1
        else:
            row["failures"] += 1
        row["first"] = timestamp if row["first"] is None or timestamp < row["first"] else row["first"]
        row["last"] = timestamp if row["last"] is None or timestamp > row["last"] else row["last"]
        location = event.get("locationDetails") or event.get("location") or {}
        if not isinstance(location, dict):
            location = {"countryOrRegion": str(location)}
        device = event.get("deviceDetail") or {}
        if not isinstance(device, dict):
            device = {}
        for target, value in (
            ("countries", location.get("countryOrRegion")),
            ("cities", location.get("city")),
            ("asns", event.get("autonomousSystemNumber")),
            ("ips", event.get("ipAddress")),
            ("devices", device.get("deviceId")),
            ("apps", event.get("appDisplayName")),
            ("client_apps", event.get("clientAppUsed")),
            ("protocols", event.get("authenticationProtocol")),
        ):
            if value not in (None, ""):
                row[target].add(str(value))

    args.output.parent.mkdir(parents=True, exist_ok=True)
    fields = [
        "user_principal_name", "event_count", "success_count", "failure_count",
        "first_utc", "last_utc", "countries", "cities", "asns", "ip_addresses",
        "device_ids", "applications", "client_applications", "authentication_protocols",
    ]
    with args.output.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields)
        writer.writeheader()
        for user in sorted(state):
            row = state[user]
            writer.writerow({
                "user_principal_name": user,
                "event_count": row["events"],
                "success_count": row["successes"],
                "failure_count": row["failures"],
                "first_utc": row["first"],
                "last_utc": row["last"],
                "countries": json.dumps(sorted(row["countries"])),
                "cities": json.dumps(sorted(row["cities"])),
                "asns": json.dumps(sorted(row["asns"])),
                "ip_addresses": json.dumps(sorted(row["ips"])),
                "device_ids": json.dumps(sorted(row["devices"])),
                "applications": json.dumps(sorted(row["apps"])),
                "client_applications": json.dumps(sorted(row["client_apps"])),
                "authentication_protocols": json.dumps(sorted(row["protocols"])),
            })

    print(f"Wrote {len(state)} user baselines to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
