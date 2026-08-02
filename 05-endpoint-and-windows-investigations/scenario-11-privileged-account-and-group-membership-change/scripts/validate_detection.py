#!/usr/bin/env python3
"""Validate Scenario 11 detection layers against the processed timeline."""

from __future__ import annotations

import argparse
import csv
from datetime import datetime, timezone
from pathlib import Path


PRIVILEGED_GROUPS = {
    "administrators",
    "domain admins",
    "enterprise admins",
    "schema admins",
    "account operators",
    "server operators",
    "backup operators",
    "dnsadmins",
}
MEMBERSHIP_ADD_EVENTS = {"4728", "4732", "4756"}
POST_CHANGE_SECURITY_EVENTS = {"4624", "4625", "4648", "4672"}


def parse_timestamp(value: str) -> datetime:
    cleaned = value.replace(" (UTC inferred)", "")
    if " " in cleaned and "T" not in cleaned:
        cleaned = cleaned.replace(" ", "T", 1)
    if cleaned.endswith("Z"):
        cleaned = cleaned[:-1] + "+00:00"
    parsed = datetime.fromisoformat(cleaned)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def account_name(value: str) -> str:
    return value.rsplit("\\", 1)[-1].lower()


def group_name(value: str) -> str:
    return value.rsplit("\\", 1)[-1].lower()


def write_results(path: Path, rows: list[dict[str, object]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "analytic_id",
                "analytic_name",
                "expected_matches",
                "observed_matches",
                "result",
                "evidence_sequences",
                "notes",
            ],
        )
        writer.writeheader()
        writer.writerows(rows)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--timeline", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    with args.timeline.open(newline="", encoding="utf-8-sig") as handle:
        timeline = list(csv.DictReader(handle))

    additions = [
        row
        for row in timeline
        if row["source"] == "Windows Security"
        and row["event_id"] in MEMBERSHIP_ADD_EVENTS
        and group_name(row["group_or_role"]) in PRIVILEGED_GROUPS
    ]

    creations = [
        row
        for row in timeline
        if row["source"] == "Windows Security" and row["event_id"] == "4720"
    ]
    correlated_pairs: list[tuple[dict[str, str], dict[str, str]]] = []
    for creation in creations:
        for addition in additions:
            same_host = creation["computer"].lower() == addition["computer"].lower()
            same_target = account_name(creation["target"]) == account_name(addition["target"])
            delta = parse_timestamp(addition["timestamp"]) - parse_timestamp(creation["timestamp"])
            within_window = 0 <= delta.total_seconds() <= 15 * 60
            if same_host and same_target and within_window:
                correlated_pairs.append((creation, addition))

    addition_targets = {account_name(row["target"]) for row in additions}
    last_addition_time = max(parse_timestamp(row["timestamp"]) for row in additions)
    post_change_target_activity = [
        row
        for row in timeline
        if parse_timestamp(row["timestamp"]) >= last_addition_time
        and account_name(row["actor"]) in addition_targets
        and (
            (row["source"] == "Windows Security" and row["event_id"] in POST_CHANGE_SECURITY_EVENTS)
            or (row["source"] == "Sysmon Operational" and row["event_id"] == "1")
        )
    ]

    results = [
        {
            "analytic_id": "S11-D1",
            "analytic_name": "Privileged membership addition",
            "expected_matches": 1,
            "observed_matches": len(additions),
            "result": "PASS" if len(additions) == 1 else "FAIL",
            "evidence_sequences": ";".join(row["sequence"] for row in additions),
            "notes": "Windows Security 4728/4732/4756 plus privileged-group inventory",
        },
        {
            "analytic_id": "S11-D2",
            "analytic_name": "New account followed by privileged addition within 15 minutes",
            "expected_matches": 1,
            "observed_matches": len(correlated_pairs),
            "result": "PASS" if len(correlated_pairs) == 1 else "FAIL",
            "evidence_sequences": ";".join(
                f"{creation['sequence']}->{addition['sequence']}"
                for creation, addition in correlated_pairs
            ),
            "notes": "Same host and normalised target name; production should prefer SID/Object ID",
        },
        {
            "analytic_id": "S11-D3",
            "analytic_name": "Post-change activity executed as target",
            "expected_matches": 0,
            "observed_matches": len(post_change_target_activity),
            "result": "PASS" if not post_change_target_activity else "FAIL",
            "evidence_sequences": ";".join(row["sequence"] for row in post_change_target_activity),
            "notes": "Checks target-attributed Security 4624/4625/4648/4672 and Sysmon Event 1",
        },
    ]
    write_results(args.output, results)


if __name__ == "__main__":
    main()
