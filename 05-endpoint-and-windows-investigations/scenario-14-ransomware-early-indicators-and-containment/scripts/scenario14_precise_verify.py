#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import re
import sqlite3
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable

LONG_TOKEN_RE = re.compile(r"(?i)\b[A-Za-z0-9+/]{100,}={0,2}\b")
RECOVERY_TERMS = re.compile(
    r"(?i)\b(vssadmin(?:\.exe)?|wmic(?:\.exe)?.{0,80}shadowcopy|"
    r"win32_shadowcopy|wbadmin(?:\.exe)?|bcdedit(?:\.exe)?|"
    r"reagentc(?:\.exe)?|diskshadow(?:\.exe)?)\b"
)
DEFENCE_TERMS = re.compile(
    r"(?i)\b(wevtutil(?:\.exe)?.{0,80}\bcl\b|clear-eventlog|"
    r"set-mppreference|add-mppreference|disable(realtime|behavior|ioav)|"
    r"auditpol(?:\.exe)?|set-auditpolicy|"
    r"netsh.{0,100}firewall.{0,80}(off|disable)|"
    r"set-netfirewallprofile.{0,80}false|"
    r"taskkill|stop-process|stop-service|net\s+stop|sc(?:\.exe)?\s+stop)\b"
)
EXFIL_TERMS = re.compile(
    r"(?i)\b(rclone|winscp|megasync|azcopy|curl|wget|bitsadmin|"
    r"7z(?:\.exe)?|rar(?:\.exe)?|winrar|compress-archive|makecab|tar(?:\.exe)?)\b"
)
RANSOM_TERMS = re.compile(
    r"(?i)\b(lockbit|lb3(?:\.exe)?|ryuk|conti|blackcat|alphv|"
    r"ransom|decrypt|restore[-_ ]?my[-_ ]?files|readme)\b"
)
SUSPICIOUS_PORTS = {"135", "139", "445", "3389", "4444", "5985", "5986", "61616", "8080"}

SPECIAL_COLUMNS = [
    "timestamp", "computer", "source", "event_id", "record_id", "account",
    "domain", "logon_id", "process_guid", "process_id",
    "parent_process_guid", "parent_process_id", "image", "command_line",
    "parent_image", "parent_command_line", "target_filename", "operation",
    "source_ip", "source_port", "destination_ip", "destination_port",
    "share_name", "object_name", "service_name", "task_name",
    "script_block_id", "message", "data_json", "tags"
]


def clean(value: Any) -> str:
    if value is None:
        return ""
    return " ".join(str(value).replace("\x00", "").replace("\r", " ").replace("\n", " ").split())


def preview(value: Any, limit: int = 500) -> str:
    text = clean(value)
    text = LONG_TOKEN_RE.sub(lambda m: f"<LONG_ENCODED_TOKEN:{len(m.group(0))}>", text)
    return text if len(text) <= limit else text[:limit] + "...<TRUNCATED>"


def host_key(value: str) -> str:
    return clean(value).split(".", 1)[0].upper()


def parse_timestamp(value: str) -> datetime | None:
    text = clean(value)
    if not text:
        return None
    try:
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        dt = datetime.fromisoformat(text)
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def parse_data(value: str) -> dict[str, str]:
    try:
        raw = json.loads(value or "{}")
    except json.JSONDecodeError:
        return {}
    return {str(k): clean(v) for k, v in raw.items()}


def write_tsv(path: Path, header: list[str], rows: Iterable[Iterable[Any]]) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle, delimiter="\t", lineterminator="\n")
        writer.writerow(header)
        for row in rows:
            writer.writerow([clean(v) for v in row])


def row_dicts(cursor: sqlite3.Cursor) -> list[dict[str, Any]]:
    names = [item[0] for item in cursor.description]
    return [dict(zip(names, row)) for row in cursor.fetchall()]


def basename_windows(path: str) -> str:
    return clean(path).replace("/", "\\").rsplit("\\", 1)[-1]


def dirname_windows(path: str) -> str:
    value = clean(path).replace("/", "\\")
    return value.rsplit("\\", 1)[0] if "\\" in value else "<none>"


def extension_windows(path: str) -> str:
    name = basename_windows(path)
    if "." not in name or name.endswith("."):
        return "<none>"
    return "." + name.rsplit(".", 1)[-1].lower()


def combined_text(row: dict[str, Any]) -> str:
    return " ".join(
        clean(row.get(name, ""))
        for name in [
            "image", "command_line", "parent_image", "parent_command_line",
            "target_filename", "object_name", "share_name", "service_name",
            "task_name", "message", "data_json", "tags"
        ]
    )


def event_export_row(row: dict[str, Any]) -> list[Any]:
    data = parse_data(clean(row.get("data_json", "")))
    return [
        row.get("timestamp", ""),
        row.get("computer", ""),
        row.get("source", ""),
        row.get("event_id", ""),
        row.get("record_id", ""),
        row.get("account", ""),
        row.get("domain", ""),
        row.get("logon_id", ""),
        row.get("process_guid", ""),
        row.get("process_id", ""),
        row.get("parent_process_guid", ""),
        row.get("parent_process_id", ""),
        row.get("image", ""),
        preview(row.get("command_line", "")),
        row.get("parent_image", ""),
        preview(row.get("parent_command_line", "")),
        row.get("target_filename", ""),
        row.get("operation", ""),
        row.get("source_ip", ""),
        row.get("source_port", ""),
        row.get("destination_ip", ""),
        row.get("destination_port", ""),
        row.get("share_name", ""),
        row.get("object_name", ""),
        row.get("service_name", ""),
        row.get("task_name", ""),
        row.get("script_block_id", ""),
        preview(row.get("message", "")),
        data.get("Hashes", ""),
        data.get("CurrentDirectory", ""),
        data.get("IntegrityLevel", ""),
        data.get("LogonType", ""),
        data.get("IpAddress", ""),
        data.get("IpPort", ""),
        data.get("WorkstationName", ""),
        data.get("TargetServerName", ""),
        row.get("tags", ""),
    ]


EVENT_EXPORT_HEADER = [
    "timestamp", "computer", "source", "event_id", "record_id", "account",
    "domain", "logon_id", "process_guid", "process_id",
    "parent_process_guid", "parent_process_id", "image", "command_line_preview",
    "parent_image", "parent_command_line_preview", "target_filename",
    "operation", "source_ip", "source_port", "destination_ip",
    "destination_port", "share_name", "object_name", "service_name",
    "task_name", "script_block_id", "message_preview", "hashes",
    "current_directory", "integrity_level", "logon_type", "ip_address",
    "ip_port", "workstation_name", "target_server_name", "tags"
]


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Precise verification for Scenario 14 first-pass SQLite index."
    )
    parser.add_argument("--db", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args()

    if not args.db.is_file():
        raise SystemExit(f"Database not found: {args.db}")

    args.output_dir.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(args.db)
    conn.row_factory = sqlite3.Row

    table_count = conn.execute(
        "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='events'"
    ).fetchone()[0]
    if table_count != 1:
        raise SystemExit("Required table 'events' was not found.")

    total_events = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]

    all_events = [
        dict(row) for row in conn.execute(
            f'SELECT {",".join(f"""\"{c}\"""" for c in SPECIAL_COLUMNS)} FROM events'
        )
    ]

    # Host alias map.
    aliases: dict[str, Counter[str]] = defaultdict(Counter)
    for row in all_events:
        aliases[host_key(row["computer"])][clean(row["computer"])] += 1

    alias_rows = []
    for logical_host, values in sorted(aliases.items()):
        alias_rows.append([
            logical_host,
            sum(values.values()),
            len(values),
            ";".join(f"{name}:{count}" for name, count in values.most_common())
        ])
    write_tsv(
        args.output_dir / "verification-host-aliases.tsv",
        ["logical_host", "event_count", "alias_count", "aliases"],
        alias_rows,
    )

    # Ransomware process candidates, with LB3 as the primary process.
    process_rows = [
        row for row in all_events
        if row["event_id"] in {"1", "4688"}
        and RANSOM_TERMS.search(combined_text(row))
    ]
    process_rows.sort(key=lambda r: (r["timestamp"], r["computer"], r["record_id"]))

    lb3_rows = [
        row for row in process_rows
        if re.search(r"(?i)(?:^|[\\/])lb3\.exe$", clean(row["image"]))
        or re.search(r"(?i)\blb3\.exe\b", clean(row["command_line"]))
    ]

    write_tsv(
        args.output_dir / "verification-ransomware-processes.tsv",
        EVENT_EXPORT_HEADER,
        (event_export_row(row) for row in process_rows),
    )

    # Parent/self/child process chain for each LB3 instance.
    all_processes = [
        row for row in all_events
        if (row["source"] == "sysmon" and row["event_id"] == "1")
        or (row["source"] == "security" and row["event_id"] == "4688")
    ]

    chain_rows: list[list[Any]] = []
    seen_chain: set[tuple[str, str, str, str]] = set()

    for lb3 in lb3_rows:
        logical_host = host_key(lb3["computer"])
        lb3_guid = clean(lb3["process_guid"])
        parent_guid = clean(lb3["parent_process_guid"])

        for candidate in all_processes:
            if host_key(candidate["computer"]) != logical_host:
                continue

            relation = ""
            if (
                parent_guid
                and clean(candidate["process_guid"]).lower() == parent_guid.lower()
            ):
                relation = "parent"
            elif (
                lb3_guid
                and clean(candidate["process_guid"]).lower() == lb3_guid.lower()
            ):
                relation = "lb3_process"
            elif (
                lb3_guid
                and clean(candidate["parent_process_guid"]).lower() == lb3_guid.lower()
            ):
                relation = "child"

            if not relation:
                continue

            key = (
                relation,
                clean(candidate["computer"]),
                clean(candidate["event_id"]),
                clean(candidate["record_id"]),
            )
            if key in seen_chain:
                continue
            seen_chain.add(key)
            chain_rows.append([relation, *event_export_row(candidate)])

    chain_rows.sort(key=lambda row: (row[1], row[0]))
    write_tsv(
        args.output_dir / "verification-process-chain.tsv",
        ["relation", *EVENT_EXPORT_HEADER],
        chain_rows,
    )

    # File impact tied directly to LB3 ProcessGuid.
    lb3_guids = {clean(row["process_guid"]).lower() for row in lb3_rows if clean(row["process_guid"])}
    lb3_hosts = {host_key(row["computer"]) for row in lb3_rows}

    lb3_files = [
        row for row in all_events
        if clean(row["process_guid"]).lower() in lb3_guids
        and row["event_id"] in {"2", "11", "15", "23", "26", "4663"}
    ]
    lb3_files.sort(key=lambda r: (r["timestamp"], r["target_filename"], r["record_id"]))

    write_tsv(
        args.output_dir / "verification-file-impact.tsv",
        EVENT_EXPORT_HEADER,
        (event_export_row(row) for row in lb3_files),
    )

    operation_counts = Counter(clean(row["operation"]) or f"event_id_{row['event_id']}" for row in lb3_files)
    paths = [
        clean(row["target_filename"] or row["object_name"])
        for row in lb3_files
        if clean(row["target_filename"] or row["object_name"])
    ]
    basename_counts = Counter(basename_windows(path) for path in paths)
    extension_counts = Counter(extension_windows(path) for path in paths)
    directories = {dirname_windows(path) for path in paths}

    write_tsv(
        args.output_dir / "verification-file-name-summary.tsv",
        ["file_name", "event_count"],
        basename_counts.most_common(),
    )
    write_tsv(
        args.output_dir / "verification-file-extension-summary.tsv",
        ["extension", "event_count"],
        extension_counts.most_common(),
    )

    # Ten-minute lead-up and two-minute follow-up around LB3.
    lb3_times = [parse_timestamp(row["timestamp"]) for row in lb3_rows]
    lb3_times = [item for item in lb3_times if item is not None]
    lead_start = min(lb3_times) - timedelta(minutes=10) if lb3_times else None
    lead_end = max(lb3_times) + timedelta(minutes=2) if lb3_times else None

    leadup_rows: list[dict[str, Any]] = []
    if lead_start and lead_end:
        for row in all_processes:
            timestamp = parse_timestamp(row["timestamp"])
            if timestamp is None:
                continue
            if host_key(row["computer"]) not in lb3_hosts:
                continue
            if lead_start <= timestamp <= lead_end:
                leadup_rows.append(row)

    leadup_rows.sort(key=lambda r: (r["timestamp"], r["record_id"]))
    write_tsv(
        args.output_dir / "verification-lb3-leadup-processes.tsv",
        EVENT_EXPORT_HEADER,
        (event_export_row(row) for row in leadup_rows),
    )

    # Recovery and defence candidates: require command-bearing or executable evidence.
    verification_candidates: list[tuple[str, dict[str, Any]]] = []
    for row in all_events:
        text = combined_text(row)
        category = ""
        if RECOVERY_TERMS.search(text):
            category = "recovery_inhibition_candidate"
        elif DEFENCE_TERMS.search(text):
            category = "defence_evasion_candidate"
        if not category:
            continue

        # Suppress keyword-only hits from group names and routine authentication.
        command_bearing = (
            row["event_id"] in {"1", "4688", "4103", "4104"}
            or bool(clean(row["command_line"]))
            or bool(RECOVERY_TERMS.search(clean(row["image"])))
            or bool(DEFENCE_TERMS.search(clean(row["image"])))
        )
        if command_bearing:
            verification_candidates.append((category, row))

    verification_candidates.sort(key=lambda item: (item[1]["timestamp"], item[0]))

    write_tsv(
        args.output_dir / "verification-recovery-defence.tsv",
        ["verification_category", *EVENT_EXPORT_HEADER],
        ([category, *event_export_row(row)] for category, row in verification_candidates),
    )

    # Network events on high-signal ports, plus all LB3-host network events in the lead-up window.
    network_rows: list[dict[str, Any]] = []
    for row in all_events:
        if row["source"] != "sysmon" or row["event_id"] != "3":
            continue
        timestamp = parse_timestamp(row["timestamp"])
        in_lb3_window = (
            lead_start is not None
            and lead_end is not None
            and timestamp is not None
            and host_key(row["computer"]) in lb3_hosts
            and lead_start - timedelta(hours=2) <= timestamp <= lead_end
        )
        if clean(row["destination_port"]) in SUSPICIOUS_PORTS or in_lb3_window:
            network_rows.append(row)

    network_rows.sort(key=lambda r: (r["timestamp"], r["record_id"]))
    write_tsv(
        args.output_dir / "verification-network.tsv",
        EVENT_EXPORT_HEADER,
        (event_export_row(row) for row in network_rows),
    )

    # Authentication in the two-hour period before LB3 on the same logical host.
    auth_rows: list[dict[str, Any]] = []
    if lead_start and lead_end:
        auth_start = lead_start - timedelta(hours=2)
        for row in all_events:
            if row["source"] != "security" or row["event_id"] not in {"4624", "4625", "4648", "4672", "4776"}:
                continue
            if host_key(row["computer"]) not in lb3_hosts:
                continue
            timestamp = parse_timestamp(row["timestamp"])
            if timestamp is None or not (auth_start <= timestamp <= lead_end):
                continue
            data = parse_data(row["data_json"])
            ip_value = clean(row["source_ip"]) or data.get("IpAddress", "")
            logon_type = data.get("LogonType", "")
            if row["event_id"] in {"4648", "4625"} or (ip_value and ip_value not in {"-", "::1", "127.0.0.1"}) or logon_type in {"3", "10"}:
                auth_rows.append(row)

    auth_rows.sort(key=lambda r: (r["timestamp"], r["record_id"]))
    write_tsv(
        args.output_dir / "verification-authentication.tsv",
        EVENT_EXPORT_HEADER,
        (event_export_row(row) for row in auth_rows),
    )

    # Collection/transfer candidates, excluding pure tag noise.
    exfil_rows: list[dict[str, Any]] = []
    for row in all_events:
        text = combined_text(row)
        if not EXFIL_TERMS.search(text):
            continue
        if row["event_id"] in {"1", "4688", "4103", "4104"} or clean(row["command_line"]):
            exfil_rows.append(row)

    exfil_rows.sort(key=lambda r: (r["timestamp"], r["record_id"]))
    write_tsv(
        args.output_dir / "verification-exfiltration-candidates.tsv",
        EVENT_EXPORT_HEADER,
        (event_export_row(row) for row in exfil_rows),
    )

    # Compact report.
    report_path = args.output_dir / "compact-verification.txt"
    with report_path.open("w", encoding="utf-8", newline="\n") as report:
        report.write("=== Scenario 14 Precise Verification ===\n\n")
        report.write(f"database={args.db}\n")
        report.write(f"total_events={total_events}\n")
        report.write(f"logical_hosts={len(aliases)}\n")
        for logical_host, values in sorted(aliases.items()):
            report.write(
                f"host={logical_host} aliases="
                f"{';'.join(f'{name}:{count}' for name, count in values.most_common())}\n"
            )

        report.write("\n=== LB3 process ===\n")
        report.write(f"lb3_process_event_count={len(lb3_rows)}\n")
        for row in lb3_rows:
            data = parse_data(row["data_json"])
            report.write(
                " | ".join([
                    f"time={row['timestamp']}",
                    f"host={row['computer']}",
                    f"record_id={row['record_id']}",
                    f"account={row['account']}",
                    f"logon_id={row['logon_id']}",
                    f"process_guid={row['process_guid']}",
                    f"pid={row['process_id']}",
                    f"image={row['image']}",
                    f"command={preview(row['command_line'], 300)}",
                    f"parent_guid={row['parent_process_guid']}",
                    f"parent_image={row['parent_image']}",
                    f"parent_command={preview(row['parent_command_line'], 300)}",
                    f"integrity={data.get('IntegrityLevel', '')}",
                    f"hashes={data.get('Hashes', '')}",
                ]) + "\n"
            )

        report.write("\n=== Process chain ===\n")
        report.write(f"chain_rows={len(chain_rows)}\n")
        for row in chain_rows[:40]:
            report.write(
                f"relation={row[0]} | time={row[1]} | host={row[2]} | "
                f"event_id={row[4]} | record_id={row[5]} | account={row[6]} | "
                f"process_guid={row[9]} | pid={row[10]} | image={row[13]} | "
                f"command={preview(row[14], 260)} | parent_guid={row[11]} | "
                f"parent_image={row[15]}\n"
            )

        report.write("\n=== LB3-linked file activity ===\n")
        report.write(f"file_event_count={len(lb3_files)}\n")
        report.write(f"unique_path_count={len(set(paths))}\n")
        report.write(f"unique_directory_count={len(directories)}\n")
        report.write(
            "operation_counts=" +
            ";".join(f"{key}:{value}" for key, value in operation_counts.most_common()) +
            "\n"
        )
        report.write(
            "extension_counts=" +
            ";".join(f"{key}:{value}" for key, value in extension_counts.most_common()) +
            "\n"
        )
        report.write(
            "top_file_names=" +
            ";".join(f"{key}:{value}" for key, value in basename_counts.most_common(20)) +
            "\n"
        )
        report.write("sample_paths:\n")
        for path in sorted(set(paths))[:30]:
            report.write(f"  {path}\n")

        report.write("\n=== Recovery and defence ===\n")
        recovery_count = sum(1 for category, _ in verification_candidates if category.startswith("recovery"))
        defence_count = sum(1 for category, _ in verification_candidates if category.startswith("defence"))
        report.write(f"command_bearing_recovery_candidates={recovery_count}\n")
        report.write(f"command_bearing_defence_candidates={defence_count}\n")
        for category, row in verification_candidates[:80]:
            report.write(
                f"category={category} | time={row['timestamp']} | host={row['computer']} | "
                f"source={row['source']} | event_id={row['event_id']} | record_id={row['record_id']} | "
                f"account={row['account']} | image={row['image']} | "
                f"command={preview(row['command_line'], 300)} | "
                f"message={preview(row['message'], 300)}\n"
            )

        report.write("\n=== Network ===\n")
        report.write(f"verification_network_rows={len(network_rows)}\n")
        port_counts = Counter(clean(row["destination_port"]) or "<none>" for row in network_rows)
        report.write(
            "destination_port_counts=" +
            ";".join(f"{key}:{value}" for key, value in port_counts.most_common()) +
            "\n"
        )
        for row in network_rows[:80]:
            report.write(
                f"time={row['timestamp']} | host={row['computer']} | account={row['account']} | "
                f"process_guid={row['process_guid']} | image={row['image']} | "
                f"src={row['source_ip']}:{row['source_port']} | "
                f"dst={row['destination_ip']}:{row['destination_port']} | "
                f"record_id={row['record_id']}\n"
            )

        report.write("\n=== Authentication ===\n")
        report.write(f"verification_auth_rows={len(auth_rows)}\n")
        auth_counter = Counter()
        for row in auth_rows:
            data = parse_data(row["data_json"])
            auth_counter[
                (
                    row["event_id"],
                    row["account"],
                    data.get("LogonType", ""),
                    row["source_ip"] or data.get("IpAddress", ""),
                )
            ] += 1
        for key, count in auth_counter.most_common(40):
            report.write(
                f"event_id={key[0]} | account={key[1]} | logon_type={key[2]} | "
                f"source_ip={key[3]} | count={count}\n"
            )

        report.write("\n=== Exfiltration candidates ===\n")
        report.write(f"command_bearing_collection_or_transfer_candidates={len(exfil_rows)}\n")
        for row in exfil_rows[:50]:
            report.write(
                f"time={row['timestamp']} | host={row['computer']} | source={row['source']} | "
                f"event_id={row['event_id']} | image={row['image']} | "
                f"command={preview(row['command_line'], 300)} | "
                f"message={preview(row['message'], 300)}\n"
            )

        report.write("\n=== Evidence-status guardrails ===\n")
        delete_count = sum(
            count for operation, count in operation_counts.items()
            if "delete" in operation.lower()
        )
        report.write(
            "- LB3-linked file creation is directly observed only when the file rows share the LB3 ProcessGuid.\n"
        )
        if paths and len(directories) >= 20:
            report.write(
                "- Distribution of similarly named text files across many directories is consistent with ransom-note placement.\n"
            )
        report.write(
            "- Ransom-note placement does not independently prove that pre-existing file content was encrypted.\n"
        )
        report.write(f"- LB3-linked delete_event_count={delete_count}.\n")
        report.write(
            "- Dedicated rename telemetry and file-content entropy are not present in this dataset.\n"
        )
        report.write(
            "- Recovery-inhibition commands remain execution attempts unless outcome telemetry independently confirms success.\n"
        )
        report.write(
            "- Network and authentication evidence must agree before remote movement is classified as confirmed.\n"
        )
        report.write(
            "- Collection or transfer-tool execution does not independently prove data exfiltration.\n"
        )

    conn.close()
    print(f"Precise verification written to: {report_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
