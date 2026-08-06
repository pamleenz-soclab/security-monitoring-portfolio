#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import re
import sqlite3
import sys
import xml.etree.ElementTree as ET
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from typing import Iterator

CONTROL_RE = re.compile(r"[\x00-\x08\x0B\x0C\x0E-\x1F]")
EVENT_START_RE = re.compile(r"<Event(?:\s|>)")
LONG_TOKEN_RE = re.compile(r"(?i)\b[A-Za-z0-9+/]{100,}={0,2}\b")

AUTH_IDS = {
    "4624", "4625", "4634", "4647", "4648", "4672",
    "4768", "4769", "4771", "4776"
}
SERVICE_TASK_IDS = {
    "4697", "4698", "4699", "4700", "4701", "4702", "7045"
}
FILE_IDS = {"2", "11", "15", "23", "26", "4663"}
NETWORK_IDS = {"3", "5140", "5145", "5156"}

RECOVERY_PATTERNS = [
    ("vssadmin", re.compile(r"(?i)\bvssadmin(?:\.exe)?\b")),
    ("shadowcopy", re.compile(r"(?i)\bshadow\s*copy\b|\bshadowcopy\b|\bwin32_shadowcopy\b")),
    ("wbadmin", re.compile(r"(?i)\bwbadmin(?:\.exe)?\b")),
    ("bcdedit", re.compile(r"(?i)\bbcdedit(?:\.exe)?\b")),
    ("reagentc", re.compile(r"(?i)\breagentc(?:\.exe)?\b")),
    ("diskshadow", re.compile(r"(?i)\bdiskshadow(?:\.exe)?\b")),
    ("recovery_disabled", re.compile(r"(?i)\brecoveryenabled\b|\bbootstatuspolicy\b|\bignoreallfailures\b")),
    ("backup_service", re.compile(
        r"(?i)\b(vss|swprv|wbengine|sqlwriter|veeam|backup|acronis|commvault|rubrik)\b"
    )),
]

DEFENCE_PATTERNS = [
    ("defender_setting", re.compile(
        r"(?i)\b(set|add)-mppreference\b|disablerealtimemonitoring|disablebehaviormonitoring|"
        r"disableioavprotection|exclusion(path|process|extension)"
    )),
    ("security_service_stop", re.compile(
        r"(?i)\b(win(defend|sense)|mpssvc|securityhealthservice|sysmon|edr|antivirus)\b"
    )),
    ("log_clear", re.compile(r"(?i)\bwevtutil(?:\.exe)?\b.*\bcl\b|\bclear-eventlog\b")),
    ("audit_change", re.compile(r"(?i)\bauditpol(?:\.exe)?\b|\bset-auditpolicy\b")),
    ("firewall_disable", re.compile(
        r"(?i)\bnetsh\b.*\bfirewall\b.*\b(off|disable)\b|"
        r"\bset-netfirewallprofile\b.*\benabled\s+\$?false\b"
    )),
    ("service_or_process_kill", re.compile(
        r"(?i)\b(taskkill|stop-process|stop-service|net\s+stop|sc(?:\.exe)?\s+stop)\b"
    )),
]

REMOTE_PATTERNS = [
    ("smb", re.compile(r"(?i)\\\\[^\\\s]+\\|\\admin\$|\\c\$|\b445\b|\bsmb\b|\bnet\s+use\b")),
    ("rdp", re.compile(r"(?i)\bmstsc(?:\.exe)?\b|\b3389\b|\brdp\b")),
    ("wmi", re.compile(r"(?i)\bwmic(?:\.exe)?\b|\bwin32_process\b|\binvoke-wmimethod\b|\bwmi\b")),
    ("winrm", re.compile(r"(?i)\bwinrm\b|\b5985\b|\b5986\b|\binvoke-command\b|\benter-pssession\b")),
    ("remote_service", re.compile(r"(?i)\bpsexec\b|\bpaexec\b|\bsc(?:\.exe)?\b\s+\\\\|\bservices\.exe\b")),
    ("remote_access_tool", re.compile(r"(?i)\b(anydesk|teamviewer|rustdesk|screenconnect|splashtop)\b")),
]

DISCOVERY_PATTERNS = [
    ("file_directory_discovery", re.compile(
        r"(?i)\b(dir|tree|findstr|where|Get-ChildItem|gci)\b"
    )),
    ("system_discovery", re.compile(
        r"(?i)\b(systeminfo|hostname|whoami|ipconfig|nltest|quser|qwinsta|net\s+(user|group|view|share))\b"
    )),
]

EXFIL_PATTERNS = [
    ("collection_or_staging", re.compile(
        r"(?i)\b(7z|rar|winrar|compress-archive|makecab|tar)\b"
    )),
    ("external_transfer_tool", re.compile(
        r"(?i)\b(rclone|winscp|megasync|azcopy|curl|wget|bitsadmin)\b"
    )),
]

RANSOM_PATTERNS = [
    ("ransomware_name_or_note", re.compile(
        r"(?i)\b(lockbit|ryuk|conti|blackcat|alphv|ransom|decrypt|restore-my-files|readme)\b"
    )),
]


def clean_text(value: object) -> str:
    if value is None:
        return ""
    text = str(value).replace("\x00", "")
    return " ".join(text.replace("\r", " ").replace("\n", " ").split())


def safe_preview(value: str, limit: int = 320) -> str:
    text = clean_text(value)
    text = LONG_TOKEN_RE.sub(lambda m: f"<LONG_ENCODED_TOKEN:{len(m.group(0))}>", text)
    return text if len(text) <= limit else text[:limit] + "...<TRUNCATED>"


def local_name(tag: str) -> str:
    return tag.split("}", 1)[-1] if "}" in tag else tag


def event_chunks(path: Path) -> Iterator[tuple[int, str]]:
    buffer = ""
    start_line = 0

    with path.open("r", encoding="utf-8-sig", errors="replace", newline="") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not buffer:
                match = EVENT_START_RE.search(line)
                if not match:
                    continue
                buffer = line[match.start():]
                start_line = line_number
            else:
                buffer += line

            while "</Event>" in buffer:
                end = buffer.find("</Event>") + len("</Event>")
                chunk = buffer[:end]
                yield start_line, chunk

                remainder = buffer[end:]
                match = EVENT_START_RE.search(remainder)
                if match:
                    buffer = remainder[match.start():]
                    start_line = line_number
                else:
                    buffer = ""
                    start_line = 0
                    break


def parse_event(source: str, source_file: str, source_line: int, xml_text: str) -> dict[str, str]:
    xml_text = CONTROL_RE.sub("", xml_text)
    root = ET.fromstring(xml_text)

    system = next((child for child in root if local_name(child.tag) == "System"), None)
    data_block = next((child for child in root if local_name(child.tag) == "EventData"), None)

    provider = ""
    event_id = ""
    timestamp = ""
    record_id = ""
    channel = ""
    computer = ""
    system_user_id = ""

    if system is not None:
        for child in system:
            name = local_name(child.tag)
            if name == "Provider":
                provider = child.attrib.get("Name", "")
            elif name == "EventID":
                event_id = clean_text(child.text)
            elif name == "TimeCreated":
                timestamp = child.attrib.get("SystemTime", "")
            elif name == "EventRecordID":
                record_id = clean_text(child.text)
            elif name == "Channel":
                channel = clean_text(child.text)
            elif name == "Computer":
                computer = clean_text(child.text)
            elif name == "Security":
                system_user_id = child.attrib.get("UserID", "")

    values: dict[str, list[str]] = defaultdict(list)

    if data_block is not None:
        for child in data_block:
            key = child.attrib.get("Name") or local_name(child.tag)
            value = "".join(child.itertext())
            values[key].append(value)

    # Capture structured UserData fields when EventData is absent or incomplete.
    for child in root:
        if local_name(child.tag) != "UserData":
            continue
        for descendant in child.iter():
            if descendant is child or len(descendant):
                continue
            key = local_name(descendant.tag)
            value = clean_text(descendant.text)
            if value:
                values[key].append(value)

    data = {key: " | ".join(clean_text(v) for v in vals if clean_text(v)) for key, vals in values.items()}

    def pick(*keys: str) -> str:
        for key in keys:
            if data.get(key):
                return data[key]
        return ""

    account = pick("User", "TargetUserName", "SubjectUserName", "AccountName", "MemberName")
    domain = pick("TargetDomainName", "SubjectDomainName", "DomainName")
    logon_id = pick("LogonId", "TargetLogonId", "SubjectLogonId")
    process_guid = pick("ProcessGuid")
    process_id = pick("ProcessId", "NewProcessId", "CallerProcessId")
    parent_process_guid = pick("ParentProcessGuid")
    parent_process_id = pick("ParentProcessId", "CreatorProcessId")
    image = pick("Image", "NewProcessName", "ProcessName", "Application")
    command_line = pick("CommandLine", "ProcessCommandLine", "HostApplication")
    parent_image = pick("ParentImage")
    parent_command_line = pick("ParentCommandLine")
    target_filename = pick("TargetFilename", "ObjectName", "RelativeTargetName")
    source_ip = pick("SourceIp", "IpAddress", "SourceAddress", "ClientAddress")
    source_port = pick("SourcePort", "IpPort", "ClientPort")
    destination_ip = pick("DestinationIp", "DestAddress", "DestinationAddress")
    destination_port = pick("DestinationPort", "DestPort")
    share_name = pick("ShareName")
    object_name = pick("ObjectName", "RelativeTargetName")
    service_name = pick("ServiceName")
    task_name = pick("TaskName")
    script_block_id = pick("ScriptBlockId")
    message = pick("ScriptBlockText", "Payload", "Message", "ContextInfo")

    operation = ""
    if source == "sysmon":
        operation = {
            "2": "file_creation_time_changed",
            "11": "file_create_or_overwrite_observed",
            "15": "file_stream_hash_observed",
            "23": "file_delete_archived",
            "26": "file_delete_detected",
        }.get(event_id, "")
    elif source == "security" and event_id == "4663":
        operation = "object_access_observed"

    combined = " ".join([
        image, command_line, parent_image, parent_command_line, target_filename,
        object_name, share_name, service_name, task_name, message,
        " ".join(data.values()),
    ])

    tags: set[str] = set()

    for name, pattern in RECOVERY_PATTERNS:
        if pattern.search(combined):
            tags.add(f"recovery_inhibition:{name}")

    for name, pattern in DEFENCE_PATTERNS:
        if pattern.search(combined):
            tags.add(f"defence_evasion:{name}")

    for name, pattern in REMOTE_PATTERNS:
        if pattern.search(combined):
            tags.add(f"remote_activity:{name}")

    for name, pattern in DISCOVERY_PATTERNS:
        if pattern.search(combined):
            tags.add(f"discovery:{name}")

    for name, pattern in EXFIL_PATTERNS:
        if pattern.search(combined):
            tags.add(f"exfiltration_candidate:{name}")

    for name, pattern in RANSOM_PATTERNS:
        if pattern.search(combined):
            tags.add(f"ransomware_indicator:{name}")

    if event_id in SERVICE_TASK_IDS:
        tags.add("service_or_task:event_id")
    if event_id in AUTH_IDS:
        tags.add("authentication:event_id")
    if event_id in NETWORK_IDS:
        tags.add("network_or_share:event_id")
    if event_id in FILE_IDS:
        tags.add("file_activity:event_id")

    # Port-driven remote service tags.
    if destination_port in {"445", "139"}:
        tags.add("remote_activity:smb_port")
    elif destination_port == "3389":
        tags.add("remote_activity:rdp_port")
    elif destination_port in {"5985", "5986"}:
        tags.add("remote_activity:winrm_port")
    elif destination_port == "135":
        tags.add("remote_activity:rpc_port")

    return {
        "source": source,
        "source_file": source_file,
        "source_line": str(source_line),
        "timestamp": timestamp,
        "provider": provider,
        "event_id": event_id,
        "record_id": record_id,
        "channel": channel,
        "computer": computer,
        "system_user_id": system_user_id,
        "account": account,
        "domain": domain,
        "logon_id": logon_id,
        "process_guid": process_guid,
        "process_id": process_id,
        "parent_process_guid": parent_process_guid,
        "parent_process_id": parent_process_id,
        "image": image,
        "command_line": command_line,
        "parent_image": parent_image,
        "parent_command_line": parent_command_line,
        "target_filename": target_filename,
        "operation": operation,
        "source_ip": source_ip,
        "source_port": source_port,
        "destination_ip": destination_ip,
        "destination_port": destination_port,
        "share_name": share_name,
        "object_name": object_name,
        "service_name": service_name,
        "task_name": task_name,
        "script_block_id": script_block_id,
        "message": message,
        "data_json": json.dumps(data, ensure_ascii=False, sort_keys=True),
        "tags": ";".join(sorted(tags)),
    }


COLUMNS = [
    "source", "source_file", "source_line", "timestamp", "provider", "event_id",
    "record_id", "channel", "computer", "system_user_id", "account", "domain",
    "logon_id", "process_guid", "process_id", "parent_process_guid",
    "parent_process_id", "image", "command_line", "parent_image",
    "parent_command_line", "target_filename", "operation", "source_ip",
    "source_port", "destination_ip", "destination_port", "share_name",
    "object_name", "service_name", "task_name", "script_block_id", "message",
    "data_json", "tags"
]


def write_tsv(path: Path, header: list[str], rows) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle, delimiter="\t", lineterminator="\n", quoting=csv.QUOTE_MINIMAL)
        writer.writerow(header)
        for row in rows:
            writer.writerow([clean_text(value) for value in row])


def extension_of(path_value: str) -> str:
    name = path_value.replace("/", "\\").rsplit("\\", 1)[-1]
    if "." not in name or name.endswith("."):
        return "<none>"
    return "." + name.rsplit(".", 1)[-1].lower()


def directory_of(path_value: str) -> str:
    normalized = path_value.replace("/", "\\")
    return normalized.rsplit("\\", 1)[0] if "\\" in normalized else "<none>"


def minute_of(timestamp: str) -> str:
    return timestamp[:16] + ":00Z" if len(timestamp) >= 16 else timestamp


def create_database(db_path: Path) -> sqlite3.Connection:
    if db_path.exists():
        db_path.unlink()
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    definitions = ", ".join(f'"{column}" TEXT' for column in COLUMNS)
    conn.execute(f"CREATE TABLE events (id INTEGER PRIMARY KEY AUTOINCREMENT, {definitions})")
    return conn


def insert_event(conn: sqlite3.Connection, event: dict[str, str]) -> None:
    placeholders = ",".join("?" for _ in COLUMNS)
    columns = ",".join(f'"{column}"' for column in COLUMNS)
    conn.execute(
        f"INSERT INTO events ({columns}) VALUES ({placeholders})",
        [event[column] for column in COLUMNS],
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--raw-dir", required=True, type=Path)
    parser.add_argument("--working-dir", required=True, type=Path)
    args = parser.parse_args()

    raw_dir = args.raw_dir
    working_dir = args.working_dir
    working_dir.mkdir(parents=True, exist_ok=True)

    sources = [
        ("sysmon", raw_dir / "windows-sysmon.log"),
        ("security", raw_dir / "windows-security.log"),
        ("powershell", raw_dir / "windows-powershell.log"),
    ]

    db_path = working_dir / "scenario14-events.sqlite"
    conn = create_database(db_path)

    parse_counts = Counter()
    parse_errors: list[tuple[str, str, str]] = []

    for source, path in sources:
        batch = 0
        for source_line, chunk in event_chunks(path):
            try:
                event = parse_event(source, path.name, source_line, chunk)
                insert_event(conn, event)
                parse_counts[source] += 1
                batch += 1
                if batch >= 1000:
                    conn.commit()
                    batch = 0
            except Exception as exc:
                parse_errors.append((path.name, str(source_line), f"{type(exc).__name__}: {exc}"))
        conn.commit()

    for sql in [
        "CREATE INDEX idx_events_timestamp ON events(timestamp)",
        "CREATE INDEX idx_events_host ON events(computer)",
        "CREATE INDEX idx_events_event_id ON events(event_id)",
        "CREATE INDEX idx_events_process_guid ON events(process_guid)",
        "CREATE INDEX idx_events_parent_guid ON events(parent_process_guid)",
        "CREATE INDEX idx_events_logon_id ON events(logon_id)",
        "CREATE INDEX idx_events_tags ON events(tags)",
    ]:
        conn.execute(sql)
    conn.commit()

    write_tsv(
        working_dir / "parse-errors.tsv",
        ["source_file", "source_line", "error"],
        parse_errors,
    )

    # Main event index.
    index_columns = [column for column in COLUMNS if column not in {"data_json", "message"}] + ["message_preview"]
    query_columns = [column for column in COLUMNS if column not in {"data_json", "message"}] + ["message"]
    rows = conn.execute(
        f'SELECT {",".join(f"""\"{c}\"""" for c in query_columns)} FROM events ORDER BY timestamp, id'
    )
    write_tsv(
        working_dir / "all-event-index.tsv",
        index_columns,
        ((*row[:-1], safe_preview(row[-1])) for row in rows),
    )

    # Event ID summary.
    rows = conn.execute(
        """
        SELECT source, provider, event_id, COUNT(*), MIN(timestamp), MAX(timestamp),
               COUNT(DISTINCT computer)
        FROM events
        GROUP BY source, provider, event_id
        ORDER BY source, COUNT(*) DESC, event_id
        """
    )
    write_tsv(
        working_dir / "event-id-summary.tsv",
        ["source", "provider", "event_id", "event_count", "first_seen", "last_seen", "host_count"],
        rows,
    )

    # Process events.
    rows = conn.execute(
        """
        SELECT timestamp, computer, source, event_id, record_id, account, domain,
               logon_id, process_guid, process_id, parent_process_guid,
               parent_process_id, image, command_line, parent_image,
               parent_command_line, system_user_id, tags
        FROM events
        WHERE (source='sysmon' AND event_id='1')
           OR (source='security' AND event_id='4688')
        ORDER BY timestamp, id
        """
    )
    write_tsv(
        working_dir / "process-events.tsv",
        [
            "timestamp", "computer", "source", "event_id", "record_id", "account",
            "domain", "logon_id", "process_guid", "process_id",
            "parent_process_guid", "parent_process_id", "image", "command_line",
            "parent_image", "parent_command_line", "system_user_id", "tags"
        ],
        rows,
    )

    # PowerShell events.
    rows = conn.execute(
        """
        SELECT timestamp, computer, event_id, record_id, account, process_id,
               script_block_id, command_line, message, tags
        FROM events
        WHERE source='powershell'
          AND event_id IN ('400','403','4103','4104')
        ORDER BY timestamp, id
        """
    )
    write_tsv(
        working_dir / "powershell-events.tsv",
        [
            "timestamp", "computer", "event_id", "record_id", "account",
            "process_id", "script_block_id", "host_application",
            "script_or_payload", "tags"
        ],
        rows,
    )

    # File events.
    file_rows = list(conn.execute(
        """
        SELECT timestamp, computer, event_id, record_id, account, process_guid,
               process_id, image, target_filename, object_name, operation, tags
        FROM events
        WHERE (source='sysmon' AND event_id IN ('2','11','15','23','26'))
           OR (source='security' AND event_id='4663')
        ORDER BY timestamp, id
        """
    ))
    write_tsv(
        working_dir / "file-events.tsv",
        [
            "timestamp", "computer", "event_id", "record_id", "account",
            "process_guid", "process_id", "image", "target_filename",
            "object_name", "operation", "tags"
        ],
        file_rows,
    )

    file_summary = defaultdict(lambda: {
        "count": 0, "first": "", "last": "", "files": set(), "extensions": set()
    })
    extension_summary = defaultdict(lambda: {
        "count": 0, "first": "", "last": "", "directories": set(), "images": set()
    })
    rate_summary = defaultdict(lambda: {
        "count": 0, "creates": 0, "deletes": 0, "time_changes": 0,
        "files": set(), "extensions": set()
    })
    scope_summary = defaultdict(lambda: {
        "count": 0, "creates": 0, "deletes": 0, "time_changes": 0,
        "files": set(), "directories": set(), "extensions": set(),
        "first": "", "last": ""
    })

    for row in file_rows:
        (
            timestamp, computer, event_id, record_id, account, process_guid,
            process_id, image, target_filename, object_name, operation, tags
        ) = row
        path_value = target_filename or object_name
        directory = directory_of(path_value) if path_value else "<none>"
        extension = extension_of(path_value) if path_value else "<none>"
        identity = process_guid or process_id or "<unknown>"

        key = (computer, identity, image, operation, directory)
        item = file_summary[key]
        item["count"] += 1
        item["first"] = item["first"] or timestamp
        item["last"] = timestamp
        if path_value:
            item["files"].add(path_value)
        item["extensions"].add(extension)

        ekey = (computer, extension, operation)
        eitem = extension_summary[ekey]
        eitem["count"] += 1
        eitem["first"] = eitem["first"] or timestamp
        eitem["last"] = timestamp
        eitem["directories"].add(directory)
        if image:
            eitem["images"].add(image)

        rkey = (minute_of(timestamp), computer, identity, image)
        ritem = rate_summary[rkey]
        ritem["count"] += 1
        if operation.startswith("file_create"):
            ritem["creates"] += 1
        elif "delete" in operation:
            ritem["deletes"] += 1
        elif "time_changed" in operation:
            ritem["time_changes"] += 1
        if path_value:
            ritem["files"].add(path_value)
        ritem["extensions"].add(extension)

        skey = (computer, identity, image)
        sitem = scope_summary[skey]
        sitem["count"] += 1
        if operation.startswith("file_create"):
            sitem["creates"] += 1
        elif "delete" in operation:
            sitem["deletes"] += 1
        elif "time_changed" in operation:
            sitem["time_changes"] += 1
        if path_value:
            sitem["files"].add(path_value)
        sitem["directories"].add(directory)
        sitem["extensions"].add(extension)
        sitem["first"] = sitem["first"] or timestamp
        sitem["last"] = timestamp

    write_tsv(
        working_dir / "file-activity-summary.tsv",
        [
            "computer", "process_identity", "image", "operation", "directory",
            "event_count", "unique_file_count", "extension_count",
            "extensions", "first_seen", "last_seen"
        ],
        (
            (
                *key, value["count"], len(value["files"]), len(value["extensions"]),
                ";".join(sorted(value["extensions"])), value["first"], value["last"]
            )
            for key, value in sorted(
                file_summary.items(),
                key=lambda item: (-item[1]["count"], item[0])
            )
        ),
    )

    write_tsv(
        working_dir / "extension-change-summary.tsv",
        [
            "computer", "extension", "operation", "event_count",
            "unique_directory_count", "image_count", "images",
            "first_seen", "last_seen", "rename_confirmed", "evidence_basis"
        ],
        (
            (
                *key, value["count"], len(value["directories"]), len(value["images"]),
                ";".join(sorted(value["images"])), value["first"], value["last"],
                "no", "extension observed in file event; no dedicated rename telemetry"
            )
            for key, value in sorted(
                extension_summary.items(),
                key=lambda item: (-item[1]["count"], item[0])
            )
        ),
    )

    write_tsv(
        working_dir / "file-rate-summary.tsv",
        [
            "minute_utc", "computer", "process_identity", "image",
            "file_event_count", "create_count", "delete_count", "time_change_count",
            "unique_file_count", "unique_extension_count", "extensions"
        ],
        (
            (
                *key, value["count"], value["creates"], value["deletes"],
                value["time_changes"], len(value["files"]), len(value["extensions"]),
                ";".join(sorted(value["extensions"]))
            )
            for key, value in sorted(
                rate_summary.items(),
                key=lambda item: (-item[1]["count"], item[0])
            )
        ),
    )

    write_tsv(
        working_dir / "impact-scope-summary.tsv",
        [
            "computer", "process_identity", "image", "file_event_count",
            "create_count", "delete_count", "time_change_count",
            "unique_file_count", "unique_directory_count", "unique_extension_count",
            "extensions", "first_seen", "last_seen", "impact_interpretation"
        ],
        (
            (
                *key, value["count"], value["creates"], value["deletes"],
                value["time_changes"], len(value["files"]), len(value["directories"]),
                len(value["extensions"]), ";".join(sorted(value["extensions"])),
                value["first"], value["last"],
                "observed file operations only; content encryption not independently confirmed"
            )
            for key, value in sorted(
                scope_summary.items(),
                key=lambda item: (-item[1]["count"], item[0])
            )
        ),
    )

    # Specialized candidate files.
    specialized = [
        (
            "recovery-inhibition-events.tsv",
            "tags LIKE '%recovery_inhibition:%'"
        ),
        (
            "defence-evasion-events.tsv",
            "tags LIKE '%defence_evasion:%'"
        ),
        (
            "service-and-task-events.tsv",
            "event_id IN ('4697','4698','4699','4700','4701','4702','7045') "
            "OR tags LIKE '%service_or_task:%'"
        ),
        (
            "authentication-events.tsv",
            "event_id IN ('4624','4625','4634','4647','4648','4672','4768','4769','4771','4776')"
        ),
        (
            "network-and-smb-events.tsv",
            "(source='sysmon' AND event_id='3') OR "
            "(source='security' AND event_id IN ('5140','5145','5156')) OR "
            "tags LIKE '%remote_activity:%'"
        ),
        (
            "suspicious-event-candidates.tsv",
            "tags <> '' AND tags NOT IN "
            "('authentication:event_id','file_activity:event_id','network_or_share:event_id')"
        ),
    ]
    specialized_header = [
        "timestamp", "computer", "source", "event_id", "record_id", "account",
        "domain", "logon_id", "process_guid", "process_id",
        "parent_process_guid", "parent_process_id", "image", "command_line",
        "parent_image", "target_filename", "operation", "source_ip",
        "source_port", "destination_ip", "destination_port", "share_name",
        "object_name", "service_name", "task_name", "script_block_id",
        "message_preview", "tags"
    ]
    select_fields = specialized_header[:-2] + ["message", "tags"]

    for filename, where_clause in specialized:
        rows = conn.execute(
            f"""
            SELECT {",".join(f'"{field}"' for field in select_fields)}
            FROM events
            WHERE {where_clause}
            ORDER BY timestamp, id
            """
        )
        write_tsv(
            working_dir / filename,
            specialized_header,
            ((*row[:-2], safe_preview(row[-2]), row[-1]) for row in rows),
        )

    # Host-account summary.
    rows = conn.execute(
        """
        SELECT computer, account, domain, source, COUNT(*), MIN(timestamp),
               MAX(timestamp), COUNT(DISTINCT NULLIF(logon_id,'')),
               COUNT(DISTINCT NULLIF(process_guid,''))
        FROM events
        GROUP BY computer, account, domain, source
        ORDER BY computer, COUNT(*) DESC, account
        """
    )
    write_tsv(
        working_dir / "host-account-summary.tsv",
        [
            "computer", "account", "domain", "source", "event_count",
            "first_seen", "last_seen", "distinct_logon_id_count",
            "distinct_process_guid_count"
        ],
        rows,
    )

    # Compact verification report.
    with (working_dir / "compact-first-pass.txt").open("w", encoding="utf-8", newline="\n") as out:
        out.write("=== Scenario 14 First-Pass Investigation Summary ===\n\n")
        out.write("=== Parse results ===\n")
        for source, _ in sources:
            out.write(f"{source}: parsed_events={parse_counts[source]}\n")
        out.write(f"parse_errors={len(parse_errors)}\n")
        out.write(f"total_events={sum(parse_counts.values())}\n\n")

        out.write("=== Source time ranges and host counts ===\n")
        for row in conn.execute(
            """
            SELECT source, COUNT(*), MIN(timestamp), MAX(timestamp),
                   COUNT(DISTINCT computer)
            FROM events GROUP BY source ORDER BY source
            """
        ):
            out.write(
                f"source={row[0]} events={row[1]} first={row[2]} "
                f"last={row[3]} hosts={row[4]}\n"
            )

        out.write("\n=== Hosts ===\n")
        for row in conn.execute(
            "SELECT computer, COUNT(*) FROM events GROUP BY computer ORDER BY COUNT(*) DESC"
        ):
            out.write(f"{row[0]}\t{row[1]}\n")

        out.write("\n=== Top event IDs by source ===\n")
        for source, _ in sources:
            out.write(f"[{source}]\n")
            for row in conn.execute(
                """
                SELECT event_id, COUNT(*) FROM events
                WHERE source=? GROUP BY event_id
                ORDER BY COUNT(*) DESC, event_id LIMIT 20
                """,
                (source,),
            ):
                out.write(f"event_id={row[0]} count={row[1]}\n")

        out.write("\n=== Candidate tag counts ===\n")
        tag_counts = Counter()
        for (tags_value,) in conn.execute("SELECT tags FROM events WHERE tags <> ''"):
            tag_counts.update(tag for tag in tags_value.split(";") if tag)
        for tag, count in tag_counts.most_common():
            out.write(f"{tag}\t{count}\n")

        out.write("\n=== File operation counts ===\n")
        for row in conn.execute(
            """
            SELECT operation, COUNT(*) FROM events
            WHERE operation <> ''
            GROUP BY operation ORDER BY COUNT(*) DESC
            """
        ):
            out.write(f"{row[0]}\t{row[1]}\n")

        out.write("\n=== Highest file-event rates per minute ===\n")
        for key, value in sorted(rate_summary.items(), key=lambda item: -item[1]["count"])[:30]:
            out.write(
                f"minute={key[0]} host={key[1]} process={key[2]} "
                f"image={safe_preview(key[3], 180)} events={value['count']} "
                f"creates={value['creates']} deletes={value['deletes']} "
                f"unique_files={len(value['files'])} "
                f"extensions={safe_preview(';'.join(sorted(value['extensions'])), 180)}\n"
            )

        out.write("\n=== Top observed file extensions ===\n")
        for key, value in sorted(extension_summary.items(), key=lambda item: -item[1]["count"])[:40]:
            out.write(
                f"host={key[0]} extension={key[1]} operation={key[2]} "
                f"count={value['count']} directories={len(value['directories'])} "
                f"images={safe_preview(';'.join(sorted(value['images'])), 200)}\n"
            )

        out.write("\n=== Authentication event counts ===\n")
        for row in conn.execute(
            """
            SELECT event_id, COUNT(*) FROM events
            WHERE source='security'
              AND event_id IN ('4624','4625','4634','4647','4648','4672','4768','4769','4771','4776')
            GROUP BY event_id ORDER BY event_id
            """
        ):
            out.write(f"event_id={row[0]} count={row[1]}\n")

        out.write("\n=== Destination port counts from Sysmon network events ===\n")
        for row in conn.execute(
            """
            SELECT destination_port, COUNT(*), COUNT(DISTINCT destination_ip)
            FROM events
            WHERE source='sysmon' AND event_id='3'
            GROUP BY destination_port
            ORDER BY COUNT(*) DESC LIMIT 30
            """
        ):
            out.write(f"port={row[0]} count={row[1]} distinct_destinations={row[2]}\n")

        out.write("\n=== Earliest high-signal candidate events ===\n")
        high_signal_clause = (
            "tags LIKE '%recovery_inhibition:%' OR "
            "tags LIKE '%defence_evasion:%' OR "
            "tags LIKE '%ransomware_indicator:%' OR "
            "tags LIKE '%remote_activity:%' OR "
            "tags LIKE '%exfiltration_candidate:%'"
        )
        for row in conn.execute(
            f"""
            SELECT timestamp, computer, source, event_id, record_id, account,
                   process_guid, process_id, image, command_line,
                   target_filename, source_ip, destination_ip,
                   destination_port, message, tags
            FROM events
            WHERE {high_signal_clause}
            ORDER BY timestamp, id
            LIMIT 120
            """
        ):
            out.write(
                " | ".join([
                    f"time={row[0]}", f"host={row[1]}", f"source={row[2]}",
                    f"event_id={row[3]}", f"record_id={row[4]}",
                    f"account={safe_preview(row[5], 80)}",
                    f"process_guid={row[6]}", f"pid={row[7]}",
                    f"image={safe_preview(row[8], 160)}",
                    f"command={safe_preview(row[9], 260)}",
                    f"target={safe_preview(row[10], 180)}",
                    f"src_ip={row[11]}", f"dst_ip={row[12]}",
                    f"dst_port={row[13]}",
                    f"message={safe_preview(row[14], 260)}",
                    f"tags={row[15]}",
                ]) + "\n"
            )

        out.write("\n=== Evidence limitations at first pass ===\n")
        out.write("- No Windows System log was supplied in the selected dataset.\n")
        out.write("- File events show observed operations, not file content or entropy.\n")
        out.write("- No dedicated file-rename telemetry has yet been identified.\n")
        out.write("- Command execution does not prove the command completed successfully.\n")
        out.write("- Network connections do not independently prove lateral movement or exfiltration.\n")
        out.write("- T1486 remains pending until file-impact evidence is correlated to the responsible process chain.\n")

    conn.close()

    print(f"Parsed total events: {sum(parse_counts.values())}")
    print(f"Parse errors: {len(parse_errors)}")
    print(f"SQLite index: {db_path}")
    print(f"Summary: {working_dir / 'compact-first-pass.txt'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
