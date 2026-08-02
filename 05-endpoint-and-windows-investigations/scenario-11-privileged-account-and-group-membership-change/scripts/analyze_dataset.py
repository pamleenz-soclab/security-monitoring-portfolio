#!/usr/bin/env python3
"""Profile Splunk T1136.001 data and extract a sanitised Scenario 11 chain."""

from __future__ import annotations

import argparse
import base64
import collections
import csv
import hashlib
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path


DATASET_ID = "cc9b25e2-efc9-11eb-926b-550bf0943fbb"
TARGET = r"ATTACKRANGE\T1136.001_Admin"
TARGET_NAME = "T1136.001_Admin"
ACTOR = r"ATTACKRANGE\Administrator"
PRIMARY_HOST = "win-dc-7216619.attackrange.local"
SECURITY_TIMESTAMP = re.compile(
    r"(?m)^(\d{2}/\d{2}/\d{4} \d{2}:\d{2}:\d{2} [AP]M)$"
)
EVENT_NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"


@dataclass
class SecurityRecord:
    timestamp: datetime
    event_id: str
    record_id: str
    computer: str
    text: str


@dataclass
class SysmonRecord:
    timestamp: str
    event_id: str
    record_id: str
    computer: str
    channel: str
    data: dict[str, str]


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def parse_security(path: Path) -> list[SecurityRecord]:
    text = path.read_text(encoding="utf-8", errors="replace")
    starts = list(SECURITY_TIMESTAMP.finditer(text))
    records: list[SecurityRecord] = []
    for index, match in enumerate(starts):
        end = starts[index + 1].start() if index + 1 < len(starts) else len(text)
        block = text[match.start() : end]
        event_id = re.search(r"(?m)^EventCode=(\d+)$", block)
        record_id = re.search(r"(?m)^RecordNumber=(\d+)$", block)
        computer = re.search(r"(?m)^ComputerName=(.+)$", block)
        if not (event_id and record_id and computer):
            continue
        records.append(
            SecurityRecord(
                timestamp=datetime.strptime(match.group(1), "%m/%d/%Y %I:%M:%S %p"),
                event_id=event_id.group(1),
                record_id=record_id.group(1),
                computer=computer.group(1).strip(),
                text=block,
            )
        )
    return records


def parse_sysmon(path: Path) -> list[SysmonRecord]:
    records: list[SysmonRecord] = []
    with path.open(encoding="utf-8", errors="replace") as handle:
        for line in handle:
            root = ET.fromstring(line)
            system = root.find(EVENT_NS + "System")
            event_data = root.find(EVENT_NS + "EventData")
            if system is None or event_data is None:
                continue
            values = {
                item.attrib.get("Name", ""): (item.text or "") for item in event_data
            }
            records.append(
                SysmonRecord(
                    timestamp=system.find(EVENT_NS + "TimeCreated").attrib["SystemTime"],
                    event_id=system.findtext(EVENT_NS + "EventID", default=""),
                    record_id=system.findtext(EVENT_NS + "EventRecordID", default=""),
                    computer=system.findtext(EVENT_NS + "Computer", default=""),
                    channel=system.findtext(EVENT_NS + "Channel", default=""),
                    data=values,
                )
            )
    return records


def section(block: str, heading: str) -> str:
    match = re.search(
        rf"(?ms)^{re.escape(heading)}:\s*\n(.*?)(?=^[A-Za-z][A-Za-z ]+:\s*$|^\d{{2}}/\d{{2}}/\d{{4}}|\Z)",
        block,
    )
    return match.group(1) if match else ""


def label(text: str, name: str) -> str:
    match = re.search(rf"(?m)^\s*{re.escape(name)}:\s*(.+?)\s*$", text)
    return match.group(1).strip() if match else ""


def security_find(
    records: list[SecurityRecord], event_id: str, contains: str = "", logon_id: str = ""
) -> SecurityRecord:
    candidates = [record for record in records if record.event_id == event_id]
    if contains:
        candidates = [record for record in candidates if contains in record.text]
    if logon_id:
        candidates = [record for record in candidates if logon_id.lower() in record.text.lower()]
    if not candidates:
        raise RuntimeError(f"Expected Security event {event_id} was not found")
    return min(candidates, key=lambda item: int(item.record_id))


def redact(command: str) -> str:
    return re.sub(
        rf'(?i)(net1?\s+user\s+/add\s+"?{re.escape(TARGET_NAME)}"?\s+)"[^"]+"',
        r'\1"[REDACTED-LAB-PASSWORD]"',
        command,
    )


def decode_parent_command(command: str) -> str:
    match = re.search(r"-encodedcommand\s+([A-Za-z0-9+/=]+)", command, re.IGNORECASE)
    if not match:
        return ""
    return base64.b64decode(match.group(1)).decode("utf-16le", errors="replace").strip()


def iso_security(value: datetime) -> str:
    return value.strftime("%Y-%m-%dT%H:%M:%S") + "Z (UTC inferred)"


def write_csv(path: Path, fieldnames: list[str], rows: list[dict[str, object]]) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--metadata", type=Path, required=True)
    parser.add_argument("--security", type=Path, required=True)
    parser.add_argument("--sysmon", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()

    args.output_dir.mkdir(parents=True, exist_ok=True)
    security = parse_security(args.security)
    sysmon = parse_sysmon(args.sysmon)
    if len(security) != 5494 or len(sysmon) != 6386:
        raise RuntimeError("Record count differs from the profiled source artifacts")

    security_counts = collections.Counter(item.event_id for item in security)
    sysmon_counts = collections.Counter(item.event_id for item in sysmon)
    security_hosts = sorted({item.computer for item in security})
    sysmon_hosts = sorted({item.computer for item in sysmon})

    profile_rows = [
        {
            "dataset_id": DATASET_ID,
            "artifact": args.metadata.name,
            "source_type": "Splunk dataset metadata",
            "size_bytes": args.metadata.stat().st_size,
            "sha256": sha256(args.metadata),
            "record_count": "1 metadata document",
            "earliest_timestamp": "2020-10-09",
            "latest_timestamp": "2020-10-09",
            "timezone": "Not applicable",
            "host_coverage": "Attack Range metadata",
            "event_id_coverage": "T1136.001 test definition",
            "identity_field_coverage": "Dataset author, ID, environment, technique, source paths",
            "limitations": "No ticket, approval, or business-change context",
        },
        {
            "dataset_id": DATASET_ID,
            "artifact": args.security.name,
            "source_type": "Windows Security rendered text",
            "size_bytes": args.security.stat().st_size,
            "sha256": sha256(args.security),
            "record_count": len(security),
            "earliest_timestamp": min(item.timestamp for item in security).isoformat(),
            "latest_timestamp": max(item.timestamp for item in security).isoformat(),
            "timezone": "Not explicit; UTC inferred by exact match with Sysmon UTC seconds",
            "host_coverage": ";".join(security_hosts),
            "event_id_coverage": ";".join(sorted(security_counts, key=int)),
            "identity_field_coverage": "Subject/New Logon/Target/Member/Group names and domains; Logon ID; record number",
            "limitations": "Numeric SIDs resolved to names; no Directory Object ID/DN; source IP is '-' for actor session",
        },
        {
            "dataset_id": DATASET_ID,
            "artifact": args.sysmon.name,
            "source_type": "Sysmon Operational XML",
            "size_bytes": args.sysmon.stat().st_size,
            "sha256": sha256(args.sysmon),
            "record_count": len(sysmon),
            "earliest_timestamp": min(item.timestamp for item in sysmon),
            "latest_timestamp": max(item.timestamp for item in sysmon),
            "timezone": "UTC (source SystemTime/UtcTime)",
            "host_coverage": ";".join(sysmon_hosts),
            "event_id_coverage": ";".join(sorted(sysmon_counts, key=int)),
            "identity_field_coverage": "User, LogonId/LogonGuid, ProcessGuid, PID, parent PID/image/command line",
            "limitations": "One-host Sysmon coverage; raw command lines contain a static lab password",
        },
    ]
    write_csv(
        args.output_dir / "dataset-profile.csv",
        list(profile_rows[0]),
        profile_rows,
    )

    count_rows = [
        {"source": "Windows Security", "event_id": event_id, "count": count}
        for event_id, count in sorted(security_counts.items(), key=lambda item: int(item[0]))
    ] + [
        {"source": "Sysmon", "event_id": event_id, "count": count}
        for event_id, count in sorted(sysmon_counts.items(), key=lambda item: int(item[0]))
    ]
    write_csv(args.output_dir / "event-id-counts.csv", ["source", "event_id", "count"], count_rows)

    create = security_find(security, "4720", TARGET_NAME)
    actor_logon_id = label(section(create.text, "Subject"), "Logon ID")
    lifecycle = {
        event_id: security_find(security, event_id, TARGET_NAME)
        for event_id in ("4720", "4722", "4724", "4738", "4732", "4726")
    }
    actor_logon = security_find(security, "4624", ACTOR, actor_logon_id)
    actor_special = security_find(security, "4672", ACTOR, actor_logon_id)
    delete = lifecycle["4726"]
    cleanup_logon_id = label(section(delete.text, "Subject"), "Logon ID")
    cleanup_logon = security_find(security, "4624", ACTOR, cleanup_logon_id)
    cleanup_special = security_find(security, "4672", ACTOR, cleanup_logon_id)
    group_changed_candidates = [
        item
        for item in security
        if item.event_id == "4735"
        and actor_logon_id.lower() in item.text.lower()
        and "Administrators" in item.text
    ]
    group_changed = min(group_changed_candidates, key=lambda item: int(item.record_id))

    target_processes = [
        item
        for item in sysmon
        if item.event_id == "1"
        and TARGET_NAME in " ".join(item.data.values())
        and item.data.get("User") == ACTOR
    ]
    process_by_record = {item.record_id: item for item in target_processes}

    timeline_rows: list[dict[str, object]] = []

    def add_security(
        sequence: int,
        record: SecurityRecord,
        action: str,
        actor: str,
        target: str,
        group: str,
        logon_id: str,
        result: str,
        correlation: str,
    ) -> None:
        timeline_rows.append(
            {
                "sequence": sequence,
                "timestamp": iso_security(record.timestamp),
                "source": "Windows Security",
                "event_id": record.event_id,
                "event_record_id": record.record_id,
                "computer": record.computer,
                "actor": actor,
                "actor_logon_id": logon_id,
                "target": target,
                "group_or_role": group,
                "process_guid": "",
                "pid": "",
                "parent_pid": "",
                "action": action,
                "result": result,
                "correlation_basis": correlation,
            }
        )

    def add_sysmon(sequence: int, record_id: str, action: str) -> None:
        item = process_by_record[record_id]
        timeline_rows.append(
            {
                "sequence": sequence,
                "timestamp": item.data.get("UtcTime", item.timestamp) + "Z",
                "source": "Sysmon Operational",
                "event_id": item.event_id,
                "event_record_id": item.record_id,
                "computer": item.computer,
                "actor": item.data.get("User", ""),
                "actor_logon_id": item.data.get("LogonId", ""),
                "target": TARGET,
                "group_or_role": "BUILTIN\\Administrators" if "localgroup" in item.data.get("CommandLine", "").lower() else "",
                "process_guid": item.data.get("ProcessGuid", ""),
                "pid": item.data.get("ProcessId", ""),
                "parent_pid": item.data.get("ParentProcessId", ""),
                "action": action + "; command=" + redact(item.data.get("CommandLine", "")),
                "result": "Process created",
                "correlation_basis": "Same user and LogonId; exact target in command; ProcessGuid/parent process fields",
            }
        )

    add_security(1, actor_logon, "Actor network logon (Logon Type 3)", ACTOR, "", "", actor_logon_id, "Audit Success", "4624 New Logon ID equals later Subject Logon ID")
    add_security(2, actor_special, "Sensitive privileges assigned to actor session", ACTOR, "", "", actor_logon_id, "Audit Success", "4672 Logon ID equals actor 4624 and change SubjectLogonId")
    add_sysmon(3, "4277", "Atomic test launched cmd.exe")
    add_sysmon(4, "4291", "net.exe requested account creation")
    add_security(5, lifecycle["4720"], "Account created", ACTOR, TARGET, "", actor_logon_id, "Audit Success", "Same actor, Logon ID, host, target and command evidence")
    add_security(6, lifecycle["4722"], "Account enabled", ACTOR, TARGET, "", actor_logon_id, "Audit Success", "Same target and SubjectLogonId as 4720")
    add_security(7, lifecycle["4724"], "Password reset recorded", ACTOR, TARGET, "", actor_logon_id, "Audit Success", "Same target and SubjectLogonId; followed by 4738 Password Last Set")
    add_security(8, lifecycle["4738"], "Account attributes changed; password set and UAC 0x15 to 0x10", ACTOR, TARGET, "", actor_logon_id, "Audit Success", "Same target and SubjectLogonId")
    add_sysmon(9, "4317", "net.exe requested privileged group addition")
    add_sysmon(10, "4330", "net1.exe executed privileged group addition")
    add_security(11, lifecycle["4732"], "Member added to security-enabled local/domain-local group", ACTOR, TARGET, r"BUILTIN\Administrators", actor_logon_id, "Audit Success", "Member Security ID equals created target; same SubjectLogonId; exact net command")
    add_security(12, group_changed, "Administrators group changed (supplemental event)", ACTOR, "", r"BUILTIN\Administrators", actor_logon_id, "Audit Success", "Same host/channel, group, actor, Logon ID and adjacent RecordNumber")
    add_security(13, cleanup_logon, "Cleanup actor network logon (Logon Type 3)", ACTOR, "", "", cleanup_logon_id, "Audit Success", "4624 New Logon ID equals deletion SubjectLogonId")
    add_security(14, cleanup_special, "Sensitive privileges assigned to cleanup session", ACTOR, "", "", cleanup_logon_id, "Audit Success", "4672 Logon ID equals cleanup 4624 and deletion SubjectLogonId")
    add_sysmon(15, "4600", "Atomic cleanup launched cmd.exe")
    add_sysmon(16, "4614", "net.exe requested account deletion")
    add_sysmon(17, "4627", "net1.exe executed account deletion")
    add_security(18, lifecycle["4726"], "Account deleted", ACTOR, TARGET, "", cleanup_logon_id, "Audit Success", "Same cleanup Logon ID; exact target; corroborating net user /del process")

    timeline_fields = [
        "sequence",
        "timestamp",
        "source",
        "event_id",
        "event_record_id",
        "computer",
        "actor",
        "actor_logon_id",
        "target",
        "group_or_role",
        "process_guid",
        "pid",
        "parent_pid",
        "action",
        "result",
        "correlation_basis",
    ]
    write_csv(args.output_dir / "privilege-change-timeline.csv", timeline_fields, timeline_rows)

    target_security_ids = collections.Counter(
        item.event_id for item in security if TARGET_NAME in item.text
    )
    target_user_processes = [item for item in sysmon if item.data.get("User") == TARGET]
    actor_source_ip = label(section(actor_logon.text, "Network Information"), "Source Network Address")
    coverage_rows = [
        {"category": "Actor identity", "status": "Available", "value": ACTOR, "basis": f"4624/4672 and change events; Logon ID {actor_logon_id}"},
        {"category": "Target identity", "status": "Available with limitation", "value": TARGET, "basis": "Name/domain resolved in 4720/4722/4724/4738/4732/4726; immutable numeric SID not present"},
        {"category": "Privileged group", "status": "Available", "value": r"BUILTIN\Administrators", "basis": "4732 plus Sysmon net localgroup command"},
        {"category": "Actor source IP", "status": "Not observed", "value": actor_source_ip or "-", "basis": "4624 field is present but empty/dash"},
        {"category": "Target successful or failed logon", "status": "Not observed", "value": "0", "basis": f"Target appears only in Security event types {','.join(sorted(target_security_ids, key=int))}; no 4624/4625"},
        {"category": "Target special privilege logon", "status": "Not observed", "value": "0", "basis": "No 4672 containing the target; observed 4672 events belong to Administrator sessions"},
        {"category": "Target explicit credential use", "status": "Not observed", "value": "0", "basis": "No 4648 containing the target"},
        {"category": "Target process execution", "status": "Not observed", "value": len(target_user_processes), "basis": "No Sysmon Event 1 with User equal to target"},
        {"category": "Explicit group-member removal", "status": "Not observed", "value": "No 4733", "basis": "Account deletion is confirmed separately by 4726"},
        {"category": "Ticket/approval/change window", "status": "Not available", "value": "", "basis": "Evidence category is absent from the public dataset"},
        {"category": "Directory Object ID/DN and immutable numeric SID", "status": "Not available", "value": "", "basis": "Rendered Security text resolves identities to names"},
        {"category": "Cross-host EDR/network follow-on", "status": "Not available", "value": "", "basis": "Selected Sysmon coverage is limited to the primary host"},
    ]
    write_csv(args.output_dir / "field-coverage.csv", ["category", "status", "value", "basis"], coverage_rows)

    create_cmd = process_by_record["4277"]
    cleanup_cmd = process_by_record["4600"]
    evidence_text = f"""# Sanitised key evidence — Scenario 11
# Source timestamps from Windows Security are timezone-unlabelled; UTC is inferred by exact alignment with Sysmon UTC.

[Actor session]
TimeCreated: {iso_security(actor_logon.timestamp)}
EventCode: 4624
EventRecordID/RecordNumber: {actor_logon.record_id}
Computer: {actor_logon.computer}
NewLogon.SecurityID: {ACTOR}
NewLogon.LogonID: {actor_logon_id} (decimal {int(actor_logon_id, 16)})
LogonType: {label(section(actor_logon.text, 'Logon Information'), 'Logon Type')}
SourceNetworkAddress: {actor_source_ip or '-'}

[Actor special privileges]
TimeCreated: {iso_security(actor_special.timestamp)}
EventCode: 4672
EventRecordID/RecordNumber: {actor_special.record_id}
Subject: {ACTOR}
SubjectLogonID: {actor_logon_id}
Interpretation: privileges belong to the actor session, not to the newly created target account.

[Atomic test process]
TimeCreated: {create_cmd.data.get('UtcTime')}Z
SysmonEventID: 1
EventRecordID: {create_cmd.record_id}
User: {create_cmd.data.get('User')}
LogonID: {create_cmd.data.get('LogonId')}
Image: {create_cmd.data.get('Image')}
ProcessGUID: {create_cmd.data.get('ProcessGuid')}
CommandLine: {redact(create_cmd.data.get('CommandLine', ''))}
DecodedParentCommand: {decode_parent_command(create_cmd.data.get('ParentCommandLine', ''))}

[Account lifecycle]
Event 4720 / Record {lifecycle['4720'].record_id}: {ACTOR} created {TARGET}; SubjectLogonID={actor_logon_id}
Event 4722 / Record {lifecycle['4722'].record_id}: target enabled; SubjectLogonID={actor_logon_id}
Event 4724 / Record {lifecycle['4724'].record_id}: password reset recorded with Audit Success; SubjectLogonID={actor_logon_id}
Event 4738 / Record {lifecycle['4738'].record_id}: Password Last Set updated; UAC 0x15 -> 0x10; SubjectLogonID={actor_logon_id}

[Privileged membership]
EventCode: 4732
EventRecordID/RecordNumber: {lifecycle['4732'].record_id}
Computer: {lifecycle['4732'].computer}
Subject: {ACTOR}
SubjectLogonID: {actor_logon_id}
Member.SecurityID: {TARGET}
Group.SecurityID: BUILTIN\\Administrators
Group.Name: Administrators
Group.Domain: Builtin
CorroboratingCommand: net localgroup administrators "{TARGET_NAME}" /add

[Cleanup]
TimeCreated: {cleanup_cmd.data.get('UtcTime')}Z
SysmonEventID: 1
EventRecordID: {cleanup_cmd.record_id}
User: {cleanup_cmd.data.get('User')}
LogonID: {cleanup_cmd.data.get('LogonId')} (decimal {int(cleanup_cmd.data.get('LogonId'), 16)})
ProcessGUID: {cleanup_cmd.data.get('ProcessGuid')}
CommandLine: {redact(cleanup_cmd.data.get('CommandLine', ''))}
DecodedParentCommand: {decode_parent_command(cleanup_cmd.data.get('ParentCommandLine', ''))}
Event 4726 / Record {lifecycle['4726'].record_id}: {TARGET} deleted by {ACTOR}; SubjectLogonID={cleanup_logon_id}

[Negative findings within selected telemetry]
Target 4624/4625: Not observed
Target 4648: Not observed
Target 4672: Not observed
Sysmon process with User={TARGET}: Not observed
Event 4733 explicit membership removal: Not observed
Ticket/approval/change-window data: Not available
Immutable numeric SID/Object ID/DN: Not available
"""
    (args.output_dir / "key-events-sanitized.log").write_text(evidence_text, encoding="utf-8")


if __name__ == "__main__":
    main()
