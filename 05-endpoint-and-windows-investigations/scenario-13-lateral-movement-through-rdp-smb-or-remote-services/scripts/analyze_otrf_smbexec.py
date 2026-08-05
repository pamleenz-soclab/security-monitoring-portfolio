#!/usr/bin/env python3
"""Reproduce the Scenario 13 findings from the fixed OTRF SMBExec dataset.

The script uses only the Python standard library. It intentionally writes
sanitised, compact evidence summaries rather than copying raw event payloads.
"""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import hashlib
import json
import pathlib
import re
import socket
import struct
from collections import Counter, defaultdict
from typing import Any, Iterable


SOURCE_IP = "172.18.39.5"
TARGET_IP = "172.18.39.6"
DOMAIN_CONTROLLER_IP = "172.18.38.5"
C2_IP = "10.10.10.5"
SOURCE_HOST = "WORKSTATION5.theshire.local"
TARGET_HOST = "WORKSTATION6.theshire.local"
DOMAIN_CONTROLLER = "MORDORDC.theshire.local"
ACCOUNT = "pgustavo"
LOGON_ID = "0x2074186"
SERVICE_NAME = "PGUJLOAKFQFVOMHGFQPX"
SOURCE_PROCESS_GUID = "{b34bc01c-f6f9-5f66-b410-000000000400}"
TARGET_POWERSHELL_GUID = "{d273d0f0-fd6c-5f66-7605-000000000800}"
KEY_EVENT_IDS = {
    1,
    3,
    12,
    13,
    4103,
    4104,
    4624,
    4672,
    4688,
    4697,
    4776,
    5140,
    5145,
    7009,
    7045,
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host-json", type=pathlib.Path, required=True)
    parser.add_argument("--network-dir", type=pathlib.Path, required=True)
    parser.add_argument("--output-dir", type=pathlib.Path, required=True)
    return parser.parse_args()


def load_events(path: pathlib.Path) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise ValueError(f"Invalid JSON on line {line_number}: {exc}") from exc
    return events


def event_utc(event: dict[str, Any]) -> dt.datetime:
    """Normalise OTRF timestamps.

    Sysmon UtcTime is preferred. Other EventTime values in this capture are
    US Eastern Daylight Time (UTC-04:00) on 2020-09-20.
    """
    if event.get("UtcTime"):
        value = dt.datetime.strptime(event["UtcTime"], "%Y-%m-%d %H:%M:%S.%f")
        return value.replace(tzinfo=dt.timezone.utc)
    value = dt.datetime.strptime(event["EventTime"], "%Y-%m-%d %H:%M:%S")
    return value.replace(tzinfo=dt.timezone(dt.timedelta(hours=-4))).astimezone(
        dt.timezone.utc
    )


def iso(value: dt.datetime) -> str:
    return value.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def sanitise_command(value: str | None) -> str:
    if not value:
        return ""
    value = re.sub(
        r"(?i)(-enc(?:odedcommand)?\s+)[A-Za-z0-9+/=]+",
        r"\1<ENCODED_PAYLOAD_REDACTED>",
        value,
    )
    value = re.sub(
        r"(?i)(-Hash\s+)[0-9a-f]{32}",
        r"\1<DEMO_NTLM_HASH_REDACTED>",
        value,
    )
    return " ".join(value.split())


def write_csv(path: pathlib.Path, fieldnames: list[str], rows: Iterable[dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def select_one(events: list[dict[str, Any]], **values: Any) -> dict[str, Any]:
    matches = [event for event in events if all(event.get(k) == v for k, v in values.items())]
    if len(matches) != 1:
        raise AssertionError(f"Expected one event for {values}, found {len(matches)}")
    return matches[0]


def select_service_registry_events(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    needle = f"Services\\{SERVICE_NAME}".lower()
    return [
        event
        for event in events
        if event.get("Hostname") == TARGET_HOST
        and event.get("EventID") in (12, 13)
        and needle in str(event.get("TargetObject", "")).lower()
    ]


def pcap_packets(path: pathlib.Path) -> Iterable[dict[str, Any]]:
    with path.open("rb") as handle:
        global_header = handle.read(24)
        magic = global_header[:4]
        if magic == b"\xd4\xc3\xb2\xa1":
            endian, scale = "<", 1_000_000
        elif magic == b"\xa1\xb2\xc3\xd4":
            endian, scale = ">", 1_000_000
        elif magic == b"\x4d\x3c\xb2\xa1":
            endian, scale = "<", 1_000_000_000
        elif magic == b"\xa1\xb2\x3c\x4d":
            endian, scale = ">", 1_000_000_000
        else:
            raise ValueError(f"Unsupported PCAP magic in {path}: {magic.hex()}")

        frame = 0
        while True:
            packet_header = handle.read(16)
            if not packet_header:
                break
            if len(packet_header) != 16:
                raise ValueError(f"Truncated PCAP packet header in {path}")
            seconds, fraction, included_length, _ = struct.unpack(
                endian + "IIII", packet_header
            )
            data = handle.read(included_length)
            frame += 1
            packet: dict[str, Any] = {
                "frame": frame,
                "timestamp": dt.datetime.fromtimestamp(
                    seconds + fraction / scale, tz=dt.timezone.utc
                ),
                "length": included_length,
                "protocol": "OTHER",
                "payload": b"",
            }
            if len(data) < 14:
                yield packet
                continue
            ether_type = struct.unpack("!H", data[12:14])[0]
            offset = 14
            if ether_type == 0x8100 and len(data) >= 18:
                ether_type = struct.unpack("!H", data[16:18])[0]
                offset = 18
            if ether_type != 0x0800 or len(data) < offset + 20:
                yield packet
                continue
            header_length = (data[offset] & 0x0F) * 4
            ip_protocol = data[offset + 9]
            packet["source_ip"] = socket.inet_ntoa(data[offset + 12 : offset + 16])
            packet["destination_ip"] = socket.inet_ntoa(data[offset + 16 : offset + 20])
            transport_offset = offset + header_length
            if ip_protocol == 6 and len(data) >= transport_offset + 20:
                packet["protocol"] = "TCP"
                packet["source_port"], packet["destination_port"] = struct.unpack(
                    "!HH", data[transport_offset : transport_offset + 4]
                )
                tcp_header_length = ((data[transport_offset + 12] >> 4) & 0x0F) * 4
                packet["payload"] = data[transport_offset + tcp_header_length :]
            elif ip_protocol == 17 and len(data) >= transport_offset + 8:
                packet["protocol"] = "UDP"
                packet["source_port"], packet["destination_port"] = struct.unpack(
                    "!HH", data[transport_offset : transport_offset + 4]
                )
                packet["payload"] = data[transport_offset + 8 :]
            yield packet


def analyse_pcaps(paths: list[pathlib.Path]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    flows: dict[tuple[str, str, int, str, int, str], dict[str, Any]] = {}
    marker_rows: list[dict[str, Any]] = []
    markers = {
        "NTLMSSP": b"ntlmssp",
        "svcctl_named_pipe": "svcctl".encode("utf-16le").lower(),
        "random_service_name": SERVICE_NAME.encode("utf-16le").lower(),
    }
    for path in paths:
        for packet in pcap_packets(path):
            if "source_ip" not in packet or "source_port" not in packet:
                continue
            key = (
                path.name,
                packet["source_ip"],
                packet["source_port"],
                packet["destination_ip"],
                packet["destination_port"],
                packet["protocol"],
            )
            if key not in flows:
                flows[key] = {
                    "capture_file": path.name,
                    "source_ip": packet["source_ip"],
                    "source_port": packet["source_port"],
                    "destination_ip": packet["destination_ip"],
                    "destination_port": packet["destination_port"],
                    "protocol": packet["protocol"],
                    "packet_count": 0,
                    "first_seen_utc": packet["timestamp"],
                    "last_seen_utc": packet["timestamp"],
                }
            flow = flows[key]
            flow["packet_count"] += 1
            flow["first_seen_utc"] = min(flow["first_seen_utc"], packet["timestamp"])
            flow["last_seen_utc"] = max(flow["last_seen_utc"], packet["timestamp"])
            lower_payload = packet["payload"].lower()
            for marker_name, marker_value in markers.items():
                if marker_value in lower_payload:
                    marker_rows.append(
                        {
                            "capture_file": path.name,
                            "frame": packet["frame"],
                            "timestamp_utc": iso(packet["timestamp"]),
                            "source": f"{packet['source_ip']}:{packet['source_port']}",
                            "destination": f"{packet['destination_ip']}:{packet['destination_port']}",
                            "marker": marker_name,
                            "interpretation": {
                                "NTLMSSP": "NTLM authentication exchange over SMB",
                                "svcctl_named_pipe": "RPC access to the Service Control Manager named pipe",
                                "random_service_name": "Service-name bytes observed in the SMB/RPC stream",
                            }[marker_name],
                        }
                    )
    flow_rows: list[dict[str, Any]] = []
    for flow in flows.values():
        if not (
            flow["source_ip"] in {SOURCE_IP, TARGET_IP, C2_IP}
            and flow["destination_ip"] in {SOURCE_IP, TARGET_IP, C2_IP}
        ):
            continue
        flow_rows.append(
            {
                **flow,
                "first_seen_utc": iso(flow["first_seen_utc"]),
                "last_seen_utc": iso(flow["last_seen_utc"]),
            }
        )
    flow_rows.sort(key=lambda row: (row["capture_file"], row["first_seen_utc"], row["source_ip"]))
    marker_rows.sort(key=lambda row: (row["capture_file"], row["frame"]))
    return flow_rows, marker_rows


def summarise_pcaps(paths: list[pathlib.Path]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for path in paths:
        packet_count = 0
        tcp_445_packet_count = 0
        first_seen: dt.datetime | None = None
        last_seen: dt.datetime | None = None
        for packet in pcap_packets(path):
            packet_count += 1
            first_seen = packet["timestamp"] if first_seen is None else min(first_seen, packet["timestamp"])
            last_seen = packet["timestamp"] if last_seen is None else max(last_seen, packet["timestamp"])
            if packet.get("protocol") == "TCP" and 445 in {
                packet.get("source_port"),
                packet.get("destination_port"),
            }:
                tcp_445_packet_count += 1
        if first_seen is None or last_seen is None:
            raise AssertionError(f"Empty PCAP: {path}")
        rows.append(
            {
                "capture_file": path.name,
                "size_bytes": path.stat().st_size,
                "packet_count": packet_count,
                "tcp_445_packet_count": tcp_445_packet_count,
                "first_seen_utc": iso(first_seen),
                "last_seen_utc": iso(last_seen),
                "duration_seconds": f"{(last_seen - first_seen).total_seconds():.6f}",
            }
        )
    return rows


def main() -> None:
    args = parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)
    events = load_events(args.host_json)
    pcap_paths = sorted(args.network_dir.glob("*.cap"))
    if len(pcap_paths) != 2:
        raise AssertionError(f"Expected two PCAPs, found {len(pcap_paths)}")

    auth = select_one(events, Hostname=TARGET_HOST, EventID=4624)
    dc_validation = select_one(events, Hostname=DOMAIN_CONTROLLER, EventID=4776)
    privileged = select_one(events, Hostname=TARGET_HOST, EventID=4672)
    share = select_one(events, Hostname=TARGET_HOST, EventID=5140)
    pipe = select_one(events, Hostname=TARGET_HOST, EventID=5145)
    service_security = select_one(events, Hostname=TARGET_HOST, EventID=4697)
    service_system = select_one(events, Hostname=TARGET_HOST, EventID=7045)
    script_block = select_one(events, Hostname=TARGET_HOST, EventID=4104)
    service_registry = select_service_registry_events(events)

    assert auth["TargetUserName"] == ACCOUNT
    assert auth["TargetLogonId"] == LOGON_ID
    assert auth["LogonType"] == "3"
    assert auth["AuthenticationPackageName"] == "NTLM"
    assert auth["LmPackageName"] == "NTLM V2"
    assert auth["IpAddress"] == SOURCE_IP
    assert auth["WorkstationName"] == "WORKSTATION5"
    assert dc_validation["Status"] == "0x0"
    assert privileged["SubjectLogonId"] == LOGON_ID
    assert share["ShareName"].endswith("\\IPC$")
    assert pipe["RelativeTargetName"].lower() == "svcctl"
    assert pipe["SubjectLogonId"] == LOGON_ID
    assert service_security["ServiceName"] == SERVICE_NAME
    assert service_security["SubjectLogonId"] == LOGON_ID
    assert service_system["ServiceName"] == SERVICE_NAME
    assert len(service_registry) >= 8

    process_events = [
        event
        for event in events
        if event.get("Hostname") == TARGET_HOST
        and event.get("EventID") == 1
        and dt.datetime(2020, 9, 20, 6, 57, 45, tzinfo=dt.timezone.utc)
        <= event_utc(event)
        <= dt.datetime(2020, 9, 20, 6, 58, 10, tzinfo=dt.timezone.utc)
    ]
    processes_by_guid = {event.get("ProcessGuid"): event for event in process_events}
    target_powershell = processes_by_guid[TARGET_POWERSHELL_GUID]
    second_cmd = processes_by_guid[target_powershell["ParentProcessGuid"]]
    first_cmd = processes_by_guid[second_cmd["ParentProcessGuid"]]
    assert str(first_cmd["ParentImage"]).lower().endswith("\\services.exe")
    for process in (first_cmd, second_cmd, target_powershell):
        assert str(process.get("User", "")).upper() == "NT AUTHORITY\\SYSTEM"
    whoami = next(
        event
        for event in process_events
        if str(event.get("Image", "")).lower().endswith("\\whoami.exe")
        and event.get("ParentProcessGuid") == TARGET_POWERSHELL_GUID
    )
    assert str(whoami.get("User", "")).upper() == "NT AUTHORITY\\SYSTEM"

    network_events = [
        event
        for event in events
        if event.get("EventID") == 3 and event.get("Channel") == "Microsoft-Windows-Sysmon/Operational"
    ]
    source_smb = next(
        event
        for event in network_events
        if event.get("Hostname") == SOURCE_HOST
        and event.get("SourceIp") == SOURCE_IP
        and event.get("DestinationIp") == TARGET_IP
        and event.get("DestinationPort") == "445"
    )
    target_inbound_smb = next(
        event
        for event in network_events
        if event.get("Hostname") == TARGET_HOST
        and event.get("SourceIp") == SOURCE_IP
        and event.get("DestinationIp") == TARGET_IP
        and event.get("DestinationPort") == "445"
    )
    target_c2 = next(
        event
        for event in network_events
        if event.get("Hostname") == TARGET_HOST
        and event.get("ProcessGuid") == TARGET_POWERSHELL_GUID
        and event.get("DestinationIp") == C2_IP
        and event.get("DestinationPort") == "80"
    )
    assert source_smb["ProcessGuid"] == SOURCE_PROCESS_GUID
    assert source_smb["User"] == "THESHIRE\\pgustavo"

    flow_rows, marker_rows = analyse_pcaps(pcap_paths)
    pcap_summary_rows = summarise_pcaps(pcap_paths)
    marker_names = {row["marker"] for row in marker_rows}
    assert {"NTLMSSP", "svcctl_named_pipe", "random_service_name"} <= marker_names

    timeline_rows = [
        {
            "timestamp_utc": iso(event_utc(target_inbound_smb)),
            "phase": "SMB connection",
            "host": TARGET_HOST,
            "telemetry": "Sysmon Event ID 3",
            "account": target_inbound_smb.get("User", ""),
            "source": f"{SOURCE_IP}:{target_inbound_smb['SourcePort']}",
            "destination": f"{TARGET_IP}:445",
            "correlation_key": "TCP 172.18.39.5:50504 -> 172.18.39.6:445",
            "finding": "Target recorded inbound SMB from WORKSTATION5",
            "confidence": "High",
        },
        {
            "timestamp_utc": iso(event_utc(auth)),
            "phase": "Authentication",
            "host": TARGET_HOST,
            "telemetry": "Security Event ID 4624",
            "account": "THESHIRE\\pgustavo",
            "source": f"{auth['WorkstationName']} / {auth['IpAddress']}:{auth['IpPort']}",
            "destination": TARGET_HOST,
            "correlation_key": LOGON_ID,
            "finding": "Successful Type 3 NTLMv2 network logon",
            "confidence": "High",
        },
        {
            "timestamp_utc": iso(event_utc(dc_validation)),
            "phase": "Credential validation",
            "host": DOMAIN_CONTROLLER,
            "telemetry": "Security Event ID 4776",
            "account": "THESHIRE\\pgustavo",
            "source": dc_validation.get("Workstation", ""),
            "destination": DOMAIN_CONTROLLER,
            "correlation_key": "Status 0x0",
            "finding": "Domain controller accepted the NTLM credential validation",
            "confidence": "High",
        },
        {
            "timestamp_utc": iso(event_utc(privileged)),
            "phase": "Privilege assignment",
            "host": TARGET_HOST,
            "telemetry": "Security Event ID 4672",
            "account": "THESHIRE\\pgustavo",
            "source": SOURCE_HOST,
            "destination": TARGET_HOST,
            "correlation_key": LOGON_ID,
            "finding": "Special privileges assigned to the same network logon session",
            "confidence": "High",
        },
        {
            "timestamp_utc": iso(event_utc(share)),
            "phase": "Remote service channel",
            "host": TARGET_HOST,
            "telemetry": "Security Event IDs 5140 and 5145",
            "account": "THESHIRE\\pgustavo",
            "source": SOURCE_IP,
            "destination": "IPC$ / svcctl",
            "correlation_key": LOGON_ID,
            "finding": "The session accessed the Service Control Manager named pipe",
            "confidence": "High",
        },
        {
            "timestamp_utc": iso(event_utc(service_security)),
            "phase": "Remote service creation",
            "host": TARGET_HOST,
            "telemetry": "Security 4697 + System 7045 + Sysmon 12/13",
            "account": "THESHIRE\\pgustavo",
            "source": SOURCE_HOST,
            "destination": TARGET_HOST,
            "correlation_key": f"{LOGON_ID} / {SERVICE_NAME}",
            "finding": "Random temporary demand-start service installed with cmd/encoded PowerShell ImagePath; target process telemetry later confirms SYSTEM execution",
            "confidence": "High",
        },
        {
            "timestamp_utc": iso(event_utc(first_cmd)),
            "phase": "Service execution",
            "host": TARGET_HOST,
            "telemetry": "Sysmon Event ID 1 + Security Event ID 4688",
            "account": "NT AUTHORITY\\SYSTEM",
            "source": "services.exe",
            "destination": "cmd.exe -> cmd.exe -> powershell.exe",
            "correlation_key": first_cmd["ProcessGuid"],
            "finding": "Service Control Manager launched the encoded PowerShell stager as SYSTEM",
            "confidence": "High",
        },
        {
            "timestamp_utc": iso(event_utc(script_block)),
            "phase": "Stager execution",
            "host": TARGET_HOST,
            "telemetry": "PowerShell Event ID 4104",
            "account": "NT AUTHORITY\\SYSTEM",
            "source": "powershell.exe",
            "destination": f"http://{C2_IP}/login/process.php",
            "correlation_key": script_block.get("ScriptBlockId", ""),
            "finding": "Decoded script disables logging/AMSI, downloads encrypted stage data, decrypts it and invokes it in memory",
            "confidence": "High",
        },
        {
            "timestamp_utc": iso(event_utc(target_c2)),
            "phase": "C2 connection",
            "host": TARGET_HOST,
            "telemetry": "Sysmon Event ID 3 + PCAP",
            "account": "NT AUTHORITY\\SYSTEM",
            "source": f"{TARGET_IP}:{target_c2['SourcePort']}",
            "destination": f"{C2_IP}:80",
            "correlation_key": TARGET_POWERSHELL_GUID,
            "finding": "The new SYSTEM PowerShell process connected to the Empire listener",
            "confidence": "High",
        },
        {
            "timestamp_utc": iso(event_utc(whoami)),
            "phase": "Post-exploitation validation",
            "host": TARGET_HOST,
            "telemetry": "Sysmon Event ID 1 + Security Event ID 4688",
            "account": "NT AUTHORITY\\SYSTEM",
            "source": "powershell.exe",
            "destination": "whoami.exe",
            "correlation_key": whoami["ParentProcessGuid"],
            "finding": "The new remote agent executed whoami as SYSTEM",
            "confidence": "High",
        },
    ]
    timeline_rows.sort(key=lambda row: row["timestamp_utc"])
    write_csv(
        args.output_dir / "attack-timeline.csv",
        list(timeline_rows[0]),
        timeline_rows,
    )

    auth_rows = [
        {
            "event_id": event["EventID"],
            "timestamp_utc": iso(event_utc(event)),
            "host": event["Hostname"],
            "account": event.get("TargetUserName") or event.get("SubjectUserName"),
            "logon_id": event.get("TargetLogonId") or event.get("SubjectLogonId", ""),
            "source_address": event.get("IpAddress", ""),
            "source_workstation": event.get("WorkstationName") or event.get("Workstation", ""),
            "target_resource": event.get("ShareName") or event.get("RelativeTargetName") or event.get("ServiceName", ""),
            "key_detail": {
                4624: "LogonType=3; AuthenticationPackage=NTLM; LmPackage=NTLM V2",
                4776: f"Credential validation status={event.get('Status')}",
                4672: "Special privileges assigned",
                5140: "IPC$ share accessed",
                5145: "svcctl named pipe accessed",
                4697: f"Service installed: {SERVICE_NAME}",
                7045: f"Service Control Manager recorded: {SERVICE_NAME}",
            }[event["EventID"]],
        }
        for event in [auth, dc_validation, privileged, share, pipe, service_security, service_system]
    ]
    write_csv(
        args.output_dir / "authentication-remote-service-evidence.csv",
        list(auth_rows[0]),
        auth_rows,
    )

    process_rows = []
    for event in sorted([first_cmd, second_cmd, target_powershell, whoami], key=event_utc):
        process_rows.append(
            {
                "timestamp_utc": iso(event_utc(event)),
                "host": event["Hostname"],
                "user": event.get("User", ""),
                "process_guid": event.get("ProcessGuid", ""),
                "image": event.get("Image", ""),
                "command_line_sanitised": sanitise_command(event.get("CommandLine")),
                "parent_process_guid": event.get("ParentProcessGuid", ""),
                "parent_image": event.get("ParentImage", ""),
                "logon_id": event.get("LogonId", ""),
            }
        )
    write_csv(args.output_dir / "remote-process-chain.csv", list(process_rows[0]), process_rows)

    scope_rows = [
        {
            "source_host": SOURCE_HOST,
            "source_ip": SOURCE_IP,
            "target_host": TARGET_HOST,
            "target_ip": TARGET_IP,
            "account_or_process": "THESHIRE\\pgustavo / powershell.exe",
            "protocol_or_service": "TCP/445 SMB; IPC$; svcctl RPC",
            "role_in_incident": "Confirmed lateral-movement source to target",
            "compromise_status": "Source-side attack process observed; initial compromise path not captured. Target SYSTEM execution confirmed",
        },
        {
            "source_host": TARGET_HOST,
            "source_ip": TARGET_IP,
            "target_host": DOMAIN_CONTROLLER,
            "target_ip": DOMAIN_CONTROLLER_IP,
            "account_or_process": "THESHIRE\\pgustavo / lsass.exe",
            "protocol_or_service": "NTLM credential validation; RPC",
            "role_in_incident": "Authentication dependency",
            "compromise_status": "No evidence that the domain controller was compromised",
        },
        {
            "source_host": TARGET_HOST,
            "source_ip": TARGET_IP,
            "target_host": "Private lab Empire listener",
            "target_ip": C2_IP,
            "account_or_process": "NT AUTHORITY\\SYSTEM / powershell.exe",
            "protocol_or_service": "TCP/80 HTTP",
            "role_in_incident": "Post-exploitation HTTP activity (listener attribution from simulation ground truth)",
            "compromise_status": "Observed bidirectional connection from the target PowerShell process",
        },
    ]
    write_csv(args.output_dir / "host-to-host-scope.csv", list(scope_rows[0]), scope_rows)

    write_csv(
        args.output_dir / "network-flow-summary.csv",
        [
            "capture_file",
            "source_ip",
            "source_port",
            "destination_ip",
            "destination_port",
            "protocol",
            "packet_count",
            "first_seen_utc",
            "last_seen_utc",
        ],
        flow_rows,
    )
    write_csv(
        args.output_dir / "pcap-marker-evidence.csv",
        [
            "capture_file",
            "frame",
            "timestamp_utc",
            "source",
            "destination",
            "marker",
            "interpretation",
        ],
        marker_rows,
    )
    write_csv(
        args.output_dir / "pcap-capture-summary.csv",
        [
            "capture_file",
            "size_bytes",
            "packet_count",
            "tcp_445_packet_count",
            "first_seen_utc",
            "last_seen_utc",
            "duration_seconds",
        ],
        pcap_summary_rows,
    )

    event_counts = Counter(
        (event.get("Hostname", ""), event.get("Channel", ""), event.get("EventID"))
        for event in events
        if event.get("EventID") in KEY_EVENT_IDS
    )
    event_count_rows = [
        {"host": host, "channel": channel, "event_id": event_id, "count": count}
        for (host, channel, event_id), count in sorted(
            event_counts.items(), key=lambda item: (item[0][0], item[0][1], item[0][2])
        )
    ]
    write_csv(
        args.output_dir / "key-event-id-counts.csv",
        ["host", "channel", "event_id", "count"],
        event_count_rows,
    )

    indicator_rows = [
        {"type": "host", "value": "WORKSTATION5", "role": "lateral-movement source", "confidence": "High"},
        {"type": "host", "value": "WORKSTATION6", "role": "lateral-movement target", "confidence": "High"},
        {"type": "account", "value": "THESHIRE\\pgustavo", "role": "credential used for remote authentication/service creation", "confidence": "High"},
        {"type": "ipv4", "value": SOURCE_IP, "role": "source endpoint", "confidence": "High"},
        {"type": "ipv4", "value": TARGET_IP, "role": "target endpoint", "confidence": "High"},
        {"type": "ipv4", "value": C2_IP, "role": "Private lab Empire listener (simulation ground truth)", "confidence": "High"},
        {"type": "service", "value": SERVICE_NAME, "role": "transient randomly named remote service", "confidence": "High"},
        {"type": "named_pipe", "value": "svcctl", "role": "remote Service Control Manager RPC channel", "confidence": "High"},
        {"type": "url", "value": f"http://{C2_IP}/login/process.php", "role": "Observed stage-one retrieval URL at a private lab endpoint", "confidence": "High"},
        {"type": "logon_id", "value": LOGON_ID, "role": "target authentication-to-service correlation key", "confidence": "High"},
    ]
    write_csv(args.output_dir / "indicator-summary.csv", list(indicator_rows[0]), indicator_rows)

    decoded = script_block["ScriptBlockText"]
    nested_url_token = "aAB0AHQAcAA6AC8ALwAxADAALgAxADAALgAxADAALgA1AA=="
    assert nested_url_token in decoded
    assert "/login/process.php" in decoded
    assert "amsiInitF" in decoded
    stager_summary = f"""# Decoded PowerShell stager findings

The raw encoded command is intentionally not copied into tracked evidence.

- Execution user: `NT AUTHORITY\\SYSTEM`
- Parent chain: `services.exe -> cmd.exe -> cmd.exe -> powershell.exe`
- PowerShell flags: `-noP -sta -w 1 -enc <redacted>`
- Observed destination: `http://{C2_IP}/login/process.php` (private lab address)
- Behaviour observed in Event ID 4104:
  - attempts to disable Script Block Logging;
  - sets the in-memory AMSI initialisation-failed flag;
  - creates a `System.Net.WebClient` using the default proxy and credentials;
  - downloads encrypted stage data over HTTP;
  - decrypts the returned data with an RC4-style routine;
  - executes the result in memory with `IEX`.
- Follow-on evidence: the same ProcessGuid `{TARGET_POWERSHELL_GUID}` connects to `{C2_IP}:80` and later spawns `whoami.exe`.

The source-side dataset records `Invoke-SMBExec` being supplied a demonstration NTLM hash. This attribution is simulation ground truth; target/network telemetry independently proves successful NTLM authentication but not the credential representation. The hash is excluded from processed evidence.
"""
    (args.output_dir / "decoded-stager-findings.md").write_text(stager_summary, encoding="utf-8")

    inventory_rows = []
    for path in [args.host_json, *pcap_paths]:
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        inventory_rows.append(
            {"file": path.name, "size_bytes": path.stat().st_size, "sha256": digest}
        )
    write_csv(
        args.output_dir / "analysed-file-inventory.csv",
        ["file", "size_bytes", "sha256"],
        inventory_rows,
    )

    summary = {
        "scenario": 13,
        "verdict": "True Positive",
        "severity": "High",
        "technique": "SMB remote service execution",
        "source": {"host": SOURCE_HOST, "ip": SOURCE_IP, "user": f"THESHIRE\\{ACCOUNT}"},
        "target": {"host": TARGET_HOST, "ip": TARGET_IP, "execution_user": "NT AUTHORITY\\SYSTEM"},
        "service": SERVICE_NAME,
        "correlation_keys": {"logon_id": LOGON_ID, "source_process_guid": SOURCE_PROCESS_GUID, "target_powershell_guid": TARGET_POWERSHELL_GUID},
        "observed_facts": [
            "Successful NTLMv2 network logon from WORKSTATION5 to WORKSTATION6",
            "IPC$ and svcctl access under the same logon session",
            "Random temporary service creation with encoded PowerShell; target process telemetry confirms SYSTEM execution",
            "services.exe-to-PowerShell SYSTEM process chain",
            f"Target PowerShell connection to private lab address {C2_IP}:80",
            "Two endpoint PCAPs independently contain NTLMSSP, svcctl and the service name",
        ],
        "ground_truth_only": [
            "The simulator supplied an NTLM hash to Invoke-SMBExec; target/network telemetry alone cannot distinguish hash use from another successful NTLM credential source",
            "Attribution of 10.10.10.5 as an Empire listener"
        ],
        "scope_limitations": [
            "No evidence of movement beyond WORKSTATION6 in this capture",
            "No evidence that MORDORDC was compromised",
            "Source PowerShell process creation predates the capture window",
            "Cross-host timestamps differ by up to about two seconds; packet order is preferred for SMB sequencing",
        ],
        "authorization_status": "Not available - no change, deployment or administrator-approval records are included",
        "not_observed": [
            "RDP",
            "WinRM",
            "Durable service persistence",
            "Movement from WORKSTATION6 to a third internal target",
            "Compromise of MORDORDC"
        ],
        "unable_to_confirm_from_target_network_telemetry": [
            "Whether plaintext or NTLM hash material was supplied",
            "WMI remote execution"
        ],
        "detection_gaps": [
            "Missing Detailed File Share auditing would remove the 5145 svcctl correlation",
            "Missing service-install, process command-line, PowerShell or east-west network telemetry would materially reduce confidence"
        ],
    }
    (args.output_dir / "analysis-summary.json").write_text(
        json.dumps(summary, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )

    print(f"Validated {len(events)} host events and {len(pcap_paths)} PCAPs")
    output_count = len([path for path in args.output_dir.iterdir() if path.is_file() and path.name != ".gitkeep"])
    print(f"Wrote {output_count} processed evidence files")
    print("Verdict: True Positive - successful SMB remote service execution as SYSTEM")


if __name__ == "__main__":
    main()
