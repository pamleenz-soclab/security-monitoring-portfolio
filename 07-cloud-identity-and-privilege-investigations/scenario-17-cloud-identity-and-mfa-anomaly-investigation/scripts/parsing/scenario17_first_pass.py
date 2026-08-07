#!/usr/bin/env python3
"""Run a concentrated first-pass analysis over the Scenario 17 synthetic dataset.

Outputs are written only to evidence/working. The parser does not modify raw
files and does not use ground-truth.json to derive the candidate assessment.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import sqlite3
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


def parse_dt(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for lineno, line in enumerate(handle, 1):
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path}:{lineno}: invalid JSON: {exc}") from exc
    return rows


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def write_csv(path: Path, rows: Iterable[dict[str, Any]], fields: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            clean = {}
            for field in fields:
                value = row.get(field, "")
                if isinstance(value, (dict, list)):
                    value = json.dumps(value, sort_keys=True, separators=(",", ":"))
                elif value is None:
                    value = ""
                clean[field] = value
            writer.writerow(clean)


def write_tsv(path: Path, rows: Iterable[dict[str, Any]], fields: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, delimiter="\t", extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            clean = {}
            for field in fields:
                value = row.get(field, "")
                if isinstance(value, (dict, list)):
                    value = json.dumps(value, sort_keys=True, separators=(",", ":"))
                elif value is None:
                    value = ""
                clean[field] = value
            writer.writerow(clean)


def status_class(row: dict[str, Any]) -> str:
    return "success" if int(row.get("status", {}).get("errorCode", -1)) == 0 else "failure"


def mfa_outcome(step: dict[str, Any]) -> str:
    method = str(step.get("authenticationMethod", ""))
    requirement = str(step.get("authenticationStepRequirement", ""))
    detail = str(step.get("authenticationStepResultDetail", "")).lower()
    if "multifactor" not in requirement.lower() and method not in {"Microsoft Authenticator", "Previously satisfied", "SMS", "Voice", "FIDO2", "Windows Hello for Business", "Certificate"}:
        return "not_mfa"
    if "claim" in detail or method == "Previously satisfied":
        return "satisfied_by_claim"
    if step.get("succeeded") is True:
        return "success"
    if "denied" in detail or "declined" in detail:
        return "denied"
    if "timeout" in detail or "no response" in detail:
        return "timeout"
    if "fraud" in detail or "suspicious" in detail:
        return "fraud_reported"
    if "interrupt" in detail:
        return "interrupted"
    return "failure"


def geo_distance_km(a: dict[str, Any], b: dict[str, Any]) -> float | None:
    try:
        lat1 = math.radians(float(a["geoCoordinates"]["latitude"]))
        lon1 = math.radians(float(a["geoCoordinates"]["longitude"]))
        lat2 = math.radians(float(b["geoCoordinates"]["latitude"]))
        lon2 = math.radians(float(b["geoCoordinates"]["longitude"]))
    except (KeyError, TypeError, ValueError):
        return None
    dlat = lat2 - lat1
    dlon = lon2 - lon1
    h = math.sin(dlat / 2) ** 2 + math.cos(lat1) * math.cos(lat2) * math.sin(dlon / 2) ** 2
    return 6371.0 * 2 * math.asin(math.sqrt(h))


def create_sqlite(db_path: Path, signins: list[dict[str, Any]], audits: list[dict[str, Any]], m365: list[dict[str, Any]], risks: list[dict[str, Any]]) -> None:
    if db_path.exists():
        db_path.unlink()
    conn = sqlite3.connect(db_path)
    conn.executescript(
        """
        PRAGMA journal_mode=WAL;
        CREATE TABLE signins (
          id TEXT PRIMARY KEY,
          created_utc TEXT,
          sign_in_log_type TEXT,
          identity_type TEXT,
          user_id TEXT,
          user_principal_name TEXT,
          app_display_name TEXT,
          resource_display_name TEXT,
          ip_address TEXT,
          country TEXT,
          city TEXT,
          asn INTEGER,
          client_app_used TEXT,
          authentication_protocol TEXT,
          is_interactive INTEGER,
          error_code INTEGER,
          failure_reason TEXT,
          additional_details TEXT,
          authentication_requirement TEXT,
          conditional_access_status TEXT,
          risk_level_during_signin TEXT,
          risk_level_aggregated TEXT,
          risk_state TEXT,
          correlation_id TEXT,
          request_id TEXT,
          original_request_id TEXT,
          session_id TEXT,
          unique_token_identifier TEXT,
          device_id TEXT,
          device_os TEXT,
          device_browser TEXT,
          device_compliant INTEGER,
          device_managed INTEGER,
          incoming_token_type TEXT,
          raw_json TEXT
        );
        CREATE TABLE authentication_steps (
          signin_id TEXT,
          step_time_utc TEXT,
          method TEXT,
          method_detail TEXT,
          requirement TEXT,
          result_detail TEXT,
          succeeded INTEGER,
          normalized_outcome TEXT
        );
        CREATE TABLE ca_policy_results (
          signin_id TEXT,
          policy_id TEXT,
          policy_name TEXT,
          result TEXT,
          grant_controls TEXT,
          session_controls TEXT
        );
        CREATE TABLE directory_audits (
          id TEXT PRIMARY KEY,
          activity_time_utc TEXT,
          activity_display_name TEXT,
          category TEXT,
          result TEXT,
          correlation_id TEXT,
          initiated_by TEXT,
          target_resources TEXT,
          raw_json TEXT
        );
        CREATE TABLE m365_audits (
          id TEXT PRIMARY KEY,
          creation_time_utc TEXT,
          operation TEXT,
          workload TEXT,
          result_status TEXT,
          user_id TEXT,
          user_key TEXT,
          client_ip TEXT,
          object_id TEXT,
          session_id TEXT,
          parameters TEXT,
          raw_json TEXT
        );
        CREATE TABLE risk_detections (
          id TEXT PRIMARY KEY,
          activity_time_utc TEXT,
          detected_time_utc TEXT,
          risk_event_type TEXT,
          risk_level TEXT,
          risk_state TEXT,
          user_id TEXT,
          user_principal_name TEXT,
          ip_address TEXT,
          request_id TEXT,
          correlation_id TEXT,
          raw_json TEXT
        );
        """
    )
    for row in signins:
        loc = row.get("locationDetails", {})
        dev = row.get("deviceDetail", {})
        values = (
            row.get("id"), row.get("createdDateTime"), row.get("signInLogType"), row.get("identityType"),
            row.get("userId"), row.get("userPrincipalName"), row.get("appDisplayName"), row.get("resourceDisplayName"),
            row.get("ipAddress"), loc.get("countryOrRegion", ""), loc.get("city", ""), row.get("autonomousSystemNumber"),
            row.get("clientAppUsed"), row.get("authenticationProtocol"), int(bool(row.get("isInteractive"))),
            int(row.get("status", {}).get("errorCode", -1)), row.get("status", {}).get("failureReason", ""),
            row.get("status", {}).get("additionalDetails", ""), row.get("authenticationRequirement"),
            row.get("conditionalAccessStatus"), row.get("riskLevelDuringSignIn"), row.get("riskLevelAggregated"),
            row.get("riskState"), row.get("correlationId"), row.get("requestId"), row.get("originalRequestId"),
            row.get("sessionId"), row.get("uniqueTokenIdentifier"), dev.get("deviceId", ""), dev.get("operatingSystem", ""),
            dev.get("browser", ""), None if dev.get("isCompliant") is None else int(bool(dev.get("isCompliant"))),
            None if dev.get("isManaged") is None else int(bool(dev.get("isManaged"))), row.get("incomingTokenType", ""),
            json.dumps(row, sort_keys=True, separators=(",", ":")),
        )
        conn.execute(f"INSERT INTO signins VALUES ({','.join('?' for _ in values)})", values)
        for step in row.get("authenticationDetails", []):
            conn.execute(
                "INSERT INTO authentication_steps VALUES (?,?,?,?,?,?,?,?)",
                (row.get("id"), step.get("authenticationStepDateTime"), step.get("authenticationMethod"),
                 step.get("authenticationMethodDetail"), step.get("authenticationStepRequirement"),
                 step.get("authenticationStepResultDetail"), int(bool(step.get("succeeded"))), mfa_outcome(step)),
            )
        for policy in row.get("conditionalAccessPolicies", []):
            conn.execute(
                "INSERT INTO ca_policy_results VALUES (?,?,?,?,?,?)",
                (row.get("id"), policy.get("id"), policy.get("displayName"), policy.get("result"),
                 json.dumps(policy.get("enforcedGrantControls", [])), json.dumps(policy.get("enforcedSessionControls", []))),
            )
    for row in audits:
        conn.execute(
            "INSERT INTO directory_audits VALUES (?,?,?,?,?,?,?,?,?)",
            (row.get("id"), row.get("activityDateTime"), row.get("activityDisplayName"), row.get("category"),
             row.get("result"), row.get("correlationId"), json.dumps(row.get("initiatedBy", {}), sort_keys=True),
             json.dumps(row.get("targetResources", []), sort_keys=True), json.dumps(row, sort_keys=True, separators=(",", ":"))),
        )
    for row in m365:
        conn.execute(
            "INSERT INTO m365_audits VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (row.get("id"), row.get("creationTime"), row.get("operation"), row.get("workload"), row.get("resultStatus"),
             row.get("userId"), row.get("userKey"), row.get("clientIP"), row.get("objectId"), row.get("sessionId"),
             json.dumps(row.get("parameters", {}), sort_keys=True), json.dumps(row, sort_keys=True, separators=(",", ":"))),
        )
    for row in risks:
        conn.execute(
            "INSERT INTO risk_detections VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (row.get("id"), row.get("activityDateTime"), row.get("detectedDateTime"), row.get("riskEventType"),
             row.get("riskLevel"), row.get("riskState"), row.get("userId"), row.get("userPrincipalName"),
             row.get("ipAddress"), row.get("requestId"), row.get("correlationId"),
             json.dumps(row, sort_keys=True, separators=(",", ":"))),
        )
    conn.commit()
    conn.close()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--raw-dir", required=True, type=Path)
    parser.add_argument("--working-dir", required=True, type=Path)
    args = parser.parse_args()

    raw = args.raw_dir.expanduser().resolve()
    working = args.working_dir.expanduser().resolve()
    working.mkdir(parents=True, exist_ok=True)

    required = [
        "entra-signins.jsonl", "entra-directory-audit.jsonl", "m365-unified-audit.jsonl",
        "identity-protection-risk-detections.jsonl", "business-context.json", "schema-basis.json",
        "ground-truth.json", "acquisition-manifest.json", "DATASET-LICENSE.txt",
    ]
    missing = [name for name in required if not (raw / name).is_file()]
    if missing:
        print("ERROR: missing required raw files:", file=sys.stderr)
        for name in missing:
            print(f"  {raw / name}", file=sys.stderr)
        return 2

    signins = load_jsonl(raw / "entra-signins.jsonl")
    audits = load_jsonl(raw / "entra-directory-audit.jsonl")
    m365 = load_jsonl(raw / "m365-unified-audit.jsonl")
    risks = load_jsonl(raw / "identity-protection-risk-detections.jsonl")
    business = load_json(raw / "business-context.json")
    schema_basis = load_json(raw / "schema-basis.json")
    manifest = load_json(raw / "acquisition-manifest.json")

    # Source record and integrity manifest.
    source_rows = []
    for path in sorted(p for p in raw.iterdir() if p.is_file()):
        source_rows.append({
            "file_name": path.name,
            "file_type": "JSONL" if path.suffix == ".jsonl" else ("JSON" if path.suffix == ".json" else "text"),
            "size_bytes": path.stat().st_size,
            "sha256": sha256(path),
            "synthetic": "true",
            "redistribution": "Generator-derived synthetic data; raw remains local by project convention",
        })
    write_tsv(working / "source-sha256-records.tsv", source_rows,
              ["file_name", "file_type", "size_bytes", "sha256", "synthetic", "redistribution"])
    write_tsv(working / "evidence-source-record.tsv", source_rows,
              ["file_name", "file_type", "size_bytes", "synthetic", "redistribution"])

    # Format and schema profile.
    schema_rows = []
    collections = {
        "entra-signins.jsonl": signins,
        "entra-directory-audit.jsonl": audits,
        "m365-unified-audit.jsonl": m365,
        "identity-protection-risk-detections.jsonl": risks,
    }
    for name, rows in collections.items():
        keys = sorted({key for row in rows for key in row.keys()})
        schema_rows.append({
            "file_name": name,
            "record_count": len(rows),
            "top_level_field_count": len(keys),
            "top_level_fields": keys,
            "all_records_synthetic": all(row.get("syntheticRecord") is True for row in rows),
            "parse_status": "valid",
        })
    write_csv(working / "format-and-schema-profile.csv", schema_rows,
              ["file_name", "record_count", "top_level_field_count", "top_level_fields", "all_records_synthetic", "parse_status"])

    # Time profile.
    time_rows = []
    for name, rows, field in [
        ("signins", signins, "createdDateTime"), ("directory_audit", audits, "activityDateTime"),
        ("m365_audit", m365, "creationTime"), ("risk_detections", risks, "activityDateTime"),
    ]:
        values = sorted(parse_dt(str(r[field])) for r in rows)
        time_rows.append({
            "source": name,
            "record_count": len(rows),
            "first_utc": values[0].isoformat().replace("+00:00", "Z") if values else "",
            "last_utc": values[-1].isoformat().replace("+00:00", "Z") if values else "",
            "timezone_basis": "UTC",
            "original_timezone_available": name == "signins",
        })
    write_csv(working / "time-range-and-timezone-profile.csv", time_rows,
              ["source", "record_count", "first_utc", "last_utc", "timezone_basis", "original_timezone_available"])

    # Identity inventory.
    identity_counts: dict[tuple[str, str, str], Counter[str]] = defaultdict(Counter)
    for s in signins:
        name = s.get("userPrincipalName") or s.get("servicePrincipalName") or s.get("managedIdentityName") or "unknown"
        ident_id = s.get("userId") or s.get("servicePrincipalId") or s.get("managedIdentityId") or ""
        key = (s.get("identityType", "unknown"), name, ident_id)
        identity_counts[key]["events"] += 1
        identity_counts[key]["success"] += status_class(s) == "success"
        identity_counts[key]["failure"] += status_class(s) == "failure"
        identity_counts[key][f"type:{s.get('signInLogType', '')}"] += 1
    identity_rows = []
    for (itype, name, ident_id), counts in sorted(identity_counts.items()):
        types = {k.split(":", 1)[1]: v for k, v in counts.items() if k.startswith("type:")}
        identity_rows.append({
            "identity_type": itype, "identity_name": name, "identity_id": ident_id,
            "event_count": counts["events"], "success_count": counts["success"], "failure_count": counts["failure"],
            "sign_in_types": types,
        })
    write_csv(working / "identity-inventory.csv", identity_rows,
              ["identity_type", "identity_name", "identity_id", "event_count", "success_count", "failure_count", "sign_in_types"])

    # Application and resource inventory.
    app_counter: dict[tuple[str, str, str, str], Counter[str]] = defaultdict(Counter)
    for s in signins:
        key = (s.get("appDisplayName", ""), s.get("appId", ""), s.get("resourceDisplayName", ""), s.get("resourceId", ""))
        app_counter[key]["events"] += 1
        app_counter[key][status_class(s)] += 1
        app_counter[key][f"client:{s.get('clientAppUsed', '')}"] += 1
        app_counter[key][f"protocol:{s.get('authenticationProtocol', '')}"] += 1
    app_rows = []
    for key, counts in sorted(app_counter.items()):
        app_rows.append({
            "app_display_name": key[0], "app_id": key[1], "resource_display_name": key[2], "resource_id": key[3],
            "event_count": counts["events"], "success_count": counts["success"], "failure_count": counts["failure"],
            "client_applications": {k.split(":", 1)[1]: v for k, v in counts.items() if k.startswith("client:")},
            "authentication_protocols": {k.split(":", 1)[1]: v for k, v in counts.items() if k.startswith("protocol:")},
        })
    write_csv(working / "application-inventory.csv", app_rows,
              ["app_display_name", "app_id", "resource_display_name", "resource_id", "event_count", "success_count", "failure_count", "client_applications", "authentication_protocols"])

    # Device inventory.
    dev_counter: dict[tuple[Any, ...], Counter[str]] = defaultdict(Counter)
    for s in signins:
        d = s.get("deviceDetail", {})
        key = (d.get("deviceId", ""), d.get("displayName", ""), d.get("operatingSystem", ""), d.get("browser", ""), d.get("isCompliant"), d.get("isManaged"), d.get("trustType", ""))
        dev_counter[key]["events"] += 1
        dev_counter[key][status_class(s)] += 1
        if s.get("userPrincipalName"):
            dev_counter[key][f"user:{s['userPrincipalName']}"] += 1
    device_rows = []
    for key, counts in sorted(dev_counter.items(), key=lambda item: str(item[0])):
        device_rows.append({
            "device_id": key[0], "device_name": key[1], "operating_system": key[2], "browser": key[3],
            "is_compliant": key[4], "is_managed": key[5], "trust_type": key[6],
            "event_count": counts["events"], "success_count": counts["success"], "failure_count": counts["failure"],
            "users": sorted(k.split(":", 1)[1] for k in counts if k.startswith("user:")),
            "device_context": "known/managed" if key[0] and key[4] is True and key[5] is True else ("unknown/unmanaged" if key[4] is False or key[5] is False else "not_available"),
        })
    write_csv(working / "device-inventory.csv", device_rows,
              ["device_id", "device_name", "operating_system", "browser", "is_compliant", "is_managed", "trust_type", "event_count", "success_count", "failure_count", "users", "device_context"])

    # IP and location inventory.
    ip_counter: dict[tuple[Any, ...], Counter[str]] = defaultdict(Counter)
    for s in signins:
        loc = s.get("locationDetails", {})
        key = (s.get("ipAddress", ""), s.get("autonomousSystemNumber"), s.get("networkProvider", ""), loc.get("countryOrRegion", ""), loc.get("state", ""), loc.get("city", ""), s.get("isAnonymousProxy"), s.get("isCorporateNetwork"))
        ip_counter[key]["events"] += 1
        ip_counter[key][status_class(s)] += 1
        if s.get("userPrincipalName"):
            ip_counter[key][f"user:{s['userPrincipalName']}"] += 1
        ip_counter[key][f"risk:{s.get('riskLevelDuringSignIn', '')}"] += 1
    ip_rows = []
    approved_ips = {n["ipAddress"] for n in business.get("approvedNetworks", [])}
    for key, counts in sorted(ip_counter.items()):
        ip_rows.append({
            "ip_address": key[0], "asn": key[1], "provider": key[2], "country": key[3], "state": key[4], "city": key[5],
            "anonymous_proxy": key[6], "corporate_network": key[7], "approved_network": key[0] in approved_ips,
            "event_count": counts["events"], "success_count": counts["success"], "failure_count": counts["failure"],
            "distinct_users": len([k for k in counts if k.startswith("user:")]),
            "risk_levels": {k.split(":", 1)[1]: v for k, v in counts.items() if k.startswith("risk:")},
        })
    write_csv(working / "source-ip-and-location-inventory.csv", ip_rows,
              ["ip_address", "asn", "provider", "country", "state", "city", "anonymous_proxy", "corporate_network", "approved_network", "event_count", "success_count", "failure_count", "distinct_users", "risk_levels"])

    # Sign-in type and service identity classifications.
    type_counter: dict[tuple[str, str, bool], Counter[str]] = defaultdict(Counter)
    for s in signins:
        key = (s.get("signInLogType", ""), s.get("identityType", ""), bool(s.get("isInteractive")))
        type_counter[key]["events"] += 1
        type_counter[key][status_class(s)] += 1
    type_rows = [{
        "sign_in_log_type": k[0], "identity_type": k[1], "is_interactive": k[2],
        "event_count": v["events"], "success_count": v["success"], "failure_count": v["failure"],
    } for k, v in sorted(type_counter.items())]
    write_csv(working / "signin-type-summary.csv", type_rows,
              ["sign_in_log_type", "identity_type", "is_interactive", "event_count", "success_count", "failure_count"])
    service_rows = []
    for s in signins:
        if s.get("identityType") in {"servicePrincipal", "managedIdentity"}:
            service_rows.append({
                "created_utc": s.get("createdDateTime"), "identity_type": s.get("identityType"),
                "identity_name": s.get("servicePrincipalName") or s.get("managedIdentityName"),
                "identity_id": s.get("servicePrincipalId") or s.get("managedIdentityId"),
                "application": s.get("appDisplayName"), "resource": s.get("resourceDisplayName"),
                "ip_address": s.get("ipAddress"), "result": status_class(s), "credential_or_token_type": s.get("incomingTokenType"),
                "classification": "workload_identity",
            })
    write_csv(working / "service-identity-classification.csv", service_rows,
              ["created_utc", "identity_type", "identity_name", "identity_id", "application", "resource", "ip_address", "result", "credential_or_token_type", "classification"])

    # Authentication result summary.
    auth_counter: dict[tuple[Any, ...], int] = Counter()
    for s in signins:
        st = s.get("status", {})
        key = (status_class(s), st.get("errorCode"), st.get("failureReason", ""), st.get("additionalDetails", ""), s.get("authenticationRequirement", ""))
        auth_counter[key] += 1
    auth_rows = [{
        "result": k[0], "error_code": k[1], "failure_reason": k[2], "additional_details": k[3],
        "authentication_requirement": k[4], "event_count": v,
    } for k, v in sorted(auth_counter.items(), key=lambda item: (item[0][0], int(item[0][1] or 0), item[0][2]))]
    write_csv(working / "authentication-result-summary.csv", auth_rows,
              ["result", "error_code", "failure_reason", "additional_details", "authentication_requirement", "event_count"])

    # MFA method and result summary.
    mfa_counter: dict[tuple[str, str, str], int] = Counter()
    mfa_event_rows = []
    for s in signins:
        for step in s.get("authenticationDetails", []):
            outcome = mfa_outcome(step)
            if outcome == "not_mfa":
                continue
            key = (step.get("authenticationMethod", ""), step.get("authenticationMethodDetail", ""), outcome)
            mfa_counter[key] += 1
            mfa_event_rows.append({
                "created_utc": s.get("createdDateTime"), "user_principal_name": s.get("userPrincipalName"),
                "sign_in_id": s.get("id"), "correlation_id": s.get("correlationId"), "ip_address": s.get("ipAddress"),
                "authentication_method": key[0], "method_detail": key[1], "outcome": outcome,
                "result_detail": step.get("authenticationStepResultDetail", ""), "sign_in_result": status_class(s),
            })
    mfa_summary_rows = [{"authentication_method": k[0], "method_detail": k[1], "outcome": k[2], "event_count": v}
                        for k, v in sorted(mfa_counter.items())]
    write_csv(working / "mfa-method-and-result-summary.csv", mfa_summary_rows,
              ["authentication_method", "method_detail", "outcome", "event_count"])
    write_csv(working / "mfa-event-detail.csv", mfa_event_rows,
              ["created_utc", "user_principal_name", "sign_in_id", "correlation_id", "ip_address", "authentication_method", "method_detail", "outcome", "result_detail", "sign_in_result"])

    # Conditional Access summary.
    ca_counter: dict[tuple[str, str, str, str], int] = Counter()
    for s in signins:
        for p in s.get("conditionalAccessPolicies", []):
            key = (p.get("id", ""), p.get("displayName", ""), p.get("result", ""), json.dumps(p.get("enforcedGrantControls", []), sort_keys=True))
            ca_counter[key] += 1
    ca_rows = [{"policy_id": k[0], "policy_name": k[1], "result": k[2], "grant_controls": k[3], "event_count": v,
                "enforcement_interpretation": "not_enforced" if k[2].startswith("reportOnly") or k[2] in {"notApplied", "notEnabled"} else "enforced_or_evaluated"}
               for k, v in sorted(ca_counter.items())]
    write_csv(working / "conditional-access-policy-summary.csv", ca_rows,
              ["policy_id", "policy_name", "result", "grant_controls", "event_count", "enforcement_interpretation"])

    # Risk signal summary.
    risk_counter: dict[tuple[str, str, str, str], int] = Counter()
    for r in risks:
        risk_counter[(r.get("riskEventType", ""), r.get("riskLevel", ""), r.get("riskState", ""), r.get("detectionTimingType", ""))] += 1
    risk_rows = [{"risk_event_type": k[0], "risk_level": k[1], "risk_state": k[2], "detection_timing": k[3], "event_count": v,
                  "evidence_class": "platform-generated risk"} for k, v in sorted(risk_counter.items())]
    write_csv(working / "risk-signal-summary.csv", risk_rows,
              ["risk_event_type", "risk_level", "risk_state", "detection_timing", "event_count", "evidence_class"])

    # Stable ID inventory.
    id_rows = []
    for s in signins:
        id_rows.append({
            "created_utc": s.get("createdDateTime"), "sign_in_id": s.get("id"), "sign_in_type": s.get("signInLogType"),
            "user_or_identity": s.get("userPrincipalName") or s.get("servicePrincipalName") or s.get("managedIdentityName"),
            "correlation_id": s.get("correlationId"), "request_id": s.get("requestId"), "original_request_id": s.get("originalRequestId"),
            "session_id": s.get("sessionId"), "unique_token_identifier": s.get("uniqueTokenIdentifier"),
            "device_id": s.get("deviceDetail", {}).get("deviceId", ""), "ip_address": s.get("ipAddress"),
            "identifier_scope_note": "Correlation/request identifiers are event or authentication-sequence troubleshooting identifiers; session and token IDs have different scopes and are not interchangeable.",
        })
    write_csv(working / "correlation-request-session-id-inventory.csv", id_rows,
              ["created_utc", "sign_in_id", "sign_in_type", "user_or_identity", "correlation_id", "request_id", "original_request_id", "session_id", "unique_token_identifier", "device_id", "ip_address", "identifier_scope_note"])

    # User baseline and location baseline, using events before 2026-06-18.
    cutoff = parse_dt("2026-06-18T00:00:00Z")
    baseline = [s for s in signins if s.get("userPrincipalName") and parse_dt(s["createdDateTime"]) < cutoff]
    by_user: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for s in baseline:
        by_user[s["userPrincipalName"]].append(s)
    baseline_rows = []
    loc_rows = []
    for user, rows in sorted(by_user.items()):
        countries = Counter(r.get("locationDetails", {}).get("countryOrRegion", "") for r in rows)
        cities = Counter(r.get("locationDetails", {}).get("city", "") for r in rows)
        asns = Counter(str(r.get("autonomousSystemNumber", "")) for r in rows)
        devices = Counter(r.get("deviceDetail", {}).get("deviceId", "") or "<empty>" for r in rows)
        apps = Counter(r.get("appDisplayName", "") for r in rows)
        ips = Counter(r.get("ipAddress", "") for r in rows)
        baseline_rows.append({
            "user_principal_name": user, "baseline_event_count": len(rows), "first_utc": min(r["createdDateTime"] for r in rows),
            "last_utc": max(r["createdDateTime"] for r in rows), "countries": countries, "cities": cities,
            "asns": asns, "ip_addresses": ips, "device_ids": devices, "applications": apps,
        })
        for r in rows:
            loc_rows.append({
                "user_principal_name": user, "ip_address": r.get("ipAddress"), "asn": r.get("autonomousSystemNumber"),
                "country": r.get("locationDetails", {}).get("countryOrRegion", ""), "city": r.get("locationDetails", {}).get("city", ""),
                "device_id": r.get("deviceDetail", {}).get("deviceId", ""), "application": r.get("appDisplayName"),
                "created_utc": r.get("createdDateTime"),
            })
    write_csv(working / "per-user-baseline.csv", baseline_rows,
              ["user_principal_name", "baseline_event_count", "first_utc", "last_utc", "countries", "cities", "asns", "ip_addresses", "device_ids", "applications"])
    write_csv(working / "location-and-asn-baseline.csv", loc_rows,
              ["user_principal_name", "ip_address", "asn", "country", "city", "device_id", "application", "created_utc"])

    # Legacy auth candidates.
    legacy_clients = {"imap", "pop", "smtp", "exchange activesync", "mapi"}
    legacy_rows = []
    for s in signins:
        client = str(s.get("clientAppUsed", "")).lower()
        protocol = str(s.get("authenticationProtocol", "")).lower()
        if s.get("identityType") == "user" and (client in legacy_clients or protocol == "ropc"):
            legacy_rows.append({
                "created_utc": s.get("createdDateTime"), "user_principal_name": s.get("userPrincipalName"),
                "ip_address": s.get("ipAddress"), "client_app_used": s.get("clientAppUsed"),
                "authentication_protocol": s.get("authenticationProtocol"), "error_code": s.get("status", {}).get("errorCode"),
                "conditional_access_status": s.get("conditionalAccessStatus"), "result": status_class(s),
                "token_issued": bool(s.get("uniqueTokenIdentifier")),
            })
    write_csv(working / "legacy-authentication-candidates.csv", legacy_rows,
              ["created_utc", "user_principal_name", "ip_address", "client_app_used", "authentication_protocol", "error_code", "conditional_access_status", "result", "token_issued"])

    # Password spray candidates: same IP, failures across >= 3 users in 15 minutes.
    spray_rows = []
    failures = [s for s in signins if status_class(s) == "failure" and int(s.get("status", {}).get("errorCode", 0)) == 50126 and s.get("userPrincipalName")]
    by_ip: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for s in failures:
        by_ip[s["ipAddress"]].append(s)
    for ip, rows in sorted(by_ip.items()):
        rows.sort(key=lambda r: r["createdDateTime"])
        users_seen = sorted({r["userPrincipalName"] for r in rows})
        duration = (parse_dt(rows[-1]["createdDateTime"]) - parse_dt(rows[0]["createdDateTime"])).total_seconds() / 60
        if len(users_seen) >= 3 and duration <= 15:
            spray_rows.append({
                "ip_address": ip, "first_utc": rows[0]["createdDateTime"], "last_utc": rows[-1]["createdDateTime"],
                "duration_minutes": round(duration, 2), "attempt_count": len(rows), "distinct_users": len(users_seen),
                "users": users_seen, "error_code": 50126, "candidate": True,
            })
    write_csv(working / "password-spray-candidates.csv", spray_rows,
              ["ip_address", "first_utc", "last_utc", "duration_minutes", "attempt_count", "distinct_users", "users", "error_code", "candidate"])

    # MFA fatigue candidates: >= 3 denied/timeout attempts then success for same user/IP within 15 minutes.
    mfa_by_user_ip: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for s in signins:
        outcomes = [mfa_outcome(step) for step in s.get("authenticationDetails", [])]
        if any(o in {"denied", "timeout", "success"} for o in outcomes):
            mfa_by_user_ip[(s.get("userPrincipalName", ""), s.get("ipAddress", ""))].append({"signin": s, "outcomes": outcomes})
    fatigue_rows = []
    for (user, ip), items in sorted(mfa_by_user_ip.items()):
        if not user:
            continue
        items.sort(key=lambda x: x["signin"]["createdDateTime"])
        failures_before = []
        for index, item in enumerate(items):
            s = item["signin"]
            if "success" in item["outcomes"] and status_class(s) == "success":
                start = parse_dt(s["createdDateTime"]) - __import__("datetime").timedelta(minutes=15)
                failures_before = [x for x in items[:index] if parse_dt(x["signin"]["createdDateTime"]) >= start and any(o in {"denied", "timeout"} for o in x["outcomes"])]
                if len(failures_before) >= 3:
                    counts = Counter(o for x in failures_before for o in x["outcomes"] if o in {"denied", "timeout"})
                    fatigue_rows.append({
                        "user_principal_name": user, "ip_address": ip,
                        "first_failure_utc": failures_before[0]["signin"]["createdDateTime"],
                        "success_utc": s["createdDateTime"], "failure_count": len(failures_before),
                        "denied_count": counts["denied"], "timeout_count": counts["timeout"],
                        "success_signin_id": s.get("id"), "session_id": s.get("sessionId"),
                        "candidate": True, "assessment_note": "Repeated denied/timeout MFA attempts followed by success; user verification is required before treating the approval as unauthorized.",
                    })
    write_csv(working / "mfa-fatigue-candidates.csv", fatigue_rows,
              ["user_principal_name", "ip_address", "first_failure_utc", "success_utc", "failure_count", "denied_count", "timeout_count", "success_signin_id", "session_id", "candidate", "assessment_note"])

    # Impossible/atypical travel candidates from successive interactive success events.
    travel_rows = []
    successful_interactive_by_user: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for s in signins:
        if s.get("userPrincipalName") and s.get("isInteractive") and status_class(s) == "success":
            successful_interactive_by_user[s["userPrincipalName"]].append(s)
    for user, rows in successful_interactive_by_user.items():
        rows.sort(key=lambda r: r["createdDateTime"])
        for prev, curr in zip(rows, rows[1:]):
            hours = (parse_dt(curr["createdDateTime"]) - parse_dt(prev["createdDateTime"])).total_seconds() / 3600
            distance = geo_distance_km(prev.get("locationDetails", {}), curr.get("locationDetails", {}))
            if distance is None or hours <= 0:
                continue
            speed = distance / hours
            if distance >= 1000 and hours <= 6:
                approved_explanation = curr.get("ipAddress") in approved_ips or prev.get("ipAddress") in approved_ips
                travel_rows.append({
                    "user_principal_name": user, "previous_utc": prev.get("createdDateTime"), "current_utc": curr.get("createdDateTime"),
                    "previous_country_city": f"{prev.get('locationDetails', {}).get('countryOrRegion', '')}/{prev.get('locationDetails', {}).get('city', '')}",
                    "current_country_city": f"{curr.get('locationDetails', {}).get('countryOrRegion', '')}/{curr.get('locationDetails', {}).get('city', '')}",
                    "distance_km": round(distance, 1), "elapsed_hours": round(hours, 2), "implied_speed_kmh": round(speed, 1),
                    "approved_network_explanation": approved_explanation,
                    "candidate": not approved_explanation,
                    "assessment_note": "GeoIP and calculated speed are investigative leads, not proof of physical travel.",
                })
    write_csv(working / "impossible-travel-candidates.csv", travel_rows,
              ["user_principal_name", "previous_utc", "current_utc", "previous_country_city", "current_country_city", "distance_km", "elapsed_hours", "implied_speed_kmh", "approved_network_explanation", "candidate", "assessment_note"])

    # Token refresh and duplicate-event analysis.
    token_rows = []
    sessions: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for s in signins:
        if s.get("sessionId"):
            sessions[s["sessionId"]].append(s)
    for session_id, rows in sorted(sessions.items()):
        rows.sort(key=lambda r: r["createdDateTime"])
        noninteractive = [r for r in rows if r.get("signInLogType") == "nonInteractiveUser"]
        tokens = [r.get("uniqueTokenIdentifier") for r in rows if r.get("uniqueTokenIdentifier")]
        fingerprints = Counter((r.get("userId"), r.get("ipAddress"), r.get("appId"), r.get("resourceId"), r.get("status", {}).get("errorCode")) for r in rows)
        token_rows.append({
            "session_id": session_id, "first_utc": rows[0]["createdDateTime"], "last_utc": rows[-1]["createdDateTime"],
            "event_count": len(rows), "interactive_count": sum(bool(r.get("isInteractive")) for r in rows),
            "noninteractive_count": len(noninteractive), "unique_token_count": len(set(tokens)),
            "same_fingerprint_repetitions": sum(v - 1 for v in fingerprints.values() if v > 1),
            "users_or_identities": sorted({r.get("userPrincipalName") or r.get("servicePrincipalName") or r.get("managedIdentityName") for r in rows}),
            "interpretation": "Non-interactive records can represent token refresh or background access; they are not separate MFA approvals.",
        })
    write_csv(working / "token-refresh-and-duplicate-event-analysis.csv", token_rows,
              ["session_id", "first_utc", "last_utc", "event_count", "interactive_count", "noninteractive_count", "unique_token_count", "same_fingerprint_repetitions", "users_or_identities", "interpretation"])

    # Follow-on activity.
    follow_rows = []
    for a in audits:
        actor = a.get("initiatedBy", {}).get("user", {})
        targets = a.get("targetResources", [])
        follow_rows.append({
            "activity_utc": a.get("activityDateTime"), "source": "Entra directory audit", "activity": a.get("activityDisplayName"),
            "result": a.get("result"), "actor": actor.get("userPrincipalName", ""), "actor_ip": actor.get("ipAddress", ""),
            "target": targets[0].get("userPrincipalName", "") if targets else "", "correlation_id": a.get("correlationId"),
            "session_id": "", "object_or_parameters": targets,
        })
    for a in m365:
        follow_rows.append({
            "activity_utc": a.get("creationTime"), "source": "M365 unified audit", "activity": a.get("operation"),
            "result": a.get("resultStatus"), "actor": a.get("userId"), "actor_ip": a.get("clientIP"),
            "target": a.get("objectId"), "correlation_id": "", "session_id": a.get("sessionId"),
            "object_or_parameters": a.get("parameters", {}),
        })
    follow_rows.sort(key=lambda r: r["activity_utc"])
    write_csv(working / "follow-on-audit-activity.csv", follow_rows,
              ["activity_utc", "source", "activity", "result", "actor", "actor_ip", "target", "correlation_id", "session_id", "object_or_parameters"])

    # Candidate compromise assessment without reading ground-truth.json.
    verification = business.get("userVerification", {})
    verified_user = verification.get("userPrincipalName", "")
    verification_outcome = verification.get("verificationOutcome", "")
    compromise_rows = []
    for user in sorted({s.get("userPrincipalName") for s in signins if s.get("userPrincipalName")}):
        user_events = [s for s in signins if s.get("userPrincipalName") == user]
        suspicious_successes = [s for s in user_events if status_class(s) == "success" and s.get("isInteractive") and (s.get("riskLevelDuringSignIn") in {"medium", "high"} or s.get("isAnonymousProxy") or s.get("deviceDetail", {}).get("isManaged") is False)]
        fatigue = [r for r in fatigue_rows if r["user_principal_name"] == user]
        spray_targeted = any(user in r["users"] for r in spray_rows)
        follow = [r for r in follow_rows if r["actor"] == user or r["target"] == user]
        unauthorized_verified = user == verified_user and "unauthorized" in verification_outcome.lower()
        evidence = []
        if spray_targeted:
            evidence.append("password_spray_pattern")
        if fatigue:
            evidence.append("repeated_mfa_failure_then_success")
        if suspicious_successes:
            evidence.append("suspicious_successful_interactive_signin")
        if follow:
            evidence.append("follow_on_audit_activity")
        if unauthorized_verified:
            evidence.append("user_verified_unauthorized")
        if unauthorized_verified and suspicious_successes and follow:
            classification = "Confirmed account compromise"
        elif suspicious_successes and (fatigue or follow):
            classification = "Possible account compromise"
        elif suspicious_successes:
            classification = "Suspicious successful sign-in"
        elif spray_targeted:
            classification = "Unsuccessful attack"
        else:
            classification = "Benign"
        compromise_rows.append({
            "user_principal_name": user, "candidate_classification": classification,
            "spray_targeted": spray_targeted, "mfa_fatigue_candidate": bool(fatigue),
            "suspicious_success_count": len(suspicious_successes), "follow_on_activity_count": len(follow),
            "user_verified_unauthorized": unauthorized_verified, "supporting_evidence": evidence,
            "assessment_boundary": "First-pass candidate only. Platform risk, telemetry facts, business verification and ground truth remain separate evidence classes.",
        })
    write_csv(working / "possible-compromise-candidates.csv", compromise_rows,
              ["user_principal_name", "candidate_classification", "spray_targeted", "mfa_fatigue_candidate", "suspicious_success_count", "follow_on_activity_count", "user_verified_unauthorized", "supporting_evidence", "assessment_boundary"])

    # Detection gaps.
    gaps = [
        {"area": "Authenticator approval context", "status": "Not available", "impact": "No Authenticator GPS or approving-device telemetry; accidental approval is confirmed through business verification, not device telemetry."},
        {"area": "Raw token material", "status": "Intentionally excluded", "impact": "No access token, refresh token, cookie, Authorization header, MFA seed or secret is present."},
        {"area": "Conditional Access internal condition trace", "status": "Not available", "impact": "Applied policy results and controls are present; internal condition evaluation traces are not modeled."},
        {"area": "Real GeoIP enrichment", "status": "Not applicable", "impact": "IPs and locations are synthetic; location analysis tests logic rather than third-party GeoIP accuracy."},
        {"area": "Cross-tenant activity", "status": "Not observed", "impact": "The scenario does not model B2B, service-provider or passthrough sign-ins."},
        {"area": "Production license behavior", "status": "Synthetic", "impact": "Risk fields emulate P2-equivalent visibility; actual tenants may return hidden or delayed values."},
        {"area": "Original portal export fidelity", "status": "Detection gap", "impact": "Field semantics follow official schemas, but the files are not byte-for-byte portal or Graph exports."},
    ]
    write_csv(working / "detection-gaps.csv", gaps, ["area", "status", "impact"])

    # SQLite database.
    create_sqlite(working / "scenario17-analysis.sqlite", signins, audits, m365, risks)

    # Compact first-pass summary.
    class_counts = Counter(r["candidate_classification"] for r in compromise_rows)
    summary_lines = [
        "SCENARIO 17 FIRST-PASS SUMMARY",
        "================================",
        f"Dataset synthetic: {manifest.get('synthetic')}",
        f"Sign-in records: {len(signins)}",
        f"Directory audit records: {len(audits)}",
        f"M365 audit records: {len(m365)}",
        f"Risk detections: {len(risks)}",
        f"Interactive user sign-ins: {sum(s.get('signInLogType') == 'interactiveUser' for s in signins)}",
        f"Non-interactive user sign-ins: {sum(s.get('signInLogType') == 'nonInteractiveUser' for s in signins)}",
        f"Service-principal sign-ins: {sum(s.get('signInLogType') == 'servicePrincipal' for s in signins)}",
        f"Managed-identity sign-ins: {sum(s.get('signInLogType') == 'managedIdentity' for s in signins)}",
        f"Successful sign-ins: {sum(status_class(s) == 'success' for s in signins)}",
        f"Failed sign-ins: {sum(status_class(s) == 'failure' for s in signins)}",
        f"Password-spray candidates: {len(spray_rows)}",
        f"MFA-fatigue candidates: {len(fatigue_rows)}",
        f"Legacy-authentication candidates: {len(legacy_rows)}",
        f"Travel candidates: {sum(bool(r['candidate']) for r in travel_rows)} suspicious / {sum(bool(r['approved_network_explanation']) for r in travel_rows)} explained by approved network",
        f"Candidate classifications: {dict(class_counts)}",
        "",
        "Evidence separation:",
        "- Telemetry-confirmed facts: parsed sign-ins, authentication steps, CA results, IDs and audit events.",
        "- Platform-generated risk: risk detections and sign-in risk fields; these are leads, not proof.",
        "- Business context: approved networks and user verification.",
        "- Ground truth: stored separately and not read for the candidate assessment.",
        "",
        f"Working output directory: {working}",
    ]
    (working / "first-pass-summary.txt").write_text("\n".join(summary_lines) + "\n", encoding="utf-8")

    # A compact output inventory.
    output_rows = []
    for path in sorted(p for p in working.iterdir() if p.is_file()):
        output_rows.append({"file_name": path.name, "size_bytes": path.stat().st_size, "sha256": sha256(path)})
    write_tsv(working / "first-pass-output-manifest.tsv", output_rows, ["file_name", "size_bytes", "sha256"])

    print("\n".join(summary_lines))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
