#!/usr/bin/env python3
"""Validate Scenario 18 synthetic evidence safety, schema shape, and referential integrity."""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

DOC_NETS = [
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
]
UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$", re.I)
FORBIDDEN_KEYS = {
    "accesstoken", "refreshtoken", "idtoken", "authorization", "cookie",
    "privatekey", "clientsecret", "secrettext", "secretvalue", "password",
}
FORBIDDEN_TEXT = ["-----BEGIN PRIVATE KEY-----", "-----BEGIN CERTIFICATE-----", "Bearer ", "eyJ"]

def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))

def load_jsonl(path: Path) -> list[Any]:
    rows = []
    for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if line.strip():
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path}:{n}: {exc}") from exc
    return rows

def walk(obj: Any, path: str = "$") -> Iterable[tuple[str, str, Any]]:
    if isinstance(obj, dict):
        for key, value in obj.items():
            yield path, key, value
            yield from walk(value, f"{path}.{key}")
    elif isinstance(obj, list):
        for index, value in enumerate(obj):
            yield from walk(value, f"{path}[{index}]")

def collect_ips(obj: Any) -> list[str]:
    ips = []
    for _, key, value in walk(obj):
        if key.lower() in {"ipaddress", "sourceip", "ip"} and isinstance(value, str):
            ips.append(value)
    return ips

def parse_utc(value: str | None) -> datetime | None:
    if not value:
        return None
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return parsed.astimezone(timezone.utc)

def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--report", required=True, type=Path)
    args = parser.parse_args()

    base = args.input.resolve()
    report_path = args.report.resolve()
    errors: list[str] = []
    warnings: list[str] = []

    required = [
        "00-package-metadata.json", "01-directory-audit.jsonl", "02-application-objects.json",
        "03-service-principal-objects.json", "04-oauth2-permission-grants.json",
        "05-app-role-assignments.json", "06-directory-role-assignments.json",
        "07-credential-metadata.json", "08-user-signins.jsonl",
        "09-service-principal-signins.jsonl", "10-api-and-resource-activity.jsonl",
        "11-business-and-governance-context.json", "12-platform-risk-signals.jsonl",
        "README-SYNTHETIC.md", "SHA256SUMS.tsv", "ground-truth/simulation-ground-truth.json",
    ]
    for name in required:
        if not (base / name).is_file():
            errors.append(f"Missing required file: {name}")

    if errors:
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(json.dumps({"status": "FAIL", "errors": errors}, indent=2) + "\n")
        print("\n".join(errors), file=sys.stderr)
        return 1

    loaded: dict[str, Any] = {}
    for path in sorted(base.rglob("*")):
        if not path.is_file() or path.name in {"SHA256SUMS.tsv", "README-SYNTHETIC.md"}:
            continue
        rel = str(path.relative_to(base))
        try:
            loaded[rel] = load_jsonl(path) if path.suffix == ".jsonl" else load_json(path)
        except Exception as exc:
            errors.append(f"Parse failure {rel}: {exc}")

    metadata = loaded["00-package-metadata.json"]
    if metadata.get("synthetic") is not True:
        errors.append("Package metadata does not assert synthetic=true")
    if metadata.get("safety", {}).get("connectsToRealTenant") is not False:
        errors.append("Safety metadata does not assert connectsToRealTenant=false")

    for rel, obj in loaded.items():
        for json_path, key, value in walk(obj):
            key_norm = key.lower().replace("_", "")
            if key_norm in FORBIDDEN_KEYS:
                allowed_marker = value in (None, False, "[NOT RECORDED]")
                if not allowed_marker:
                    errors.append(f"Forbidden material key/value at {rel}:{json_path}.{key}")
            if isinstance(value, str):
                for marker in FORBIDDEN_TEXT:
                    if marker in value:
                        errors.append(f"Forbidden material marker {marker!r} at {rel}:{json_path}.{key}")
                if "@" in value and not value.endswith("@synthetic.example"):
                    warnings.append(f"Non-UPN string contains @ outside synthetic.example at {rel}:{json_path}.{key}")
        for ip_text in collect_ips(obj):
            try:
                ip = ipaddress.ip_address(ip_text)
                if not any(ip in net for net in DOC_NETS):
                    errors.append(f"Non-documentation IP at {rel}: {ip_text}")
            except ValueError:
                errors.append(f"Invalid IP at {rel}: {ip_text}")

    apps = loaded["02-application-objects.json"]
    sps = loaded["03-service-principal-objects.json"]
    oauth = loaded["04-oauth2-permission-grants.json"]
    app_roles = loaded["05-app-role-assignments.json"]
    creds = loaded["07-credential-metadata.json"]
    sp_signins = loaded["09-service-principal-signins.jsonl"]

    app_ids = {row["appId"] for row in apps}
    app_object_ids = {row["id"] for row in apps}
    sp_ids = {row["id"] for row in sps}
    sp_app_ids = {row["appId"] for row in sps}
    cred_ids = {row["keyId"] for row in creds}
    creds_by_id = {row["keyId"]: row for row in creds}

    if not app_ids.issubset(sp_app_ids):
        warnings.append("At least one application appId has no same-tenant service principal snapshot")

    for row in oauth:
        if row["clientId"] not in sp_ids:
            errors.append(f"OAuth grant clientId is not a service-principal object ID: {row['id']}")
        if row["resourceId"] not in sp_ids:
            errors.append(f"OAuth grant resourceId is not a service-principal object ID: {row['id']}")
        if row["consentType"] == "AllPrincipals" and row["principalId"] is not None:
            errors.append(f"AllPrincipals grant must have principalId=null: {row['id']}")

    for row in app_roles:
        if row["principalId"] not in sp_ids:
            errors.append(f"App-role principalId missing from SP inventory: {row['id']}")
        if row["resourceId"] not in sp_ids:
            errors.append(f"App-role resourceId missing from SP inventory: {row['id']}")

    for row in creds:
        if row["applicationObjectId"] not in app_object_ids:
            errors.append(f"Credential applicationObjectId missing: {row['keyId']}")
        if row["servicePrincipalObjectId"] not in sp_ids:
            errors.append(f"Credential servicePrincipalObjectId missing: {row['keyId']}")
        if row.get("materialRecorded") is not False:
            errors.append(f"Credential materialRecorded must be false: {row['keyId']}")

    for row in sp_signins:
        if row["ServicePrincipalId"] not in sp_ids:
            errors.append(f"Sign-in ServicePrincipalId missing from object inventory: {row['Id']}")
        key_id = row.get("ServicePrincipalCredentialKeyId")
        fic_id = row.get("FederatedCredentialId")
        if key_id and key_id not in cred_ids:
            errors.append(f"Sign-in credential key ID missing from metadata: {row['Id']}")
        if fic_id and fic_id not in cred_ids:
            errors.append(f"Sign-in federated credential ID missing from metadata: {row['Id']}")
        matched_id = key_id or fic_id
        if matched_id and matched_id in creds_by_id:
            cred = creds_by_id[matched_id]
            signin_time = parse_utc(row.get("CreatedDateTime"))
            start_time = parse_utc(cred.get("startDateTime"))
            end_time = parse_utc(cred.get("endDateTime"))
            if signin_time and start_time and signin_time < start_time:
                errors.append(
                    f"Sign-in predates credential validity: {row['Id']} uses {matched_id} "
                    f"at {row.get('CreatedDateTime')} before {cred.get('startDateTime')}"
                )
            if signin_time and end_time and signin_time > end_time:
                errors.append(
                    f"Sign-in occurs after credential expiry: {row['Id']} uses {matched_id} "
                    f"at {row.get('CreatedDateTime')} after {cred.get('endDateTime')}"
                )

    # Verify SHA-256 manifest without trusting the manifest itself.
    manifest_lines = (base / "SHA256SUMS.tsv").read_text(encoding="utf-8").splitlines()
    for line in manifest_lines[1:]:
        rel, size_text, expected = line.split("\t")
        path = base / rel
        if not path.is_file():
            errors.append(f"Manifest references missing file: {rel}")
            continue
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
        if actual != expected:
            errors.append(f"SHA-256 mismatch: {rel}")
        if path.stat().st_size != int(size_text):
            errors.append(f"Size mismatch: {rel}")

    report = {
        "status": "PASS" if not errors else "FAIL",
        "input": str(base),
        "filesChecked": len(required),
        "objectsChecked": sum(len(v) if isinstance(v, list) else 1 for v in loaded.values()),
        "errors": errors,
        "warnings": sorted(set(warnings)),
        "checks": {
            "syntheticMarker": True,
            "secretMaterialAbsent": not any("Forbidden material" in e for e in errors),
            "documentationIpsOnly": not any("IP" in e for e in errors),
            "referentialIntegrity": not any(("missing" in e.lower() or "not a service" in e.lower()) for e in errors),
            "sha256Manifest": not any(("SHA-256" in e or "Size mismatch" in e) for e in errors),
        },
    }
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"status": report["status"], "errors": len(errors), "warnings": len(report["warnings"]), "report": str(report_path)}, indent=2))
    return 0 if not errors else 1

if __name__ == "__main__":
    raise SystemExit(main())
