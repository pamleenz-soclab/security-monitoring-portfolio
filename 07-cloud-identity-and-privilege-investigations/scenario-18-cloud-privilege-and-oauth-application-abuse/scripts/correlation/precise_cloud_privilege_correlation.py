#!/usr/bin/env python3
"""Perform stable-ID correlation without using cross-product time proximity as proof."""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from datetime import datetime, timezone
from typing import Any

def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))

def load_jsonl(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]

def parse_utc(value: str | None) -> datetime | None:
    if not value:
        return None
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return parsed.astimezone(timezone.utc)

def sign_in_within_validity(signin: dict[str, Any], cred: dict[str, Any]) -> bool:
    signin_time = parse_utc(signin.get("CreatedDateTime"))
    start = parse_utc(cred.get("startDateTime"))
    end = parse_utc(cred.get("endDateTime"))
    if signin_time is None:
        return False
    return (start is None or signin_time >= start) and (end is None or signin_time <= end)

def write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    fields = [
        "link_type", "left_source", "left_event_or_object_id", "right_source",
        "right_event_or_object_id", "stable_key_type", "stable_key_value",
        "evidence_strength", "finding", "boundary",
    ]
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)

def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    raw = args.input.resolve()
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=True)

    apps = load_json(raw / "02-application-objects.json")
    sps = load_json(raw / "03-service-principal-objects.json")
    oauth = load_json(raw / "04-oauth2-permission-grants.json")
    roles = load_json(raw / "05-app-role-assignments.json")
    creds = load_json(raw / "07-credential-metadata.json")
    audits = load_jsonl(raw / "01-directory-audit.jsonl")
    signins = load_jsonl(raw / "09-service-principal-signins.jsonl")
    api = load_jsonl(raw / "10-api-and-resource-activity.jsonl")

    rows: list[dict[str, Any]] = []
    apps_by_appid = {x["appId"]: x for x in apps}
    sps_by_id = {x["id"]: x for x in sps}
    creds_by_id = {x["keyId"]: x for x in creds}
    signins_by_token = {x["UniqueTokenIdentifier"]: x for x in signins if x.get("UniqueTokenIdentifier")}

    for sp in sps:
        app = apps_by_appid.get(sp["appId"])
        if app:
            rows.append({
                "link_type": "Application definition to tenant service principal",
                "left_source": "application_objects", "left_event_or_object_id": app["id"],
                "right_source": "service_principal_objects", "right_event_or_object_id": sp["id"],
                "stable_key_type": "appId", "stable_key_value": sp["appId"],
                "evidence_strength": "Confirmed", "finding": "Application object and service principal map through appId",
                "boundary": "Does not mean the object IDs are interchangeable",
            })

    for grant in oauth:
        if grant["clientId"] in sps_by_id:
            rows.append({
                "link_type": "Delegated grant to client service principal",
                "left_source": "oauth2_permission_grants", "left_event_or_object_id": grant["id"],
                "right_source": "service_principal_objects", "right_event_or_object_id": grant["clientId"],
                "stable_key_type": "servicePrincipal object ID", "stable_key_value": grant["clientId"],
                "evidence_strength": "Confirmed", "finding": "OAuth grant belongs to the client service principal",
                "boundary": "Grant existence does not prove delegated token use",
            })

    for role in roles:
        rows.append({
            "link_type": "Application permission to client service principal",
            "left_source": "app_role_assignments", "left_event_or_object_id": role["id"],
            "right_source": "service_principal_objects", "right_event_or_object_id": role["principalId"],
            "stable_key_type": "servicePrincipal object ID", "stable_key_value": role["principalId"],
            "evidence_strength": "Confirmed", "finding": f"Application permission assigned: {role.get('appRoleValue')}",
            "boundary": "Assignment success does not prove use",
        })

    for signin in signins:
        key_id = signin.get("ServicePrincipalCredentialKeyId") or signin.get("FederatedCredentialId")
        if key_id and key_id in creds_by_id:
            cred = creds_by_id[key_id]
            if not sign_in_within_validity(signin, cred):
                continue
            rows.append({
                "link_type": "Credential metadata to service-principal sign-in",
                "left_source": "credential_metadata", "left_event_or_object_id": key_id,
                "right_source": "service_principal_signins", "right_event_or_object_id": signin["Id"],
                "stable_key_type": "credential key/federated credential ID", "stable_key_value": key_id,
                "evidence_strength": "Confirmed",
                "finding": f"{cred['credentialType']} metadata was used in a successful sign-in",
                "boundary": "Does not by itself identify the human controlling the credential",
            })

    for activity in api:
        token_id = activity.get("UniqueTokenIdentifier")
        signin = signins_by_token.get(token_id)
        if signin:
            rows.append({
                "link_type": "Service-principal sign-in token to API activity",
                "left_source": "service_principal_signins", "left_event_or_object_id": signin["Id"],
                "right_source": "api_activity", "right_event_or_object_id": activity["requestId"],
                "stable_key_type": "UniqueTokenIdentifier", "stable_key_value": token_id,
                "evidence_strength": "Confirmed",
                "finding": f"Token issued in sign-in was used for API operation: {activity['operation']}",
                "boundary": "Specific permission claim is not logged in the API activity",
            })

    # App-initiated audit event can be linked using service-principal ID and request/operation IDs.
    for event in audits:
        app = (event.get("initiatedBy") or {}).get("app")
        if not app:
            continue
        request_ids = {x.get("value") for x in event.get("additionalDetails", []) if x.get("key") == "RequestId"}
        operation_ids = {x.get("value") for x in event.get("additionalDetails", []) if x.get("key") == "OperationId"}
        for activity in api:
            stable = None
            stable_type = None
            if activity.get("requestId") in request_ids:
                stable, stable_type = activity["requestId"], "requestId"
            elif activity.get("operationId") in operation_ids:
                stable, stable_type = activity["operationId"], "operationId"
            if stable and activity.get("servicePrincipalId") == app.get("servicePrincipalId"):
                rows.append({
                    "link_type": "API operation to resulting directory audit",
                    "left_source": "api_activity", "left_event_or_object_id": activity["requestId"],
                    "right_source": "directory_audit", "right_event_or_object_id": event["id"],
                    "stable_key_type": f"{stable_type} + servicePrincipal object ID",
                    "stable_key_value": f"{stable}|{app.get('servicePrincipalId')}",
                    "evidence_strength": "Confirmed",
                    "finding": f"API operation produced directory audit event: {event['activityDisplayName']}",
                    "boundary": "The audit correlationId is not treated as equivalent to the API correlationId",
                })

    write_csv(out / "precise-cloud-privilege-correlation.csv", rows)

    findings = {
        "groundTruthRead": False,
        "confirmedStableIdLinks": len(rows),
        "credentialUsedAfterAddition": any(r["link_type"] == "Credential metadata to service-principal sign-in" and "Client secret" in r["finding"] for r in rows),
        "federatedCredentialUsedAfterAddition": any(r["link_type"] == "Credential metadata to service-principal sign-in" and "Federated identity" in r["finding"] for r in rows),
        "tokenLinkedToApiActivity": any(r["link_type"] == "Service-principal sign-in token to API activity" for r in rows),
        "apiLinkedToAuditChange": any(r["link_type"] == "API operation to resulting directory audit" for r in rows),
        "delegatedGrantUse": "Not observed",
        "specificApplicationPermissionUse": "Inferred; API activity does not log the permission claim",
        "telemetryConclusion": "Possible application identity compromise",
    }
    (out / "precise-cloud-privilege-correlation-summary.json").write_text(
        json.dumps(findings, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps(findings, indent=2))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
