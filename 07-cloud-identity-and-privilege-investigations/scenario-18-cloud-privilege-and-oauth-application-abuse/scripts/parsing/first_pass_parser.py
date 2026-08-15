#!/usr/bin/env python3
"""Create first-pass working outputs without reading synthetic ground truth."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import sqlite3
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))

def load_jsonl(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]

def write_csv(path: Path, rows: list[dict[str, Any]], fields: list[str] | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if fields is None:
        fields = sorted({key for row in rows for key in row}) if rows else ["status"]
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore", lineterminator="\n")
        writer.writeheader()
        for row in rows:
            writer.writerow({k: "" if row.get(k) is None else row.get(k) for k in fields})

def json_compact(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))

def top_fields(records: list[dict[str, Any]]) -> Counter:
    result = Counter()
    for row in records:
        result.update(row.keys())
    return result

def parse_utc(value: str | None) -> datetime | None:
    if not value:
        return None
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return parsed.astimezone(timezone.utc)

def within_credential_validity(signin: dict[str, Any], cred: dict[str, Any]) -> bool:
    signin_time = parse_utc(signin.get("CreatedDateTime"))
    start_time = parse_utc(cred.get("startDateTime"))
    end_time = parse_utc(cred.get("endDateTime"))
    if signin_time is None:
        return False
    if start_time and signin_time < start_time:
        return False
    if end_time and signin_time > end_time:
        return False
    return True

def parse_modified(targets: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows = []
    for target in targets:
        for prop in target.get("modifiedProperties", []):
            rows.append({
                "target_id": target.get("id"),
                "target_type": target.get("type"),
                "target_display_name": target.get("displayName"),
                "property": prop.get("displayName"),
                "old_value": prop.get("oldValue"),
                "new_value": prop.get("newValue"),
            })
    return rows

def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    raw = args.input.resolve()
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=True)

    metadata = load_json(raw / "00-package-metadata.json")
    audits = load_jsonl(raw / "01-directory-audit.jsonl")
    apps = load_json(raw / "02-application-objects.json")
    sps = load_json(raw / "03-service-principal-objects.json")
    oauth = load_json(raw / "04-oauth2-permission-grants.json")
    app_roles = load_json(raw / "05-app-role-assignments.json")
    dir_roles = load_json(raw / "06-directory-role-assignments.json")
    creds = load_json(raw / "07-credential-metadata.json")
    user_signins = load_jsonl(raw / "08-user-signins.jsonl")
    sp_signins = load_jsonl(raw / "09-service-principal-signins.jsonl")
    api = load_jsonl(raw / "10-api-and-resource-activity.jsonl")
    governance = load_json(raw / "11-business-and-governance-context.json")
    risk = load_jsonl(raw / "12-platform-risk-signals.jsonl")

    datasets = {
        "directory_audit": audits, "application_objects": apps, "service_principal_objects": sps,
        "oauth_grants": oauth, "app_role_assignments": app_roles, "directory_role_assignments": dir_roles,
        "credential_metadata": creds, "user_signins": user_signins, "service_principal_signins": sp_signins,
        "api_activity": api, "platform_risk": risk,
    }

    schema_rows = []
    for name, records in datasets.items():
        counts = top_fields(records)
        for field, count in sorted(counts.items()):
            schema_rows.append({"dataset": name, "record_count": len(records), "field": field, "records_with_field": count})
    write_csv(out / "schema-profile.csv", schema_rows, ["dataset", "record_count", "field", "records_with_field"])

    time_rows = []
    for source_name, records, field in [
        ("directory_audit", audits, "activityDateTime"),
        ("user_signins", user_signins, "CreatedDateTime"),
        ("service_principal_signins", sp_signins, "CreatedDateTime"),
        ("api_activity", api, "TimeGenerated"),
        ("platform_risk", risk, "TimeGenerated"),
    ]:
        values = sorted(row.get(field) for row in records if row.get(field))
        time_rows.append({
            "source": source_name,
            "timestamp_field": field,
            "record_count": len(values),
            "minimum_utc": values[0] if values else None,
            "maximum_utc": values[-1] if values else None,
            "original_timezone_context": metadata.get("originalTimezoneContext"),
            "normalised_timezone": "UTC",
        })
    write_csv(out / "time-and-timezone-profile.csv", time_rows)

    audit_summary_rows = []
    audit_modified_rows = []
    for event in audits:
        initiated = event.get("initiatedBy", {})
        user_actor = initiated.get("user") or {}
        app_actor = initiated.get("app") or {}
        targets = event.get("targetResources", [])
        audit_summary_rows.append({
            "event_id": event.get("id"),
            "time_utc": event.get("activityDateTime"),
            "activity_display_name": event.get("activityDisplayName"),
            "operation_type": event.get("operationType"),
            "category": event.get("category"),
            "result": event.get("result"),
            "result_reason": event.get("resultReason"),
            "logged_by_service": event.get("loggedByService"),
            "initiated_by_type": "User" if user_actor else "Application" if app_actor else "Unknown",
            "initiating_principal_id": user_actor.get("id") or app_actor.get("servicePrincipalId"),
            "initiating_upn": user_actor.get("userPrincipalName"),
            "initiating_app_id": app_actor.get("appId"),
            "initiating_service_principal_id": app_actor.get("servicePrincipalId"),
            "initiating_ip": user_actor.get("ipAddress"),
            "target_count": len(targets),
            "target_ids": "; ".join(str(x.get("id") or "") for x in targets),
            "target_types": "; ".join(str(x.get("type") or "") for x in targets),
            "target_display_names": "; ".join(str(x.get("displayName") or "") for x in targets),
            "correlation_id": event.get("correlationId"),
        })
        for prop in parse_modified(targets):
            audit_modified_rows.append({
                "event_id": event.get("id"),
                "time_utc": event.get("activityDateTime"),
                "activity_display_name": event.get("activityDisplayName"),
                **prop,
            })
    write_csv(out / "directory-audit-summary.csv", audit_summary_rows)
    write_csv(out / "audit-modified-properties.csv", audit_modified_rows)

    principal_map: dict[str, dict[str, Any]] = {}

    def observe_principal(
        principal_id: str,
        principal_type: str,
        display_name: str | None,
        upn_or_app_id: str | None,
        source: str,
        ip_address: str | None,
    ) -> None:
        entry = principal_map.setdefault(principal_id, {
            "principal_id": principal_id,
            "principal_type": principal_type,
            "display_name": display_name,
            "upn_or_app_id": upn_or_app_id,
            "_sources": set(),
            "_ips": set(),
            "observation_count": 0,
        })
        entry["observation_count"] += 1
        entry["_sources"].add(source)
        if ip_address:
            entry["_ips"].add(ip_address)
        if not entry.get("display_name") and display_name:
            entry["display_name"] = display_name
        if not entry.get("upn_or_app_id") and upn_or_app_id:
            entry["upn_or_app_id"] = upn_or_app_id

    for event in audits:
        initiated = event.get("initiatedBy", {})
        if initiated.get("user"):
            user = initiated["user"]
            observe_principal(
                user["id"], "User", user.get("displayName"), user.get("userPrincipalName"),
                "directory_audit", user.get("ipAddress"),
            )
        if initiated.get("app"):
            app = initiated["app"]
            key = app.get("servicePrincipalId") or app.get("appId")
            observe_principal(
                key, "ServicePrincipal", app.get("displayName"), app.get("appId"),
                "directory_audit", None,
            )
    for row in user_signins:
        observe_principal(
            row["UserId"], "User", row.get("UserDisplayName"), row.get("UserPrincipalName"),
            "user_signin", row.get("IPAddress"),
        )
    for row in sp_signins:
        observe_principal(
            row["ServicePrincipalId"], "ServicePrincipal", row.get("ServicePrincipalName"), row.get("AppId"),
            "service_principal_signin", row.get("IPAddress"),
        )

    principal_rows = []
    for entry in principal_map.values():
        principal_rows.append({
            "principal_id": entry["principal_id"],
            "principal_type": entry["principal_type"],
            "display_name": entry.get("display_name"),
            "upn_or_app_id": entry.get("upn_or_app_id"),
            "observed_ips": "; ".join(sorted(entry["_ips"])),
            "sources": "; ".join(sorted(entry["_sources"])),
            "observation_count": entry["observation_count"],
        })
    write_csv(out / "principal-inventory.csv", principal_rows)

    app_by_appid = {row["appId"]: row for row in apps}
    sp_rows = []
    for sp in sps:
        app = app_by_appid.get(sp["appId"])
        sp_rows.append({
            "app_id": sp["appId"],
            "application_object_id": app.get("id") if app else None,
            "service_principal_object_id": sp["id"],
            "display_name": sp.get("displayName"),
            "service_principal_type": sp.get("servicePrincipalType"),
            "account_enabled": sp.get("accountEnabled"),
            "application_created_utc": app.get("createdDateTime") if app else None,
            "service_principal_created_utc": sp.get("createdDateTime"),
            "publisher_domain": app.get("publisherDomain") if app else None,
            "verified_publisher": (app.get("verifiedPublisher") or {}).get("displayName") if app else None,
            "owner_count": len(app.get("owners", [])) if app else 0,
        })
    write_csv(out / "application-service-principal-inventory.csv", sp_rows)

    mapping_rows = [{
        "app_id": row["app_id"],
        "application_object_id": row["application_object_id"],
        "service_principal_object_id": row["service_principal_object_id"],
        "display_name": row["display_name"],
        "mapping_status": "Stable appId match" if row["application_object_id"] else "No local application object observed",
    } for row in sp_rows]
    write_csv(out / "app-object-sp-id-mapping.csv", mapping_rows)

    oauth_rows = []
    for grant in oauth:
        oauth_rows.append({
            "grant_id": grant["id"], "client_service_principal_id": grant["clientId"],
            "resource_service_principal_id": grant["resourceId"], "consent_type": grant["consentType"],
            "principal_id": grant.get("principalId"), "scope": grant.get("scope"),
            "permission_type": "Delegated", "created_utc": grant.get("createdDateTime"),
            "consent_interpretation": "Tenant-wide admin consent" if grant["consentType"] == "AllPrincipals" else "User-specific consent",
        })
    write_csv(out / "oauth-grant-inventory.csv", oauth_rows)

    permission_rows = []
    for grant in oauth:
        for scope in grant.get("scope", "").split():
            permission_rows.append({
                "source_id": grant["id"], "source_type": "OAuth2PermissionGrant",
                "permission": scope, "permission_type": "Delegated",
                "consent_type": grant["consentType"], "principal_id": grant.get("principalId"),
                "client_service_principal_id": grant["clientId"], "resource_service_principal_id": grant["resourceId"],
            })
    for assignment in app_roles:
        permission_rows.append({
            "source_id": assignment["id"], "source_type": "AppRoleAssignment",
            "permission": assignment.get("appRoleValue"), "permission_type": "Application",
            "consent_type": "Administrator assignment", "principal_id": assignment["principalId"],
            "client_service_principal_id": assignment["principalId"], "resource_service_principal_id": assignment["resourceId"],
        })
    write_csv(out / "delegated-vs-application-permission-analysis.csv", permission_rows)

    role_rows = []
    for assignment in app_roles:
        role_rows.append({
            "assignment_id": assignment["id"], "role_domain": "Application role / API permission",
            "principal_id": assignment["principalId"], "principal_type": assignment["principalType"],
            "role_or_permission": assignment.get("appRoleValue"), "resource_id": assignment["resourceId"],
            "assignment_type": "Active", "schedule_type": "Permanent", "pim_activated": False,
            "created_utc": assignment.get("createdDateTime"),
        })
    for assignment in dir_roles:
        role_rows.append({
            "assignment_id": assignment["id"], "role_domain": "Entra directory role",
            "principal_id": assignment["principalId"], "principal_type": assignment["principalType"],
            "role_or_permission": assignment.get("roleDisplayName"), "resource_id": assignment.get("roleDefinitionId"),
            "assignment_type": assignment.get("assignmentType"), "schedule_type": assignment.get("scheduleType"),
            "pim_activated": assignment.get("activatedThroughPIM"), "created_utc": assignment.get("startDateTime"),
        })
    write_csv(out / "role-assignment-inventory.csv", role_rows)

    credential_rows = []
    for cred in creds:
        id_matching_signins = [
            row for row in sp_signins
            if row.get("ServicePrincipalCredentialKeyId") == cred["keyId"] or row.get("FederatedCredentialId") == cred["keyId"]
        ]
        valid_matching_signins = [
            row for row in id_matching_signins if within_credential_validity(row, cred)
        ]
        invalid_time_signins = [
            row for row in id_matching_signins if not within_credential_validity(row, cred)
        ]
        credential_rows.append({
            "app_id": cred["appId"], "application_object_id": cred["applicationObjectId"],
            "service_principal_object_id": cred["servicePrincipalObjectId"],
            "credential_type": cred["credentialType"], "key_id": cred["keyId"],
            "display_name": cred["displayName"], "start_utc": cred.get("startDateTime"),
            "end_utc": cred.get("endDateTime"), "usage": cred.get("usage"),
            "material_recorded": cred.get("materialRecorded"), "change_ticket": cred.get("changeTicket"),
            "subsequent_signin_count": len(valid_matching_signins),
            "first_matching_signin_utc": min((x["CreatedDateTime"] for x in valid_matching_signins), default=None),
            "invalid_time_signin_count": len(invalid_time_signins),
            "status_at_package_end": cred.get("statusAtPackageEnd"),
        })
    write_csv(out / "credential-change-inventory.csv", credential_rows)

    sp_signin_rows = []
    for row in sp_signins:
        sp_signin_rows.append({
            "signin_id": row["Id"], "created_utc": row["CreatedDateTime"], "app_id": row["AppId"],
            "service_principal_id": row["ServicePrincipalId"], "service_principal_name": row["ServicePrincipalName"],
            "credential_key_id": row.get("ServicePrincipalCredentialKeyId"),
            "federated_credential_id": row.get("FederatedCredentialId"),
            "client_credential_type": row.get("ClientCredentialType"),
            "authentication_protocol": row.get("AuthenticationProtocol"),
            "resource_id": row.get("ResourceId"), "resource_name": row.get("ResourceDisplayName"),
            "ip_address": row.get("IPAddress"), "asn": row.get("AutonomousSystemNumber"),
            "country": (row.get("Location") or {}).get("countryOrRegion"),
            "result_type": row.get("ResultType"), "correlation_id": row.get("CorrelationId"),
            "original_request_id": row.get("OriginalRequestId"), "unique_token_identifier": row.get("UniqueTokenIdentifier"),
        })
    write_csv(out / "service-principal-signin-summary.csv", sp_signin_rows)

    api_rows = []
    for row in api:
        api_rows.append({
            "time_utc": row["TimeGenerated"], "workload": row["workload"], "operation": row["operation"],
            "actor_type": row["actorType"], "service_principal_id": row.get("servicePrincipalId"),
            "app_id": row.get("appId"), "token_type": row.get("tokenType"),
            "permission_type": row.get("permissionType"), "permission_claim_logged": row.get("permissionClaimLogged"),
            "target_type": row.get("targetType"), "target_object_id": row.get("targetObjectId"),
            "target_name": row.get("targetName"), "result": row.get("result"),
            "source_ip": row.get("sourceIp"), "asn": row.get("autonomousSystemNumber"),
            "country": (row.get("location") or {}).get("countryOrRegion"),
            "request_id": row.get("requestId"), "operation_id": row.get("operationId"),
            "correlation_id": row.get("correlationId"), "unique_token_identifier": row.get("UniqueTokenIdentifier"),
            "data_access_outcome": row.get("dataAccessOutcome"), "response_bytes": row.get("responseBytes"),
        })
    write_csv(out / "api-resource-activity-summary.csv", api_rows)

    timeline_rows = []
    for event in audits:
        initiated = event.get("initiatedBy", {})
        user_actor = initiated.get("user") or {}
        app_actor = initiated.get("app") or {}
        targets = event.get("targetResources", [])
        timeline_rows.append({
            "time_utc": event.get("activityDateTime"),
            "source": "DirectoryAudit",
            "event_type": event.get("category"),
            "actor_type": "User" if user_actor else "ServicePrincipal" if app_actor else "Unknown",
            "actor_id": user_actor.get("id") or app_actor.get("servicePrincipalId"),
            "actor_name": user_actor.get("displayName") or app_actor.get("displayName"),
            "app_id": app_actor.get("appId"),
            "service_principal_id": app_actor.get("servicePrincipalId"),
            "activity": event.get("activityDisplayName"),
            "target": "; ".join(str(x.get("displayName") or x.get("id") or "") for x in targets),
            "result": event.get("result"),
            "source_ip": user_actor.get("ipAddress"),
            "correlation_id": event.get("correlationId"),
            "request_id": next((x.get("value") for x in event.get("additionalDetails", []) if x.get("key") == "RequestId"), None),
            "operation_id": next((x.get("value") for x in event.get("additionalDetails", []) if x.get("key") == "OperationId"), None),
            "token_id": None,
            "evidence_label": "Confirmed",
        })
    for row in user_signins:
        timeline_rows.append({
            "time_utc": row.get("CreatedDateTime"), "source": "UserSignIn", "event_type": "User sign-in",
            "actor_type": "User", "actor_id": row.get("UserId"), "actor_name": row.get("UserDisplayName"),
            "app_id": row.get("AppId"), "service_principal_id": None, "activity": "Interactive user sign-in",
            "target": row.get("ResourceDisplayName"), "result": "success" if (row.get("Status") or {}).get("errorCode") == 0 else "failure",
            "source_ip": row.get("IPAddress"), "correlation_id": row.get("CorrelationId"),
            "request_id": row.get("OriginalRequestId"), "operation_id": None,
            "token_id": row.get("UniqueTokenIdentifier"), "evidence_label": "Confirmed",
        })
    for row in sp_signins:
        timeline_rows.append({
            "time_utc": row.get("CreatedDateTime"), "source": "ServicePrincipalSignIn", "event_type": "Service principal sign-in",
            "actor_type": "ServicePrincipal", "actor_id": row.get("ServicePrincipalId"), "actor_name": row.get("ServicePrincipalName"),
            "app_id": row.get("AppId"), "service_principal_id": row.get("ServicePrincipalId"),
            "activity": f"Application sign-in using {row.get('ClientCredentialType')}",
            "target": row.get("ResourceDisplayName"), "result": "success" if str(row.get("ResultType")) == "0" else "failure",
            "source_ip": row.get("IPAddress"), "correlation_id": row.get("CorrelationId"),
            "request_id": row.get("OriginalRequestId"), "operation_id": None,
            "token_id": row.get("UniqueTokenIdentifier"), "evidence_label": "Confirmed",
        })
    for row in api:
        timeline_rows.append({
            "time_utc": row.get("TimeGenerated"), "source": "APIActivity", "event_type": row.get("workload"),
            "actor_type": row.get("actorType"), "actor_id": row.get("actorObjectId"), "actor_name": None,
            "app_id": row.get("appId"), "service_principal_id": row.get("servicePrincipalId"),
            "activity": row.get("operation"), "target": row.get("targetName"), "result": row.get("result"),
            "source_ip": row.get("sourceIp"), "correlation_id": row.get("correlationId"),
            "request_id": row.get("requestId"), "operation_id": row.get("operationId"),
            "token_id": row.get("UniqueTokenIdentifier"), "evidence_label": "Confirmed",
        })
    for row in risk:
        timeline_rows.append({
            "time_utc": row.get("TimeGenerated"), "source": "PlatformRisk", "event_type": "Platform-generated risk",
            "actor_type": "ServicePrincipal", "actor_id": row.get("Id"), "actor_name": row.get("DisplayName"),
            "app_id": row.get("AppId"), "service_principal_id": row.get("Id"),
            "activity": row.get("OperationName"), "target": None, "result": row.get("RiskState"),
            "source_ip": None, "correlation_id": row.get("CorrelationId"),
            "request_id": None, "operation_id": None, "token_id": None,
            "evidence_label": "Platform-generated risk",
        })
    timeline_rows.sort(key=lambda x: (x.get("time_utc") or "", x.get("source") or ""))
    write_csv(out / "cloud-privilege-event-timeline.csv", timeline_rows)

    owner_rows = []
    for verification in governance.get("ownerVerification", []):
        owner_rows.append({
            "verified_utc": verification.get("verifiedAtUtc"),
            "application_object_id": verification.get("applicationObjectId"),
            "owner_id": verification.get("ownerId"),
            "statement": verification.get("statement"),
            "ticket_found": verification.get("ticketFound"),
            "evidence_type": "Business/governance context",
        })
    write_csv(out / "owner-verification-summary.csv", owner_rows)

    id_rows = []
    for event in audits:
        id_rows.append({
            "source": "directory_audit", "event_id": event["id"], "time_utc": event["activityDateTime"],
            "app_id": (event.get("initiatedBy", {}).get("app") or {}).get("appId"),
            "service_principal_id": (event.get("initiatedBy", {}).get("app") or {}).get("servicePrincipalId"),
            "correlation_id": event.get("correlationId"), "request_id": None, "operation_id": None,
            "token_id": None, "semantic_boundary": "Directory audit operation",
        })
    for row in sp_signins:
        id_rows.append({
            "source": "service_principal_signin", "event_id": row["Id"], "time_utc": row["CreatedDateTime"],
            "app_id": row.get("AppId"), "service_principal_id": row.get("ServicePrincipalId"),
            "correlation_id": row.get("CorrelationId"), "request_id": row.get("OriginalRequestId"),
            "operation_id": None, "token_id": row.get("UniqueTokenIdentifier"),
            "semantic_boundary": "Token request / service principal sign-in",
        })
    for row in api:
        id_rows.append({
            "source": "api_activity", "event_id": row.get("requestId"), "time_utc": row["TimeGenerated"],
            "app_id": row.get("appId"), "service_principal_id": row.get("servicePrincipalId"),
            "correlation_id": row.get("correlationId"), "request_id": row.get("requestId"),
            "operation_id": row.get("operationId"), "token_id": row.get("UniqueTokenIdentifier"),
            "semantic_boundary": "Resource/API operation",
        })
    write_csv(out / "correlation-request-id-inventory.csv", id_rows)

    baseline = governance["applicationBaseline"]
    write_csv(out / "application-baseline.csv", [{
        "application_object_id": baseline["applicationObjectId"], "app_id": baseline["appId"],
        "service_principal_object_id": baseline["servicePrincipalObjectId"],
        "business_owner": baseline["businessOwner"], "technical_owner": baseline["technicalOwner"],
        "expected_resources": "; ".join(baseline["expectedResources"]),
        "expected_credential_types": "; ".join(baseline["expectedCredentialTypes"]),
        "expected_source_countries": "; ".join(baseline["expectedSourceCountries"]),
        "expected_source_ips": "; ".join(baseline["expectedSourceIps"]),
        "expected_permissions": "; ".join(baseline["expectedPermissions"]),
        "last_known_signin_utc": baseline["lastKnownSignInUtc"],
        "baseline_status_at_incident": baseline["baselineStatusAtIncident"],
    }])
    admin_base = governance["administratorBaseline"]
    write_csv(out / "administrator-baseline.csv", [{
        "administrator_id": admin_base["administratorId"], "upn": admin_base["userPrincipalName"],
        "expected_source_countries": "; ".join(admin_base["expectedSourceCountries"]),
        "expected_source_ips": "; ".join(admin_base["expectedSourceIps"]),
        "normal_working_hours": admin_base["normalWorkingHoursLocal"],
        "normal_operations": "; ".join(admin_base["normalOperations"]),
        "not_normally_performed": "; ".join(admin_base["notNormallyPerformed"]),
    }])

    consent_candidates = []
    for row in oauth_rows:
        score = 0
        reasons = []
        if row["consent_type"] == "AllPrincipals":
            score += 4; reasons.append("tenant-wide delegated grant")
        scopes = row["scope"].split()
        if "Mail.ReadWrite" in scopes:
            score += 4; reasons.append("mail read/write scope")
        if "offline_access" in scopes:
            score += 1; reasons.append("offline_access present")
        consent_candidates.append({**row, "risk_score": score, "reasons": "; ".join(reasons), "candidate_status": "Review" if score >= 4 else "Baseline/low risk"})
    write_csv(out / "suspicious-consent-candidates.csv", consent_candidates)

    approved_windows = governance.get("approvedChanges", [])
    sp_to_app_object = {
        row["service_principal_object_id"]: row["application_object_id"] for row in sp_rows
        if row.get("application_object_id")
    }

    def approved_for_time(principal_id: str, created_utc: str | None) -> bool:
        app_object_id = sp_to_app_object.get(principal_id)
        event_time = parse_utc(created_utc)
        if not app_object_id or not event_time:
            return False
        for change in approved_windows:
            if change.get("applicationObjectId") != app_object_id:
                continue
            start = parse_utc(change.get("windowStartUtc"))
            end = parse_utc(change.get("windowEndUtc"))
            if start and end and start <= event_time <= end:
                return True
        return False

    role_candidates = []
    for row in role_rows:
        score = 0
        reasons = []
        approved = approved_for_time(row["principal_id"], row.get("created_utc"))
        if row["principal_type"] == "ServicePrincipal":
            score += 2; reasons.append("service principal assignment")
        if row["role_or_permission"] in {"Application.ReadWrite.All", "AppRoleAssignment.ReadWrite.All"}:
            score += 5; reasons.append("permission can modify applications or assignments")
        if row["role_or_permission"] in {"Sites.Read.All", "Files.Read.All"}:
            score += 4; reasons.append("broad data-read application permission")
        if row["role_domain"] == "Entra directory role":
            score += 5; reasons.append("directory role assigned to application identity")
        if not approved:
            score += 4; reasons.append("no approved change window")
        else:
            reasons.append("inside approved change window")
        role_candidates.append({
            **row,
            "approved_change_window": approved,
            "risk_score": score,
            "reasons": "; ".join(reasons),
            "candidate_status": "Review" if score >= 5 and not approved else "Approved/baseline",
        })
    write_csv(out / "suspicious-role-assignment-candidates.csv", role_candidates)

    cred_candidates = []
    for row in credential_rows:
        score = 0
        reasons = []
        approved = bool(row["change_ticket"])
        if not approved:
            score += 4; reasons.append("no approved change ticket")
        else:
            reasons.append("approved change ticket present")
        if row["subsequent_signin_count"]:
            if approved:
                reasons.append("credential ID observed in valid post-creation sign-in")
            else:
                score += 5; reasons.append("credential ID observed in valid post-creation sign-in")
        if row["invalid_time_signin_count"]:
            score += 10; reasons.append("credential ID observed outside validity period")
        if row["credential_type"] == "Federated identity credential":
            if approved:
                reasons.append("approved external trust relationship")
            else:
                score += 2; reasons.append("external trust persistence path")
        cred_candidates.append({
            **row,
            "approval_status": "Approved" if approved else "No approved change",
            "risk_score": score,
            "reasons": "; ".join(reasons),
            "candidate_status": "Review" if score >= 5 else "Approved/baseline",
        })
    write_csv(out / "suspicious-credential-candidates.csv", cred_candidates)

    write_csv(out / "follow-on-api-activity.csv", api_rows)

    persistence_rows = [
        {
            "mechanism": "Client secret", "object_id": next(x["key_id"] for x in credential_rows if x["credential_type"] == "Client secret"),
            "evidence": "Credential metadata plus matching service-principal sign-in key ID",
            "evidence_label": "Confirmed", "removal_required": "Remove credential and disable/contain service principal",
        },
        {
            "mechanism": "Federated identity credential", "object_id": next(x["key_id"] for x in credential_rows if x["display_name"] == "emergency-build"),
            "evidence": "Audit addition plus matching FederatedCredentialId in later sign-in",
            "evidence_label": "Confirmed", "removal_required": "Remove federated credential and review issuer/subject trust",
        },
        {
            "mechanism": "Application permissions", "object_id": sp_rows[0]["service_principal_object_id"],
            "evidence": "App-role assignments exist and application-only API activity followed; individual permission claim is not logged",
            "evidence_label": "Inferred", "removal_required": "Remove app-role assignments",
        },
    ]
    write_csv(out / "persistence-assessment.csv", persistence_rows)

    revocation_rows = [
        {"action": "Revoke user sessions", "scope": "Compromised administrator user sessions", "terminates_application_only_access": "No", "notes": "Does not remove service-principal credentials or app-role assignments"},
        {"action": "Remove OAuth delegated grant", "scope": "Delegated access on behalf of users", "terminates_application_only_access": "No", "notes": "Separate from application permissions"},
        {"action": "Remove app-role assignments", "scope": "Application permissions", "terminates_application_only_access": "Prevents newly authorised API use after enforcement", "notes": "Already issued tokens may remain valid until expiry or resource enforcement"},
        {"action": "Remove client secret", "scope": "Future authentication using that secret", "terminates_application_only_access": "Not necessarily immediately", "notes": "Does not automatically revoke every previously issued access token"},
        {"action": "Remove federated credential", "scope": "Future token exchange for that trust", "terminates_application_only_access": "Not necessarily immediately", "notes": "Review tokens already issued"},
        {"action": "Disable service principal", "scope": "Application identity", "terminates_application_only_access": "Strong containment control", "notes": "Validate effect and downstream dependencies"},
    ]
    write_csv(out / "revocation-scope-assessment.csv", revocation_rows)

    owner_denial = governance["ownerVerification"][0]["ticketFound"] is False
    possible = [{
        "candidate": "Primary application identity",
        "service_principal_id": baseline["servicePrincipalObjectId"],
        "facts": "Unapproved high-risk grants; unapproved secret; exact credential-key sign-in match; app-only API activity; application-created federated credential; exact federated-ID sign-in match; owner denied change",
        "telemetry_conclusion": "Possible application identity compromise",
        "owner_verification": owner_denial,
        "ground_truth_read": False,
    }]
    write_csv(out / "possible-compromise-candidates.csv", possible)

    gaps = [
        {"area": "Permission claim", "status": "Not available", "impact": "A specific app-role permission used for each API call cannot be directly proven from these API records"},
        {"area": "Delegated grant use", "status": "Not observed", "impact": "No delegated user token or mailbox activity is present"},
        {"area": "Secret material", "status": "Not available by design", "impact": "Audit metadata does not prove who saw the secret value"},
        {"area": "Attacker control", "status": "Inferred", "impact": "Telemetry supports possible compromise; isolated ground truth is required for simulation validation"},
        {"area": "Cross-product correlationId", "status": "Detection gap / semantic limitation", "impact": "Correlation IDs are not assumed to have the same scope across audit, sign-in, and API products"},
        {"area": "Production licensing and retention", "status": "Not available in synthetic package", "impact": "Real investigations may lack service-principal sign-ins or Graph activity due to licensing, export, or retention"},
    ]
    write_csv(out / "detection-gaps.csv", gaps)

    # Acquisition and hash records.
    acquisition_rows = []
    for path in sorted(raw.rglob("*")):
        if path.is_file():
            acquisition_rows.append({
                "relative_path": str(path.relative_to(raw)),
                "size_bytes": path.stat().st_size,
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                "source_type": "synthetic generator",
                "original_modified": "No",
            })
    write_csv(out / "acquisition-manifest.csv", acquisition_rows)
    fields = ["relative_path", "size_bytes", "sha256", "source_type", "original_modified"]
    for tsv_name in ["acquisition-manifest.tsv", "source-sha256-records.tsv"]:
        with (out / tsv_name).open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=fields, delimiter="\t", lineterminator="\n")
            writer.writeheader()
            writer.writerows(acquisition_rows)
    evidence_source_record = {
        "sourceType": "Deterministic synthetic event generator",
        "packageName": metadata["packageName"],
        "packageVersion": metadata["packageVersion"],
        "synthetic": True,
        "externalTenantAccess": False,
        "groundTruthUsedForFirstPass": False,
        "schemaSources": metadata.get("schemaSources", []),
        "analysisBoundary": metadata.get("analysisBoundary", {}),
    }
    (out / "evidence-source-record.json").write_text(
        json.dumps(evidence_source_record, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    # Store raw records as JSON in SQLite for precise follow-up without modifying raw evidence.
    db_path = out / "scenario18-working.sqlite"
    if db_path.exists():
        db_path.unlink()
    conn = sqlite3.connect(db_path)
    try:
        for table, records in datasets.items():
            conn.execute(f'CREATE TABLE "{table}" (row_number INTEGER PRIMARY KEY, json_record TEXT NOT NULL)')
            conn.executemany(f'INSERT INTO "{table}" (row_number, json_record) VALUES (?, ?)',
                             [(i, json.dumps(row, sort_keys=True)) for i, row in enumerate(records, 1)])
        conn.commit()
    finally:
        conn.close()

    summary = {
        "package": metadata["packageName"],
        "groundTruthRead": False,
        "counts": {name: len(records) for name, records in datasets.items()},
        "initialAssessment": "Possible application identity compromise",
        "keyFindings": [
            "Tenant-wide delegated grant and four application permissions were added to the primary service principal.",
            "An active permanent Entra directory role was assigned to the service principal.",
            "A new client-secret key ID was later observed in a successful service-principal sign-in.",
            "The corresponding application-only token ID was observed in successful Graph/API activity.",
            "The application identity created a federated credential, and that exact federated credential ID was later used.",
            "No delegated-token or mailbox use was observed.",
            "Owner verification found no approval or change ticket for the incident changes.",
        ],
    }
    (out / "compact-first-pass-summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (out / "compact-first-pass-summary.txt").write_text(
        "\n".join([
            "Scenario 18 first-pass summary",
            "Ground truth read: NO",
            f"Directory audit events: {len(audits)}",
            f"Service-principal sign-ins: {len(sp_signins)}",
            f"API activities: {len(api)}",
            "Initial assessment: Possible application identity compromise",
            "Strongest link: new credential key ID -> service-principal sign-in -> token ID -> API activity",
            "Delegated permission use: Not observed",
            "Specific application permission claim per API call: Not available",
        ]) + "\n",
        encoding="utf-8",
    )
    print((out / "compact-first-pass-summary.txt").read_text(encoding="utf-8"))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
