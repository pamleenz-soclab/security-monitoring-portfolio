#!/usr/bin/env python3
"""Generate a deterministic synthetic Microsoft Entra identity investigation dataset.

The dataset is synthetic. It uses reserved documentation IP ranges, example.invalid
identities, private-use ASNs, and deterministic UUIDs. No real tenant, account,
secret, token, or Microsoft service is contacted.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable

DATASET_VERSION = "1.0.0"
GENERATOR_VERSION = "1.0.0"
NAMESPACE = uuid.UUID("63fcbdf0-33ea-4a27-b243-51d9f6544d91")


def uid(label: str) -> str:
    return str(uuid.uuid5(NAMESPACE, label))


def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_jsonl(path: Path, rows: Iterable[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def location(country: str, state: str, city: str, lat: float, lon: float) -> dict[str, Any]:
    return {
        "city": city,
        "state": state,
        "countryOrRegion": country,
        "geoCoordinates": {"latitude": lat, "longitude": lon},
    }


def status(error_code: int, failure_reason: str, additional_details: str) -> dict[str, Any]:
    return {
        "errorCode": error_code,
        "failureReason": failure_reason,
        "additionalDetails": additional_details,
    }


def auth_step(
    dt: datetime,
    method: str,
    detail: str,
    requirement: str,
    result_detail: str,
    succeeded: bool,
) -> dict[str, Any]:
    return {
        "authenticationStepDateTime": iso(dt),
        "authenticationMethod": method,
        "authenticationMethodDetail": detail,
        "authenticationStepRequirement": requirement,
        "authenticationStepResultDetail": result_detail,
        "succeeded": succeeded,
    }


def ca_policy(
    label: str,
    display: str,
    result: str,
    grants: list[str] | None = None,
    sessions: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "id": uid(f"ca-policy:{label}"),
        "displayName": display,
        "result": result,
        "enforcedGrantControls": grants or [],
        "enforcedSessionControls": sessions or [],
    }


def device(
    label: str | None,
    os_name: str,
    browser: str,
    compliant: bool | None,
    managed: bool | None,
    trust: str | None,
) -> dict[str, Any]:
    return {
        "deviceId": uid(f"device:{label}") if label else "",
        "displayName": label or "",
        "operatingSystem": os_name,
        "browser": browser,
        "isCompliant": compliant,
        "isManaged": managed,
        "trustType": trust or "",
    }


def signin(
    *,
    label: str,
    dt: datetime,
    sign_in_type: str,
    identity_type: str,
    user: dict[str, Any] | None,
    app: dict[str, str],
    resource: dict[str, str],
    ip: dict[str, Any],
    client_app: str,
    protocol: str,
    is_interactive: bool,
    event_types: list[str],
    result_status: dict[str, Any],
    auth_requirement: str,
    auth_policies: list[str],
    auth_details: list[dict[str, Any]],
    auth_methods: list[str],
    auth_processing: list[dict[str, str]],
    ca_status: str,
    ca_policies: list[dict[str, Any]],
    device_detail: dict[str, Any],
    risk_during: str = "none",
    risk_aggregated: str = "none",
    risk_state: str = "none",
    risk_detail: str = "none",
    risk_events: list[str] | None = None,
    session_label: str | None = None,
    token_label: str | None = None,
    original_request_label: str | None = None,
    incoming_token_type: str = "none",
    service_principal: dict[str, str] | None = None,
    managed_identity: dict[str, str] | None = None,
    network_names: list[str] | None = None,
    notes: list[str] | None = None,
) -> dict[str, Any]:
    corr = uid(f"correlation:{label}")
    request = uid(f"request:{label}")
    original = uid(f"original-request:{original_request_label or label}")
    row: dict[str, Any] = {
        "syntheticRecord": True,
        "datasetVersion": DATASET_VERSION,
        "recordType": "signIn",
        "signInLogType": sign_in_type,
        "identityType": identity_type,
        "id": uid(f"signin:{label}"),
        "createdDateTime": iso(dt),
        "createdDateTimeOriginalOffset": iso(dt),
        "timeZoneBasis": "UTC",
        "userDisplayName": user["displayName"] if user else "",
        "userPrincipalName": user["userPrincipalName"] if user else "",
        "userId": user["userId"] if user else "",
        "appDisplayName": app["displayName"],
        "appId": app["appId"],
        "resourceDisplayName": resource["displayName"],
        "resourceId": resource["resourceId"],
        "ipAddress": ip["ipAddress"],
        "autonomousSystemNumber": ip["asn"],
        "networkProvider": ip["provider"],
        "isAnonymousProxy": ip["isAnonymousProxy"],
        "isCorporateNetwork": ip["isCorporateNetwork"],
        "location": ip["countryCode"],
        "locationDetails": ip["locationDetails"],
        "clientAppUsed": client_app,
        "authenticationProtocol": protocol,
        "isInteractive": is_interactive,
        "signInEventTypes": event_types,
        "status": result_status,
        "authenticationRequirement": auth_requirement,
        "authenticationRequirementPolicies": auth_policies,
        "authenticationDetails": auth_details,
        "authenticationMethodsUsed": auth_methods,
        "authenticationProcessingDetails": auth_processing,
        "conditionalAccessStatus": ca_status,
        "conditionalAccessPolicies": ca_policies,
        "deviceDetail": device_detail,
        "riskLevelDuringSignIn": risk_during,
        "riskLevelAggregated": risk_aggregated,
        "riskState": risk_state,
        "riskDetail": risk_detail,
        "riskEventTypes_v2": risk_events or [],
        "correlationId": corr,
        "requestId": request,
        "originalRequestId": original,
        "sessionId": uid(f"session:{session_label}") if session_label else "",
        "uniqueTokenIdentifier": uid(f"token:{token_label}") if token_label else "",
        "incomingTokenType": incoming_token_type,
        "servicePrincipalId": service_principal["id"] if service_principal else "",
        "servicePrincipalName": service_principal["displayName"] if service_principal else "",
        "managedIdentityId": managed_identity["id"] if managed_identity else "",
        "managedIdentityName": managed_identity["displayName"] if managed_identity else "",
        "networkLocationDetails": [
            {"networkType": "namedNetwork", "networkNames": network_names or []}
        ] if network_names else [],
        "syntheticNotes": notes or [],
    }
    return row


def audit_record(
    *,
    label: str,
    dt: datetime,
    activity: str,
    category: str,
    result: str,
    initiated_by: dict[str, Any],
    targets: list[dict[str, Any]],
    correlation_label: str | None = None,
    operation_type: str = "Update",
    logged_by: str = "Core Directory",
) -> dict[str, Any]:
    return {
        "syntheticRecord": True,
        "datasetVersion": DATASET_VERSION,
        "recordType": "directoryAudit",
        "id": uid(f"audit:{label}"),
        "activityDateTime": iso(dt),
        "activityDisplayName": activity,
        "category": category,
        "operationType": operation_type,
        "result": result,
        "resultReason": "",
        "loggedByService": logged_by,
        "correlationId": uid(f"correlation:{correlation_label or label}"),
        "initiatedBy": initiated_by,
        "targetResources": targets,
        "additionalDetails": [],
    }


def m365_record(
    *,
    label: str,
    dt: datetime,
    operation: str,
    workload: str,
    user: dict[str, Any],
    ip: dict[str, Any],
    object_id: str,
    parameters: dict[str, Any],
    session_label: str,
) -> dict[str, Any]:
    return {
        "syntheticRecord": True,
        "datasetVersion": DATASET_VERSION,
        "recordType": "m365Audit",
        "id": uid(f"m365:{label}"),
        "creationTime": iso(dt),
        "operation": operation,
        "workload": workload,
        "resultStatus": "Succeeded",
        "userId": user["userPrincipalName"],
        "userKey": user["userId"],
        "clientIP": ip["ipAddress"],
        "objectId": object_id,
        "sessionId": uid(f"session:{session_label}"),
        "parameters": parameters,
    }


def risk_record(
    *,
    label: str,
    dt: datetime,
    detected: datetime,
    sign_in: dict[str, Any],
    user: dict[str, Any],
    risk_type: str,
    level: str,
    timing: str,
    detail: str,
) -> dict[str, Any]:
    return {
        "syntheticRecord": True,
        "datasetVersion": DATASET_VERSION,
        "recordType": "riskDetection",
        "id": uid(f"risk:{label}"),
        "requestId": sign_in["requestId"],
        "correlationId": sign_in["correlationId"],
        "riskEventType": risk_type,
        "riskState": "atRisk",
        "riskLevel": level,
        "riskDetail": detail,
        "source": "activeDirectory",
        "detectionTimingType": timing,
        "activity": "signin",
        "tokenIssuerType": "AzureAD",
        "ipAddress": sign_in["ipAddress"],
        "location": sign_in["locationDetails"],
        "activityDateTime": iso(dt),
        "detectedDateTime": iso(detected),
        "lastUpdatedDateTime": iso(detected),
        "userId": user["userId"],
        "userDisplayName": user["displayName"],
        "userPrincipalName": user["userPrincipalName"],
        "additionalInfo": "Synthetic Identity Protection signal for portfolio analysis.",
    }


def build_dataset(raw_dir: Path) -> dict[str, Any]:
    tenant = {
        "displayName": "Compliant Secure Synthetic Tenant",
        "tenantId": uid("tenant:compliant-secure"),
        "primaryDomain": "compliant-secure.example.invalid",
        "licenseModel": "Synthetic Entra ID P2-equivalent telemetry",
        "dataClassification": "Fully synthetic; no real tenant data",
    }

    users = {
        "maya": {
            "displayName": "Maya Chen",
            "userPrincipalName": "maya.chen@compliant-secure.example.invalid",
            "userId": uid("user:maya"),
            "department": "Finance",
            "role": "Finance Manager",
            "normalCountry": "NZ",
            "normalTimeZone": "Pacific/Auckland",
            "knownDevices": [uid("device:MAYA-MBP-01")],
            "expectedApplications": ["Microsoft 365", "Exchange Online", "SharePoint Online"],
            "breakGlass": False,
            "serviceAccount": False,
        },
        "liam": {
            "displayName": "Liam Ng",
            "userPrincipalName": "liam.ng@compliant-secure.example.invalid",
            "userId": uid("user:liam"),
            "department": "Engineering",
            "role": "Cloud Engineer",
            "normalCountry": "NZ",
            "normalTimeZone": "Pacific/Auckland",
            "knownDevices": [uid("device:LIAM-WIN-01")],
            "expectedApplications": ["Azure Portal", "Microsoft Graph", "Microsoft 365"],
            "breakGlass": False,
            "serviceAccount": False,
        },
        "noah": {
            "displayName": "Noah Wilson",
            "userPrincipalName": "noah.wilson@compliant-secure.example.invalid",
            "userId": uid("user:noah"),
            "department": "Sales",
            "role": "Account Executive",
            "normalCountry": "NZ",
            "normalTimeZone": "Pacific/Auckland",
            "knownDevices": [uid("device:NOAH-IOS-01")],
            "expectedApplications": ["Microsoft 365", "Exchange Online"],
            "breakGlass": False,
            "serviceAccount": False,
        },
        "olivia": {
            "displayName": "Olivia Patel",
            "userPrincipalName": "olivia.patel@compliant-secure.example.invalid",
            "userId": uid("user:olivia"),
            "department": "People and Culture",
            "role": "HR Advisor",
            "normalCountry": "NZ",
            "normalTimeZone": "Pacific/Auckland",
            "knownDevices": [uid("device:OLIVIA-MBP-01")],
            "expectedApplications": ["Microsoft 365", "SharePoint Online"],
            "breakGlass": False,
            "serviceAccount": False,
        },
        "ethan": {
            "displayName": "Ethan Brown",
            "userPrincipalName": "ethan.brown@compliant-secure.example.invalid",
            "userId": uid("user:ethan"),
            "department": "Operations",
            "role": "Operations Analyst",
            "normalCountry": "NZ",
            "normalTimeZone": "Pacific/Auckland",
            "knownDevices": [uid("device:ETHAN-WIN-01")],
            "expectedApplications": ["Microsoft 365", "Exchange Online"],
            "breakGlass": False,
            "serviceAccount": False,
        },
    }

    service_principal = {
        "displayName": "Backup Automation",
        "id": uid("service-principal:backup-automation"),
        "appId": uid("app:backup-automation"),
        "credentialType": "certificate",
        "owner": "Platform Engineering",
    }
    managed_identity = {
        "displayName": "Reporting VM Managed Identity",
        "id": uid("managed-identity:reporting-vm"),
        "resourceId": "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-synthetic/providers/Microsoft.Compute/virtualMachines/vm-reporting",
        "owner": "Data Platform",
    }

    apps = {
        "m365": {"displayName": "Microsoft 365", "appId": uid("app:m365")},
        "outlook": {"displayName": "Office 365 Exchange Online", "appId": uid("app:outlook")},
        "sharepoint": {"displayName": "SharePoint Online", "appId": uid("app:sharepoint")},
        "azure": {"displayName": "Microsoft Azure Portal", "appId": uid("app:azure-portal")},
        "graph": {"displayName": "Microsoft Graph", "appId": uid("app:graph")},
        "legacy": {"displayName": "Exchange Online", "appId": uid("app:legacy-exchange")},
        "backup": {"displayName": service_principal["displayName"], "appId": service_principal["appId"]},
        "mi": {"displayName": managed_identity["displayName"], "appId": uid("app:reporting-mi")},
    }
    resources = {
        "m365": {"displayName": "Microsoft 365", "resourceId": uid("resource:m365")},
        "exchange": {"displayName": "Office 365 Exchange Online", "resourceId": uid("resource:exchange")},
        "sharepoint": {"displayName": "SharePoint Online", "resourceId": uid("resource:sharepoint")},
        "graph": {"displayName": "Microsoft Graph", "resourceId": uid("resource:graph")},
        "vault": {"displayName": "Azure Key Vault", "resourceId": uid("resource:key-vault")},
        "storage": {"displayName": "Azure Storage", "resourceId": uid("resource:storage")},
    }

    ips = {
        "home_akl": {
            "ipAddress": "192.0.2.44",
            "asn": 64512,
            "provider": "Example Fibre NZ",
            "countryCode": "NZ",
            "locationDetails": location("NZ", "Auckland", "Auckland", -36.8485, 174.7633),
            "isAnonymousProxy": False,
            "isCorporateNetwork": False,
        },
        "office_akl": {
            "ipAddress": "192.0.2.80",
            "asn": 64513,
            "provider": "Compliant Secure Corporate Internet",
            "countryCode": "NZ",
            "locationDetails": location("NZ", "Auckland", "Auckland", -36.8500, 174.7650),
            "isAnonymousProxy": False,
            "isCorporateNetwork": True,
        },
        "vpn_sydney": {
            "ipAddress": "203.0.113.10",
            "asn": 64520,
            "provider": "Compliant Secure Corporate VPN",
            "countryCode": "AU",
            "locationDetails": location("AU", "New South Wales", "Sydney", -33.8688, 151.2093),
            "isAnonymousProxy": False,
            "isCorporateNetwork": True,
        },
        "attacker_ro": {
            "ipAddress": "198.51.100.77",
            "asn": 64550,
            "provider": "Example Privacy Hosting",
            "countryCode": "RO",
            "locationDetails": location("RO", "Bucharest", "Bucharest", 44.4268, 26.1025),
            "isAnonymousProxy": True,
            "isCorporateNetwork": False,
        },
        "attacker_de": {
            "ipAddress": "198.51.100.88",
            "asn": 64551,
            "provider": "Example Virtual Hosting",
            "countryCode": "DE",
            "locationDetails": location("DE", "Hesse", "Frankfurt", 50.1109, 8.6821),
            "isAnonymousProxy": False,
            "isCorporateNetwork": False,
        },
        "azure_nz": {
            "ipAddress": "203.0.113.50",
            "asn": 64530,
            "provider": "Synthetic Azure New Zealand",
            "countryCode": "NZ",
            "locationDetails": location("NZ", "Auckland", "Auckland", -36.8485, 174.7633),
            "isAnonymousProxy": False,
            "isCorporateNetwork": True,
        },
    }

    policies = {
        "mfa": ca_policy("mfa-all", "SYN-CA-Require-MFA-All-Users", "success", ["mfa"]),
        "legacy": ca_policy("block-legacy", "SYN-CA-Block-Legacy-Authentication", "notApplied", ["block"]),
        "finance_report": ca_policy(
            "finance-compliant-report",
            "SYN-CA-Require-Compliant-Device-Finance-ReportOnly",
            "reportOnlySuccess",
            ["compliantDevice"],
        ),
        "risk": ca_policy("risk-mfa", "SYN-CA-Require-MFA-High-SignIn-Risk", "notApplied", ["mfa"]),
    }

    signins: list[dict[str, Any]] = []
    audits: list[dict[str, Any]] = []
    m365: list[dict[str, Any]] = []
    risks: list[dict[str, Any]] = []

    # Baseline period: 14 days and at least 10 sign-ins for the target user.
    baseline_start = datetime(2026, 6, 3, 20, 30, tzinfo=timezone.utc)
    baseline_users = ["maya", "liam", "noah", "olivia", "ethan"]
    user_device_labels = {
        "maya": ("MAYA-MBP-01", "macOS", "Safari", "AzureAD"),
        "liam": ("LIAM-WIN-01", "Windows 11", "Edge", "AzureAD"),
        "noah": ("NOAH-IOS-01", "iOS", "Mobile Safari", "AzureAD"),
        "olivia": ("OLIVIA-MBP-01", "macOS", "Chrome", "AzureAD"),
        "ethan": ("ETHAN-WIN-01", "Windows 11", "Edge", "AzureAD"),
    }
    for day in range(14):
        for idx, key in enumerate(baseline_users):
            user = users[key]
            label, os_name, browser, trust = user_device_labels[key]
            dt = baseline_start + timedelta(days=day, minutes=idx * 7)
            app_key = "outlook" if idx % 2 == 0 else "m365"
            resource_key = "exchange" if app_key == "outlook" else "m365"
            s = signin(
                label=f"baseline-{key}-{day}",
                dt=dt,
                sign_in_type="interactiveUser",
                identity_type="user",
                user=user,
                app=apps[app_key],
                resource=resources[resource_key],
                ip=ips["home_akl"] if day % 3 else ips["office_akl"],
                client_app="Browser" if key != "noah" else "Mobile Apps and Desktop clients",
                protocol="oAuth2",
                is_interactive=True,
                event_types=["interactiveUser"],
                result_status=status(0, "", "MFA requirement satisfied by claim in the token."),
                auth_requirement="multiFactorAuthentication",
                auth_policies=["conditionalAccess"],
                auth_details=[
                    auth_step(dt, "Password", "Password hash synchronization", "Primary authentication", "Correct password", True),
                    auth_step(dt + timedelta(seconds=2), "Previously satisfied", "MFA claim", "Multifactor authentication", "MFA requirement satisfied by claim in the token", True),
                ],
                auth_methods=["Password", "Previously satisfied"],
                auth_processing=[{"key": "Legacy TLS", "value": "False"}],
                ca_status="success",
                ca_policies=[policies["mfa"], policies["legacy"]],
                device_detail=device(label, os_name, browser, True, True, trust),
                session_label=f"baseline-session-{key}-{day}",
                token_label=f"baseline-token-{key}-{day}",
                network_names=["Auckland Office"] if day % 3 == 0 else [],
            )
            signins.append(s)

            # A background refresh to establish normal non-interactive behavior.
            n = signin(
                label=f"baseline-refresh-{key}-{day}",
                dt=dt + timedelta(minutes=25),
                sign_in_type="nonInteractiveUser",
                identity_type="user",
                user=user,
                app=apps[app_key],
                resource=resources[resource_key],
                ip=ips["home_akl"] if day % 3 else ips["office_akl"],
                client_app="Mobile Apps and Desktop clients",
                protocol="oAuth2",
                is_interactive=False,
                event_types=["nonInteractiveUser"],
                result_status=status(0, "", "Token refresh completed without user interaction."),
                auth_requirement="multiFactorAuthentication",
                auth_policies=["conditionalAccess"],
                auth_details=[
                    auth_step(dt + timedelta(minutes=25), "Previously satisfied", "MFA claim", "Multifactor authentication", "MFA requirement satisfied by claim in the token", True)
                ],
                auth_methods=["Previously satisfied"],
                auth_processing=[{"key": "Incoming token type", "value": "refreshToken"}],
                ca_status="success",
                ca_policies=[policies["mfa"], policies["legacy"]],
                device_detail=device(label, os_name, browser, True, True, trust),
                session_label=f"baseline-session-{key}-{day}",
                token_label=f"baseline-refresh-token-{key}-{day}",
                incoming_token_type="refreshToken",
            )
            signins.append(n)

    # Benign location anomaly through approved corporate VPN.
    vpn_dt = datetime(2026, 6, 17, 23, 55, tzinfo=timezone.utc)
    vpn_signin = signin(
        label="maya-approved-vpn",
        dt=vpn_dt,
        sign_in_type="interactiveUser",
        identity_type="user",
        user=users["maya"],
        app=apps["m365"],
        resource=resources["m365"],
        ip=ips["vpn_sydney"],
        client_app="Browser",
        protocol="oAuth2",
        is_interactive=True,
        event_types=["interactiveUser"],
        result_status=status(0, "", "MFA completed using number matching."),
        auth_requirement="multiFactorAuthentication",
        auth_policies=["conditionalAccess"],
        auth_details=[
            auth_step(vpn_dt, "Password", "Password hash synchronization", "Primary authentication", "Correct password", True),
            auth_step(vpn_dt + timedelta(seconds=5), "Microsoft Authenticator", "Authenticator app notification with number matching", "Multifactor authentication", "MFA completed in Microsoft Entra ID", True),
        ],
        auth_methods=["Password", "Microsoft Authenticator"],
        auth_processing=[{"key": "Number matching", "value": "True"}],
        ca_status="success",
        ca_policies=[policies["mfa"], policies["legacy"], policies["finance_report"]],
        device_detail=device("MAYA-MBP-01", "macOS", "Safari", True, True, "AzureAD"),
        risk_during="low",
        risk_aggregated="low",
        risk_state="atRisk",
        risk_detail="none",
        risk_events=["newCountry"],
        session_label="maya-approved-vpn-session",
        token_label="maya-approved-vpn-token",
        network_names=["Approved Corporate VPN - Sydney"],
        notes=["Business context confirms this is an approved corporate VPN exit."],
    )
    signins.append(vpn_signin)

    incident_start = datetime(2026, 6, 18, 1, 40, tzinfo=timezone.utc)

    # Distributed password spray against multiple users.
    spray_targets = ["maya", "liam", "noah", "olivia", "ethan"]
    spray_signins: list[dict[str, Any]] = []
    for round_no, ip_key in enumerate(["attacker_ro", "attacker_de"]):
        for idx, key in enumerate(spray_targets):
            dt = incident_start + timedelta(seconds=round_no * 70 + idx * 9)
            s = signin(
                label=f"spray-{round_no}-{key}",
                dt=dt,
                sign_in_type="interactiveUser",
                identity_type="user",
                user=users[key],
                app=apps["m365"],
                resource=resources["m365"],
                ip=ips[ip_key],
                client_app="Browser",
                protocol="oAuth2",
                is_interactive=True,
                event_types=["interactiveUser"],
                result_status=status(50126, "Error validating credentials due to invalid username or password.", "Primary authentication failed before MFA evaluation."),
                auth_requirement="multiFactorAuthentication",
                auth_policies=["conditionalAccess"],
                auth_details=[
                    auth_step(dt, "Password", "Password hash synchronization", "Primary authentication", "Invalid username or password", False)
                ],
                auth_methods=["Password"],
                auth_processing=[{"key": "Legacy TLS", "value": "False"}],
                ca_status="notApplied",
                ca_policies=[
                    ca_policy("mfa-all", "SYN-CA-Require-MFA-All-Users", "notApplied", ["mfa"]),
                    ca_policy("block-legacy", "SYN-CA-Block-Legacy-Authentication", "notApplied", ["block"]),
                ],
                device_detail=device(None, "Windows 11", "Chrome", None, None, None),
                risk_during="medium",
                risk_aggregated="medium",
                risk_state="atRisk",
                risk_detail="none",
                risk_events=["anonymizedIPAddress"] if ip_key == "attacker_ro" else ["unfamiliarFeatures"],
                notes=["Conditional Access did not produce an enforced decision because primary authentication failed."],
            )
            signins.append(s)
            spray_signins.append(s)

    # MFA fatigue sequence after correct primary credentials for Maya.
    fatigue_outcomes = [
        ("denied", "MFA denied; user declined the authentication", 500121),
        ("timeout", "MFA timeout; no response received", 500121),
        ("denied", "MFA denied; user declined the authentication", 500121),
        ("timeout", "MFA timeout; no response received", 500121),
    ]
    fatigue_signins: list[dict[str, Any]] = []
    for idx, (outcome, detail, error) in enumerate(fatigue_outcomes):
        dt = datetime(2026, 6, 18, 1, 44, tzinfo=timezone.utc) + timedelta(seconds=idx * 65)
        s = signin(
            label=f"maya-mfa-fatigue-{idx}",
            dt=dt,
            sign_in_type="interactiveUser",
            identity_type="user",
            user=users["maya"],
            app=apps["m365"],
            resource=resources["m365"],
            ip=ips["attacker_ro"],
            client_app="Browser",
            protocol="oAuth2",
            is_interactive=True,
            event_types=["interactiveUser"],
            result_status=status(error, "Authentication failed during strong authentication request.", detail),
            auth_requirement="multiFactorAuthentication",
            auth_policies=["conditionalAccess", "identityProtection"],
            auth_details=[
                auth_step(dt, "Password", "Password hash synchronization", "Primary authentication", "Correct password", True),
                auth_step(dt + timedelta(seconds=4), "Microsoft Authenticator", "Authenticator app notification with number matching", "Multifactor authentication", detail, False),
            ],
            auth_methods=["Password", "Microsoft Authenticator"],
            auth_processing=[{"key": "Number matching", "value": "True"}],
            ca_status="failure",
            ca_policies=[
                ca_policy("mfa-all", "SYN-CA-Require-MFA-All-Users", "failure", ["mfa"]),
                ca_policy("risk-mfa", "SYN-CA-Require-MFA-High-SignIn-Risk", "failure", ["mfa"]),
                ca_policy("finance-compliant-report", "SYN-CA-Require-Compliant-Device-Finance-ReportOnly", "reportOnlyFailure", ["compliantDevice"]),
            ],
            device_detail=device(None, "Windows 11", "Chrome", False, False, None),
            risk_during="high",
            risk_aggregated="high",
            risk_state="atRisk",
            risk_detail="none",
            risk_events=["anonymizedIPAddress", "unfamiliarFeatures"],
            notes=[f"Synthetic MFA fatigue outcome: {outcome}."],
        )
        signins.append(s)
        fatigue_signins.append(s)

    success_dt = datetime(2026, 6, 18, 1, 49, 10, tzinfo=timezone.utc)
    success_signin = signin(
        label="maya-suspicious-success",
        dt=success_dt,
        sign_in_type="interactiveUser",
        identity_type="user",
        user=users["maya"],
        app=apps["m365"],
        resource=resources["m365"],
        ip=ips["attacker_ro"],
        client_app="Browser",
        protocol="oAuth2",
        is_interactive=True,
        event_types=["interactiveUser"],
        result_status=status(0, "", "MFA completed using Microsoft Authenticator number matching."),
        auth_requirement="multiFactorAuthentication",
        auth_policies=["conditionalAccess", "identityProtection"],
        auth_details=[
            auth_step(success_dt, "Password", "Password hash synchronization", "Primary authentication", "Correct password", True),
            auth_step(success_dt + timedelta(seconds=5), "Microsoft Authenticator", "Authenticator app notification with number matching", "Multifactor authentication", "MFA completed in Microsoft Entra ID", True),
        ],
        auth_methods=["Password", "Microsoft Authenticator"],
        auth_processing=[{"key": "Number matching", "value": "True"}],
        ca_status="success",
        ca_policies=[
            ca_policy("mfa-all", "SYN-CA-Require-MFA-All-Users", "success", ["mfa"]),
            ca_policy("risk-mfa", "SYN-CA-Require-MFA-High-SignIn-Risk", "success", ["mfa"]),
            ca_policy("block-legacy", "SYN-CA-Block-Legacy-Authentication", "notApplied", ["block"]),
            ca_policy("finance-compliant-report", "SYN-CA-Require-Compliant-Device-Finance-ReportOnly", "reportOnlyFailure", ["compliantDevice"]),
        ],
        device_detail=device(None, "Windows 11", "Chrome", False, False, None),
        risk_during="high",
        risk_aggregated="high",
        risk_state="atRisk",
        risk_detail="none",
        risk_events=["anonymizedIPAddress", "unfamiliarFeatures", "unlikelyTravel"],
        session_label="maya-incident-session",
        token_label="maya-incident-initial-token",
        notes=["Report-only compliant-device policy failed but did not block token issuance."],
    )
    signins.append(success_signin)

    # Background token use after the interactive sign-in.
    for idx, (minute, app_key, resource_key) in enumerate([(52, "outlook", "exchange"), (55, "sharepoint", "sharepoint"), (62, "graph", "graph")]):
        dt = datetime(2026, 6, 18, 1, minute % 60, tzinfo=timezone.utc)
        if minute >= 60:
            dt = datetime(2026, 6, 18, 2, minute - 60, tzinfo=timezone.utc)
        n = signin(
            label=f"maya-incident-refresh-{idx}",
            dt=dt,
            sign_in_type="nonInteractiveUser",
            identity_type="user",
            user=users["maya"],
            app=apps[app_key],
            resource=resources[resource_key],
            ip=ips["attacker_ro"],
            client_app="Mobile Apps and Desktop clients",
            protocol="oAuth2",
            is_interactive=False,
            event_types=["nonInteractiveUser"],
            result_status=status(0, "", "Token refresh completed without additional user interaction."),
            auth_requirement="multiFactorAuthentication",
            auth_policies=["conditionalAccess"],
            auth_details=[
                auth_step(dt, "Previously satisfied", "MFA claim", "Multifactor authentication", "MFA requirement satisfied by claim in the token", True)
            ],
            auth_methods=["Previously satisfied"],
            auth_processing=[{"key": "Incoming token type", "value": "refreshToken"}],
            ca_status="success",
            ca_policies=[
                ca_policy("mfa-all", "SYN-CA-Require-MFA-All-Users", "success", ["mfa"]),
                ca_policy("finance-compliant-report", "SYN-CA-Require-Compliant-Device-Finance-ReportOnly", "reportOnlyFailure", ["compliantDevice"]),
            ],
            device_detail=device(None, "Windows 11", "Chrome", False, False, None),
            risk_during="high",
            risk_aggregated="high",
            risk_state="atRisk",
            risk_detail="none",
            risk_events=["anonymizedIPAddress", "unfamiliarFeatures"],
            session_label="maya-incident-session",
            token_label=f"maya-incident-refresh-token-{idx}",
            incoming_token_type="refreshToken",
            notes=["Non-interactive event represents background token activity, not a new MFA approval."],
        )
        signins.append(n)

    # Legacy authentication attempt blocked by Conditional Access.
    legacy_dt = datetime(2026, 6, 18, 2, 8, tzinfo=timezone.utc)
    legacy_signin = signin(
        label="maya-legacy-imap-blocked",
        dt=legacy_dt,
        sign_in_type="interactiveUser",
        identity_type="user",
        user=users["maya"],
        app=apps["legacy"],
        resource=resources["exchange"],
        ip=ips["attacker_de"],
        client_app="IMAP",
        protocol="ropc",
        is_interactive=True,
        event_types=["interactiveUser"],
        result_status=status(53003, "Access has been blocked by Conditional Access policies.", "Legacy authentication was blocked; no token was issued."),
        auth_requirement="singleFactorAuthentication",
        auth_policies=["conditionalAccess"],
        auth_details=[auth_step(legacy_dt, "Password", "Password hash synchronization", "Primary authentication", "Correct password", True)],
        auth_methods=["Password"],
        auth_processing=[{"key": "Legacy authentication", "value": "True"}],
        ca_status="failure",
        ca_policies=[
            ca_policy("block-legacy", "SYN-CA-Block-Legacy-Authentication", "failure", ["block"]),
            ca_policy("mfa-all", "SYN-CA-Require-MFA-All-Users", "notApplied", ["mfa"]),
        ],
        device_detail=device(None, "", "", None, None, None),
        risk_during="high",
        risk_aggregated="high",
        risk_state="atRisk",
        risk_detail="none",
        risk_events=["unfamiliarFeatures"],
        notes=["Correct primary credentials do not imply access; Conditional Access blocked token issuance."],
    )
    signins.append(legacy_signin)

    # Normal service principal and managed identity sign-ins.
    sp_dt = datetime(2026, 6, 18, 0, 15, tzinfo=timezone.utc)
    signins.append(signin(
        label="normal-service-principal",
        dt=sp_dt,
        sign_in_type="servicePrincipal",
        identity_type="servicePrincipal",
        user=None,
        app=apps["backup"],
        resource=resources["vault"],
        ip=ips["azure_nz"],
        client_app="Other clients",
        protocol="oAuth2",
        is_interactive=False,
        event_types=["servicePrincipal"],
        result_status=status(0, "", "Client credential authentication succeeded."),
        auth_requirement="singleFactorAuthentication",
        auth_policies=[],
        auth_details=[auth_step(sp_dt, "Certificate", "Client certificate", "Primary authentication", "Certificate credential validated", True)],
        auth_methods=["Certificate"],
        auth_processing=[{"key": "Client credential type", "value": "certificate"}],
        ca_status="notApplied",
        ca_policies=[],
        device_detail=device(None, "", "", None, None, None),
        service_principal=service_principal,
        session_label="backup-sp-session",
        token_label="backup-sp-token",
        incoming_token_type="clientCredentials",
    ))

    mi_dt = datetime(2026, 6, 18, 0, 20, tzinfo=timezone.utc)
    signins.append(signin(
        label="normal-managed-identity",
        dt=mi_dt,
        sign_in_type="managedIdentity",
        identity_type="managedIdentity",
        user=None,
        app=apps["mi"],
        resource=resources["storage"],
        ip=ips["azure_nz"],
        client_app="Other clients",
        protocol="oAuth2",
        is_interactive=False,
        event_types=["managedIdentity"],
        result_status=status(0, "", "Managed identity token acquisition succeeded."),
        auth_requirement="singleFactorAuthentication",
        auth_policies=[],
        auth_details=[],
        auth_methods=[],
        auth_processing=[{"key": "Credential management", "value": "Azure managed"}],
        ca_status="notApplied",
        ca_policies=[],
        device_detail=device(None, "", "", None, None, None),
        managed_identity=managed_identity,
        session_label="reporting-mi-session",
        token_label="reporting-mi-token",
        incoming_token_type="managedIdentity",
    ))

    # Follow-on audit activity tied to the incident user and session.
    audits.append(audit_record(
        label="maya-add-auth-method",
        dt=datetime(2026, 6, 18, 2, 12, tzinfo=timezone.utc),
        activity="User registered security info",
        category="UserManagement",
        result="success",
        initiated_by={
            "user": {
                "id": users["maya"]["userId"],
                "userPrincipalName": users["maya"]["userPrincipalName"],
                "ipAddress": ips["attacker_ro"]["ipAddress"],
            }
        },
        targets=[{
            "id": users["maya"]["userId"],
            "displayName": users["maya"]["displayName"],
            "type": "User",
            "userPrincipalName": users["maya"]["userPrincipalName"],
            "modifiedProperties": [{
                "displayName": "AuthenticationMethods",
                "oldValue": "[Microsoft Authenticator]",
                "newValue": "[Microsoft Authenticator, Mobile phone]",
            }],
        }],
        correlation_label="maya-suspicious-success",
    ))

    m365.append(m365_record(
        label="maya-inbox-rule",
        dt=datetime(2026, 6, 18, 2, 16, tzinfo=timezone.utc),
        operation="New-InboxRule",
        workload="Exchange",
        user=users["maya"],
        ip=ips["attacker_ro"],
        object_id=users["maya"]["userPrincipalName"],
        parameters={
            "Name": "ArchiveInvoices",
            "ForwardTo": "external-review@example.invalid",
            "DeleteMessage": True,
            "StopProcessingRules": True,
        },
        session_label="maya-incident-session",
    ))

    for idx, filename in enumerate(["FY26-Forecast.xlsx", "Payroll-Summary.xlsx", "Supplier-Bank-Changes.xlsx"]):
        m365.append(m365_record(
            label=f"maya-file-download-{idx}",
            dt=datetime(2026, 6, 18, 2, 20 + idx, tzinfo=timezone.utc),
            operation="FileDownloaded",
            workload="SharePoint",
            user=users["maya"],
            ip=ips["attacker_ro"],
            object_id=f"https://compliant-secure.example.invalid/sites/finance/{filename}",
            parameters={"FileName": filename, "Site": "Finance", "SensitivityLabel": "Confidential"},
            session_label="maya-incident-session",
        ))

    # Containment actions performed by an administrator after user verification.
    admin = {
        "id": uid("user:soc-admin"),
        "userPrincipalName": "soc.admin@compliant-secure.example.invalid",
        "ipAddress": ips["office_akl"]["ipAddress"],
    }
    audits.append(audit_record(
        label="contain-revoke-sessions",
        dt=datetime(2026, 6, 18, 3, 5, tzinfo=timezone.utc),
        activity="Revoke all refresh tokens for user",
        category="UserManagement",
        result="success",
        initiated_by={"user": admin},
        targets=[{"id": users["maya"]["userId"], "displayName": users["maya"]["displayName"], "type": "User", "userPrincipalName": users["maya"]["userPrincipalName"], "modifiedProperties": []}],
        operation_type="Update",
    ))
    audits.append(audit_record(
        label="contain-reset-password",
        dt=datetime(2026, 6, 18, 3, 7, tzinfo=timezone.utc),
        activity="Reset password (by admin)",
        category="UserManagement",
        result="success",
        initiated_by={"user": admin},
        targets=[{"id": users["maya"]["userId"], "displayName": users["maya"]["displayName"], "type": "User", "userPrincipalName": users["maya"]["userPrincipalName"], "modifiedProperties": []}],
        operation_type="Update",
    ))
    audits.append(audit_record(
        label="contain-delete-auth-method",
        dt=datetime(2026, 6, 18, 3, 10, tzinfo=timezone.utc),
        activity="Delete user authentication method",
        category="UserManagement",
        result="success",
        initiated_by={"user": admin},
        targets=[{
            "id": users["maya"]["userId"],
            "displayName": users["maya"]["displayName"],
            "type": "User",
            "userPrincipalName": users["maya"]["userPrincipalName"],
            "modifiedProperties": [{"displayName": "AuthenticationMethods", "oldValue": "[Microsoft Authenticator, Mobile phone]", "newValue": "[Microsoft Authenticator]"}],
        }],
        operation_type="Delete",
    ))

    # Risk detections linked by request/correlation ID.
    risks.append(risk_record(
        label="spray-campaign",
        dt=spray_signins[0]["createdDateTime"] and incident_start,
        detected=incident_start + timedelta(minutes=2),
        sign_in=spray_signins[0],
        user=users["maya"],
        risk_type="passwordSpray",
        level="high",
        timing="realtime",
        detail="none",
    ))
    risks.append(risk_record(
        label="anonymous-ip-success",
        dt=success_dt,
        detected=success_dt + timedelta(minutes=1),
        sign_in=success_signin,
        user=users["maya"],
        risk_type="anonymizedIPAddress",
        level="high",
        timing="realtime",
        detail="none",
    ))
    risks.append(risk_record(
        label="unfamiliar-success",
        dt=success_dt,
        detected=success_dt + timedelta(minutes=1),
        sign_in=success_signin,
        user=users["maya"],
        risk_type="unfamiliarFeatures",
        level="high",
        timing="realtime",
        detail="none",
    ))
    risks.append(risk_record(
        label="atypical-travel",
        dt=success_dt,
        detected=success_dt + timedelta(hours=2),
        sign_in=success_signin,
        user=users["maya"],
        risk_type="unlikelyTravel",
        level="medium",
        timing="offline",
        detail="none",
    ))
    risks.append(risk_record(
        label="suspicious-mfa-approval",
        dt=success_dt,
        detected=success_dt + timedelta(minutes=2),
        sign_in=success_signin,
        user=users["maya"],
        risk_type="authenticatorPhishing",
        level="high",
        timing="realtime",
        detail="none",
    ))

    business_context = {
        "syntheticRecord": True,
        "datasetVersion": DATASET_VERSION,
        "tenant": tenant,
        "users": list(users.values()),
        "servicePrincipals": [service_principal],
        "managedIdentities": [managed_identity],
        "approvedNetworks": [
            {"name": "Auckland Office", "ipAddress": ips["office_akl"]["ipAddress"], "asn": ips["office_akl"]["asn"]},
            {"name": "Approved Corporate VPN - Sydney", "ipAddress": ips["vpn_sydney"]["ipAddress"], "asn": ips["vpn_sydney"]["asn"]},
        ],
        "approvedTravel": [],
        "userVerification": {
            "ticketId": "SYN-IR-2026-0017",
            "verifiedAt": "2026-06-18T02:55:00Z",
            "userPrincipalName": users["maya"]["userPrincipalName"],
            "statements": [
                "The user was in Auckland and had no approved travel to Romania or Germany.",
                "The user denied two unexpected Authenticator prompts and ignored two others.",
                "The user later approved one prompt while attempting to stop repeated notifications.",
                "The Windows 11 Chrome device in the suspicious sign-in is not owned or managed by the organization.",
                "The user did not create the external-forwarding inbox rule or download the listed finance files.",
            ],
            "verificationOutcome": "User confirmed the successful sign-in and follow-on actions were unauthorized.",
        },
        "licensingAndRetention": {
            "identityProtection": "Synthetic P2-equivalent fields included",
            "signInRetentionDays": 30,
            "auditRetentionDays": 30,
            "knownGaps": [
                "No Authenticator GPS or device-registration telemetry is included.",
                "No raw access token, refresh token, cookie, MFA seed, or secret is present.",
                "The dataset does not model cross-tenant sign-in behavior.",
                "Conditional Access policy evaluation is represented through applied policy results; detailed internal condition traces are not included.",
            ],
        },
    }

    ground_truth = {
        "syntheticRecord": True,
        "datasetVersion": DATASET_VERSION,
        "handling": "Ground truth must remain analytically separate from telemetry-confirmed facts.",
        "event": "A distributed password spray obtained Maya Chen's correct password. Repeated MFA requests led to an accidental approval. The actor received a session, used refresh-token flows, added an authentication method, created an external-forwarding inbox rule, and downloaded finance documents. Conditional Access blocked a separate legacy IMAP attempt. Other users were attacked but not compromised. The Sydney sign-in was an approved corporate VPN event. Service-principal and managed-identity sign-ins were normal workload activity.",
        "classificationByEntity": {
            users["maya"]["userPrincipalName"]: "Confirmed account compromise",
            users["liam"]["userPrincipalName"]: "Unsuccessful attack",
            users["noah"]["userPrincipalName"]: "Unsuccessful attack",
            users["olivia"]["userPrincipalName"]: "Unsuccessful attack",
            users["ethan"]["userPrincipalName"]: "Unsuccessful attack",
            service_principal["displayName"]: "Benign",
            managed_identity["displayName"]: "Benign",
        },
        "benignAnomalies": [
            "Maya Chen sign-in through the approved Sydney corporate VPN.",
        ],
        "attackInfrastructure": [ips["attacker_ro"]["ipAddress"], ips["attacker_de"]["ipAddress"]],
        "incidentSessionId": success_signin["sessionId"],
        "incidentUserId": users["maya"]["userId"],
    }

    schema_basis = {
        "syntheticRecord": True,
        "datasetVersion": DATASET_VERSION,
        "schemaBasis": [
            {
                "name": "Azure Monitor SigninLogs table",
                "url": "https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/signinlogs",
                "usage": "Core sign-in fields, authentication details, Conditional Access, device, risk, request, session and token identifiers.",
            },
            {
                "name": "Microsoft Entra sign-in log types",
                "url": "https://learn.microsoft.com/en-us/entra/identity/monitoring-health/concept-sign-ins",
                "usage": "Interactive, non-interactive, service-principal and managed-identity classification.",
            },
            {
                "name": "Microsoft Entra MFA reporting",
                "url": "https://learn.microsoft.com/en-us/entra/identity/authentication/howto-mfa-reporting",
                "usage": "Interpretation of authentication steps and previously satisfied MFA claims.",
            },
            {
                "name": "Applied Conditional Access policy",
                "url": "https://learn.microsoft.com/en-us/graph/api/resources/appliedconditionalaccesspolicy?view=graph-rest-1.0",
                "usage": "Policy result, grant control and session control representation.",
            },
            {
                "name": "Microsoft Entra risk detections",
                "url": "https://learn.microsoft.com/en-us/entra/id-protection/concept-identity-protection-risks",
                "usage": "Risk event types and licensing-aware interpretation.",
            },
        ],
        "normalizationNotes": [
            "Field names use Microsoft Graph lower-camel-case where practical.",
            "Status is represented as a nested object with errorCode, failureReason and additionalDetails.",
            "This is a synthetic teaching dataset, not a byte-for-byte export from any Microsoft portal or API.",
            "All UUIDs are deterministic UUIDv5 values generated from synthetic labels.",
            "All public IP addresses are from RFC 5737 documentation ranges; ASNs are private-use values.",
        ],
    }

    # Sort and write files.
    signins.sort(key=lambda x: (x["createdDateTime"], x["id"]))
    audits.sort(key=lambda x: (x["activityDateTime"], x["id"]))
    m365.sort(key=lambda x: (x["creationTime"], x["id"]))
    risks.sort(key=lambda x: (x["activityDateTime"], x["id"]))

    write_jsonl(raw_dir / "entra-signins.jsonl", signins)
    write_jsonl(raw_dir / "entra-directory-audit.jsonl", audits)
    write_jsonl(raw_dir / "m365-unified-audit.jsonl", m365)
    write_jsonl(raw_dir / "identity-protection-risk-detections.jsonl", risks)
    write_json(raw_dir / "business-context.json", business_context)
    write_json(raw_dir / "ground-truth.json", ground_truth)
    write_json(raw_dir / "schema-basis.json", schema_basis)
    (raw_dir / "DATASET-LICENSE.txt").write_text(
        "Scenario 17 synthetic dataset\n\n"
        "To the extent possible under law, the dataset author dedicates the generated synthetic data to the public domain under CC0 1.0.\n"
        "No real tenant, account, secret, token, or personal data is included.\n",
        encoding="utf-8",
    )

    files = sorted(p for p in raw_dir.iterdir() if p.is_file() and not p.name.startswith("."))
    manifest = {
        "datasetName": "Scenario 17 Synthetic Entra Identity and MFA Anomaly Dataset",
        "datasetVersion": DATASET_VERSION,
        "generatorVersion": GENERATOR_VERSION,
        "generatedAt": "2026-08-07T00:00:00Z",
        "deterministicContent": True,
        "synthetic": True,
        "fileCount": len(files),
        "files": [
            {"fileName": p.name, "sizeBytes": p.stat().st_size, "sha256": sha256(p)}
            for p in files
        ],
        "recordCounts": {
            "signIns": len(signins),
            "directoryAudits": len(audits),
            "m365AuditEvents": len(m365),
            "riskDetections": len(risks),
        },
    }
    write_json(raw_dir / "acquisition-manifest.json", manifest)
    return manifest


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--raw-dir", required=True, type=Path, help="Scenario evidence/raw directory")
    parser.add_argument("--force", action="store_true", help="Replace existing generated files in the raw directory")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    raw_dir: Path = args.raw_dir.expanduser().resolve()
    raw_dir.mkdir(parents=True, exist_ok=True)
    generated_names = {
        "entra-signins.jsonl",
        "entra-directory-audit.jsonl",
        "m365-unified-audit.jsonl",
        "identity-protection-risk-detections.jsonl",
        "business-context.json",
        "ground-truth.json",
        "schema-basis.json",
        "DATASET-LICENSE.txt",
        "acquisition-manifest.json",
    }
    existing = [raw_dir / name for name in generated_names if (raw_dir / name).exists()]
    if existing and not args.force:
        print("ERROR: generated files already exist. Re-run with --force to replace them:", file=sys.stderr)
        for path in sorted(existing):
            print(f"  {path}", file=sys.stderr)
        return 2
    if args.force:
        for path in existing:
            if path.is_file():
                path.unlink()
    manifest = build_dataset(raw_dir)
    print("Synthetic Scenario 17 dataset generated.")
    print(f"Raw directory: {raw_dir}")
    print(f"Files: {manifest['fileCount'] + 1}")
    for key, value in manifest["recordCounts"].items():
        print(f"{key}: {value}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
