#!/usr/bin/env python3
"""Generate one deterministic, explicitly synthetic Scenario 18 evidence package."""

from __future__ import annotations

import argparse
import csv
import hashlib
import ipaddress
import json
import shutil
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

NAMESPACE = uuid.UUID("9d8168f5-fc44-4cd8-b66b-29ec8685e521")
SCHEMA_VERSION = "scenario18-synthetic-v1.1"
GENERATED_AT = "2026-08-07T00:38:00Z"

def sid(label: str) -> str:
    return str(uuid.uuid5(NAMESPACE, label))

def write_json(path: Path, obj: Any) -> None:
    path.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8")

def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True) + "\n")

def audit_event(
    label: str,
    ts: str,
    activity: str,
    operation_type: str,
    category: str,
    initiator: dict[str, Any],
    targets: list[dict[str, Any]],
    correlation_label: str,
    result_reason: str = "",
    logged_by: str = "Core Directory",
    result: str = "success",
    additional: list[dict[str, str]] | None = None,
) -> dict[str, Any]:
    return {
        "id": sid(f"audit:{label}"),
        "activityDateTime": ts,
        "activityDisplayName": activity,
        "operationType": operation_type,
        "category": category,
        "result": result,
        "resultReason": result_reason,
        "correlationId": sid(f"corr:{correlation_label}"),
        "loggedByService": logged_by,
        "initiatedBy": initiator,
        "targetResources": targets,
        "additionalDetails": additional or [],
        "_synthetic": {
            "synthetic": True,
            "schemaBasis": "Microsoft Graph directoryAudit / Azure Monitor AuditLogs",
            "schemaVersion": SCHEMA_VERSION,
        },
    }

def user_initiator(user_id: str, display: str, upn: str, ip: str) -> dict[str, Any]:
    return {
        "user": {
            "id": user_id,
            "displayName": display,
            "userPrincipalName": upn,
            "ipAddress": ip,
        },
        "app": None,
    }

def app_initiator(app_id: str, sp_id: str, display: str) -> dict[str, Any]:
    return {
        "user": None,
        "app": {
            "appId": app_id,
            "servicePrincipalId": sp_id,
            "displayName": display,
        },
    }

def modified(display: str, old: Any, new: Any) -> dict[str, Any]:
    return {
        "displayName": display,
        "oldValue": json.dumps(old, sort_keys=True) if old is not None else None,
        "newValue": json.dumps(new, sort_keys=True) if new is not None else None,
    }

def target(
    object_id: str,
    display: str,
    object_type: str,
    modified_properties: list[dict[str, Any]] | None = None,
    upn: str | None = None,
) -> dict[str, Any]:
    return {
        "id": object_id,
        "displayName": display,
        "type": object_type,
        "userPrincipalName": upn,
        "modifiedProperties": modified_properties or [],
    }

def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args()

    out = args.output.resolve()
    if out.exists():
        if not args.force:
            print(f"Refusing to overwrite existing evidence: {out}", file=sys.stderr)
            return 2
        shutil.rmtree(out)
    (out / "ground-truth").mkdir(parents=True, exist_ok=True)

    tenant_id = sid("tenant:scenario18")
    workspace_id = sid("workspace:scenario18")

    admin_incident_id = sid("user:cloud-admin-incident")
    admin_change_id = sid("user:approved-change-admin")
    responder_id = sid("user:incident-responder")
    finance_user_id = sid("user:finance-manager")
    survey_user_id = sid("user:survey-user")
    owner_id = sid("user:application-owner")

    app_object_id = sid("application:primary:object")
    app_id = sid("application:primary:appId")
    sp_id = sid("servicePrincipal:primary")
    graph_sp_id = sid("servicePrincipal:resource:graph")
    graph_app_id = sid("application:resource:graph:appId")

    ci_app_object_id = sid("application:ci:object")
    ci_app_id = sid("application:ci:appId")
    ci_sp_id = sid("servicePrincipal:ci")
    survey_app_object_id = sid("application:survey:object")
    survey_app_id = sid("application:survey:appId")
    survey_sp_id = sid("servicePrincipal:survey")

    legacy_cert_key = sid("credential:primary:legacy-cert")
    approved_cert_key = sid("credential:primary:approved-cert")
    incident_secret_key = sid("credential:primary:incident-secret")
    incident_fic_id = sid("credential:primary:incident-fic")
    ci_fic_id = sid("credential:ci:approved-fic")

    graph_permissions = {
        "Application.ReadWrite.All": sid("graph-role:Application.ReadWrite.All"),
        "AppRoleAssignment.ReadWrite.All": sid("graph-role:AppRoleAssignment.ReadWrite.All"),
        "Sites.Read.All": sid("graph-role:Sites.Read.All"),
        "Files.Read.All": sid("graph-role:Files.Read.All"),
    }
    graph_scopes = {
        "User.Read": sid("graph-scope:User.Read"),
        "Mail.ReadWrite": sid("graph-scope:Mail.ReadWrite"),
        "offline_access": sid("graph-scope:offline_access"),
    }

    app_objects = [
        {
            "id": app_object_id,
            "appId": app_id,
            "displayName": "Northstar Data Operations Connector [SYNTHETIC]",
            "createdDateTime": "2025-11-10T03:00:00Z",
            "signInAudience": "AzureADMyOrg",
            "publisherDomain": "synthetic.example",
            "verifiedPublisher": {"displayName": None, "verifiedPublisherId": None, "addedDateTime": None},
            "owners": [{"id": owner_id, "displayName": "Application Owner", "userPrincipalName": "application.owner@synthetic.example"}],
            "requiredResourceAccess": [
                {
                    "resourceAppId": graph_app_id,
                    "resourceAccess": [
                        {"id": graph_permissions["Application.ReadWrite.All"], "type": "Role", "value": "Application.ReadWrite.All"},
                        {"id": graph_permissions["Sites.Read.All"], "type": "Role", "value": "Sites.Read.All"},
                    ],
                }
            ],
            "passwordCredentials": [
                {
                    "keyId": incident_secret_key,
                    "displayName": "backup-rotation",
                    "startDateTime": "2026-06-15T01:18:00Z",
                    "endDateTime": "2027-06-15T01:18:00Z",
                    "hint": None,
                    "secretText": None,
                    "materialRecorded": False,
                }
            ],
            "keyCredentials": [
                {
                    "keyId": legacy_cert_key,
                    "displayName": "prod-cert-2025",
                    "type": "AsymmetricX509Cert",
                    "usage": "Verify",
                    "startDateTime": "2025-04-01T00:00:00Z",
                    "endDateTime": "2026-06-30T00:00:00Z",
                    "customKeyIdentifier": "SYNTHETIC-LEGACY-THUMBPRINT-NOT-A-CERTIFICATE",
                    "privateKeyRecorded": False,
                },
                {
                    "keyId": approved_cert_key,
                    "displayName": "prod-cert-2026",
                    "type": "AsymmetricX509Cert",
                    "usage": "Verify",
                    "startDateTime": "2026-06-11T10:05:00Z",
                    "endDateTime": "2027-06-11T10:05:00Z",
                    "customKeyIdentifier": "SYNTHETIC-ROTATED-THUMBPRINT-NOT-A-CERTIFICATE",
                    "privateKeyRecorded": False,
                }
            ],
            "federatedIdentityCredentials": [
                {
                    "id": incident_fic_id,
                    "name": "emergency-build",
                    "issuer": "https://token.actions.githubusercontent.com",
                    "subject": "repo:synthetic-labs/unapproved-recovery:ref:refs/heads/main",
                    "audiences": ["api://AzureADTokenExchange"],
                    "description": "Synthetic unapproved federated credential",
                }
            ],
            "_synthetic": {"synthetic": True, "schemaBasis": "Microsoft Graph application"},
        },
        {
            "id": ci_app_object_id,
            "appId": ci_app_id,
            "displayName": "Approved CI Deployment [SYNTHETIC]",
            "createdDateTime": "2025-08-20T04:00:00Z",
            "signInAudience": "AzureADMyOrg",
            "publisherDomain": "synthetic.example",
            "verifiedPublisher": {"displayName": "Synthetic Engineering", "verifiedPublisherId": sid("publisher:synthetic"), "addedDateTime": "2025-08-20T04:10:00Z"},
            "owners": [{"id": owner_id, "displayName": "Application Owner", "userPrincipalName": "application.owner@synthetic.example"}],
            "requiredResourceAccess": [],
            "passwordCredentials": [],
            "keyCredentials": [],
            "federatedIdentityCredentials": [
                {
                    "id": ci_fic_id,
                    "name": "github-prod-deploy",
                    "issuer": "https://token.actions.githubusercontent.com",
                    "subject": "repo:synthetic-labs/approved-deploy:environment:production",
                    "audiences": ["api://AzureADTokenExchange"],
                    "description": "Approved CI/CD workload identity",
                }
            ],
            "_synthetic": {"synthetic": True, "schemaBasis": "Microsoft Graph application"},
        },
        {
            "id": survey_app_object_id,
            "appId": survey_app_id,
            "displayName": "Approved Survey Tool [SYNTHETIC]",
            "createdDateTime": "2026-01-12T00:00:00Z",
            "signInAudience": "AzureADMultipleOrgs",
            "publisherDomain": "synthetic.example",
            "verifiedPublisher": {"displayName": "Synthetic SaaS Publisher", "verifiedPublisherId": sid("publisher:survey"), "addedDateTime": "2026-01-12T01:00:00Z"},
            "owners": [],
            "requiredResourceAccess": [{"resourceAppId": graph_app_id, "resourceAccess": [{"id": graph_scopes["User.Read"], "type": "Scope", "value": "User.Read"}]}],
            "passwordCredentials": [],
            "keyCredentials": [],
            "federatedIdentityCredentials": [],
            "_synthetic": {"synthetic": True, "schemaBasis": "Microsoft Graph application"},
        },
    ]

    service_principals = [
        {
            "id": sp_id,
            "appId": app_id,
            "displayName": "Northstar Data Operations Connector [SYNTHETIC]",
            "createdDateTime": "2025-11-10T03:02:00Z",
            "servicePrincipalType": "Application",
            "accountEnabled": True,
            "appRoleAssignmentRequired": False,
            "publisherName": "Synthetic Internal",
            "owners": [{"id": owner_id, "displayName": "Application Owner"}],
            "passwordCredentials": app_objects[0]["passwordCredentials"],
            "keyCredentials": app_objects[0]["keyCredentials"],
            "federatedIdentityCredentials": app_objects[0]["federatedIdentityCredentials"],
            "_synthetic": {"synthetic": True, "schemaBasis": "Microsoft Graph servicePrincipal"},
        },
        {
            "id": graph_sp_id,
            "appId": graph_app_id,
            "displayName": "Microsoft Graph resource representation [SYNTHETIC]",
            "createdDateTime": "2025-01-01T00:00:00Z",
            "servicePrincipalType": "Application",
            "accountEnabled": True,
            "appRoleAssignmentRequired": False,
            "appRoles": [{"id": role_id, "value": value, "displayName": value, "isEnabled": True} for value, role_id in graph_permissions.items()],
            "oauth2PermissionScopes": [{"id": scope_id, "value": value, "adminConsentDisplayName": value, "isEnabled": True} for value, scope_id in graph_scopes.items()],
            "_synthetic": {"synthetic": True, "schemaBasis": "Microsoft Graph servicePrincipal; permission IDs are synthetic"},
        },
        {
            "id": ci_sp_id,
            "appId": ci_app_id,
            "displayName": "Approved CI Deployment [SYNTHETIC]",
            "createdDateTime": "2025-08-20T04:02:00Z",
            "servicePrincipalType": "Application",
            "accountEnabled": True,
            "appRoleAssignmentRequired": False,
            "passwordCredentials": [],
            "keyCredentials": [],
            "federatedIdentityCredentials": app_objects[1]["federatedIdentityCredentials"],
            "_synthetic": {"synthetic": True, "schemaBasis": "Microsoft Graph servicePrincipal"},
        },
        {
            "id": survey_sp_id,
            "appId": survey_app_id,
            "displayName": "Approved Survey Tool [SYNTHETIC]",
            "createdDateTime": "2026-01-12T00:02:00Z",
            "servicePrincipalType": "Application",
            "accountEnabled": True,
            "appRoleAssignmentRequired": False,
            "passwordCredentials": [],
            "keyCredentials": [],
            "federatedIdentityCredentials": [],
            "_synthetic": {"synthetic": True, "schemaBasis": "Microsoft Graph servicePrincipal"},
        },
    ]

    oauth_grants = [
        {
            "id": sid("oauthGrant:primary:admin-consent"),
            "clientId": sp_id,
            "consentType": "AllPrincipals",
            "principalId": None,
            "resourceId": graph_sp_id,
            "scope": "offline_access Mail.ReadWrite",
            "createdDateTime": "2026-06-15T01:14:00Z",
            "_synthetic": {"synthetic": True, "schemaBasis": "Microsoft Graph oAuth2PermissionGrant"},
        },
        {
            "id": sid("oauthGrant:survey:user-consent"),
            "clientId": survey_sp_id,
            "consentType": "Principal",
            "principalId": survey_user_id,
            "resourceId": graph_sp_id,
            "scope": "User.Read",
            "createdDateTime": "2026-06-14T03:20:00Z",
            "_synthetic": {"synthetic": True, "schemaBasis": "Microsoft Graph oAuth2PermissionGrant"},
        },
    ]

    app_role_assignments = []
    for permission in graph_permissions:
        app_role_assignments.append({
            "id": sid(f"appRoleAssignment:primary:{permission}"),
            "createdDateTime": {
                "Application.ReadWrite.All": "2026-06-15T01:15:00Z",
                "AppRoleAssignment.ReadWrite.All": "2026-06-15T01:15:30Z",
                "Sites.Read.All": "2026-06-15T01:16:00Z",
                "Files.Read.All": "2026-06-15T01:16:30Z",
            }[permission],
            "principalId": sp_id,
            "principalType": "ServicePrincipal",
            "principalDisplayName": "Northstar Data Operations Connector [SYNTHETIC]",
            "resourceId": graph_sp_id,
            "resourceDisplayName": "Microsoft Graph resource representation [SYNTHETIC]",
            "appRoleId": graph_permissions[permission],
            "appRoleValue": permission,
            "_synthetic": {"synthetic": True, "schemaBasis": "Microsoft Graph appRoleAssignment"},
        })

    directory_role_assignments = [
        {
            "id": sid("directoryRoleAssignment:primary:cloud-app-admin"),
            "principalId": sp_id,
            "principalType": "ServicePrincipal",
            "roleDefinitionId": sid("directoryRoleDefinition:cloud-application-administrator"),
            "roleDisplayName": "Cloud Application Administrator [SYNTHETIC ROLE]",
            "assignmentType": "Active",
            "scheduleType": "Permanent",
            "startDateTime": "2026-06-15T01:17:00Z",
            "endDateTime": None,
            "activatedThroughPIM": False,
            "_synthetic": {"synthetic": True, "schemaBasis": "Entra directory role assignment"},
        }
    ]

    credential_metadata = [
        {
            "applicationObjectId": app_object_id,
            "servicePrincipalObjectId": sp_id,
            "appId": app_id,
            "credentialType": "Certificate",
            "keyId": legacy_cert_key,
            "displayName": "prod-cert-2025",
            "startDateTime": "2025-04-01T00:00:00Z",
            "endDateTime": "2026-06-30T00:00:00Z",
            "usage": "Verify",
            "statusAtPackageEnd": "Removed during containment",
            "materialRecorded": False,
            "changeTicket": "LEGACY-SYNTHETIC-BASELINE",
        },
        {
            "applicationObjectId": app_object_id,
            "servicePrincipalObjectId": sp_id,
            "appId": app_id,
            "credentialType": "Certificate",
            "keyId": approved_cert_key,
            "displayName": "prod-cert-2026",
            "startDateTime": "2026-06-11T10:05:00Z",
            "endDateTime": "2027-06-11T10:05:00Z",
            "usage": "Verify",
            "statusAtPackageEnd": "Removed during containment",
            "materialRecorded": False,
            "changeTicket": "CHG-SYN-2026-0611",
        },
        {
            "applicationObjectId": app_object_id,
            "servicePrincipalObjectId": sp_id,
            "appId": app_id,
            "credentialType": "Client secret",
            "keyId": incident_secret_key,
            "displayName": "backup-rotation",
            "startDateTime": "2026-06-15T01:18:00Z",
            "endDateTime": "2027-06-15T01:18:00Z",
            "usage": "Sign",
            "statusAtPackageEnd": "Removed during containment",
            "materialRecorded": False,
            "changeTicket": None,
        },
        {
            "applicationObjectId": app_object_id,
            "servicePrincipalObjectId": sp_id,
            "appId": app_id,
            "credentialType": "Federated identity credential",
            "keyId": incident_fic_id,
            "displayName": "emergency-build",
            "startDateTime": "2026-06-15T01:36:00Z",
            "endDateTime": None,
            "usage": "FederatedTrust",
            "statusAtPackageEnd": "Removed during containment",
            "materialRecorded": False,
            "changeTicket": None,
        },
        {
            "applicationObjectId": ci_app_object_id,
            "servicePrincipalObjectId": ci_sp_id,
            "appId": ci_app_id,
            "credentialType": "Federated identity credential",
            "keyId": ci_fic_id,
            "displayName": "github-prod-deploy",
            "startDateTime": "2026-06-12T09:00:00Z",
            "endDateTime": None,
            "usage": "FederatedTrust",
            "statusAtPackageEnd": "Active",
            "materialRecorded": False,
            "changeTicket": "CHG-SYN-2026-0612",
        },
    ]

    approved_admin = user_initiator(admin_change_id, "Approved Change Administrator", "approved.admin@synthetic.example", "192.0.2.20")
    incident_admin = user_initiator(admin_incident_id, "Cloud Administrator Two", "cloud.admin2@synthetic.example", "203.0.113.77")
    responder = user_initiator(responder_id, "Incident Responder", "incident.responder@synthetic.example", "192.0.2.25")
    primary_app_initiator = app_initiator(app_id, sp_id, "Northstar Data Operations Connector [SYNTHETIC]")

    directory_audit = [
        audit_event(
            "approved-cert-rotation", "2026-06-11T10:05:00Z", "Update application - Certificates and secrets management", "Update",
            "ApplicationManagement", approved_admin,
            [target(app_object_id, "Northstar Data Operations Connector [SYNTHETIC]", "Application",
                    [modified("KeyDescription", [], [{"keyId": approved_cert_key, "displayName": "prod-cert-2026", "type": "AsymmetricX509Cert", "usage": "Verify"}])])],
            "approved-cert-rotation", "Approved certificate rotation", additional=[{"key": "ChangeTicket", "value": "CHG-SYN-2026-0611"}]
        ),
        audit_event(
            "approved-ci-fic", "2026-06-12T09:00:00Z", "Add federated identity credential", "Add",
            "ApplicationManagement", approved_admin,
            [target(ci_app_object_id, "Approved CI Deployment [SYNTHETIC]", "Application",
                    [modified("FederatedIdentityCredentials", [], [{"id": ci_fic_id, "name": "github-prod-deploy"}])])],
            "approved-ci-fic", "Approved CI/CD workload identity", additional=[{"key": "ChangeTicket", "value": "CHG-SYN-2026-0612"}]
        ),
        audit_event(
            "benign-user-consent", "2026-06-14T03:20:00Z", "Consent to application", "Add",
            "ApplicationManagement",
            user_initiator(survey_user_id, "Survey User", "survey.user@synthetic.example", "198.51.100.45"),
            [target(survey_sp_id, "Approved Survey Tool [SYNTHETIC]", "ServicePrincipal",
                    [modified("ConsentType", None, "Principal"), modified("Scope", None, "User.Read")])],
            "benign-user-consent", "User consent to approved low-risk delegated permission"
        ),
        audit_event(
            "incident-admin-consent", "2026-06-15T01:14:00Z", "Consent to application", "Add",
            "ApplicationManagement", incident_admin,
            [target(sp_id, "Northstar Data Operations Connector [SYNTHETIC]", "ServicePrincipal",
                    [modified("ConsentType", None, "AllPrincipals"), modified("Scope", None, "offline_access Mail.ReadWrite")])],
            "incident-admin-consent", "Tenant-wide admin consent recorded"
        ),
    ]

    for permission, ts in [
        ("Application.ReadWrite.All", "2026-06-15T01:15:00Z"),
        ("AppRoleAssignment.ReadWrite.All", "2026-06-15T01:15:30Z"),
        ("Sites.Read.All", "2026-06-15T01:16:00Z"),
        ("Files.Read.All", "2026-06-15T01:16:30Z"),
    ]:
        directory_audit.append(audit_event(
            f"incident-app-role-{permission}", ts, "Add app role assignment to service principal", "Assign",
            "ApplicationManagement", incident_admin,
            [
                target(sp_id, "Northstar Data Operations Connector [SYNTHETIC]", "ServicePrincipal",
                       [modified("AppRole.Value", None, permission), modified("AppRole.Id", None, graph_permissions[permission])]),
                target(graph_sp_id, "Microsoft Graph resource representation [SYNTHETIC]", "ServicePrincipal"),
            ],
            f"incident-app-role-{permission}", f"Application permission {permission} assigned"
        ))

    directory_audit.extend([
        audit_event(
            "incident-directory-role", "2026-06-15T01:17:00Z", "Add member to role", "Assign",
            "RoleManagement", incident_admin,
            [
                target(sp_id, "Northstar Data Operations Connector [SYNTHETIC]", "ServicePrincipal"),
                target(directory_role_assignments[0]["roleDefinitionId"], "Cloud Application Administrator [SYNTHETIC ROLE]", "Role",
                       [modified("AssignmentType", None, "Active"), modified("ScheduleType", None, "Permanent")]),
            ],
            "incident-directory-role", "Service principal assigned active permanent directory role"
        ),
        audit_event(
            "incident-add-secret", "2026-06-15T01:18:00Z", "Add service principal credentials", "Update",
            "ApplicationManagement", incident_admin,
            [target(sp_id, "Northstar Data Operations Connector [SYNTHETIC]", "ServicePrincipal",
                    [modified("PasswordCredentials", [], [{
                        "keyId": incident_secret_key,
                        "displayName": "backup-rotation",
                        "startDateTime": "2026-06-15T01:18:00Z",
                        "endDateTime": "2027-06-15T01:18:00Z",
                        "secretValue": "[NOT RECORDED]",
                    }])])],
            "incident-add-secret", "Credential metadata added; secret material not present"
        ),
        audit_event(
            "incident-add-fic", "2026-06-15T01:36:00Z", "Add federated identity credential", "Add",
            "ApplicationManagement", primary_app_initiator,
            [target(app_object_id, "Northstar Data Operations Connector [SYNTHETIC]", "Application",
                    [modified("FederatedIdentityCredentials", [], [{
                        "id": incident_fic_id,
                        "name": "emergency-build",
                        "issuer": "https://token.actions.githubusercontent.com",
                        "subject": "repo:synthetic-labs/unapproved-recovery:ref:refs/heads/main",
                        "audiences": ["api://AzureADTokenExchange"],
                    }])])],
            "incident-add-fic", "Application identity added an additional federated credential",
            additional=[{"key": "RequestId", "value": sid("request:add-fic")}, {"key": "OperationId", "value": sid("operation:add-fic")}]
        ),
    ])

    # Containment operations are separate actions, not proof of maliciousness.
    containment_events = [
        ("disable-sp", "2026-06-15T03:18:00Z", "Disable service principal", "Update", "ApplicationManagement",
         [target(sp_id, "Northstar Data Operations Connector [SYNTHETIC]", "ServicePrincipal", [modified("AccountEnabled", True, False)])]),
        ("remove-oauth-grant", "2026-06-15T03:20:00Z", "Delete delegated permission grant", "Delete", "ApplicationManagement",
         [target(oauth_grants[0]["id"], "Tenant-wide delegated permission grant [SYNTHETIC]", "OAuth2PermissionGrant")]),
        ("remove-app-roles", "2026-06-15T03:22:00Z", "Remove app role assignment from service principal", "Unassign", "ApplicationManagement",
         [target(sp_id, "Northstar Data Operations Connector [SYNTHETIC]", "ServicePrincipal")]),
        ("remove-directory-role", "2026-06-15T03:24:00Z", "Remove member from role", "Unassign", "RoleManagement",
         [target(sp_id, "Northstar Data Operations Connector [SYNTHETIC]", "ServicePrincipal"),
          target(directory_role_assignments[0]["roleDefinitionId"], "Cloud Application Administrator [SYNTHETIC ROLE]", "Role")]),
        ("remove-secret", "2026-06-15T03:26:00Z", "Remove service principal credentials", "Update", "ApplicationManagement",
         [target(sp_id, "Northstar Data Operations Connector [SYNTHETIC]", "ServicePrincipal",
                 [modified("PasswordCredentials", [{"keyId": incident_secret_key}], [])])]),
        ("remove-fic", "2026-06-15T03:28:00Z", "Delete federated identity credential", "Delete", "ApplicationManagement",
         [target(app_object_id, "Northstar Data Operations Connector [SYNTHETIC]", "Application",
                 [modified("FederatedIdentityCredentials", [{"id": incident_fic_id}], [])])]),
        ("revoke-admin-session", "2026-06-15T03:30:00Z", "Revoke all refresh tokens for user", "Update", "UserManagement",
         [target(admin_incident_id, "Cloud Administrator Two", "User", upn="cloud.admin2@synthetic.example")]),
    ]
    for label, ts, activity, op, category, targets in containment_events:
        directory_audit.append(audit_event(
            f"containment-{label}", ts, activity, op, category, responder, targets,
            f"containment-{label}", "Incident containment action", logged_by="Core Directory"
        ))

    user_signins = [
        {
            "Id": sid("userSignIn:approved-admin-baseline"),
            "CreatedDateTime": "2026-06-11T09:55:00Z",
            "UserId": admin_change_id,
            "UserPrincipalName": "approved.admin@synthetic.example",
            "UserDisplayName": "Approved Change Administrator",
            "AppId": sid("portal:entra-admin-center"),
            "AppDisplayName": "Microsoft Entra admin center [SYNTHETIC REPRESENTATION]",
            "ResourceId": graph_sp_id,
            "ResourceDisplayName": "Microsoft Graph resource representation [SYNTHETIC]",
            "IPAddress": "192.0.2.20",
            "AutonomousSystemNumber": 64520,
            "Location": {"city": "Auckland", "state": "Auckland", "countryOrRegion": "NZ"},
            "AuthenticationProtocol": "none",
            "ClientCredentialType": "none",
            "Status": {"errorCode": 0, "failureReason": None},
            "CorrelationId": sid("corr:userSignIn:approved-admin-baseline"),
            "OriginalRequestId": sid("request:userSignIn:approved-admin-baseline"),
            "UniqueTokenIdentifier": sid("token:userSignIn:approved-admin-baseline"),
            "SignInEventTypes": ["interactiveUser"],
            "_synthetic": {"synthetic": True, "schemaBasis": "Azure Monitor SigninLogs"},
        },
        {
            "Id": sid("userSignIn:incident-admin"),
            "CreatedDateTime": "2026-06-15T00:59:00Z",
            "UserId": admin_incident_id,
            "UserPrincipalName": "cloud.admin2@synthetic.example",
            "UserDisplayName": "Cloud Administrator Two",
            "AppId": sid("portal:entra-admin-center"),
            "AppDisplayName": "Microsoft Entra admin center [SYNTHETIC REPRESENTATION]",
            "ResourceId": graph_sp_id,
            "ResourceDisplayName": "Microsoft Graph resource representation [SYNTHETIC]",
            "IPAddress": "203.0.113.77",
            "AutonomousSystemNumber": 64550,
            "Location": {"city": "Singapore", "state": None, "countryOrRegion": "SG"},
            "AuthenticationProtocol": "none",
            "ClientCredentialType": "none",
            "Status": {"errorCode": 0, "failureReason": None},
            "CorrelationId": sid("corr:userSignIn:incident-admin"),
            "OriginalRequestId": sid("request:userSignIn:incident-admin"),
            "UniqueTokenIdentifier": sid("token:userSignIn:incident-admin"),
            "SignInEventTypes": ["interactiveUser"],
            "RiskLevelDuringSignIn": "medium",
            "RiskState": "atRisk",
            "_synthetic": {"synthetic": True, "schemaBasis": "Azure Monitor SigninLogs"},
        },
    ]

    token_secret = sid("token:primary:secret")
    token_fic = sid("token:primary:fic")
    sp_signins = [
        {
            "Id": sid("spSignIn:baseline-cert"),
            "CreatedDateTime": "2026-04-30T02:00:00Z",
            "TimeGenerated": "2026-04-30T02:00:01Z",
            "AADTenantId": tenant_id,
            "TenantId": workspace_id,
            "AppId": app_id,
            "ServicePrincipalId": sp_id,
            "ServicePrincipalName": "Northstar Data Operations Connector [SYNTHETIC]",
            "ServicePrincipalCredentialKeyId": legacy_cert_key,
            "ServicePrincipalCredentialThumbprint": "SYNTHETIC-LEGACY-THUMBPRINT-NOT-A-CERTIFICATE",
            "FederatedCredentialId": None,
            "ClientCredentialType": "clientAssertion",
            "AuthenticationProtocol": "oauth2ClientCredentials",
            "ResourceId": sid("resource:azure-storage"),
            "ResourceDisplayName": "Azure Storage [SYNTHETIC REPRESENTATION]",
            "ResourceServicePrincipalId": sid("servicePrincipal:resource:storage"),
            "IPAddress": "192.0.2.50",
            "AutonomousSystemNumber": 64520,
            "Location": {"city": "Auckland", "state": "Auckland", "countryOrRegion": "NZ"},
            "ResultType": "0",
            "ResultDescription": "Success",
            "CorrelationId": sid("corr:spSignIn:baseline-cert"),
            "OriginalRequestId": sid("request:spSignIn:baseline-cert"),
            "UniqueTokenIdentifier": sid("token:spSignIn:baseline-cert"),
            "SignInEventTypes": ["servicePrincipal"],
            "_synthetic": {"synthetic": True, "schemaBasis": "Azure Monitor AADServicePrincipalSignInLogs"},
        },
        {
            "Id": sid("spSignIn:incident-secret"),
            "CreatedDateTime": "2026-06-15T01:24:00Z",
            "TimeGenerated": "2026-06-15T01:24:01Z",
            "AADTenantId": tenant_id,
            "TenantId": workspace_id,
            "AppId": app_id,
            "ServicePrincipalId": sp_id,
            "ServicePrincipalName": "Northstar Data Operations Connector [SYNTHETIC]",
            "ServicePrincipalCredentialKeyId": incident_secret_key,
            "ServicePrincipalCredentialThumbprint": None,
            "FederatedCredentialId": None,
            "ClientCredentialType": "clientSecret",
            "AuthenticationProtocol": "oauth2ClientCredentials",
            "ResourceId": graph_app_id,
            "ResourceDisplayName": "Microsoft Graph resource representation [SYNTHETIC]",
            "ResourceServicePrincipalId": graph_sp_id,
            "IPAddress": "203.0.113.77",
            "AutonomousSystemNumber": 64550,
            "Location": {"city": "Singapore", "state": None, "countryOrRegion": "SG"},
            "ResultType": "0",
            "ResultDescription": "Success",
            "CorrelationId": sid("corr:spSignIn:incident-secret"),
            "OriginalRequestId": sid("request:spSignIn:incident-secret"),
            "UniqueTokenIdentifier": token_secret,
            "SignInEventTypes": ["servicePrincipal"],
            "_synthetic": {"synthetic": True, "schemaBasis": "Azure Monitor AADServicePrincipalSignInLogs"},
        },
        {
            "Id": sid("spSignIn:incident-fic"),
            "CreatedDateTime": "2026-06-15T02:05:00Z",
            "TimeGenerated": "2026-06-15T02:05:01Z",
            "AADTenantId": tenant_id,
            "TenantId": workspace_id,
            "AppId": app_id,
            "ServicePrincipalId": sp_id,
            "ServicePrincipalName": "Northstar Data Operations Connector [SYNTHETIC]",
            "ServicePrincipalCredentialKeyId": None,
            "ServicePrincipalCredentialThumbprint": None,
            "FederatedCredentialId": incident_fic_id,
            "ClientCredentialType": "federatedIdentityCredential",
            "AuthenticationProtocol": "oauth2ClientCredentials",
            "ResourceId": graph_app_id,
            "ResourceDisplayName": "Microsoft Graph resource representation [SYNTHETIC]",
            "ResourceServicePrincipalId": graph_sp_id,
            "IPAddress": "198.51.100.90",
            "AutonomousSystemNumber": 64555,
            "Location": {"city": "Seattle", "state": "Washington", "countryOrRegion": "US"},
            "ResultType": "0",
            "ResultDescription": "Success",
            "CorrelationId": sid("corr:spSignIn:incident-fic"),
            "OriginalRequestId": sid("request:spSignIn:incident-fic"),
            "UniqueTokenIdentifier": token_fic,
            "SignInEventTypes": ["servicePrincipal"],
            "_synthetic": {"synthetic": True, "schemaBasis": "Azure Monitor AADServicePrincipalSignInLogs"},
        },
        {
            "Id": sid("spSignIn:ci-approved"),
            "CreatedDateTime": "2026-06-12T09:15:00Z",
            "TimeGenerated": "2026-06-12T09:15:01Z",
            "AADTenantId": tenant_id,
            "TenantId": workspace_id,
            "AppId": ci_app_id,
            "ServicePrincipalId": ci_sp_id,
            "ServicePrincipalName": "Approved CI Deployment [SYNTHETIC]",
            "ServicePrincipalCredentialKeyId": None,
            "ServicePrincipalCredentialThumbprint": None,
            "FederatedCredentialId": ci_fic_id,
            "ClientCredentialType": "federatedIdentityCredential",
            "AuthenticationProtocol": "oauth2ClientCredentials",
            "ResourceId": sid("resource:azure-resource-manager"),
            "ResourceDisplayName": "Azure Resource Manager [SYNTHETIC REPRESENTATION]",
            "ResourceServicePrincipalId": sid("servicePrincipal:resource:arm"),
            "IPAddress": "198.51.100.22",
            "AutonomousSystemNumber": 64525,
            "Location": {"city": "Sydney", "state": "New South Wales", "countryOrRegion": "AU"},
            "ResultType": "0",
            "ResultDescription": "Success",
            "CorrelationId": sid("corr:spSignIn:ci-approved"),
            "OriginalRequestId": sid("request:spSignIn:ci-approved"),
            "UniqueTokenIdentifier": sid("token:spSignIn:ci-approved"),
            "SignInEventTypes": ["servicePrincipal"],
            "_synthetic": {"synthetic": True, "schemaBasis": "Azure Monitor AADServicePrincipalSignInLogs"},
        },
    ]

    api_activities = []
    api_specs = [
        ("list-applications", "2026-06-15T01:26:00Z", "Microsoft Graph", "List applications", "Directory", sid("target:directory:applications"), "Applications collection", "metadata_enumerated", token_secret, "203.0.113.77", 64550, "SG"),
        ("list-service-principals", "2026-06-15T01:27:00Z", "Microsoft Graph", "List servicePrincipals", "Directory", sid("target:directory:servicePrincipals"), "Service principals collection", "metadata_enumerated", token_secret, "203.0.113.77", 64550, "SG"),
        ("list-sites", "2026-06-15T01:29:00Z", "Microsoft Graph", "List sites", "SharePointSite", sid("target:site:finance"), "Finance Collaboration Site [SYNTHETIC]", "metadata_enumerated", token_secret, "203.0.113.77", 64550, "SG"),
        ("list-drive-items", "2026-06-15T01:31:00Z", "Microsoft Graph", "List driveItems", "OneDrive", sid("target:drive:finance"), "Finance Shared Drive [SYNTHETIC]", "metadata_enumerated", token_secret, "203.0.113.77", 64550, "SG"),
        ("download-file", "2026-06-15T01:33:00Z", "Microsoft Graph", "Download driveItem content", "File", sid("target:file:forecast"), "FY26-Forecast-Synthetic.xlsx", "file_content_returned", token_secret, "203.0.113.77", 64550, "SG"),
        ("add-fic-api", "2026-06-15T01:36:00Z", "Microsoft Graph", "Create federatedIdentityCredential", "Application", app_object_id, "Northstar Data Operations Connector [SYNTHETIC]", "object_modified", token_secret, "203.0.113.77", 64550, "SG"),
        ("post-fic-list-apps", "2026-06-15T02:08:00Z", "Microsoft Graph", "List applications", "Directory", sid("target:directory:applications"), "Applications collection", "metadata_enumerated", token_fic, "198.51.100.90", 64555, "US"),
    ]
    for label, ts, workload, operation, target_type, target_id, target_name, outcome, token_id, ip, asn, country in api_specs:
        request_id = sid("request:add-fic") if label == "add-fic-api" else sid(f"request:api:{label}")
        operation_id = sid("operation:add-fic") if label == "add-fic-api" else sid(f"operation:api:{label}")
        api_activities.append({
            "TimeGenerated": ts,
            "workload": workload,
            "operation": operation,
            "actorType": "ServicePrincipal",
            "actorObjectId": sp_id,
            "appId": app_id,
            "clientAppId": app_id,
            "servicePrincipalId": sp_id,
            "tokenType": "application",
            "permissionType": "Application",
            "permissionClaimLogged": False,
            "resourceDisplayName": workload,
            "resourceId": graph_sp_id,
            "targetType": target_type,
            "targetObjectId": target_id,
            "targetName": target_name,
            "result": "success",
            "sourceIp": ip,
            "autonomousSystemNumber": asn,
            "location": {"countryOrRegion": country},
            "correlationId": sid(f"corr:api:{label}"),
            "requestId": request_id,
            "operationId": operation_id,
            "UniqueTokenIdentifier": token_id,
            "dataAccessOutcome": outcome,
            "responseBytes": 32768 if label == "download-file" else None,
            "_synthetic": {"synthetic": True, "schemaBasis": "Generic normalised Graph/M365 API activity"},
        })

    governance = {
        "tenantAlias": "SYNTHETIC-TENANT-18",
        "normalChangeWindow": {"timezone": "Pacific/Auckland", "days": ["Tuesday"], "start": "22:00", "end": "23:00"},
        "approvedChanges": [
            {
                "ticket": "CHG-SYN-2026-0611",
                "applicationObjectId": app_object_id,
                "summary": "Rotate production certificate",
                "approvedBy": "application.owner@synthetic.example",
                "approvedAdministratorId": admin_change_id,
                "windowStartUtc": "2026-06-11T10:00:00Z",
                "windowEndUtc": "2026-06-11T11:00:00Z",
            },
            {
                "ticket": "CHG-SYN-2026-0612",
                "applicationObjectId": ci_app_object_id,
                "summary": "Create approved GitHub Actions federated identity",
                "approvedBy": "application.owner@synthetic.example",
                "approvedAdministratorId": admin_change_id,
                "windowStartUtc": "2026-06-12T09:00:00Z",
                "windowEndUtc": "2026-06-12T10:00:00Z",
            },
        ],
        "applicationBaseline": {
            "applicationObjectId": app_object_id,
            "appId": app_id,
            "servicePrincipalObjectId": sp_id,
            "businessOwner": "Data Operations",
            "technicalOwner": "application.owner@synthetic.example",
            "expectedResources": ["Azure Storage [SYNTHETIC REPRESENTATION]"],
            "expectedCredentialTypes": ["Certificate"],
            "expectedSourceCountries": ["NZ"],
            "expectedSourceIps": ["192.0.2.50"],
            "expectedPermissions": ["Storage.Read [SYNTHETIC]"],
            "lastKnownSignInUtc": "2026-04-30T02:00:00Z",
            "baselineStatusAtIncident": "Dormant for more than 30 days",
        },
        "administratorBaseline": {
            "administratorId": admin_incident_id,
            "userPrincipalName": "cloud.admin2@synthetic.example",
            "expectedSourceCountries": ["NZ"],
            "expectedSourceIps": ["192.0.2.30"],
            "normalWorkingHoursLocal": "08:00-18:00 Pacific/Auckland",
            "normalOperations": ["User and group administration"],
            "notNormallyPerformed": ["Application consent", "Service principal credential changes", "Directory role assignment to applications"],
        },
        "ownerVerification": [
            {
                "verifiedAtUtc": "2026-06-15T03:05:00Z",
                "applicationObjectId": app_object_id,
                "ownerId": owner_id,
                "statement": "No deployment, consent, role assignment, secret rotation, or federated credential change was approved for 2026-06-15.",
                "ticketFound": False,
            }
        ],
        "incidentTicket": {
            "id": "INC-SYN-2026-0615",
            "openedAtUtc": "2026-06-15T03:00:00Z",
            "scope": "Synthetic cloud privilege and application identity investigation",
        },
        "_synthetic": {"synthetic": True, "schemaBasis": "Synthetic business and governance context"},
    }

    risk_signals = [
        {
            "TimeGenerated": "2026-06-15T01:25:00Z",
            "Id": sp_id,
            "AppId": app_id,
            "DisplayName": "Northstar Data Operations Connector [SYNTHETIC]",
            "ServicePrincipalType": "Application",
            "RiskLevel": "medium",
            "RiskState": "atRisk",
            "RiskDetail": "unfamiliarFeatures",
            "OperationName": "Risky service principal detected",
            "CorrelationId": sid("corr:risk:primary-sp"),
            "_synthetic": {"synthetic": True, "schemaBasis": "Azure Monitor AADRiskyServicePrincipals"},
        }
    ]

    package_metadata = {
        "packageName": "Scenario 18 Synthetic Cloud Privilege Event Package",
        "packageVersion": "1.1.0",
        "generatedAtUtc": GENERATED_AT,
        "synthetic": True,
        "generatorNamespace": str(NAMESPACE),
        "scenario": "Scenario 18 — Cloud Privilege and OAuth Application Abuse",
        "primaryEventStartUtc": "2026-06-15T00:59:00Z",
        "primaryEventEndUtc": "2026-06-15T03:30:00Z",
        "originalTimezoneContext": "Pacific/Auckland",
        "safety": {
            "connectsToRealTenant": False,
            "containsRealSecrets": False,
            "containsPrivateKeys": False,
            "containsTokens": False,
            "containsRealTenantIdentifiers": False,
            "allUpnsUse": "synthetic.example",
            "allIpsUseDocumentationRanges": True,
        },
        "schemaSources": [
            {"title": "Microsoft Graph directoryAudit resource", "retrievedDate": "2026-08-07", "purpose": "Audit record structure"},
            {"title": "Microsoft Graph oAuth2PermissionGrant resource", "retrievedDate": "2026-08-07", "purpose": "Delegated permission grants"},
            {"title": "Microsoft Graph appRoleAssignment resource", "retrievedDate": "2026-08-07", "purpose": "Application permission assignments"},
            {"title": "Azure Monitor AADServicePrincipalSignInLogs table", "retrievedDate": "2026-08-07", "purpose": "Service principal sign-in fields and credential key linkage"},
            {"title": "Microsoft Entra activity log schemas", "retrievedDate": "2026-08-07", "purpose": "Correlation and timestamp boundaries"},
        ],
        "analysisBoundary": {
            "correlationId": "May support troubleshooting inside a product or flow; equality is not assumed across products.",
            "credentialUse": "Credential key or federated credential ID match can show which credential metadata was used for a sign-in.",
            "permissionUse": "API activity does not directly log the permission claim in this package; use of a specific assigned permission remains an inference.",
            "attackerControl": "First-pass telemetry supports possible compromise; ground truth is isolated from analyst scripts.",
        },
    }

    ground_truth = {
        "synthetic": True,
        "warning": "Do not provide this file to the first-pass parser or correlation scripts.",
        "eventNarrative": "A simulated attacker used a compromised administrator session to grant tenant-wide delegated permissions, assign application permissions and a directory role, add a client secret, use that secret for application-only Graph activity, and create and use a federated identity credential for persistence.",
        "labels": ["Confirmed cloud privilege abuse", "Confirmed application identity compromise"],
        "initiatingAdminSessionCompromised": True,
        "incidentSecretObtainedBySimulatedAttacker": True,
        "incidentFederatedCredentialControlledBySimulatedAttacker": True,
        "delegatedGrantActuallyUsed": False,
        "applicationPermissionsActuallyUsed": True,
        "businessImpact": {
            "directoryEnumerated": True,
            "sharePointSitesEnumerated": True,
            "oneDriveItemsEnumerated": True,
            "fileContentReturned": True,
            "mailboxAccess": False,
        },
        "controlRecords": {
            "approvedCertificateRotation": sid("audit:approved-cert-rotation"),
            "approvedCiFederatedCredential": sid("audit:approved-ci-fic"),
            "benignUserConsent": sid("audit:benign-user-consent"),
        },
    }

    readme = """# Synthetic evidence package

This directory contains a deterministic synthetic event package for Scenario 18.

It is not an export from Microsoft Entra, Azure, Microsoft Graph, Microsoft 365, or a production tenant.

Credential records contain metadata only. The string `[NOT RECORDED]` is a safety marker, not a secret.

The `ground-truth/` directory must remain excluded from first-pass analysis.
"""

    write_json(out / "00-package-metadata.json", package_metadata)
    write_jsonl(out / "01-directory-audit.jsonl", directory_audit)
    write_json(out / "02-application-objects.json", app_objects)
    write_json(out / "03-service-principal-objects.json", service_principals)
    write_json(out / "04-oauth2-permission-grants.json", oauth_grants)
    write_json(out / "05-app-role-assignments.json", app_role_assignments)
    write_json(out / "06-directory-role-assignments.json", directory_role_assignments)
    write_json(out / "07-credential-metadata.json", credential_metadata)
    write_jsonl(out / "08-user-signins.jsonl", user_signins)
    write_jsonl(out / "09-service-principal-signins.jsonl", sp_signins)
    write_jsonl(out / "10-api-and-resource-activity.jsonl", api_activities)
    write_json(out / "11-business-and-governance-context.json", governance)
    write_jsonl(out / "12-platform-risk-signals.jsonl", risk_signals)
    write_json(out / "ground-truth" / "simulation-ground-truth.json", ground_truth)
    (out / "README-SYNTHETIC.md").write_text(readme, encoding="utf-8")

    manifest_rows = []
    for path in sorted(out.rglob("*")):
        if path.is_file() and path.name != "SHA256SUMS.tsv":
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            manifest_rows.append((str(path.relative_to(out)), path.stat().st_size, digest))
    with (out / "SHA256SUMS.tsv").open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle, delimiter="\t")
        writer.writerow(["relative_path", "size_bytes", "sha256"])
        writer.writerows(manifest_rows)

    print(json.dumps({
        "status": "generated",
        "output": str(out),
        "files": len(manifest_rows) + 1,
        "directoryAuditEvents": len(directory_audit),
        "servicePrincipalSignIns": len(sp_signins),
        "apiActivities": len(api_activities),
    }, indent=2))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
