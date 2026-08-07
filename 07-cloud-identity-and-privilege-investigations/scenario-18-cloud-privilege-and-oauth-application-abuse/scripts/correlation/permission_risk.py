#!/usr/bin/env python3
"""Assess delegated and application permissions while preserving permission-type context."""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from typing import Any

CATALOG = {
    "RoleManagement.ReadWrite.Directory": (10, "Can modify directory role management"),
    "AppRoleAssignment.ReadWrite.All": (10, "Can create or remove application role assignments"),
    "Application.ReadWrite.All": (9, "Can modify application and service-principal objects"),
    "Directory.ReadWrite.All": (9, "Broad directory write capability"),
    "User.ReadWrite.All": (9, "Broad user write capability"),
    "Group.ReadWrite.All": (9, "Broad group write capability"),
    "Files.ReadWrite.All": (9, "Broad file read/write capability"),
    "Sites.ReadWrite.All": (9, "Broad SharePoint site read/write capability"),
    "Mail.ReadWrite": (8, "Mailbox read/write capability; impact depends on delegated or application type"),
    "Mail.Send": (8, "Can send mail; impact depends on delegated or application type"),
    "Files.Read.All": (8, "Broad file read capability"),
    "Sites.Read.All": (8, "Broad SharePoint site read capability"),
    "Mail.Read": (7, "Mailbox read capability"),
    "offline_access": (4, "Allows refresh-token based delegated access; not unlimited access"),
    "User.Read": (1, "Basic signed-in user profile access"),
}

def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))

def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    raw = args.input.resolve()
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=True)

    grants = load_json(raw / "04-oauth2-permission-grants.json")
    assignments = load_json(raw / "05-app-role-assignments.json")

    rows = []
    for grant in grants:
        for permission in grant.get("scope", "").split():
            score, capability = CATALOG.get(permission, (5, "Permission not present in local risk catalog"))
            if grant["consentType"] == "AllPrincipals":
                score = min(10, score + 1)
            rows.append({
                "source_id": grant["id"], "client_service_principal_id": grant["clientId"],
                "resource_service_principal_id": grant["resourceId"], "permission": permission,
                "permission_type": "Delegated", "consent_type": grant["consentType"],
                "principal_id": grant.get("principalId"), "risk_score": score,
                "risk_band": "High" if score >= 8 else "Medium" if score >= 4 else "Low",
                "capability": capability,
                "interpretation_boundary": "Delegated permission requires a user context; grant does not prove use",
            })
    for assignment in assignments:
        permission = assignment.get("appRoleValue")
        score, capability = CATALOG.get(permission, (6, "Application permission not present in local risk catalog"))
        rows.append({
            "source_id": assignment["id"], "client_service_principal_id": assignment["principalId"],
            "resource_service_principal_id": assignment["resourceId"], "permission": permission,
            "permission_type": "Application", "consent_type": "Administrator assignment",
            "principal_id": assignment["principalId"], "risk_score": score,
            "risk_band": "High" if score >= 8 else "Medium" if score >= 4 else "Low",
            "capability": capability,
            "interpretation_boundary": "Application permission allows app-only access; assignment does not prove use",
        })

    fields = list(rows[0].keys())
    with (out / "permission-risk-assessment.csv").open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)

    summary = {
        "totalPermissions": len(rows),
        "highRisk": sum(1 for x in rows if x["risk_band"] == "High"),
        "delegated": sum(1 for x in rows if x["permission_type"] == "Delegated"),
        "application": sum(1 for x in rows if x["permission_type"] == "Application"),
        "highestRisk": sorted(rows, key=lambda x: x["risk_score"], reverse=True)[:5],
    }
    (out / "permission-risk-summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({k: v for k, v in summary.items() if k != "highestRisk"}, indent=2))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
