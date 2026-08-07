#!/usr/bin/env python3
"""Create public, sanitised Scenario 17 evidence from local working outputs."""
from __future__ import annotations

import argparse
import csv
import json
import shutil
import hashlib
import re
from pathlib import Path
from typing import Iterable

IDENTITY_MAP = {
    "maya.chen@compliant-secure.example.invalid": "USER-001",
    "liam.ng@compliant-secure.example.invalid": "USER-002",
    "noah.wilson@compliant-secure.example.invalid": "USER-003",
    "olivia.patel@compliant-secure.example.invalid": "USER-004",
    "ethan.brown@compliant-secure.example.invalid": "USER-005",
    "soc.admin@compliant-secure.example.invalid": "ADMIN-001",
    "Backup Automation": "SP-001",
    "Reporting VM Managed Identity": "MI-001",
    "external-review@example.invalid": "EXTERNAL-DEST-001",
}
ID_MAP = {
    "36b3e986-083e-51f5-8686-87914076c750": "SIGNIN-INCIDENT-001",
    "e7d719e9-7a02-5fc3-9b43-9edd645625d0": "SESSION-001",
    "9080a721-94e4-592d-88b5-165e7c3d5141": "CORRELATION-001",
    "07a8096d-805a-58cf-9f10-a7384e9965a7": "REQUEST-001",
    "82bf3684-0619-592b-82a9-9658f519a5b8": "USER-ID-001",
}
UUID_RE = re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}\b")


def uuid_alias(match: re.Match[str]) -> str:
    return "SYNID-" + hashlib.sha256(match.group(0).lower().encode()).hexdigest()[:12].upper()


IP_ROLE = {
    "198.51.100.77": "ATTACK-IP-01",
    "198.51.100.88": "ATTACK-IP-02",
    "203.0.113.10": "CORP-VPN-01",
    "192.0.2.80": "CORP-OFFICE-01",
    "192.0.2.44": "BASELINE-ISP-01",
    "203.0.113.50": "AZURE-EGRESS-01",
}


def clean(value: object) -> str:
    if value is None:
        return ""
    text = str(value)
    for source, alias in IDENTITY_MAP.items():
        text = text.replace(source, alias)
    for source, alias in ID_MAP.items():
        text = text.replace(source, alias)
    text = text.replace("https://compliant-secure.example.invalid", "https://tenant.example.invalid")
    text = text.replace("Compliant Secure", "Synthetic Organisation")
    text = text.replace("Maya Chen", "User 001")
    text = UUID_RE.sub(uuid_alias, text)
    return text


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8", newline="") as fh:
        return [dict(row) for row in csv.DictReader(fh)]


def write_csv(path: Path, rows: Iterable[dict[str, object]], fields: list[str] | None = None) -> None:
    rows = list(rows)
    if fields is None:
        fields = list(rows[0]) if rows else []
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow({key: clean(row.get(key, "")) for key in fields})


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scenario-dir", required=True, type=Path)
    args = parser.parse_args()

    scenario = args.scenario_dir.expanduser().resolve()
    working = scenario / "evidence" / "working"
    processed = scenario / "evidence" / "processed"
    processed.mkdir(parents=True, exist_ok=True)

    required = [
        "precise-incident-timeline.csv", "precise-identifier-linkage.csv",
        "precise-evidence-assessment.csv", "identity-inventory.csv",
        "application-inventory.csv", "source-ip-and-location-inventory.csv",
        "device-inventory.csv", "authentication-result-summary.csv",
        "mfa-method-and-result-summary.csv", "conditional-access-policy-summary.csv",
        "risk-signal-summary.csv", "legacy-authentication-candidates.csv",
        "mfa-fatigue-candidates.csv", "password-spray-candidates.csv",
        "follow-on-audit-activity.csv", "detection-gaps.csv",
        "source-sha256-records.tsv",
    ]
    missing = [name for name in required if not (working / name).is_file()]
    if missing:
        print("ERROR: missing working outputs:")
        for name in missing:
            print(f"  {working / name}")
        return 2

    timeline = read_csv(working / "precise-incident-timeline.csv")
    timeline_out = []
    for row in timeline:
        row = {key: clean(value) for key, value in row.items()}
        row["ip_role"] = IP_ROLE.get(row.get("ip_address", ""), "")
        timeline_out.append(row)
    timeline_fields = [
        "time_utc", "source", "category", "identity", "ip_address", "ip_role",
        "application_or_activity", "result", "evidence_class", "stable_link", "details",
    ]
    write_csv(processed / "cloud-identity-event-timeline.csv", timeline_out, timeline_fields)

    identity_rows = []
    classifications = {
        "USER-001": "Confirmed account compromise",
        "USER-002": "Unsuccessful attack", "USER-003": "Unsuccessful attack",
        "USER-004": "Unsuccessful attack", "USER-005": "Unsuccessful attack",
        "SP-001": "Benign", "MI-001": "Benign",
    }
    for row in read_csv(working / "identity-inventory.csv"):
        alias = IDENTITY_MAP.get(row["identity_name"], clean(row["identity_name"]))
        identity_rows.append({
            "identity_alias": alias,
            "identity_type": row["identity_type"],
            "event_count": row["event_count"],
            "success_count": row["success_count"],
            "failure_count": row["failure_count"],
            "sign_in_types": row["sign_in_types"],
            "final_classification": classifications.get(alias, "Unable to confirm"),
        })
    write_csv(processed / "identity-and-signin-type-summary.csv", identity_rows)

    app_rows = []
    for row in read_csv(working / "application-inventory.csv"):
        app_rows.append({key: row[key] for key in (
            "app_display_name", "resource_display_name", "event_count",
            "success_count", "failure_count", "client_applications",
            "authentication_protocols"
        )})
    write_csv(processed / "application-and-resource-summary.csv", app_rows)

    ip_assessments = {
        "ATTACK-IP-01": "Malicious infrastructure in scenario ground truth; suspicious independent of GeoIP.",
        "ATTACK-IP-02": "Second attack source; password spray and blocked legacy-authentication attempt.",
        "CORP-VPN-01": "Approved corporate VPN exit; benign anomaly.",
        "CORP-OFFICE-01": "Approved corporate office egress used for response activity.",
        "BASELINE-ISP-01": "Normal synthetic user baseline network.",
        "AZURE-EGRESS-01": "Expected synthetic Azure workload egress.",
    }
    ip_rows = []
    for row in read_csv(working / "source-ip-and-location-inventory.csv"):
        role = IP_ROLE.get(row["ip_address"], "")
        new = dict(row)
        new["ip_role"] = role
        new["assessment"] = ip_assessments.get(role, "")
        ip_rows.append(new)
    ip_fields = ["ip_address", "ip_role"] + [
        key for key in ip_rows[0].keys() if key not in ("ip_address", "ip_role", "assessment")
    ] + ["assessment"]
    write_csv(processed / "source-ip-and-location-analysis.csv", ip_rows, ip_fields)

    device_alias = {}
    device_rows = []
    for row in read_csv(working / "device-inventory.csv"):
        raw_id = row.get("device_id", "")
        if raw_id and raw_id not in device_alias:
            device_alias[raw_id] = f"DEVICE-{len(device_alias)+1:03d}"
        device_rows.append({
            "device_alias": device_alias.get(raw_id, "NOT-AVAILABLE"),
            "device_name": row.get("device_name", ""),
            "operating_system": row.get("operating_system", ""),
            "browser": row.get("browser", ""),
            "is_compliant": row.get("is_compliant", ""),
            "is_managed": row.get("is_managed", ""),
            "trust_type": row.get("trust_type", ""),
            "event_count": row.get("event_count", ""),
            "success_count": row.get("success_count", ""),
            "failure_count": row.get("failure_count", ""),
            "users": clean(row.get("users", "")),
            "device_context": row.get("device_context", ""),
        })
    write_csv(processed / "device-context-analysis.csv", device_rows)

    auth_rows = read_csv(working / "authentication-result-summary.csv")
    for row in auth_rows:
        code = row.get("error_code", "")
        if code == "50126":
            note = "Invalid username/password; does not prove correct credentials."
        elif code == "53003":
            note = "Conditional Access blocked the request; no token/session issued."
        elif code == "500121":
            note = "MFA challenge failed; primary authentication had already succeeded."
        else:
            note = "Successful authentication or token activity; inspect authentication details and session context."
        row["investigation_interpretation"] = note
    write_csv(processed / "authentication-result-analysis.csv", auth_rows)

    mfa_rows = read_csv(working / "mfa-method-and-result-summary.csv")
    boundary = {
        "denied": "Denial is telemetry-confirmed; motive is not.",
        "timeout": "Timeout is telemetry-confirmed; push bombing requires sequence/context.",
        "success": "Success confirms method completion, not user authorization.",
        "satisfied_by_claim": "No fresh user interaction should be inferred.",
    }
    for row in mfa_rows:
        row["evidence_boundary"] = boundary.get(row.get("outcome", ""), "")
    write_csv(processed / "mfa-method-and-result-analysis.csv", mfa_rows)

    policy_alias = {
        "SYN-CA-Require-MFA-High-SignIn-Risk": "CA-POLICY-001",
        "SYN-CA-Block-Legacy-Authentication": "CA-POLICY-002",
        "SYN-CA-Require-Compliant-Device-Finance-ReportOnly": "CA-POLICY-003",
        "SYN-CA-Require-MFA-All-Users": "CA-POLICY-004",
    }
    ca_rows = []
    for row in read_csv(working / "conditional-access-policy-summary.csv"):
        result = row["result"]
        if result.startswith("reportOnly"):
            interpretation = "Report-only evaluation; did not block or grant access."
        elif result == "notApplied":
            interpretation = "Not applied; exact internal condition trace not available."
        else:
            interpretation = "Enforced policy result; interpret with overall sign-in result and grant controls."
        ca_rows.append({
            "policy_alias": policy_alias.get(row["policy_name"], "CA-POLICY-OTHER"),
            "result": result,
            "grant_controls": row["grant_controls"],
            "event_count": row["event_count"],
            "enforcement_interpretation": row["enforcement_interpretation"],
            "final_interpretation": interpretation,
        })
    write_csv(processed / "conditional-access-analysis.csv", ca_rows)

    risk_rows = read_csv(working / "risk-signal-summary.csv")
    for row in risk_rows:
        row["assessment"] = "Platform-generated lead; corroborating evidence only, not proof of compromise."
    write_csv(processed / "risk-signal-assessment.csv", risk_rows)

    write_csv(
        processed / "correlation-and-session-analysis.csv",
        [{key: clean(value) for key, value in row.items()}
         for row in read_csv(working / "precise-identifier-linkage.csv")]
    )

    legacy = read_csv(working / "legacy-authentication-candidates.csv")
    for row in legacy:
        row["user_principal_name"] = clean(row["user_principal_name"])
        row["final_classification"] = "Unsuccessful attack"
        row["assessment"] = "IMAP/ROPC was blocked by enforced Conditional Access; no session or token was issued."
    write_csv(processed / "legacy-authentication-analysis.csv", legacy)

    fatigue = read_csv(working / "mfa-fatigue-candidates.csv")
    for row in fatigue:
        row["user_principal_name"] = clean(row["user_principal_name"])
        row["success_signin_id"] = "SIGNIN-INCIDENT-001"
        row["session_id"] = "SESSION-001"
        row["final_assessment"] = (
            "MFA fatigue/push bombing confirmed by repeated failures, later success, "
            "and user verification that the approval was unauthorized."
        )
    write_csv(processed / "mfa-fatigue-assessment.csv", fatigue)

    spray = read_csv(working / "password-spray-candidates.csv")
    for row in spray:
        row["ip_role"] = IP_ROLE.get(row["ip_address"], "")
        row["users"] = clean(row["users"])
        row["final_assessment"] = "Distributed password-spray source; five users targeted with error 50126."
    spray_fields = ["ip_address", "ip_role"] + [
        key for key in spray[0].keys() if key not in ("ip_address", "ip_role", "final_assessment")
    ] + ["final_assessment"]
    write_csv(processed / "password-spray-assessment.csv", spray, spray_fields)

    follow = read_csv(working / "follow-on-audit-activity.csv")
    containment = {
        "Revoke all refresh tokens for user",
        "Reset password (by admin)",
        "Delete user authentication method",
    }
    for row in follow:
        for key in list(row):
            row[key] = clean(row[key])
        row["activity_role"] = (
            "Containment/remediation" if row["activity"] in containment
            else "Unauthorized follow-on activity"
        )
    write_csv(processed / "follow-on-activity-analysis.csv", follow)

    write_csv(
        processed / "account-compromise-assessment.csv",
        [{key: clean(value) for key, value in row.items()}
         for row in read_csv(working / "precise-evidence-assessment.csv")]
    )
    write_csv(processed / "detection-gap-analysis.csv",
              read_csv(working / "detection-gaps.csv"))

    excerpts = [
        {
            "excerpt_id": "EX-001", "evidence_class": "Telemetry-confirmed fact",
            "time_utc": "2026-06-18T01:40:00Z–01:41:46Z",
            "entity_or_identifier": "ATTACK-IP-01/02",
            "sanitised_observation": "10 invalid-password failures across five users",
            "interpretation": "Confirms distributed password spray; no successful authentication implied.",
        },
        {
            "excerpt_id": "EX-002", "evidence_class": "Telemetry-confirmed fact",
            "time_utc": "2026-06-18T01:44:00Z–01:47:15Z",
            "entity_or_identifier": "USER-001",
            "sanitised_observation": "Two MFA denials and two timeouts after correct primary authentication",
            "interpretation": "Supports MFA fatigue pattern; intent requires context.",
        },
        {
            "excerpt_id": "EX-003", "evidence_class": "Telemetry-confirmed fact",
            "time_utc": "2026-06-18T01:49:10Z",
            "entity_or_identifier": "SIGNIN-INCIDENT-001",
            "sanitised_observation": "Number matching succeeded and SESSION-001 was created",
            "interpretation": "Confirms method completion and session creation, not authorization by itself.",
        },
        {
            "excerpt_id": "EX-004", "evidence_class": "Conditional Access",
            "time_utc": "2026-06-18T01:49:10Z",
            "entity_or_identifier": "CA-POLICY-003",
            "sanitised_observation": "Report-only device policy returned reportOnlyFailure",
            "interpretation": "Did not block the sign-in.",
        },
        {
            "excerpt_id": "EX-005", "evidence_class": "Session correlation",
            "time_utc": "2026-06-18T01:52:00Z–02:22:00Z",
            "entity_or_identifier": "SESSION-001",
            "sanitised_observation": "Three non-interactive token events and four M365 events shared the session",
            "interpretation": "Confirms session continuity; not repeated MFA approval.",
        },
        {
            "excerpt_id": "EX-006", "evidence_class": "Business verification",
            "time_utc": "2026-06-18T02:55:00Z",
            "entity_or_identifier": "SYN-IR-2026-0017",
            "sanitised_observation": "User confirmed the sign-in and follow-on actions were unauthorized",
            "interpretation": "Provides the authorization boundary for confirmed compromise.",
        },
    ]
    excerpt_path = processed / "sanitised-evidence-excerpts.tsv"
    with excerpt_path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(excerpts[0]), delimiter="\t")
        writer.writeheader()
        writer.writerows(excerpts)

    shutil.copy2(working / "source-sha256-records.tsv",
                 processed / "source-sha256-records.tsv")
    (processed / "DATASET-LICENSE.txt").write_text(
        "Scenario 17 synthetic dataset\n\n"
        "To the extent possible under law, the generated synthetic dataset is "
        "dedicated to the public domain under CC0 1.0.\n"
        "No real tenant, account, secret, token, or personal data is included.\n",
        encoding="utf-8",
    )

    print(f"Processed evidence written to {processed}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
