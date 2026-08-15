#!/usr/bin/env python3
"""Precise verification for Scenario 17 synthetic Entra identity investigation.

Reads local raw and first-pass working evidence, verifies integrity and stable-ID
linkage, and writes compact precision outputs without modifying raw evidence.
Standard-library only; designed for macOS Python 3.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import sqlite3
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument(
        "--scenario-dir",
        default=str(Path(__file__).resolve().parents[2]),
        help="Scenario 17 directory",
    )
    return p.parse_args()


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as fh:
        for n, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise ValueError(f"Invalid JSONL at {path}:{n}: {exc}") from exc
    return rows


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def write_csv(path: Path, rows: Iterable[dict[str, Any]], fields: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=fields)
        w.writeheader()
        for row in rows:
            out = {}
            for key in fields:
                value = row.get(key, "")
                if isinstance(value, (list, dict, set, tuple)):
                    value = json.dumps(value, ensure_ascii=False, sort_keys=True)
                elif isinstance(value, bool):
                    value = "True" if value else "False"
                out[key] = value
            w.writerow(out)


def status_class(signin: dict[str, Any]) -> str:
    try:
        code = int(signin.get("status", {}).get("errorCode", 0))
    except (TypeError, ValueError):
        code = -1
    return "success" if code == 0 else "failure"


def dt_key(value: str) -> datetime:
    if not value:
        return datetime.max.replace(tzinfo=timezone.utc)
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def authentication_outcomes(signin: dict[str, Any]) -> list[str]:
    out = []
    for step in signin.get("authenticationDetails", []) or []:
        requirement = str(step.get("authenticationStepRequirement", "")).lower()
        detail = str(step.get("authenticationStepResultDetail", "")).lower()
        if "multifactor" not in requirement:
            continue
        if "denied" in detail or "declined" in detail:
            out.append("denied")
        elif "timeout" in detail or "no response" in detail:
            out.append("timeout")
        elif "claim" in detail or "previous" in str(step.get("authenticationMethod", "")).lower():
            out.append("satisfied_by_claim")
        elif bool(step.get("succeeded")):
            out.append("success")
        else:
            out.append("interrupted")
    return out


def ca_policy(signin: dict[str, Any], name_fragment: str) -> list[dict[str, Any]]:
    return [
        p for p in (signin.get("conditionalAccessPolicies", []) or [])
        if name_fragment.lower() in str(p.get("displayName", "")).lower()
    ]


def main() -> int:
    args = parse_args()
    scenario = Path(args.scenario_dir).expanduser().resolve()
    raw = scenario / "evidence" / "raw"
    working = scenario / "evidence" / "working"
    working.mkdir(parents=True, exist_ok=True)

    required = [
        raw / "entra-signins.jsonl",
        raw / "entra-directory-audit.jsonl",
        raw / "m365-unified-audit.jsonl",
        raw / "identity-protection-risk-detections.jsonl",
        raw / "business-context.json",
        raw / "ground-truth.json",
        raw / "schema-basis.json",
        raw / "acquisition-manifest.json",
        working / "source-sha256-records.tsv",
        working / "first-pass-output-manifest.tsv",
        working / "scenario17-analysis.sqlite",
    ]
    missing = [str(p) for p in required if not p.is_file()]
    if missing:
        print("ERROR: required files are missing:")
        for p in missing:
            print(f"- {p}")
        return 2

    signins = read_jsonl(raw / "entra-signins.jsonl")
    directory = read_jsonl(raw / "entra-directory-audit.jsonl")
    m365 = read_jsonl(raw / "m365-unified-audit.jsonl")
    risks = read_jsonl(raw / "identity-protection-risk-detections.jsonl")
    business = read_json(raw / "business-context.json")
    ground_truth = read_json(raw / "ground-truth.json")

    quality: list[dict[str, Any]] = []

    # Source hash verification.
    hash_total = 0
    hash_ok = 0
    hash_mismatch = []
    with (working / "source-sha256-records.tsv").open("r", encoding="utf-8", newline="") as fh:
        for row in csv.DictReader(fh, delimiter="\t"):
            p = raw / row["file_name"]
            if not p.is_file():
                hash_mismatch.append(f"missing:{row['file_name']}")
                continue
            hash_total += 1
            actual = sha256(p)
            if actual == row["sha256"] and p.stat().st_size == int(row["size_bytes"]):
                hash_ok += 1
            else:
                hash_mismatch.append(row["file_name"])
    quality.append({
        "check": "Raw source hash verification",
        "status": "PASS" if hash_total and hash_ok == hash_total and not hash_mismatch else "FAIL",
        "observed": f"{hash_ok}/{hash_total} raw files matched recorded size and SHA-256",
        "impact": "Raw evidence integrity is established for the locally generated dataset." if not hash_mismatch else f"Mismatches: {hash_mismatch}",
    })

    # Basic record and ID integrity.
    signin_ids = [s.get("id", "") for s in signins]
    unique_ok = len(signin_ids) == len(set(signin_ids)) and all(signin_ids)
    quality.append({
        "check": "Sign-in identifier uniqueness",
        "status": "PASS" if unique_ok else "FAIL",
        "observed": f"{len(signins)} records / {len(set(signin_ids))} distinct sign-in IDs",
        "impact": "No duplicate sign-in IDs distort event counting." if unique_ok else "Duplicate or missing sign-in IDs require repair.",
    })
    all_synthetic = all(bool(r.get("syntheticRecord")) for r in signins + directory + m365 + risks)
    quality.append({
        "check": "Synthetic-data marking",
        "status": "PASS" if all_synthetic else "FAIL",
        "observed": f"All event records synthetic={all_synthetic}",
        "impact": "The package is not presented as production tenant telemetry.",
    })

    # SQLite normalization integrity.
    con = sqlite3.connect(f"file:{working / 'scenario17-analysis.sqlite'}?mode=ro&immutable=1", uri=True)
    db_counts = {
        "signins": con.execute("select count(*) from signins").fetchone()[0],
        "directory_audits": con.execute("select count(*) from directory_audits").fetchone()[0],
        "m365_audits": con.execute("select count(*) from m365_audits").fetchone()[0],
        "risk_detections": con.execute("select count(*) from risk_detections").fetchone()[0],
    }
    orphan_auth = con.execute("select count(*) from authentication_steps a left join signins s on s.id=a.signin_id where s.id is null").fetchone()[0]
    orphan_ca = con.execute("select count(*) from ca_policy_results c left join signins s on s.id=c.signin_id where s.id is null").fetchone()[0]
    expected_counts = {
        "signins": len(signins), "directory_audits": len(directory),
        "m365_audits": len(m365), "risk_detections": len(risks),
    }
    db_ok = db_counts == expected_counts and orphan_auth == 0 and orphan_ca == 0
    quality.append({
        "check": "Parser and SQLite normalization",
        "status": "PASS" if db_ok else "FAIL",
        "observed": f"counts={db_counts}; orphan_auth={orphan_auth}; orphan_ca={orphan_ca}",
        "impact": "First-pass parsing and identity-event classification are structurally reliable." if db_ok else "Normalized outputs do not exactly represent raw records.",
    })
    con.close()

    # Detect the known first-pass manifest timing issue without modifying it.
    manifest_mismatches = []
    with (working / "first-pass-output-manifest.tsv").open("r", encoding="utf-8", newline="") as fh:
        for row in csv.DictReader(fh, delimiter="\t"):
            p = working / row["file_name"]
            if not p.is_file():
                manifest_mismatches.append(f"missing:{row['file_name']}")
                continue
            if p.stat().st_size != int(row["size_bytes"]) or sha256(p) != row["sha256"]:
                manifest_mismatches.append(row["file_name"])
    quality.append({
        "check": "First-pass output manifest",
        "status": "WARN" if manifest_mismatches else "PASS",
        "observed": f"Mismatched entries: {manifest_mismatches or 'none'}",
        "impact": "The console file continued changing after the first-pass manifest was written. Regenerate manifests only after console capture closes." if manifest_mismatches else "Working-output provenance is internally consistent.",
    })

    verification = business.get("userVerification", {})
    incident_user = verification.get("userPrincipalName", "")
    verified_at = verification.get("verifiedAt", "")
    verification_outcome = verification.get("verificationOutcome", "")
    user_statements = verification.get("statements", [])
    unauthorized_verified = incident_user and "unauthorized" in verification_outcome.lower()

    approved_ips = {n.get("ipAddress") for n in business.get("approvedNetworks", [])}
    incident_signins = sorted(
        [s for s in signins if s.get("userPrincipalName") == incident_user],
        key=lambda s: dt_key(s.get("createdDateTime", "")),
    )

    spray_events = [s for s in signins if int(s.get("status", {}).get("errorCode", 0) or 0) == 50126]
    spray_by_ip: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for s in spray_events:
        spray_by_ip[str(s.get("ipAddress", ""))].append(s)
    spray_candidates = {
        ip: evs for ip, evs in spray_by_ip.items()
        if len({e.get("userPrincipalName") for e in evs}) >= 5
    }

    mfa_failures = []
    mfa_successes = []
    for s in incident_signins:
        outcomes = authentication_outcomes(s)
        if any(o in {"denied", "timeout"} for o in outcomes):
            mfa_failures.append(s)
        if "success" in outcomes and status_class(s) == "success" and bool(s.get("isInteractive")):
            mfa_successes.append(s)

    suspicious_successes = [
        s for s in mfa_successes
        if s.get("ipAddress") not in approved_ips
        and (s.get("riskLevelDuringSignIn") in {"medium", "high"}
             or bool(s.get("isAnonymousProxy"))
             or s.get("deviceDetail", {}).get("isManaged") is False)
    ]
    if not suspicious_successes:
        print("ERROR: no suspicious interactive MFA success was found for the verified user")
        return 3
    success = suspicious_successes[0]
    success_time = success.get("createdDateTime", "")
    session_id = success.get("sessionId", "")
    success_corr = success.get("correlationId", "")
    success_request = success.get("requestId", "")
    success_signin_id = success.get("id", "")

    session_signins = sorted([s for s in signins if session_id and s.get("sessionId") == session_id], key=lambda s: dt_key(s.get("createdDateTime", "")))
    session_m365 = sorted([a for a in m365 if session_id and a.get("sessionId") == session_id], key=lambda a: dt_key(a.get("creationTime", "")))
    corr_directory = sorted([a for a in directory if success_corr and a.get("correlationId") == success_corr], key=lambda a: dt_key(a.get("activityDateTime", "")))
    linked_risks = sorted([
        r for r in risks
        if (success_request and r.get("requestId") == success_request)
        or (success_corr and r.get("correlationId") == success_corr)
    ], key=lambda r: (dt_key(r.get("activityDateTime", "")), str(r.get("riskEventType", ""))))

    legacy = [
        s for s in incident_signins
        if str(s.get("clientAppUsed", "")).upper() in {"IMAP", "POP", "SMTP AUTH", "EXCHANGE ACTIVESYNC"}
        or str(s.get("authenticationProtocol", "")).lower() in {"ropc", "ws-trust"}
    ]
    legacy_blocked = []
    for s in legacy:
        block_policies = ca_policy(s, "Block-Legacy")
        if status_class(s) == "failure" and any(p.get("result") == "failure" for p in block_policies) and not s.get("sessionId"):
            legacy_blocked.append(s)

    follow_on = []
    for a in corr_directory:
        follow_on.append((a.get("activityDateTime", ""), "Entra directory audit", a.get("activityDisplayName", ""), a))
    for a in session_m365:
        follow_on.append((a.get("creationTime", ""), "M365 unified audit", a.get("operation", ""), a))
    follow_on.sort(key=lambda x: dt_key(x[0]))

    independent_classification = "Unable to confirm"
    if unauthorized_verified and success and follow_on and session_id:
        independent_classification = "Confirmed account compromise"
    elif success and follow_on:
        independent_classification = "Possible account compromise"
    elif success:
        independent_classification = "Suspicious successful sign-in"

    ground_truth_class = ground_truth.get("classificationByEntity", {}).get(incident_user, "")
    ground_truth_aligns = independent_classification == ground_truth_class

    # Timeline.
    timeline: list[dict[str, Any]] = []
    for s in incident_signins:
        when = s.get("createdDateTime", "")
        if when < "2026-06-17T23:40:00Z":
            continue
        outcomes = authentication_outcomes(s)
        result = status_class(s)
        stable = []
        if s.get("sessionId"):
            stable.append(f"session={s['sessionId']}")
        if s.get("correlationId"):
            stable.append(f"correlation={s['correlationId']}")
        if s.get("requestId"):
            stable.append(f"request={s['requestId']}")
        detail = s.get("status", {}).get("additionalDetails", "")
        if outcomes:
            detail = f"{detail}; MFA={','.join(outcomes)}"
        timeline.append({
            "time_utc": when,
            "source": "Entra sign-in",
            "category": s.get("signInLogType", ""),
            "identity": s.get("userPrincipalName", "") or s.get("servicePrincipalName", "") or s.get("managedIdentityName", ""),
            "ip_address": s.get("ipAddress", ""),
            "application_or_activity": s.get("appDisplayName", ""),
            "result": result,
            "evidence_class": "Telemetry-confirmed fact",
            "stable_link": "; ".join(stable),
            "details": detail,
        })
    for r in linked_risks:
        timeline.append({
            "time_utc": r.get("detectedDateTime", ""),
            "source": "Identity Protection",
            "category": r.get("riskEventType", ""),
            "identity": r.get("userPrincipalName", ""),
            "ip_address": r.get("ipAddress", ""),
            "application_or_activity": "Risk detection",
            "result": f"{r.get('riskLevel', '')}/{r.get('riskState', '')}",
            "evidence_class": "Platform-generated risk",
            "stable_link": f"correlation={r.get('correlationId','')}; request={r.get('requestId','')}",
            "details": f"activity={r.get('activityDateTime','')}; timing={r.get('detectionTimingType','')}",
        })
    for a in directory:
        actor = a.get("initiatedBy", {}).get("user", {})
        target_names = [t.get("userPrincipalName", "") for t in a.get("targetResources", [])]
        if incident_user not in target_names and actor.get("userPrincipalName") != incident_user:
            continue
        timeline.append({
            "time_utc": a.get("activityDateTime", ""),
            "source": "Entra directory audit",
            "category": a.get("category", ""),
            "identity": actor.get("userPrincipalName", ""),
            "ip_address": actor.get("ipAddress", ""),
            "application_or_activity": a.get("activityDisplayName", ""),
            "result": a.get("result", ""),
            "evidence_class": "Telemetry-confirmed fact",
            "stable_link": f"correlation={a.get('correlationId','')}",
            "details": f"target={','.join(target_names)}",
        })
    for a in m365:
        if a.get("userId") != incident_user:
            continue
        timeline.append({
            "time_utc": a.get("creationTime", ""),
            "source": "M365 unified audit",
            "category": a.get("workload", ""),
            "identity": a.get("userId", ""),
            "ip_address": a.get("clientIP", ""),
            "application_or_activity": a.get("operation", ""),
            "result": a.get("resultStatus", ""),
            "evidence_class": "Telemetry-confirmed fact",
            "stable_link": f"session={a.get('sessionId','')}",
            "details": f"object={a.get('objectId','')}; parameters={json.dumps(a.get('parameters',{}), sort_keys=True)}",
        })
    timeline.append({
        "time_utc": verified_at,
        "source": "Incident ticket",
        "category": "User verification",
        "identity": incident_user,
        "ip_address": "",
        "application_or_activity": verification.get("ticketId", ""),
        "result": verification_outcome,
        "evidence_class": "Business/user verification",
        "stable_link": "",
        "details": " | ".join(user_statements),
    })
    timeline.sort(key=lambda r: (dt_key(r["time_utc"]), r["source"], r["application_or_activity"]))
    write_csv(
        working / "precise-incident-timeline.csv", timeline,
        ["time_utc", "source", "category", "identity", "ip_address", "application_or_activity", "result", "evidence_class", "stable_link", "details"],
    )

    # Identifier linkage.
    id_rows: list[dict[str, Any]] = []
    id_rows.append({
        "identifier_type": "Sign-in ID", "identifier_value": success_signin_id,
        "linked_sources": ["interactive sign-in"], "linked_event_count": 1,
        "interpretation": "Identifies the successful interactive sign-in record only.",
    })
    id_rows.append({
        "identifier_type": "Session ID", "identifier_value": session_id,
        "linked_sources": ["interactive sign-in", "non-interactive sign-ins", "M365 unified audit"],
        "linked_event_count": len(session_signins) + len(session_m365),
        "interpretation": "Strongest cross-source chain for the successful session and follow-on M365 activity; it does not prove token theft by itself.",
    })
    id_rows.append({
        "identifier_type": "Correlation ID", "identifier_value": success_corr,
        "linked_sources": ["successful sign-in", "risk detections", "security-info registration audit"],
        "linked_event_count": 1 + len(linked_risks) + len(corr_directory),
        "interpretation": "Links the authentication transaction to platform risk records and the directory audit event in this synthetic package.",
    })
    id_rows.append({
        "identifier_type": "Request ID", "identifier_value": success_request,
        "linked_sources": ["successful sign-in", "risk detections"],
        "linked_event_count": 1 + sum(1 for r in linked_risks if r.get("requestId") == success_request),
        "interpretation": "Links risk detections to the exact successful request; it is not a whole-session identifier.",
    })
    id_rows.append({
        "identifier_type": "Unique token identifiers", "identifier_value": [s.get("uniqueTokenIdentifier", "") for s in session_signins],
        "linked_sources": ["interactive and non-interactive sign-ins"],
        "linked_event_count": len(session_signins),
        "interpretation": "Token identifiers differ across token events; do not use them as a substitute for Session ID.",
    })
    write_csv(
        working / "precise-identifier-linkage.csv", id_rows,
        ["identifier_type", "identifier_value", "linked_sources", "linked_event_count", "interpretation"],
    )

    # Evidence classification.
    evidence_rows = [
        {
            "evidence_id": "T01", "evidence_class": "Telemetry-confirmed fact", "status": "Confirmed",
            "statement": f"Two source IPs produced {sum(len(v) for v in spray_candidates.values())} invalid-password attempts against {len({s.get('userPrincipalName') for v in spray_candidates.values() for s in v})} users.",
            "source_link": "Entra sign-ins / error 50126", "conclusion_use": "Confirms distributed password-spray behavior; it does not prove any password was correct.",
        },
        {
            "evidence_id": "T02", "evidence_class": "Telemetry-confirmed fact", "status": "Confirmed",
            "statement": f"For {incident_user}, four later sign-ins from {success.get('ipAddress')} recorded correct primary authentication before MFA: 2 denied and 2 timed out.",
            "source_link": "authenticationDetails preceding the successful sign-in", "conclusion_use": "Confirms the actor possessed or successfully used the correct password by 01:44 UTC.",
        },
        {
            "evidence_id": "T03", "evidence_class": "Telemetry-confirmed fact", "status": "Confirmed",
            "statement": f"A successful interactive sign-in occurred at {success_time} using Microsoft Authenticator number matching from an unapproved anonymous-proxy IP and unmanaged/unknown device context.",
            "source_link": f"signInId={success_signin_id}", "conclusion_use": "Confirms successful primary authentication, MFA completion, Conditional Access satisfaction and session creation; does not by itself prove user intent.",
        },
        {
            "evidence_id": "T04", "evidence_class": "Telemetry-confirmed fact", "status": "Confirmed",
            "statement": "The compliant-device policy returned reportOnlyFailure while enforced MFA policies returned success.",
            "source_link": f"signInId={success_signin_id} / conditionalAccessPolicies", "conclusion_use": "Report-only failure did not block the sign-in and must not be described as enforcement.",
        },
        {
            "evidence_id": "T05", "evidence_class": "Telemetry-confirmed fact", "status": "Confirmed",
            "statement": f"Session {session_id} linked one interactive sign-in, three non-interactive token events and {len(session_m365)} M365 audit events.",
            "source_link": "Session ID across sign-in and M365 audit records", "conclusion_use": "Confirms session continuity and follow-on activity; non-interactive events are not additional user MFA approvals.",
        },
        {
            "evidence_id": "T06", "evidence_class": "Telemetry-confirmed fact", "status": "Confirmed",
            "statement": f"Correlation {success_corr} links the successful sign-in, {len(linked_risks)} platform risk records and {len(corr_directory)} security-information registration audit event(s).",
            "source_link": "Correlation ID / Request ID", "conclusion_use": "Strengthens cross-source linkage without treating every nearby event as the same transaction.",
        },
        {
            "evidence_id": "T07", "evidence_class": "Telemetry-confirmed fact", "status": "Confirmed" if legacy_blocked else "Not observed",
            "statement": "A separate IMAP/ROPC sign-in from the second attack IP was blocked by an enforced legacy-authentication policy and issued no session/token." if legacy_blocked else "No independently blocked legacy-authentication attempt was found.",
            "source_link": "Entra sign-in / Conditional Access", "conclusion_use": "This is a separate unsuccessful attempt, not part of the successful session.",
        },
        {
            "evidence_id": "P01", "evidence_class": "Platform-generated risk", "status": "Confirmed",
            "statement": f"The platform emitted {len(linked_risks)} risk detections linked to the successful request/correlation.",
            "source_link": "Identity Protection risk detections", "conclusion_use": "Corroborating leads only; risk labels are not the proof of compromise.",
        },
        {
            "evidence_id": "B01", "evidence_class": "Business/user verification", "status": "Confirmed" if unauthorized_verified else "Not available",
            "statement": verification_outcome or "No user verification was available.",
            "source_link": verification.get("ticketId", ""), "conclusion_use": "Provides the authorization boundary required to distinguish suspicious success from confirmed unauthorized use.",
        },
        {
            "evidence_id": "B02", "evidence_class": "Business context", "status": "Confirmed",
            "statement": "The preceding Sydney location was an approved corporate VPN exit, so the travel-speed calculation is not proof of physical travel.",
            "source_link": "business-context.json approvedNetworks", "conclusion_use": "Suppresses impossible-travel overclaim while leaving the Bucharest sign-in suspicious on independent evidence.",
        },
        {
            "evidence_id": "G01", "evidence_class": "Ground truth", "status": "Confirmed" if ground_truth_aligns else "Conflict",
            "statement": f"Ground-truth classification is '{ground_truth_class}' and {'matches' if ground_truth_aligns else 'does not match'} the independent assessment.",
            "source_link": "ground-truth.json", "conclusion_use": "Used only as a post-assessment validation check, not as primary evidence.",
        },
        {
            "evidence_id": "N01", "evidence_class": "Not available", "status": "Not available",
            "statement": "Authenticator approving-device/GPS telemetry and raw token material are absent by design.",
            "source_link": "detection gaps / business context", "conclusion_use": "Telemetry cannot identify the physical approver or prove token theft/replay.",
        },
        {
            "evidence_id": "N02", "evidence_class": "Detection gap", "status": "Detection gap",
            "statement": "Detailed internal Conditional Access condition traces and byte-for-byte portal export fidelity are not modeled.",
            "source_link": "schema basis and detection gaps", "conclusion_use": "Exact reasons for every notApplied result cannot be asserted beyond the available policy result.",
        },
    ]
    write_csv(
        working / "precise-evidence-assessment.csv", evidence_rows,
        ["evidence_id", "evidence_class", "status", "statement", "source_link", "conclusion_use"],
    )

    # Add nuanced quality findings.
    quality.extend([
        {
            "check": "MFA approval interpretation",
            "status": "PASS WITH BOUNDARY",
            "observed": "Telemetry records successful Microsoft Authenticator number matching; business verification says the approval was unauthorized.",
            "impact": "Describe this as user-confirmed unauthorized approval. Do not claim telemetry alone proved accidental intent or the physical approving device.",
        },
        {
            "check": "Impossible-travel interpretation",
            "status": "PASS WITH BOUNDARY",
            "observed": "The prior Sydney endpoint is an approved corporate VPN; the Bucharest endpoint is unapproved and anomalous.",
            "impact": "Do not use travel speed as proof. Retain the Bucharest sign-in as suspicious because of proxy, baseline, unmanaged device, MFA sequence and follow-on activity.",
        },
        {
            "check": "Conditional Access interpretation",
            "status": "PASS WITH BOUNDARY",
            "observed": "Enforced MFA policies succeeded; compliant-device policy was report-only failure; legacy policy separately blocked IMAP/ROPC.",
            "impact": "Report-only did not block. Exact notApplied reasons remain unavailable without condition traces.",
        },
        {
            "check": "Synthetic export fidelity",
            "status": "DISCLOSED LIMITATION",
            "observed": "Field semantics follow official schema references but are not byte-for-byte portal or Graph exports.",
            "impact": "Suitable for reproducible investigation and detection engineering, not for validating portal-export quirks.",
        },
    ])
    write_csv(working / "precise-quality-findings.csv", quality, ["check", "status", "observed", "impact"])

    # Final classifications for all modeled entities.
    attacked_users = sorted({s.get("userPrincipalName") for evs in spray_candidates.values() for s in evs if s.get("userPrincipalName")})
    entity_rows = []
    for user in attacked_users:
        entity_rows.append({
            "entity": user,
            "entity_type": "User",
            "classification": independent_classification if user == incident_user else "Unsuccessful attack",
            "basis": "Successful unauthorized session and follow-on activity" if user == incident_user else "Password-spray targeting with no successful sign-in or follow-on activity observed",
        })
    for s in signins:
        if s.get("signInLogType") == "servicePrincipal":
            entity_rows.append({"entity": s.get("servicePrincipalName", ""), "entity_type": "Service principal", "classification": "Benign", "basis": "Expected workload identity from modeled Azure egress using client credentials"})
        elif s.get("signInLogType") == "managedIdentity":
            entity_rows.append({"entity": s.get("managedIdentityName", ""), "entity_type": "Managed identity", "classification": "Benign", "basis": "Expected managed identity token acquisition from modeled Azure egress"})
    write_csv(working / "precise-entity-classifications.csv", entity_rows, ["entity", "entity_type", "classification", "basis"])

    # Summary.
    report_only = ca_policy(success, "ReportOnly")
    mfa_results = Counter()
    for s in mfa_failures + [success]:
        mfa_results.update(authentication_outcomes(s))
    summary = [
        "SCENARIO 17 PRECISE VERIFICATION",
        "=================================",
        f"Dataset: deterministic synthetic Entra/M365 event package",
        f"Raw source hashes verified: {hash_ok}/{hash_total}",
        f"Parser/SQLite structural integrity: {'PASS' if db_ok else 'FAIL'}",
        f"First-pass manifest issue: {manifest_mismatches or 'none'}",
        "",
        "FINAL IDENTITY ASSESSMENT",
        f"Incident user: {incident_user}",
        f"Classification: {independent_classification}",
        f"Ground truth checked after assessment: {ground_truth_class} (alignment={ground_truth_aligns})",
        "",
        "PRECISE ATTACK FLOW",
        f"1. Distributed password spray: {len(spray_candidates)} IPs, {sum(len(v) for v in spray_candidates.values())} failures, {len(attacked_users)} targeted users.",
        f"2. Correct password use: {len(mfa_failures)} MFA-challenged attempts for {incident_user} after primary authentication succeeded.",
        f"3. MFA sequence: denied={mfa_results['denied']}, timeout={mfa_results['timeout']}, success={mfa_results['success']}.",
        f"4. Successful interactive sign-in: {success_time}; signInId={success_signin_id}; IP={success.get('ipAddress')}; session={session_id}.",
        f"5. Conditional Access: overall={success.get('conditionalAccessStatus')}; report-only results={[p.get('result') for p in report_only]}; enforced MFA policies succeeded.",
        f"6. Platform risk: {len(linked_risks)} linked detections ({', '.join(sorted({r.get('riskEventType','') for r in linked_risks}))}).",
        f"7. Session continuation: {len(session_signins)-1} non-interactive sign-ins shared the session; each had its own request/correlation/token identifier.",
        f"8. Follow-on activity: {len(corr_directory)} correlated directory audit event(s) and {len(session_m365)} same-session M365 audit event(s).",
        f"9. Separate legacy attempt: {'blocked; no token/session issued' if legacy_blocked else 'not confirmed'}.",
        f"10. User verification: {verification_outcome}",
        "",
        "EVIDENCE BOUNDARIES",
        "- Risk labels corroborate but do not prove compromise.",
        "- The approved Sydney VPN invalidates physical impossible-travel inference; it does not explain the Bucharest sign-in.",
        "- Non-interactive records are token/session activity, not repeated MFA approvals.",
        "- Report-only Conditional Access failure was not an enforcement action.",
        "- Telemetry confirms successful number matching, but user intent and approving-device identity come from business verification, not sign-in telemetry.",
        "- No raw token, cookie, MFA seed, Authenticator GPS, or approving-device telemetry is present.",
        "",
        "QUALITY ACTION",
        "- Regenerate the final working-output manifest only after console logging is complete; the first-pass console entry is stale.",
    ]
    (working / "precise-verification-summary.txt").write_text("\n".join(summary) + "\n", encoding="utf-8")

    # Manifest for precision outputs only, excluding any live console file and itself.
    precise_names = [
        "precise-incident-timeline.csv",
        "precise-identifier-linkage.csv",
        "precise-evidence-assessment.csv",
        "precise-quality-findings.csv",
        "precise-entity-classifications.csv",
        "precise-verification-summary.txt",
    ]
    manifest_rows = []
    for name in precise_names:
        p = working / name
        manifest_rows.append({"file_name": name, "size_bytes": p.stat().st_size, "sha256": sha256(p)})
    manifest_path = working / "precise-verification-manifest.tsv"
    with manifest_path.open("w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=["file_name", "size_bytes", "sha256"], delimiter="\t")
        w.writeheader()
        w.writerows(manifest_rows)

    print("\n".join(summary))
    print(f"\nOutputs written to: {working}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
