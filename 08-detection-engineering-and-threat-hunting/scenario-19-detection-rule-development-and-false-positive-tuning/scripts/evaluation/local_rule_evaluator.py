#!/usr/bin/env python3
"""Canonical local evaluator for Scenario 19 v3.

This validates portfolio rule semantics only. It is not a Sentinel, Splunk,
Elastic, Sigma, WAF, endpoint or identity-provider implementation.
"""
from datetime import datetime, timedelta


def dt(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def r1901(events):
    relevant = [e for e in events if e.get("event_action") == "mfa"]
    if any(not e.get("user_name_or_alias") or not e.get("source_ip") or not e.get("event_time") or not e.get("event_outcome") for e in relevant):
        return None
    successes = [e for e in relevant if e.get("event_outcome") == "success"]
    for s in successes:
        st = dt(s["event_time"])
        failures = [
            e for e in relevant
            if e.get("event_outcome") in ("denied", "timeout")
            and e["user_name_or_alias"] == s["user_name_or_alias"]
            and e["source_ip"] == s["source_ip"]
            and st - timedelta(minutes=15) <= dt(e["event_time"]) <= st
        ]
        if len(failures) >= 3:
            return True
    return False


def r1902(events):
    has_follow = any(e.get("event_action") in ("process_start", "network_connect", "registry_change") for e in events)
    incomplete_task = any(
        e.get("event_action") == "task_create" and not (e.get("command_line") or e.get("process_name"))
        for e in events
    )
    suspicious_tokens = ("encodedcommand", "-enc", "iex", "invoke-expression", "downloadstring", "frombase64string", "hidden")
    for e in events:
        cmd = (e.get("command_line") or "").lower()
        proc = (e.get("process_name") or "").lower()
        user = (e.get("user_name_or_alias") or "").lower()
        trig = (e.get("trigger") or "").lower()
        if e.get("event_action") == "task_create" and user == "system" and ("powershell" in proc or "powershell" in cmd) and (trig == "onlogon" or "onlogon" in cmd) and any(t in cmd for t in suspicious_tokens):
            return True

    for p in events:
        if p.get("event_action") != "process_start" or (p.get("process_name") or "").lower() != "powershell.exe" or (p.get("user_name_or_alias") or "").lower() != "system":
            continue
        if not p.get("event_time") or not p.get("host_name"):
            continue
        pt = dt(p["event_time"])
        host = p.get("host_name")
        task = p.get("task_name")
        for q in events:
            if q is p or q.get("host_name") != host or not q.get("event_time"):
                continue
            if task and q.get("task_name") not in (None, "", task):
                continue
            qt = dt(q["event_time"])
            if not (pt <= qt <= pt + timedelta(minutes=5)):
                continue
            child = (q.get("process_name") or "").lower()
            parent = (q.get("parent_process_name") or "").lower()
            if q.get("event_action") == "process_start" and child in ("csc.exe", "mshta.exe", "regsvr32.exe", "rundll32.exe") and parent in ("", "powershell.exe"):
                return True
            if q.get("event_action") in ("network_connect", "registry_change"):
                return True

    if incomplete_task and not has_follow:
        return None
    return False


def r1903(events):
    relevant = [e for e in events if any(str(x).startswith("942") for x in (e.get("waf_rule_ids") or []))]
    if any(not e.get("source_ip") or not e.get("http_host") or not e.get("transaction_id") or not e.get("event_time") for e in relevant):
        return None
    specialist = {"942160", "942190", "942360"}
    tx = {}
    for e in relevant:
        rules = {str(x) for x in (e.get("waf_rule_ids") or [])}
        tx.setdefault(e["transaction_id"], set()).update(rules)
    if any(len(rs) >= 2 or rs & specialist for rs in tx.values()):
        return True

    groups = {}
    for e in relevant:
        groups.setdefault((e["source_ip"], e["http_host"]), []).append((dt(e["event_time"]), e["transaction_id"]))
    for vals in groups.values():
        vals = sorted(vals)
        for t, _ in vals:
            ids = {txid for tt, txid in vals if t <= tt <= t + timedelta(minutes=5)}
            if len(ids) >= 20:
                return True
    return False


def r1904(events):
    relevant = [e for e in events if e.get("event_action") in ("credential_add", "sp_signin")]
    incomplete = any(
        not e.get("service_principal_id") or not e.get("credential_key_id") or not e.get("event_time")
        for e in relevant
    )
    adds = [e for e in relevant if e.get("event_action") == "credential_add" and e.get("service_principal_id") and e.get("credential_key_id") and e.get("event_time")]
    signs = [e for e in relevant if e.get("event_action") == "sp_signin" and e.get("event_outcome") == "success" and e.get("service_principal_id") and e.get("credential_key_id") and e.get("event_time")]
    for a in adds:
        at = dt(a["event_time"])
        for s in signs:
            st = dt(s["event_time"])
            if a["service_principal_id"] == s["service_principal_id"] and a["credential_key_id"] == s["credential_key_id"] and at <= st <= at + timedelta(hours=24):
                return True
    return None if incomplete else False


def r1905(events):
    incomplete = False
    for e in events:
        if e.get("event_id") in (4728, 4732, 4756) or e.get("event_action") == "group_member_add":
            if e.get("group_is_privileged") is None:
                incomplete = True
                continue
            if e.get("group_is_privileged") and (e.get("group_id") or e.get("group_name")):
                return True
    return None if incomplete else False


def r1906(events):
    relevant = [e for e in events if e.get("event_action") == "dns_query"]
    incomplete = any(not e.get("source_ip") or not e.get("destination_ip") or not e.get("event_time") for e in relevant)

    seen = set()
    ded = []
    for e in relevant:
        if not e.get("source_ip") or not e.get("destination_ip") or not e.get("event_time"):
            continue
        key = ("id", e.get("event_record_id")) if e.get("event_record_id") else (
            "fp", e.get("event_time"), e.get("source_ip"), e.get("destination_ip"),
            e.get("dns_transaction_id"), e.get("dns_qr"), e.get("dns_query"), e.get("frame_length"),
        )
        if key in seen:
            continue
        seen.add(key)
        ded.append(e)

    groups = {}
    for e in ded:
        if e.get("chunk_index") is None or not e.get("transfer_object"):
            continue
        groups.setdefault((e["source_ip"], e["destination_ip"], e["transfer_object"]), []).append(e)
    for vals in groups.values():
        vals = sorted(vals, key=lambda e: dt(e["event_time"]))
        for e in vals:
            t = dt(e["event_time"])
            chunks = {x["chunk_index"] for x in vals if t <= dt(x["event_time"]) <= t + timedelta(minutes=5)}
            if len(chunks) >= 5:
                return True
    return None if incomplete else False


EVALUATORS = {
    "R19-01": r1901,
    "R19-02": r1902,
    "R19-03": r1903,
    "R19-04": r1904,
    "R19-05": r1905,
    "R19-06": r1906,
}


def evaluate(case):
    value = EVALUATORS[case["rule_id"]](case["events"])
    return "Unable to evaluate" if value is None else ("Match" if value else "No match")
