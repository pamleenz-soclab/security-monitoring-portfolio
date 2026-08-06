#!/usr/bin/env python3
"""Parse ModSecurity native audit logs into investigation-oriented CSV/SQLite outputs.

Stdlib-only. It preserves raw, decoded-once, and decoded-twice values separately and
never recursively decodes beyond two passes.
"""
from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import json
import os
import re
import sqlite3
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable
from urllib.parse import unquote_plus, urlsplit

SECTION_RE = re.compile(r"^--(?P<boundary>[A-Za-z0-9_.:-]+)-(?P<section>[A-Z])--\s*$")
A_LINE_RE = re.compile(
    r'^\[(?P<ts>[^]]+)\]\s+(?P<txid>\S+)\s+(?P<client_ip>\S+)\s+(?P<client_port>\d+)\s+(?P<server_ip>\S+)\s+(?P<server_port>\d+)'
)
REQ_RE = re.compile(r"^(?P<method>[A-Z!#$%&'*+.^_`|~-]+)\s+(?P<target>\S+)\s+(?P<protocol>HTTP/\S+)$")
STATUS_RE = re.compile(r"^HTTP/\S+\s+(?P<status>\d{3})(?:\s+(?P<reason>.*))?$")
BRACKET_FIELD_RE = re.compile(r'\[(?P<key>[A-Za-z0-9_-]+)\s+"(?P<value>(?:\\.|[^"\\])*)"\]')
RULE_ID_RE = re.compile(r"^\d{3,10}$")
SQLI_TEXT_RE = re.compile(r"sql\s*injection|attack-sqli|libinjection", re.I)
SQLI_PATTERN_RULES = [
    ("union_select", re.compile(r"\bunion\b.{0,40}\bselect\b", re.I | re.S)),
    ("boolean_tautology", re.compile(r"(?:\bor\b|\band\b)\s+[\w'\"]+\s*=\s*[\w'\"]+", re.I)),
    ("sql_comment", re.compile(r"--|/\*|#")),
    ("time_delay", re.compile(r"\b(?:sleep|benchmark|pg_sleep|waitfor\s+delay)\s*\(", re.I)),
    ("stacked_query", re.compile(r";\s*(?:select|insert|update|delete|drop|alter|exec|execute)\b", re.I)),
    ("information_schema", re.compile(r"\binformation_schema\b", re.I)),
]


def clip(value: str | None, n: int = 4000) -> str:
    if value is None:
        return ""
    value = value.replace("\x00", "\\x00")
    return value if len(value) <= n else value[:n] + "…[truncated]"


def write_csv(path: Path, rows: list[dict], fieldnames: list[str] | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not fieldnames:
        fieldnames = list(rows[0].keys()) if rows else ["status"]
    with path.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        w.writeheader()
        if rows:
            w.writerows(rows)


def write_tsv(path: Path, rows: list[dict], fieldnames: list[str] | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not fieldnames:
        fieldnames = list(rows[0].keys()) if rows else ["status"]
    with path.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames, delimiter="\t", extrasaction="ignore")
        w.writeheader()
        if rows:
            w.writerows(rows)


def parse_headers(text: str) -> tuple[str, dict[str, str]]:
    lines = text.splitlines()
    first = lines[0].strip() if lines else ""
    headers: dict[str, str] = {}
    current = ""
    for line in lines[1:]:
        if line[:1] in (" ", "\t") and current:
            headers[current] += " " + line.strip()
            continue
        if ":" not in line:
            continue
        k, v = line.split(":", 1)
        current = k.strip().lower()
        headers[current] = v.strip()
    return first, headers


def parse_timestamp(raw: str) -> tuple[str, str]:
    for fmt in ("%d/%b/%Y:%H:%M:%S %z", "%d/%b/%Y:%H:%M:%S.%f %z"):
        try:
            dt = datetime.strptime(raw, fmt)
            return dt.astimezone(timezone.utc).isoformat(), dt.strftime("%z")
        except ValueError:
            pass
    return "", ""


def safe_urlsplit(target: str):
    try:
        return urlsplit(target)
    except ValueError:
        return urlsplit("")


def decode_profile(raw: str) -> dict[str, str]:
    once = unquote_plus(raw)
    twice = unquote_plus(once)
    indicators: list[str] = []
    if re.search(r"%[0-9A-Fa-f]{2}", raw): indicators.append("percent_encoding")
    if re.search(r"%25[0-9A-Fa-f]{2}", raw): indicators.append("double_encoding_indicator")
    if re.search(r"%u[0-9A-Fa-f]{4}", raw): indicators.append("percent_u_unicode")
    if "+" in raw: indicators.append("plus_as_space_possible")
    if raw.lstrip().startswith(("{", "[")): indicators.append("json_like")
    compact = re.sub(r"\s+", "", raw)
    if len(compact) >= 16 and len(compact) % 4 == 0 and re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", compact):
        try:
            base64.b64decode(compact, validate=True)
            indicators.append("base64_candidate")
        except Exception:
            pass
    flags = [name for name, rx in SQLI_PATTERN_RULES if rx.search(twice)]
    return {
        "raw_value": clip(raw),
        "decoded_once": clip(once),
        "decoded_twice": clip(twice),
        "changed_once": str(once != raw).lower(),
        "changed_twice": str(twice != once).lower(),
        "encoding_indicators": ";".join(indicators) or "none_observed",
        "sqli_pattern_indicators": ";".join(flags) or "none_observed",
    }


def parse_bracket_fields(line: str) -> dict[str, list[str]]:
    out: dict[str, list[str]] = defaultdict(list)
    for m in BRACKET_FIELD_RE.finditer(line):
        out[m.group("key").lower()].append(m.group("value").replace('\\"', '"'))
    return out


def looks_text(path: Path) -> bool:
    try:
        with path.open("rb") as f:
            sample = f.read(8192)
    except OSError:
        return False
    if not sample:
        return False
    if b"\x00" in sample:
        return False
    return True


def find_audit_files(root: Path) -> list[Path]:
    candidates: list[Path] = []
    for p in root.rglob("*"):
        if not p.is_file() or p.name.startswith(".") or p.suffix.lower() in {".zip", ".gz", ".bz2", ".xz", ".7z", ".png", ".jpg", ".pdf"}:
            continue
        if not looks_text(p):
            continue
        try:
            with p.open("r", encoding="latin-1", errors="replace") as f:
                found = False
                for _ in range(5000):
                    line = f.readline()
                    if not line:
                        break
                    if SECTION_RE.match(line.rstrip("\r\n")):
                        found = True
                        break
                if found:
                    candidates.append(p)
        except OSError:
            pass
    return sorted(candidates)


@dataclass
class AuditTx:
    source_file: str
    boundary: str
    sections: dict[str, list[str]] = field(default_factory=lambda: defaultdict(list))

    def text(self, key: str) -> str:
        return "".join(self.sections.get(key, []))


def iter_transactions(path: Path, root: Path) -> Iterable[AuditTx]:
    current: AuditTx | None = None
    section = ""
    with path.open("r", encoding="latin-1", errors="replace", newline="") as f:
        for line in f:
            m = SECTION_RE.match(line.rstrip("\r\n"))
            if m:
                boundary, sec = m.group("boundary"), m.group("section")
                if sec == "A":
                    if current is not None:
                        yield current
                    current = AuditTx(str(path.relative_to(root)), boundary)
                elif current is None:
                    current = AuditTx(str(path.relative_to(root)), boundary)
                section = sec
                if sec == "Z":
                    yield current
                    current = None
                    section = ""
                continue
            if current is not None and section:
                current.sections[section].append(line)
    if current is not None:
        yield current


def make_tx_key(source_file: str, boundary: str, txid: str) -> str:
    raw = f"{source_file}|{boundary}|{txid}"
    return hashlib.sha256(raw.encode("utf-8", "replace")).hexdigest()[:20]


def parse_transaction(tx: AuditTx) -> tuple[dict, list[dict], list[dict]]:
    a_text, b_text, c_text, e_text, f_text, h_text = (tx.text(k) for k in "ABCEFH")
    a_first = next((x.strip() for x in a_text.splitlines() if x.strip()), "")
    am = A_LINE_RE.match(a_first)
    meta = {k: "" for k in ["timestamp_raw", "timestamp_utc", "timezone_offset", "txid", "client_ip", "client_port", "server_ip", "server_port"]}
    if am:
        gd = am.groupdict()
        meta.update({"timestamp_raw": gd["ts"], "txid": gd["txid"], "client_ip": gd["client_ip"], "client_port": gd["client_port"], "server_ip": gd["server_ip"], "server_port": gd["server_port"]})
        meta["timestamp_utc"], meta["timezone_offset"] = parse_timestamp(gd["ts"])

    request_line, headers = parse_headers(b_text)
    rm = REQ_RE.match(request_line)
    method = rm.group("method") if rm else ""
    target = rm.group("target") if rm else ""
    protocol = rm.group("protocol") if rm else ""
    parts = safe_urlsplit(target)
    path = parts.path
    raw_query = parts.query

    f_first, response_headers = parse_headers(f_text)
    sm = STATUS_RE.match(f_first)
    response_status = sm.group("status") if sm else ""
    if not response_status:
        m = re.search(r"(?:^|\n)Status:\s*(\d{3})", f_text, re.I)
        if m: response_status = m.group(1)

    rule_rows: list[dict] = []
    action_raw = ""
    engine_mode = ""
    producer = ""
    stopwatch = ""
    for line in h_text.splitlines():
        low = line.lower()
        if low.startswith("action:"):
            action_raw = line.split(":", 1)[1].strip()
        elif low.startswith("engine-mode:"):
            engine_mode = line.split(":", 1)[1].strip().strip('"')
        elif low.startswith("producer:"):
            producer = line.split(":", 1)[1].strip()
        elif low.startswith("stopwatch:"):
            stopwatch = line.split(":", 1)[1].strip()
        fields = parse_bracket_fields(line)
        rid = fields.get("id", [""])[0]
        if rid and RULE_ID_RE.fullmatch(rid):
            tags = fields.get("tag", [])
            row = {
                "rule_id": rid,
                "rule_message": clip(fields.get("msg", [""])[0]),
                "severity": fields.get("severity", [""])[0],
                "matched_data": clip(fields.get("data", [""])[0]),
                "matched_variable": clip(fields.get("match", [""])[0]),
                "rule_file": fields.get("file", [""])[0],
                "rule_line": fields.get("line", [""])[0],
                "rule_version": fields.get("ver", [""])[0],
                "tags": ";".join(tags),
                "raw_message": clip(line),
            }
            if not row["matched_variable"]:
                mv = re.search(r"against variable ['\"]([^'\"]+)['\"]", line, re.I)
                if mv: row["matched_variable"] = mv.group(1)
            row["is_sqli_rule"] = str(bool(row["rule_id"].startswith("942") or SQLI_TEXT_RE.search(" ".join([row["rule_message"], row["tags"], row["matched_data"]])))).lower()
            rule_rows.append(row)

    txid = meta["txid"] or tx.boundary
    tx_key = make_tx_key(tx.source_file, tx.boundary, txid)
    for row in rule_rows:
        row["transaction_key"] = tx_key
        row["txid"] = txid
        row["timestamp_utc"] = meta["timestamp_utc"]
        row["client_ip"] = meta["client_ip"]
        row["method"] = method
        row["raw_target"] = clip(target)

    sqli_hits = [r for r in rule_rows if r.get("is_sqli_rule") == "true"]
    h_low = h_text.lower()
    if "detectiononly" in engine_mode.lower() or "detectiononly" in h_low:
        action_category = "detect_alert_only"
    elif re.search(r"intercepted|access denied|denied with code|deny", action_raw, re.I) or "access denied" in h_low:
        action_category = "block_candidate"
    elif action_raw:
        action_category = "other_or_unknown_action"
    else:
        action_category = "unknown"

    anomaly_score = ""
    for r in rule_rows:
        m = re.search(r"(?:total\s+score|anomaly\s+score)[^0-9-]*(-?\d+)", r["rule_message"] + " " + r["matched_data"], re.I)
        if m:
            anomaly_score = m.group(1)

    tx_row = {
        "transaction_key": tx_key,
        "source_file": tx.source_file,
        "boundary": tx.boundary,
        **meta,
        "request_line": clip(request_line),
        "method": method,
        "protocol": protocol,
        "raw_target": clip(target),
        "path": clip(path),
        "raw_query": clip(raw_query),
        "host": clip(headers.get("host", "")),
        "user_agent": clip(headers.get("user-agent", "")),
        "x_forwarded_for": clip(headers.get("x-forwarded-for", "")),
        "content_type": clip(headers.get("content-type", "")),
        "request_content_length": headers.get("content-length", ""),
        "cookie_present": str(bool(headers.get("cookie"))).lower(),
        "authorization_present": str(bool(headers.get("authorization"))).lower(),
        "request_body_present": str(bool(c_text.strip())).lower(),
        "request_body_bytes": str(len(c_text.encode("latin-1", "replace"))),
        "response_status": response_status,
        "response_content_length": response_headers.get("content-length", ""),
        "response_body_present": str(bool(e_text)).lower(),
        "response_body_bytes_observed": str(len(e_text.encode("latin-1", "replace"))),
        "action_raw": clip(action_raw),
        "action_category": action_category,
        "engine_mode": clip(engine_mode),
        "producer": clip(producer),
        "stopwatch_raw": clip(stopwatch),
        "rule_count": str(len(rule_rows)),
        "sqli_rule_count": str(len(sqli_hits)),
        "sqli_rule_ids": ";".join(sorted({r["rule_id"] for r in sqli_hits})),
        "anomaly_score_observed": anomaly_score,
        "sections_present": "".join(k for k in "ABCEFHIKZ" if tx.sections.get(k)),
        "section_a_present": str(bool(a_text)).lower(),
        "section_b_present": str(bool(b_text)).lower(),
        "section_c_present": str(bool(c_text)).lower(),
        "section_e_present": str(bool(e_text)).lower(),
        "section_f_present": str(bool(f_text)).lower(),
        "section_h_present": str(bool(h_text)).lower(),
        "source_identity_note": "ModSecurity client address retained; X-Forwarded-For is not trusted without proxy-chain configuration",
    }

    enc_rows: list[dict] = []
    if raw_query:
        for pair in re.split(r"[&;]", raw_query):
            if "=" in pair:
                name, value = pair.split("=", 1)
            else:
                name, value = pair, ""
            enc_rows.append({"transaction_key": tx_key, "txid": txid, "location": "query", "name": clip(name), **decode_profile(value)})
    if path:
        enc_rows.append({"transaction_key": tx_key, "txid": txid, "location": "path", "name": "request_path", **decode_profile(path)})
    for hn in ("user-agent", "referer", "x-forwarded-for", "cookie"):
        if headers.get(hn):
            enc_rows.append({"transaction_key": tx_key, "txid": txid, "location": "header", "name": hn, **decode_profile(headers[hn])})
    if c_text.strip():
        body = c_text.strip("\r\n")
        ctype = headers.get("content-type", "").lower()
        if "application/x-www-form-urlencoded" in ctype:
            for pair in re.split(r"[&;]", body):
                if "=" in pair: name, value = pair.split("=", 1)
                else: name, value = pair, ""
                enc_rows.append({"transaction_key": tx_key, "txid": txid, "location": "body_form", "name": clip(name), **decode_profile(value)})
        else:
            enc_rows.append({"transaction_key": tx_key, "txid": txid, "location": "body", "name": "request_body", **decode_profile(body)})

    return tx_row, rule_rows, enc_rows


def count_table(rows: list[dict], keys: list[str], value_name: str = "count") -> list[dict]:
    c = Counter(tuple(r.get(k, "") for k in keys) for r in rows)
    return [{**dict(zip(keys, key)), value_name: n} for key, n in c.most_common()]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", required=True, type=Path)
    ap.add_argument("--output", required=True, type=Path)
    args = ap.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)

    audit_files = find_audit_files(args.input)
    if not audit_files:
        print("ERROR: no ModSecurity native audit-log section markers found", file=sys.stderr)
        return 4

    transactions: list[dict] = []
    rules: list[dict] = []
    encodings: list[dict] = []
    parse_errors: list[dict] = []
    for p in audit_files:
        try:
            for tx in iter_transactions(p, args.input):
                t, r, e = parse_transaction(tx)
                transactions.append(t); rules.extend(r); encodings.extend(e)
        except Exception as exc:
            parse_errors.append({"source_file": str(p.relative_to(args.input)), "error": repr(exc)})

    sqli_keys = {t["transaction_key"] for t in transactions if int(t.get("sqli_rule_count") or 0) > 0}
    sqli_tx = [t for t in transactions if t["transaction_key"] in sqli_keys]
    sqli_rules = [r for r in rules if r.get("is_sqli_rule") == "true"]
    sqli_enc = [e for e in encodings if e["transaction_key"] in sqli_keys]

    write_csv(args.output / "transactions.csv", transactions)
    write_csv(args.output / "rule-hits.csv", rules)
    write_csv(args.output / "encoding-analysis.csv", sqli_enc)
    write_csv(args.output / "parse-errors.csv", parse_errors)

    rule_inventory_map: dict[tuple, dict] = {}
    for r in rules:
        key = (r["rule_id"], r["rule_message"], r["severity"], r["tags"])
        ent = rule_inventory_map.setdefault(key, {"rule_id": key[0], "rule_message": key[1], "severity": key[2], "tags": key[3], "hit_count": 0, "transaction_keys": set()})
        ent["hit_count"] += 1; ent["transaction_keys"].add(r["transaction_key"])
    rule_inventory = []
    for ent in rule_inventory_map.values():
        rule_inventory.append({**{k:v for k,v in ent.items() if k != "transaction_keys"}, "transaction_count": len(ent["transaction_keys"])})
    rule_inventory.sort(key=lambda x: (-x["hit_count"], x["rule_id"]))
    write_csv(args.output / "waf-rule-inventory.csv", rule_inventory)
    write_csv(args.output / "waf-action-inventory.csv", count_table(transactions, ["action_category", "action_raw", "engine_mode", "response_status"]))
    write_csv(args.output / "http-status-inventory.csv", count_table(transactions, ["response_status"]))
    write_csv(args.output / "request-method-inventory.csv", count_table(transactions, ["method"]))

    uri_param = []
    param_counter: Counter[tuple] = Counter()
    for e in encodings:
        if e["location"] in {"query", "body_form"}:
            param_counter[(e["location"], e["name"], e["transaction_key"] in sqli_keys)] += 1
    for (loc, name, is_sqli), count in param_counter.most_common():
        uri_param.append({"location": loc, "parameter_name": name, "sqli_transaction": str(is_sqli).lower(), "occurrence_count": count})
    write_csv(args.output / "uri-and-parameter-inventory.csv", uri_param)

    request_corr = []
    for t in sqli_tx:
        present = [t[f"section_{k.lower()}_present"] == "true" for k in "ABFH"]
        confidence = "high" if all(present) and t["txid"] else "medium" if sum(present) >= 3 else "low"
        request_corr.append({
            "transaction_key": t["transaction_key"], "txid": t["txid"], "timestamp_utc": t["timestamp_utc"],
            "client_ip": t["client_ip"], "method": t["method"], "host": t["host"], "raw_target": t["raw_target"],
            "user_agent": t["user_agent"], "waf_rule_ids": t["sqli_rule_ids"], "waf_action": t["action_category"],
            "response_status": t["response_status"], "sections_present": t["sections_present"],
            "within_modsecurity_transaction_correlation": confidence,
            "independent_access_log_correlation": "Not available",
        })
    write_csv(args.output / "request-correlation-table.csv", request_corr)
    write_csv(args.output / "waf-to-access-log-correlation.csv", [
        {"transaction_key": t["transaction_key"], "txid": t["txid"], "waf_request_observed": "Confirmed", "independent_access_log": "Not available", "correlation_result": "Unable to perform independent WAF-to-server correlation"}
        for t in sqli_tx
    ])
    write_csv(args.output / "application-backend-correlation.csv", [
        {"transaction_key": t["transaction_key"], "txid": t["txid"], "application_log": "Not available", "database_audit": "Not available", "backend_execution": "Unable to confirm", "business_impact": "Unable to confirm"}
        for t in sqli_tx
    ])
    write_csv(args.output / "response-size-and-latency-analysis.csv", [
        {"transaction_key": t["transaction_key"], "txid": t["txid"], "status": t["response_status"], "response_content_length_header": t["response_content_length"], "response_body_bytes_observed": t["response_body_bytes_observed"], "stopwatch_raw": t["stopwatch_raw"], "latency_interpretation": "Raw stopwatch retained; no exploit inference without baseline and repeated validation"}
        for t in sqli_tx
    ])

    group: dict[tuple, list[dict]] = defaultdict(list)
    for t in sqli_tx:
        group[(t["client_ip"], t["user_agent"], t["host"])].append(t)
    repeated = []
    for (ip, ua, host), vals in group.items():
        times = sorted(v["timestamp_utc"] for v in vals if v["timestamp_utc"])
        repeated.append({
            "client_ip": ip, "user_agent": ua, "host": host, "request_count": len(vals),
            "first_seen_utc": times[0] if times else "", "last_seen_utc": times[-1] if times else "",
            "distinct_paths": len({v["path"] for v in vals}), "distinct_methods": len({v["method"] for v in vals}),
            "distinct_rule_ids": len({rid for v in vals for rid in v["sqli_rule_ids"].split(";") if rid}),
            "automation_indicator": "possible" if len(vals) >= 10 or len({v["path"] for v in vals}) >= 5 else "not established",
            "session_note": "Grouping aid only; same IP/User-Agent does not prove one attack session",
        })
    repeated.sort(key=lambda x: -x["request_count"])
    write_csv(args.output / "repeated-source-and-scanning-summary.csv", repeated)

    outcomes = []
    for t in sqli_tx:
        if t["action_category"] == "block_candidate":
            preliminary = "Blocked candidate"
            rationale = "SQLi rule hit plus disruptive/intercept indication; requires config and final-response verification"
        elif t["action_category"] == "detect_alert_only":
            preliminary = "Attempted candidate"
            rationale = "SQLi rule hit in detection-only context; backend outcome not available"
        else:
            preliminary = "Attempted candidate"
            rationale = "SQLi rule hit observed, but final WAF execution action is not established"
        completeness = sum(t[f"section_{k.lower()}_present"] == "true" for k in "ABCFH")
        outcomes.append({
            "transaction_key": t["transaction_key"], "txid": t["txid"], "timestamp_utc": t["timestamp_utc"],
            "client_ip": t["client_ip"], "method": t["method"], "host": t["host"], "raw_target": t["raw_target"],
            "sqli_rule_ids": t["sqli_rule_ids"], "action_category": t["action_category"], "action_raw": t["action_raw"],
            "engine_mode": t["engine_mode"], "response_status": t["response_status"], "evidence_completeness_score_0_to_5": completeness,
            "preliminary_outcome": preliminary, "rationale": rationale,
            "backend_result": "Unable to confirm", "success_evidence": "Not available", "final_outcome": "Pending precise verification",
        })
    outcomes.sort(key=lambda x: (-int(x["evidence_completeness_score_0_to_5"]), x["timestamp_utc"], x["transaction_key"]))
    write_csv(args.output / "possible-exploit-outcome-candidates.csv", outcomes)
    write_csv(args.output / "candidate-ranking.csv", outcomes[:100])
    (args.output / "candidate-transaction-keys.txt").write_text("\n".join(x["transaction_key"] for x in outcomes[:20]) + ("\n" if outcomes else ""), encoding="utf-8")

    write_csv(args.output / "follow-on-activity-candidates.csv", [{
        "status": "Not available", "reason": "Dataset contains WAF audit transactions but no endpoint, file, process, application, or database telemetry", "claim_boundary": "Do not infer Web shell, command execution, RCE, or data extraction"
    }])
    gaps = [
        ("Independent reverse-proxy/web access log", "Not available", "Cannot independently prove that the same request was recorded by Nginx/Apache access logging"),
        ("Application request/exception log", "Not available", "Cannot confirm route handling, SQL exception, authentication bypass, or response classification"),
        ("Database/backend audit", "Not available", "Cannot confirm SQL execution, affected rows, table access, or data extraction"),
        ("Endpoint/file/process telemetry", "Not available", "Cannot confirm Web shell creation, child processes, command execution, or persistence"),
        ("Response body", "Partially available", "ModSecurity section E may be absent or truncated; HTTP status alone is not exploit outcome"),
        ("Trusted proxy chain", "Not established", "X-Forwarded-For cannot be treated as the real source without configuration evidence"),
        ("Allowed/non-alerted request baseline", "Detection gap", "Audit-only malicious subset cannot measure false negatives or normal-request prevalence"),
        ("Application latency baseline", "Not available", "A single slow transaction cannot establish time-based SQL injection"),
    ]
    write_tsv(args.output / "detection-gaps.tsv", [{"telemetry_or_boundary": a, "evidence_label": b, "investigative_effect": c} for a,b,c in gaps])

    write_csv(args.output / "source-ip-and-host-inventory.csv", count_table(transactions, ["client_ip", "host", "user_agent"]))

    db = sqlite3.connect(args.output / "analysis.sqlite")
    try:
        def load(table: str, rows: list[dict]):
            if not rows: return
            cols = list(rows[0].keys())
            db.execute(f'DROP TABLE IF EXISTS "{table}"')
            db.execute(f'CREATE TABLE "{table}" ({", ".join(f"\"{c}\" TEXT" for c in cols)})')
            db.executemany(f'INSERT INTO "{table}" ({", ".join(f"\"{c}\"" for c in cols)}) VALUES ({", ".join("?" for _ in cols)})', [[str(r.get(c, "")) for c in cols] for r in rows])
        load("transactions", transactions); load("rule_hits", rules); load("encoding_analysis", encodings); load("outcome_candidates", outcomes)
        db.execute('CREATE INDEX IF NOT EXISTS idx_tx_key ON transactions(transaction_key)')
        db.execute('CREATE INDEX IF NOT EXISTS idx_tx_txid ON transactions(txid)')
        db.execute('CREATE INDEX IF NOT EXISTS idx_tx_time ON transactions(timestamp_utc)')
        db.execute('CREATE INDEX IF NOT EXISTS idx_tx_ip ON transactions(client_ip)')
        db.execute('CREATE INDEX IF NOT EXISTS idx_rules_key ON rule_hits(transaction_key)')
        db.execute('CREATE INDEX IF NOT EXISTS idx_rules_id ON rule_hits(rule_id)')
        db.commit()
    finally:
        db.close()

    section_counts = Counter()
    for t in transactions:
        for sec in "ABCEFH":
            if t[f"section_{sec.lower()}_present"] == "true": section_counts[sec] += 1
    schema_lines = [
        f"audit_files={len(audit_files)}", f"transactions={len(transactions)}", f"rule_hits={len(rules)}",
        f"sqli_transactions={len(sqli_tx)}", f"parse_errors={len(parse_errors)}",
    ] + [f"section_{k}_transactions={section_counts[k]}" for k in "ABCEFH"]
    (args.output / "format-and-schema-profile.txt").write_text("\n".join(schema_lines) + "\n", encoding="utf-8")

    times = sorted(t["timestamp_utc"] for t in transactions if t["timestamp_utc"])
    tzs = Counter(t["timezone_offset"] for t in transactions if t["timezone_offset"])
    (args.output / "time-range-and-timezone-profile.txt").write_text(
        f"first_seen_utc={times[0] if times else ''}\nlast_seen_utc={times[-1] if times else ''}\ntimezone_offsets={json.dumps(tzs, ensure_ascii=False)}\n",
        encoding="utf-8"
    )

    top_rules = Counter(r["rule_id"] for r in sqli_rules).most_common(10)
    top_status = Counter(t["response_status"] or "missing" for t in sqli_tx).most_common(10)
    top_actions = Counter(t["action_category"] for t in sqli_tx).most_common()
    summary = [
        "Scenario 15 first-pass summary",
        f"Audit files parsed: {len(audit_files)}",
        f"Transactions parsed: {len(transactions)}",
        f"Rule hits parsed: {len(rules)}",
        f"SQLi-related transactions: {len(sqli_tx)}",
        f"Parse errors: {len(parse_errors)}",
        f"Time range UTC: {(times[0] if times else 'unknown')} to {(times[-1] if times else 'unknown')}",
        "",
        "SQLi action categories:", *[f"  {k}: {v}" for k,v in top_actions],
        "SQLi response statuses:", *[f"  {k}: {v}" for k,v in top_status],
        "Top SQLi rule IDs:", *[f"  {k}: {v}" for k,v in top_rules],
        "",
        "Evidence boundary: independent web access logs, application logs, database audit, and endpoint telemetry are not available in this dataset.",
        "No successful exploitation, database impact, Web shell, RCE, or data extraction is inferred by this parser.",
    ]
    (args.output / "compact-first-pass-summary.txt").write_text("\n".join(summary) + "\n", encoding="utf-8")
    print("\n".join(summary))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
