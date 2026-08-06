#!/usr/bin/env python3
"""Precise validation for Scenario 15 ModSecurity SQLi candidates.

Reads local first-pass CSVs and original extracted ModSecurity audit logs.
Writes all results to evidence/working/precise-validation. Original evidence is
read-only. Full raw selected transactions stay local and are excluded from the
upload ZIP; the ZIP contains only redacted/minimal excerpts and summaries.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import io
import re
import sys
import zipfile
from collections import Counter, defaultdict
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

DEFAULT_TXIDS = [
    "aIbgBD4IPTLxBnOxY7J7rQAAABQ",  # repeated time-based SQLi, 403
    "aIbgCAUA0eMD2lcHYtGmmwAAAAM",  # repeated time-based SQLi, 403
    "aIWEDLDwIxHfcGraKWWSsAAAAAo",  # UNION SELECT in order_id, 404
    "aIVVouq5vQMKq02KFfSFpAAAAAI",  # benign-password false-positive control
]

MARKER_RE = re.compile(r"^--([A-Za-z0-9]+)-([A-Z])--\s*$")
DURATION_RE = re.compile(r"^\s*\d+\s+(\d+)")
SQL_SIGNAL_RE = re.compile(
    r"\bunion\b|\bselect\b|\bsleep\s*\(|\bbenchmark\s*\(|"
    r"\bpg_sleep\s*\(|\bwaitfor\b|information_schema|@@version|"
    r"\bdatabase\s*\(|\bversion\s*\(|\bconcat\s*\(|"
    r"\bor\b\s+\d+\s*[*+=<>-]|\band\b\s+\d+\s*[*+=<>-]",
    re.IGNORECASE,
)
BENIGN_CONTEXT_RE = re.compile(
    r"REQUEST_COOKIES:.*_session|ARGS:pwd:\s*admin123!@#|"
    r"wordpress_test_cookie",
    re.IGNORECASE,
)
ACTION_RE = re.compile(
    r"Action:\s*[^\r\n]+|Access denied[^\r\n]*|Intercepted\s*\([^\r\n]*\)",
    re.IGNORECASE,
)
BLOCK_RULE_RE = re.compile(r'\[id\s+"(?:949110|949111|949120|980130|980140|980170)"\]', re.IGNORECASE)
ANOMALY_RE = re.compile(r"(?:Inbound|Outbound).*Anomaly[^\r\n]*|anomaly score[^\r\n]*", re.IGNORECASE)
ENGINE_RE = re.compile(r"Engine-Mode:\s*[^\r\n]+|SecRuleEngine\s+\w+", re.IGNORECASE)
SENSITIVE_HEADER_RE = re.compile(
    r"^(Cookie|Authorization|Proxy-Authorization|Set-Cookie):.*$",
    re.IGNORECASE | re.MULTILINE,
)


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser()
    p.add_argument("scenario_dir", type=Path)
    p.add_argument("--txid", action="append", dest="txids")
    return p.parse_args()


def read_csv_rows(path: Path) -> Iterable[dict]:
    with path.open("r", encoding="utf-8", errors="replace", newline="") as fh:
        yield from csv.DictReader(fh)


def write_csv(path: Path, rows: Sequence[dict], fieldnames: Sequence[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def duration_us(stopwatch: str) -> str:
    m = DURATION_RE.match(stopwatch or "")
    return m.group(1) if m else ""


def split_sections(text: str) -> Dict[str, str]:
    sections: Dict[str, List[str]] = defaultdict(list)
    current: Optional[str] = None
    for line in text.splitlines(keepends=True):
        m = MARKER_RE.match(line.rstrip("\r\n"))
        if m:
            current = m.group(2)
            continue
        if current:
            sections[current].append(line)
    return {k: "".join(v) for k, v in sections.items()}


def extract_selected_transactions(root: Path, txids: Sequence[str]) -> Dict[str, Tuple[Path, str]]:
    wanted = set(txids)
    found: Dict[str, Tuple[Path, str]] = {}
    for log_path in sorted(root.rglob("modsec_audit*.log")):
        with log_path.open("r", encoding="latin-1", errors="replace", newline="") as fh:
            buffer: List[str] = []
            boundary: Optional[str] = None
            in_tx = False
            for line in fh:
                marker = MARKER_RE.match(line.rstrip("\r\n"))
                if marker and marker.group(2) == "A":
                    buffer = [line]
                    boundary = marker.group(1)
                    in_tx = True
                    continue
                if in_tx:
                    buffer.append(line)
                    if marker and marker.group(1) == boundary and marker.group(2) == "Z":
                        text = "".join(buffer)
                        for txid in wanted - found.keys():
                            if txid in text:
                                found[txid] = (log_path, text)
                        in_tx = False
                        buffer = []
                        boundary = None
                        if len(found) == len(wanted):
                            return found
    return found


def classify(ids: Sequence[str], text: str) -> Tuple[str, int, str]:
    ids_set = {x for x in ids if x}
    high = bool((ids_set - {"942100"}) or SQL_SIGNAL_RE.search(text))
    benign = bool(ids_set == {"942100"} and BENIGN_CONTEXT_RE.search(text))
    if high:
        label = "high_signal_sqli_attempt"
        base = 80
    elif benign:
        label = "likely_false_positive"
        base = 10
    else:
        label = "needs_manual_review"
        base = 40
    if "942160" in ids_set or re.search(r"sleep\s*\(|benchmark\s*\(", text, re.I):
        base += 10
    if "942190" in ids_set or re.search(r"union\s+all?\s*select", text, re.I):
        base += 8
    return label, min(base, 100), ";".join(sorted(ids_set))


def safe_name(txid: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.@-]", "_", txid)


def main() -> int:
    args = parse_args()
    scenario = args.scenario_dir.expanduser().resolve()
    first = scenario / "evidence" / "working" / "first-pass"
    extracted = scenario / "evidence" / "working" / "extracted"
    out = scenario / "evidence" / "working" / "precise-validation"
    local_raw = out / "local-raw-transactions"
    out.mkdir(parents=True, exist_ok=True)
    local_raw.mkdir(parents=True, exist_ok=True)

    txids = args.txids or DEFAULT_TXIDS
    txid_set = set(txids)

    tx_csv = first / "transactions.csv"
    hits_csv = first / "rule-hits.csv"
    if not tx_csv.exists() or not hits_csv.exists():
        print("Missing first-pass transactions.csv or rule-hits.csv", file=sys.stderr)
        return 2
    if not extracted.exists():
        print(f"Missing extracted evidence directory: {extracted}", file=sys.stderr)
        return 2

    selected_tx: List[dict] = []
    dominant_sequence: List[dict] = []
    sqli_transactions: List[dict] = []
    tx_by_key: Dict[str, dict] = {}

    for row in read_csv_rows(tx_csv):
        tx_by_key[row["transaction_key"]] = row
        if row.get("txid") in txid_set:
            selected_tx.append(row)
        if row.get("client_ip") == "100.77.175.132" and row.get("host") == "df7754e.hu":
            r = dict(row)
            dus = duration_us(row.get("stopwatch_raw", ""))
            r["duration_us"] = dus
            r["duration_ms"] = f"{int(dus)/1000:.3f}" if dus else ""
            dominant_sequence.append(r)
        try:
            if int(row.get("sqli_rule_count") or 0) > 0:
                sqli_transactions.append(row)
        except ValueError:
            pass

    selected_keys = {r["transaction_key"] for r in selected_tx}
    selected_hits: List[dict] = []
    sqli_hits_by_key: Dict[str, List[dict]] = defaultdict(list)
    dominant_hits_by_key: Dict[str, List[dict]] = defaultdict(list)

    for row in read_csv_rows(hits_csv):
        key = row.get("transaction_key", "")
        if key in selected_keys:
            selected_hits.append(row)
        if str(row.get("is_sqli_rule", "")).lower() == "true":
            sqli_hits_by_key[key].append(row)
            if row.get("client_ip") == "100.77.175.132":
                dominant_hits_by_key[key].append(row)

    # Corrected ranking based on signal rather than completeness.
    corrected: List[dict] = []
    class_counter: Counter = Counter()
    for row in sqli_transactions:
        key = row["transaction_key"]
        hits = sqli_hits_by_key.get(key, [])
        ids = [h.get("rule_id", "") for h in hits]
        matched = " || ".join(h.get("matched_data", "") for h in hits)
        label, score, unique_ids = classify(ids, matched)
        class_counter[label] += 1
        corrected.append({
            "signal_score": score,
            "classification": label,
            "transaction_key": key,
            "txid": row.get("txid", ""),
            "timestamp_utc": row.get("timestamp_utc", ""),
            "client_ip": row.get("client_ip", ""),
            "method": row.get("method", ""),
            "host": row.get("host", ""),
            "raw_target": row.get("raw_target", ""),
            "response_status": row.get("response_status", ""),
            "action_category": row.get("action_category", ""),
            "rule_ids": unique_ids,
            "matched_data_excerpt": matched[:1000],
        })
    corrected.sort(key=lambda r: (-int(r["signal_score"]), r["timestamp_utc"], r["txid"]))

    # Add matched-data summaries to dominant sequence.
    sequence_out: List[dict] = []
    for row in dominant_sequence:
        hits = dominant_hits_by_key.get(row["transaction_key"], [])
        matched = " || ".join(h.get("matched_data", "") for h in hits)
        ids = sorted({h.get("rule_id", "") for h in hits if h.get("rule_id")})
        label, score, _ = classify(ids, matched)
        r = dict(row)
        r["signal_classification"] = label
        r["signal_score"] = score
        r["matched_data_excerpt"] = matched[:1000]
        sequence_out.append(r)

    raw_found = extract_selected_transactions(extracted, txids)
    action_rows: List[dict] = []
    excerpt_blocks: List[str] = []
    missing = []
    for txid in txids:
        item = raw_found.get(txid)
        if not item:
            missing.append(txid)
            continue
        log_path, text = item
        local_path = local_raw / f"{safe_name(txid)}.log"
        local_path.write_text(text, encoding="utf-8", errors="replace")
        sections = split_sections(text)
        h = sections.get("H", "")
        f = sections.get("F", "")
        b = sections.get("B", "")
        c = sections.get("C", "")
        response_line = next((ln.strip() for ln in f.splitlines() if ln.strip()), "")
        action_matches = sorted(set(ACTION_RE.findall(h)))
        block_matches = sorted(set(BLOCK_RULE_RE.findall(h)))
        anomaly_matches = sorted(set(ANOMALY_RE.findall(h)))
        engine_matches = sorted(set(ENGINE_RE.findall(h)))
        if action_matches or block_matches:
            hint = "Blocking evidence present; verify exact rule/action semantics"
        else:
            hint = "No final blocking marker found in H section; status alone is insufficient"
        action_rows.append({
            "txid": txid,
            "source_file": str(log_path.relative_to(extracted)),
            "response_status_line": response_line,
            "action_evidence": " | ".join(action_matches),
            "blocking_rule_evidence": " | ".join(block_matches),
            "anomaly_evidence": " | ".join(anomaly_matches),
            "engine_evidence": " | ".join(engine_matches),
            "conclusion_hint": hint,
        })
        excerpt = "\n".join([
            f"===== TXID {txid} =====",
            "--- Section B (request) ---",
            SENSITIVE_HEADER_RE.sub(lambda m: f"{m.group(1)}: [REDACTED]", b).rstrip(),
            "--- Section C (request body) ---",
            c.rstrip(),
            "--- Section F (final response headers) ---",
            SENSITIVE_HEADER_RE.sub(lambda m: f"{m.group(1)}: [REDACTED]", f).rstrip(),
            "--- Section H (audit trailer) ---",
            SENSITIVE_HEADER_RE.sub(lambda m: f"{m.group(1)}: [REDACTED]", h).rstrip(),
            "",
        ])
        excerpt_blocks.append(excerpt)

    # Write outputs.
    if selected_tx:
        write_csv(out / "selected-transactions.csv", selected_tx, list(selected_tx[0].keys()))
    if selected_hits:
        write_csv(out / "selected-rule-hits.csv", selected_hits, list(selected_hits[0].keys()))
    write_csv(
        out / "corrected-candidate-ranking.csv",
        corrected,
        ["signal_score", "classification", "transaction_key", "txid", "timestamp_utc", "client_ip", "method", "host", "raw_target", "response_status", "action_category", "rule_ids", "matched_data_excerpt"],
    )
    if sequence_out:
        write_csv(out / "dominant-source-sequence.csv", sequence_out, list(sequence_out[0].keys()))
    write_csv(
        out / "action-markers.tsv",
        action_rows,
        ["txid", "source_file", "response_status_line", "action_evidence", "blocking_rule_evidence", "anomaly_evidence", "engine_evidence", "conclusion_hint"],
    )
    # Convert comma CSV above to actual TSV for readability.
    tsv_path = out / "action-markers.tsv"
    with tsv_path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=["txid", "source_file", "response_status_line", "action_evidence", "blocking_rule_evidence", "anomaly_evidence", "engine_evidence", "conclusion_hint"], delimiter="\t")
        writer.writeheader(); writer.writerows(action_rows)

    (out / "selected-redacted-excerpts.txt").write_text("\n".join(excerpt_blocks), encoding="utf-8")

    summary_lines = [
        "Scenario 15 precise validation summary",
        f"Selected TXIDs requested: {len(txids)}",
        f"Selected raw transactions found: {len(raw_found)}",
        f"Missing TXIDs: {','.join(missing) if missing else 'none'}",
        "",
        "First-pass SQLi signal classification (heuristic triage, not final outcome):",
    ]
    for k in ["high_signal_sqli_attempt", "likely_false_positive", "needs_manual_review"]:
        summary_lines.append(f"  {k}: {class_counter.get(k, 0)}")
    summary_lines.extend([
        "",
        "Dominant sequence:",
        f"  source=100.77.175.132 host=df7754e.hu transactions={len(sequence_out)}",
        "",
        "Action validation:",
    ])
    for r in action_rows:
        summary_lines.append(
            f"  {r['txid']} response={r['response_status_line'] or 'not observed'} "
            f"action={r['action_evidence'] or 'not observed'} "
            f"blocking_rule={r['blocking_rule_evidence'] or 'not observed'}"
        )
    summary_lines.extend([
        "",
        "Evidence boundary: No independent access log, application log, database audit, or endpoint telemetry is added by this validation.",
        "Do not infer successful SQL execution, data access, Web shell, RCE, or exfiltration.",
    ])
    (out / "precise-validation-summary.txt").write_text("\n".join(summary_lines) + "\n", encoding="utf-8")

    # Create upload ZIP. Exclude full local raw transactions.
    upload_zip = scenario / "evidence" / "working" / "scenario-15-precise-validation-results.zip"
    include_names = [
        "precise-validation-summary.txt",
        "selected-transactions.csv",
        "selected-rule-hits.csv",
        "corrected-candidate-ranking.csv",
        "dominant-source-sequence.csv",
        "action-markers.tsv",
        "selected-redacted-excerpts.txt",
    ]
    with zipfile.ZipFile(upload_zip, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as z:
        for name in include_names:
            p = out / name
            if p.exists():
                z.write(p, arcname=name)
    digest = hashlib.sha256(upload_zip.read_bytes()).hexdigest()
    print((out / "precise-validation-summary.txt").read_text(encoding="utf-8"))
    print(f"Upload ZIP: {upload_zip}")
    print(f"Upload ZIP SHA-256: {digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
