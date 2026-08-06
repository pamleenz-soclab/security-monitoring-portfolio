# Scenario 15 — SQL Injection and WAF Alert Correlation

## Portfolio objective

This scenario reconstructs a production WAF investigation from the originating HTTP request through ModSecurity rule matches and the final response recorded inside the WAF transaction. It deliberately separates detection, enforcement and exploit outcome.

## Final assessment

**Scenario result: `Attempted`**

A sustained automated SQL injection campaign was confirmed against the anonymised host `df7754e.hu`. The dominant anonymised source `100.77.175.132` generated **3,465 related requests**, including **3,396 SQLi-related requests**, from `2025-07-28T02:20:59+00:00` to `2025-07-28T07:48:58+00:00`. The sequence contained Boolean-based, UNION-based, concatenated and time-based payloads.

ModSecurity/OWASP CRS rule matches were confirmed. However, the SQLi transactions did not contain a final `Action: Intercepted`, `Access denied` or blocking-evaluation marker. HTTP 403 responses were therefore not treated as proof of WAF enforcement. Application logs, database audit and endpoint telemetry were unavailable, so SQL execution, data access, Web shell activity, RCE and business impact could not be confirmed.

## Evidence classification

| Question | Assessment | Evidence label |
|---|---|---|
| SQL injection requests present | Yes | Confirmed |
| Automated campaign | High confidence | Inferred |
| WAF SQLi detection | Yes | Confirmed |
| Final WAF block action | Not established | Unable to confirm |
| 15-second delay from `sleep(15)` | Not observed | Not observed |
| SQL query execution | No backend evidence | Not available / Unable to confirm |
| Successful exploitation | Not established | Unable to confirm |
| Web shell, RCE or data extraction | No suitable telemetry | Not available |

## Investigation highlights

- 151,845 ModSecurity transactions parsed with zero parser errors.
- 4,342 SQLi-related transactions identified.
- Heuristic triage classified 3,910 as high signal, 46 as likely false positives and 386 for manual review.
- Representative `sleep(15)` requests completed in 57.704 ms and 56.976 ms.
- Among dominant-sequence HTTP 403 requests, Rule 942160 transactions had a 48.808 ms median duration versus 49.505 ms for non-942160 transactions.
- A WordPress login password value `admin123!@#` demonstrated why Rule 942100-only alerts require contextual review.

## Repository structure

- `evidence/processed/` — sanitised, publishable evidence.
- `detections/` — Sigma-style detections and generic logic.
- `queries/` — Microsoft Sentinel KQL, Splunk SPL and Elastic ES|QL.
- `scripts/` — acquisition, safe extraction, parsing, precise validation, processed-evidence generation and package validation.
- `evidence/raw/` and `evidence/working/` — local-only directories protected by `.gitignore`.

## Reproduction

The safe wrapper does not attack any target. It operates only on the published offline dataset:

```bash
bash scripts/reproduce-safe.sh /path/to/this/scenario --acquire
```

Review `source-and-license-record.md`, `validation-checklist.md` and `github-publishing-guide.md` before publishing.
