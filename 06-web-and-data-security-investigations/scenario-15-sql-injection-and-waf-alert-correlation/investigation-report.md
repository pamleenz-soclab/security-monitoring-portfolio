# Investigation Report

## 1. Executive finding

The investigation confirmed a sustained automated SQL injection campaign against the anonymised host `df7754e.hu`. The final scenario outcome is **Attempted**. WAF detection was confirmed; final WAF enforcement and successful exploitation were not confirmed.

## 2. Scope

The investigation used native ModSecurity audit telemetry from a thirty-day production-derived dataset. The available evidence supports request, rule and response reconstruction within each ModSecurity transaction. It does not include an independent reverse-proxy access log, application log, database audit or endpoint telemetry.

## 3. Event reconstruction

The dominant anonymised source `100.77.175.132` generated 3,465 related requests between `2025-07-28T02:20:59+00:00` and `2025-07-28T07:48:58+00:00`. A fixed Chrome-like User-Agent and systematic payload variation support a high-confidence inference of automation. Of the related requests, 3,396 matched SQLi rules, including Boolean, UNION, concatenated and time-based patterns.

### Dominant sequence statistics

| Metric | Value |
|---|---:|
| Related requests | 3,465 |
| SQLi-related requests | 3,396 |
| High-signal SQLi requests | 3,303 |
| POST SQLi requests | 2,747 |
| GET SQLi requests | 649 |
| Distinct SQLi paths | 15 |

## 4. Representative evidence

### Time-based attempts

Transactions `aIbgBD4IPTLxBnOxY7J7rQAAABQ` and `aIbgCAUA0eMD2lcHYtGmmwAAAAM` contained repeated `sleep(15)` expressions and matched Rules 942100, 942160 and 942360. Both returned HTTP 403, but completed in 57.704 ms and 56.976 ms. No final interception marker was present.

### UNION-based attempt

Transaction `aIWEDLDwIxHfcGraKWWSsAAAAAo` placed a sanitised `UNION ALL SELECT … CONCAT(…) … -- -` fragment in the `order_id` request-body parameter. It matched Rules 942100, 942190 and 942360 and returned HTTP 404 in 2.602 ms. No backend result was available.

### False-positive candidate

Transaction `aIVVouq5vQMKq02KFfSFpAAAAAI` contained the URL-encoded password value `admin123%21%40%23`, decoded as `admin123!@#`. Rule 942100/libinjection matched it without specialist SQLi-rule support. This is assessed as a likely false positive.

## 5. WAF enforcement assessment

`Engine-Mode: "ENABLED"` confirms that the engine was active. It does not establish that a particular SQLi transaction was intercepted. The validated SQLi transactions contained warning messages, but no `Action: Intercepted`, `Access denied`, Rule 949110 or equivalent final blocking marker. HTTP 403 was therefore not attributed to the WAF solely from status.

**Assessment:**

- WAF rule match: **Confirmed**
- WAF final enforcement: **Unable to confirm**
- WAF block marker: **Not observed**

## 6. Exploit outcome assessment

The repeated time-based payloads did not produce the requested delay. This weakens the hypothesis that the injected delay function executed. It does not prove that no request reached application code or that no other SQL statement was processed.

No application exception, database query, affected-row count, response-content proof, file event, process event or exfiltration evidence was available.

**Assessment:**

- SQL query execution: **Unable to confirm**
- Successful exploitation: **Not established**
- Data access/modification: **Not available**
- Web shell/RCE: **Not available**
- Business impact: **Unable to confirm**

## 7. Ground truth versus telemetry

The dataset author describes the source traffic as malicious and blocked. That description is retained as dataset-author ground truth. The local telemetry review independently confirms malicious SQLi attempts and rule detection, but does not confirm final WAF interception for the SQLi subset.

## 8. Final conclusion

The event is classified as **Attempted**. The evidence demonstrates a high-volume automated SQL injection campaign and reliable WAF detection. It does not demonstrate successful exploitation, and it does not provide sufficient transaction-level evidence to label the requests as WAF-blocked.
