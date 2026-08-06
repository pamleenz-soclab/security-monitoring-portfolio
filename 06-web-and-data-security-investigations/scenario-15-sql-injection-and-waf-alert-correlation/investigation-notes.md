# Investigation Notes

## Method

1. Verified source archive integrity using the published MD5 and a locally generated SHA-256.
2. Safely extracted the ZIP with path-traversal and symlink checks.
3. Parsed 30 native ModSecurity audit files by transaction boundary.
4. Preserved raw timestamp and converted the original `+0200` timestamps to UTC.
5. Correlated A/B/C/E/F/H sections by transaction ID.
6. Identified SQLi rules through Rule 942xxx IDs, SQLi tags and libinjection messages.
7. Preserved raw, once-decoded and twice-decoded representations without recursive decoding.
8. Classified candidates using rule diversity, explicit SQL syntax, matched variables and repeated behaviour.
9. Validated four representative transactions directly against sanitised B/C/F/H excerpts.
10. Separated telemetry-confirmed facts, dataset-author ground truth, inference and unavailable evidence.

## Parsing reliability

- Audit files parsed: 30
- Transactions: 151,845
- Rule hits: 351,440
- Parser errors: 0
- Transactions with A/B/F/H sections: complete across the parsed set
- SQLi-related transactions: 4,342

## Signal classification

| Classification | Count | Meaning |
|---|---:|---|
| High-signal SQLi attempt | 3910 | Explicit SQL syntax and/or specialised SQLi rules |
| Likely false positive | 46 | Rule 942100-only password or cookie context |
| Needs manual review | 386 | Insufficient contextual or peer-rule support |

The classification is a triage aid, not an exploit-outcome label.

## Dominant sequence

- Source: `100.77.175.132` (anonymised)
- Host: `df7754e.hu`
- Related requests: 3,465
- SQLi-related: 3,396
- High signal: 3,303
- SQLi methods: POST 2,747; GET 649
- SQLi response statuses: 403=2058, 503=616, 301=351, 302=302, 404=51, 400=18

## Action validation

The validated SQLi transactions contained `Message: Warning` records and `Engine-Mode: "ENABLED"`, but no final interception or blocking-evaluation marker. The parser successfully identified interception markers elsewhere in the dataset, so the absence in the SQLi subset is meaningful. It does not prove that no other control returned the response status.

## Time-based analysis

Two repeated `sleep(15)` requests completed in 57.704 ms and 56.976 ms. Within the dominant sequence, 403 transactions with Rule 942160 had a median duration of 48.808 ms; comparable 403 transactions without Rule 942160 had a median of 49.505 ms. A 15-second effect was not observed.

## Evidence boundaries

- ModSecurity client address is retained as the source field; X-Forwarded-For is not trusted without proxy-chain configuration.
- HTTP status is not treated as exploit outcome or enforcement evidence by itself.
- Response size is supporting context only.
- Missing backend telemetry prevents confirmation of SQL execution or data impact.
