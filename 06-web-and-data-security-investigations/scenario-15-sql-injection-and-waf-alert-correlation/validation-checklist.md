# Validation Checklist

## Evidence integrity

- [ ] Original archive MD5 matches the published value.
- [ ] Original archive SHA-256 matches `source-sha256-records.tsv`.
- [ ] Raw and working directories are Git ignored.
- [ ] Parser errors are reviewed and documented.
- [ ] Source timestamp and UTC conversion are preserved.

## Correlation

- [ ] Transaction IDs are stable across request, rule and response sections.
- [ ] X-Forwarded-For is used only after validating the trusted proxy chain.
- [ ] Independent access-log absence is recorded.
- [ ] Request ID semantics are not assumed across different products.

## SQLi analysis

- [ ] Raw, once-decoded and twice-decoded values remain distinct.
- [ ] No unbounded recursive decoding is performed.
- [ ] Payload location is recorded.
- [ ] Rule 942100-only matches receive context review.
- [ ] Rule match count is not treated as exploit-success count.

## Outcome assessment

- [ ] HTTP 200 is not treated as successful exploitation.
- [ ] HTTP 403 is not treated as WAF block without final-action evidence.
- [ ] Time-based conclusions use repeated observations and a comparison baseline.
- [ ] No database impact is claimed without backend telemetry.
- [ ] No Web shell or RCE is claimed without file/process evidence.
- [ ] Final result uses an approved label.

## Publishing

- [ ] No raw archive, extracted log, SQLite database or large temporary file is staged.
- [ ] Cookie, Authorization, token and session values are absent.
- [ ] Payload excerpts are minimal and sanitised.
- [ ] Source and license attribution is present.
- [ ] `python3 scripts/portfolio_validator.py . --git-aware` passes.
