# Hunting Methodology

## Evidence-first method

Each hunt was evaluated in the following order:

1. define a falsifiable behavioural hypothesis;
2. identify the telemetry required to test it;
3. load only selected processed evidence;
4. normalise the fields required for local correlation;
5. pivot by stable entities such as user, session, ProcessGuid, Logon ID, source IP, application ID, or service-principal ID;
6. reconstruct sequence or correlation where appropriate;
7. record positive, negative, or unable-to-assess outcomes;
8. compare observed behaviour against existing repository detection logic;
9. separate detection gaps from logging/visibility gaps;
10. derive bounded detection opportunities without implementing new rules.

## Local analysis boundary

The hunts were evaluated with local Python query/correlation logic over processed CSV evidence. The original one-off evaluator is not published as a production engine. Query semantics are documented in `hunt-query-guide.md`, and the published package is checked by `scripts/validate_portfolio.py`.

It does not emulate native SIEM behaviour such as:

- ingestion-time field parsing;
- scheduled rule execution;
- alert suppression;
- native join/operator edge cases;
- index/table configuration;
- platform-specific time bucketing;
- production rule enablement.

Therefore, native KQL/SPL/ES|QL/Sigma files are treated as semantic references unless their validation status is separately documented.

## Coverage state model

### Telemetry

- **Available** — sufficient processed telemetry exists for the stated observation.
- **Partial** — some telemetry exists, but a field/join/source limitation prevents full assessment.
- **Not available** — the required source is absent.
- **Unable to assess** — the available material is insufficient to make a defensible telemetry conclusion.

### Detection

- **Detected** — the behaviour/step is represented by an applicable detection and the stated validation basis supports that conclusion.
- **Partially detected** — existing logic covers a subset of the behaviour/chain.
- **Hunt only** — the behaviour is queryable or investigable, but not represented as equivalent validated alerting coverage.
- **No detection** — usable telemetry exists and no applicable detection artifact was found.
- **Unable to assess** — detection cannot be evaluated because the behaviour itself cannot be assessed.

### Validation

- **Source validated**
- **Fixture validated**
- **Syntax reviewed**
- **Semantic approximation**
- **Not tested**

## Strict interpretation rules

- `No hunt result` ≠ `behaviour did not occur`.
- `No rule` ≠ `no visibility`.
- `Rule file exists` ≠ `covered`.
- `ATT&CK mapping exists` ≠ `detection coverage`.
- Missing backend evidence is a logging/visibility problem before it is a detection problem.
