# Scenario Scope

## In scope

Scenario 20 reuses **processed, sanitised, public portfolio evidence** from selected prior scenarios to answer coverage questions across four domains:

- identity and authentication;
- endpoint and Windows process activity;
- network and Web activity;
- cloud identity and privilege activity.

The formal hunts are HC-01, HC-03, HC-05, HC-07, HC-08, HC-09, HC-10, and HC-12.

## Out of scope

This scenario does not:

- re-run or modify Scenario 01–19 raw evidence;
- copy another scenario's `evidence/raw/` or `evidence/working/`;
- claim that a repository rule is deployed in a live SOC;
- implement, tune, or regression-test new detection rules;
- calculate an ATT&CK-technique-count coverage percentage;
- reconstruct a new incident beyond the bounded hunt questions;
- treat a negative hunt result as proof that the behaviour did not occur.

## Relationship to Scenario 19

Scenario 19 follows:

```text
Known target behaviour
→ Detection requirement
→ Rule development
→ Fixture validation
→ False-positive analysis
→ Tuning
→ Regression
```

Scenario 20 follows:

```text
Hypothesis
→ Search broader telemetry
→ Assess visibility
→ Compare existing detection
→ Identify partial / missing coverage
→ Record detection or logging gap
→ Propose detection opportunity
```

A detection opportunity is intentionally left as a future engineering candidate. Scenario 20 stops before new rule implementation and regression testing.
