# Fixture Design

Public fixtures are minimal and deactivated. They use aliases, documentation IP ranges and `.invalid` domains. No raw evidence, production tenant identifiers, tokens, secrets, cookies or private keys are included.

Two provenance classes are used:

1. `synthetic`: purpose-built controls for boundary, benign, missing-field, NAT, duplicate and schema cases.
2. `sanitised-derived-temporal-shift`: minimal transformations of processed source evidence that preserve relevant sequence/timing semantics while replacing identifiers and shifting time.

Ground truth and expected rule outcomes are declared before evaluation. `tests/expected/expected-results.csv` is the authoritative regression oracle. Fixtures also carry expected labels for readability, but the provenance guard requires those duplicate labels to agree with the external oracle and with `evidence/processed/fixture-ground-truth.csv`; editing a fixture label alone cannot make the test pass.

A failed rule test is retained until rule logic or an independently justified ground-truth error is corrected. Source evidence that is only a likely false-positive candidate remains review-only and is not promoted to verified benign truth.
