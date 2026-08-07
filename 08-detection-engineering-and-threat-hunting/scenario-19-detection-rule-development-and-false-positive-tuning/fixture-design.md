# Fixture Design

Public fixtures are minimal and deactivated. They use aliases, documentation IP ranges and `.invalid` domains. No raw evidence, production tenant identifiers, tokens, secrets, cookies or private keys are included.

Two provenance classes are used:

1. `synthetic`: purpose-built controls for boundary, benign, missing-field, NAT, duplicate and schema cases.
2. `sanitised-derived-temporal-shift`: minimal transformations of processed source evidence that preserve relevant sequence/timing semantics while replacing identifiers and shifting time.

Ground truth is defined before rule execution. A failed rule test is retained; fixture truth is not edited to make a rule pass. Source evidence that is only a likely false-positive candidate remains review-only and is not promoted to verified benign truth.
