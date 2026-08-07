# False-Positive Analysis

False Positive and Benign Positive are deliberately separated.

- R19-05 authorised Atomic privileged-group modification is a Benign Positive: the rule correctly detects its target behaviour.
- R19-04 approved credential rotation followed by use is also a Benign Positive under the core behavioural rule; change context is analyst enrichment unless governed suppression is explicitly implemented.
- R19-03 has 46 source-derived `likely false-positive` candidates associated with Rule 942100-only patterns. They support tuning analysis but are not independently verified benign ground truth and therefore do not justify a production FP-rate claim.

Tuning avoids brittle display-name allowlists. Stable governance data, stable IDs, thresholds, exact deduplication and correlation context are preferred.
