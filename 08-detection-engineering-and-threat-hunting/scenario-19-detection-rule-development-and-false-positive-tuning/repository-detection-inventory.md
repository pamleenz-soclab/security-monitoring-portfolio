# Repository Detection Inventory

The Stage 1 inventory found all 18 completed scenarios and scanned 596 public files while excluding `evidence/raw/` and `evidence/working/`. It identified 88 detection-related files, 93 query-related files, 161 processed/sanitised evidence files, 190 rule/documented-logic entries, and 132 candidate fixture files. Only 63 of the 190 rule/logic entries were actual rule files; 127 were documentation references or examples.

This distinction drove the selection process: Scenario 19 treats existing rules as hypotheses/starting points until requirements, field dependencies, fixtures and test results are explicit. See `evidence/processed/repository-detection-inventory.csv` and `rule-selection-record.md`.
