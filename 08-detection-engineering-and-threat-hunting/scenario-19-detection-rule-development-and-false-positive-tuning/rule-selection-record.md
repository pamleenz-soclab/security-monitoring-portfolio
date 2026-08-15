# Rule Selection Record

Ten candidates were reviewed. Six were selected to balance authentication, endpoint, web/network, cloud privilege, tuning, correlation and deduplication.

Selected: R19-01 (Scenario 17), R19-02 (Scenario 12), R19-03 (Scenario 15), R19-04 (Scenario 18), R19-05 (Scenario 11), and R19-06 (Scenario 16).

Repeated SSH failures were reserved because Scenario 17 provided richer structured authentication evidence. Scenario 10 PowerShell was reserved because Scenario 12 already had stronger lifecycle material. Additional Scenario 18 cloud detections were reserved to avoid turning Scenario 19 into a cloud-only portfolio and to preserve the Scenario 20 threat-hunting boundary.

The selection decision is retained in `evidence/processed/rule-candidate-matrix.csv`. A repository-wide file-count inventory is intentionally not published because later cleanup of earlier scenarios would make that snapshot stale without changing the six rule-selection decisions.
