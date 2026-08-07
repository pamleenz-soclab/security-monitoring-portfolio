# Detection Coverage Assessment

Host-side visibility is strong for Execution, Persistence, Credential Access, Lateral Movement, and process-attributed Command and Control.

The highest-value engineering pattern is correlation rather than single-event alerting:

- ProcessGuid lineage for the initial execution chain.
- Suspicious SourceProcessGuid tied to LSASS access.
- Target Logon ID linking authentication to `wsmprovhost`.
- Logon ID + source IP linking ADMIN$/PSEXESVC/svcctl.
- Parent ProcessGuid linking PSEXESVC to Python.
- Exact Python ProcessGuid linking execution to 348 network events.

Independent Zeek evidence cannot validate the exact host incident because its timestamps do not overlap. This is a visibility/temporal-alignment limitation, not a reason to weaken the valid host-side network evidence.

See `evidence/processed/detection-coverage-matrix.csv`.
