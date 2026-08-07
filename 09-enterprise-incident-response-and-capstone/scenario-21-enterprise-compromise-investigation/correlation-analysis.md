# Correlation Analysis

The authoritative structured matrix is:

`evidence/processed/correlation-matrix.csv`

The strongest relationships are structural:

- exact `ProcessGuid` / `ParentProcessGuid` chains,
- exact `SourceProcessGuid` from the malicious PowerShell to LSASS,
- exact target `LogonId` from authentication to `wsmprovhost`,
- stable Logon IDs linking SMB share/service-control events,
- exact parent ProcessGuid linking PSEXESVC to Python,
- exact Python ProcessGuid linking payload execution to 348 network records.

The WinRM source-to-target bridge is intentionally **Moderate** because the stable source ProcessGuid does not cross into target-host authentication telemetry.

No Zeek record is promoted into the host incident chain because the capture window does not overlap.
