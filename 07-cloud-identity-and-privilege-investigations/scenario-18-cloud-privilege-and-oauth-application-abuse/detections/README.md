# Detection Content

The detection set covers ten Scenario 18 behaviours across Microsoft Sentinel KQL, Splunk SPL, Elastic ES|QL-style examples, and a generic rule catalog.

## Production requirements

- Validate the exact audit-event `TargetResources` and `modifiedProperties` shape against the connected tenant before enabling alerts.
- Confirm service-principal sign-in and Microsoft Graph activity retention and licensing.
- Resolve app-role IDs to permission values using the resource service principal where the audit record does not directly expose the value.
- For token-level Graph correlation, prefer the Microsoft-documented link between `AADServicePrincipalSignInLogs.UniqueTokenIdentifier` and `MicrosoftGraphActivityLogs.SignInActivityId`.
- Treat `Roles` / `Scopes` in Graph activity as additional permission-claim evidence when present; do not backfill them into source evidence that did not record them.
- Distinguish a genuinely dormant application from a newly created application or one with history outside the retained lookback.
- Add approved-change, owner, publisher, CI/CD, source-network, credential-rotation, and permission baselines.
- Test with benign controls and the deterministic synthetic event package.

Splunk and Elastic files use normalised placeholder fields and require local field mapping. These examples are detection-engineering starting points, not turnkey production rules.
