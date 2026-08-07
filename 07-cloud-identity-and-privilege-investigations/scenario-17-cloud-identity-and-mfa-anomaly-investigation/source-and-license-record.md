# Source and Licence Record

## Synthetic dataset

**Name:** Scenario 17 Synthetic Entra Identity and MFA Anomaly Dataset
**Version:** 1.0.0
**Generation:** Deterministic local Python generator
**Network access:** None
**Real tenant data:** None
**Licence:** CC0 1.0 dedication for the generated synthetic data

The source package is generated into `evidence/raw/`, remains local, and is ignored by Git. The publishable package contains only sanitised derivatives and source hash records.

## Portfolio documents and code

**Licence:** MIT
**Scope:** Markdown documentation, KQL, SPL, ES|QL, generic detections, Python scripts, shell wrappers, and validators.

## Schema and semantic references

The synthetic fields are based on the following official Microsoft documentation:

1. Microsoft Entra sign-in log types
   https://learn.microsoft.com/en-us/entra/identity/monitoring-health/concept-sign-ins

2. Non-interactive user sign-ins
   https://learn.microsoft.com/en-us/entra/identity/monitoring-health/concept-noninteractive-sign-ins

3. Azure Monitor `SigninLogs` schema
   https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/signinlogs

4. MFA authentication details
   https://learn.microsoft.com/en-us/entra/identity/authentication/howto-mfa-reporting

5. Applied Conditional Access policy resource
   https://learn.microsoft.com/en-us/graph/api/resources/appliedconditionalaccesspolicy?view=graph-rest-1.0

6. Conditional Access report-only evaluation
   https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-conditional-access-report-only

7. Microsoft Entra risk detections
   https://learn.microsoft.com/en-us/entra/id-protection/concept-identity-protection-risks

8. Microsoft password-spray investigation playbook
   https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-password-spray

## Rejected source

CyberDefenders AzureSpray was evaluated but not acquired. Its retired Premium access boundary prevented evidence download through the authenticated free account. No restricted content from that lab is included.
