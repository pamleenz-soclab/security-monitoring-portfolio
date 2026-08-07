# Impact Assessment

The evidence proves a serious technical **security compromise** of two endpoints: unauthorized execution, persistence, SYSTEM execution, lateral movement, and process-attributed command-and-control behavior succeeded.

It does **not** prove an ATT&CK Impact-stage or real business disruption. No ransomware, destructive business-data modification, service outage, or equivalent outcome is demonstrated.

Credential access is bounded: malicious PowerShell accessed LSASS, but no recovered credential output is available. The certificate-export attempt explicitly failed.

Collection/staging is observed, but no source-derived evidence proves staged material left the environment. Exfiltration therefore remains `Not observed / Unable to assess`.

See `evidence/processed/impact-assessment.csv`.
