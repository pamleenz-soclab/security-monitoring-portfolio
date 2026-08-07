# Detection Engineering

Scenario 19 demonstrates a requirements-first detection lifecycle. Existing investigations supplied observable behaviour and processed evidence, but existing query/rule files were not assumed correct. Each selected rule was expressed as a canonical semantic contract, tested with explicit fixtures, tuned, re-tested, and compared with source evidence.

The strongest engineering outcomes were negative discoveries: a stable SessionId was not present on the MFA failure events; a completion marker was absent on a confirmed interrupted DNS-exfiltration attempt; and existing cloud platform translations did not all correlate the same stable service-principal and credential identities. These findings changed rule logic rather than being hidden as test exceptions.

The final v3 rules remain candidates, not production-certified detections. Native SIEM execution, performance, enterprise baselines and production tuning remain deployment work.
