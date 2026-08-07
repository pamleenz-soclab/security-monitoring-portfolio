# Interview Walkthrough

A concise walkthrough:

**1. Problem:** Previous SOC scenarios produced detections, but I wanted to prove a full detection-engineering lifecycle rather than only write rules.

**2. Selection:** I inventoried Scenarios 01–18 and selected six behaviours with the strongest processed evidence and tuning value.

**3. Engineering:** I defined a canonical schema, requirements and public fixtures, then used a local Python evaluator to test core semantics independently of any SIEM syntax.

**4. Tuning example:** DNS initially required a completion marker. Source evidence showed a confirmed interrupted 128-chunk exfiltration attempt without one, so I changed completion to confidence enrichment and kept unique chunk correlation as the trigger.

**5. Portability example:** The cloud credential rule existed in KQL/SPL/ES|QL, but the implementations did not all enforce the same service-principal + credential join and 24-hour window. I documented them as non-equivalent and produced aligned v3 candidates.

**6. Boundary:** The rules are portfolio-tested candidates, not production-certified detections; native execution, enterprise baselines, cost and performance remain Not tested.
