# False-Negative Analysis

No false negatives were observed in the curated final v3 regression suite, but this is not evidence of complete recall.

Source review identified real tuning risks: requiring SessionId would have weakened R19-01 because the failure events lacked a stable session; token-only R19-02 logic could miss unobfuscated loaders; R19-03 can miss low-and-slow or single-rule successful SQLi; R19-06 completion-marker requirements would miss an observed interrupted 128-chunk exfiltration attempt.

The final v3 rules address the first, second and completion-marker issues while documenting residual threshold/schema risks in `evidence/processed/tuning-risk-register.csv`.
