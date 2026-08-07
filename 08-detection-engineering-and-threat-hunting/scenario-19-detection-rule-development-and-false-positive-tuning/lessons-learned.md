# Lessons Learned

1. Stable identifiers matter more than familiar-looking field names. Service-principal object IDs, app IDs and application object IDs cannot be casually substituted.
2. A tuning condition can create a false negative. Requiring SessionId or a DNS completion marker looked attractive until source evidence disproved the assumption.
3. Deduplication must precede thresholds. A correlation/grouping key is not automatically a safe duplicate key.
4. Benign Positive is essential for detection engineering. Suppressing every authorised target behaviour can weaken coverage and hide abuse of trusted administration paths.
5. Cross-platform conversion requires a semantic contract. Query syntax that compiles or looks similar can still differ in windowing, grouping, null handling and entity identity.
6. Fixture metrics are regression evidence, not production accuracy statistics.
