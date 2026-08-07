# Evidence Inventory

The authoritative structured inventory is:

`evidence/processed/evidence-inventory.csv`

Primary incident decisions use Windows Security, Sysmon, PowerShell, and System telemetry from the Day 1 host source. Upstream Zeek/PCAP artifacts are retained as source-associated network evidence, but their capture window does not overlap the May 2 host incident and they are not used as same-event corroboration.

Raw evidence remains local and Git-ignored. Source URLs, pinned commit, file sizes, and SHA-256 values are retained in the source acquisition and hash records.
