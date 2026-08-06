# Executive Summary

A file server in the simulated enterprise environment covertly transferred business-style documents through DNS over approximately four days. The activity was deliberately slow and would not have been reliably detected by a simple large-upload threshold.

The investigation confirmed that **31 files totaling 2,042,802 bytes** were reconstructed on an attacker-controlled receiver. Each receiver file exactly matched its source file by SHA-256. An additional file was only partially attempted and was not counted as confirmed data loss.

The channel used compressed and Base64-encoded DNS labels, sequential chunk numbers, and per-file completion markers. No encryption, separate staging archive, or evidence-destruction activity was validated. The source service was configured to run as root, increasing the potential collection scope.

The highest-priority controls are to isolate the source host, block the malicious domain and receiver path, preserve endpoint and DNS evidence, rotate privileged credentials, restrict direct DNS egress, centralise resolver logging, and deploy detections that combine structured DNS grammar, high query uniqueness, long labels, sustained cadence, and endpoint process context.
