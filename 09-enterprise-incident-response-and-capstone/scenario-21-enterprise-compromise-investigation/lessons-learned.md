# Lessons Learned

The most important lesson is that high-recall automated triage must be followed by precision review.

Three LSASS candidates initially looked similar. Precision validation showed two were normal `wininit.exe`/`csrss.exe` activity and only one was the exact malicious PowerShell ProcessGuid.

A 5145 event for `Temp\python.exe` initially looked like possible file transfer. Its requested access was only `ReadAttributes`, so it was not used as copy/write evidence. A separate `PSEXESVC.exe` event contained the actual WriteData/AppendData rights.

The PFX-export event was also decisive: the source explicitly states that the private key was non-exportable, so the result is an unsuccessful attempt.

Finally, a source repository can contain both host and Zeek artifacts under a Day 1 label without the captures being event-time aligned. Correlating them without checking timestamps would have created a false multi-domain conclusion.

Stable identifiers produced the strongest results. ATT&CK helped organize behaviors but did not establish causality.
