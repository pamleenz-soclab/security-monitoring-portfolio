# Validation Checklist

- [ ] Raw and working evidence remain Git-ignored and untracked.
- [ ] Pinned upstream commit and source SHA-256 records are retained.
- [ ] Master timeline preserves source time, normalized time basis, and uncertainty.
- [ ] Initial Access remains Not available / Unable to assess.
- [ ] Failed PFX export is never described as successful.
- [ ] Only the incident-correlated PowerShell LSASS event is retained; wininit/csrss candidates are excluded.
- [ ] `Temp\python.exe` 5145 is not described as a file write.
- [ ] PSEXESVC write/svcctl/service evidence uses the correct session context.
- [ ] Zeek is not described as same-event corroboration of May 2 host events.
- [ ] Exfiltration and ATT&CK/business Impact are not claimed.
- [ ] NEWYORK and UTICA are not labeled compromised.
- [ ] `192.168.0.4/5` are labeled environment-specific RFC1918 observables.
- [ ] Containment/recovery are clearly marked design-only.
- [ ] Public excerpts redact the archive password and do not republish encoded payload bodies.
- [ ] Final validator passes.
- [ ] `git diff --cached --check` passes before commit.
