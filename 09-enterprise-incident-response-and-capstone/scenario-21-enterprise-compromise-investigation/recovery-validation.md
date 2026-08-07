# Recovery Validation

Recovery is not equivalent to rebooting a host or changing a password.

The validation matrix requires proof that:

- malicious persistence no longer exists,
- affected credentials/sessions are invalidated,
- malicious WinRM/PsExec sessions are gone,
- malicious processes are absent and do not recur,
- network controls enforce the intended blocks,
- staged data is reviewed,
- required services/access are restored,
- no additional suspicious activity appears during a defined monitoring window.

Because this is a historical emulation dataset, these controls are **not claimed as executed**.

See `evidence/processed/recovery-validation-matrix.csv`.
