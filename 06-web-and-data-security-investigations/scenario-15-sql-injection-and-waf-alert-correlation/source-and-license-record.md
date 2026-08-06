# Source and License Record

## Dataset

- **Title:** A Thirty-Day Dataset of Malicious HTTP Requests Blocked by OWASP ModSecurity on a Production Web Server
- **Publisher:** Zenodo
- **Record:** 17178461
- **DOI:** `10.5281/zenodo.17178461`
- **Archive:** `owasp.zip`
- **Observed size:** 29,524,147 bytes
- **Expected and observed MD5:** `95b7a8237abc163d8ca31e49f7318efd`
- **Observed SHA-256:** `3c4c976f58cd2da61a543a237ede770529ceee59cdb09295a5998d420a8b30b8`
- **Acquired:** 2026-08-06T05:57:00Z
- **License:** CC BY 4.0 as stated by the source record/publication metadata

## Attribution statement

This portfolio scenario uses a transformed and sanitised analysis derived from the dataset identified above. The original archive is not redistributed in the Git repository. Attribution, DOI, integrity values and the distinction between source-author ground truth and locally observed telemetry are preserved.

## Ground-truth boundary

The dataset title and author description characterise the requests as malicious and blocked. This is recorded as **dataset-author ground truth**. The local transaction-level review did not find final interception markers for the SQLi subset, so the author description is not substituted for locally observed enforcement evidence.

## Redistribution policy

- Do not commit the original archive or extracted logs.
- Publish only sanitised derived tables and minimal excerpts.
- Preserve this attribution record.
- Do not disclose Cookie, Authorization, token, session or personal data.
