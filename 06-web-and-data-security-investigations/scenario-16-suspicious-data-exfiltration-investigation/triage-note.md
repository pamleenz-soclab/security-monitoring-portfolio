# Triage Note

## Alert concept

A file server generated sustained, highly structured DNS queries to a dedicated external domain. Queries embedded chunk indexes, encoded payload labels, and source filenames.

## Initial severity

**High**, escalated to **Critical** after receiver-side hash verification.

## Entities

- Host: `internal_share`
- Source IP: `10.143.0.103`
- Account context: `root` (ground-truth service configuration)
- Service: `put`
- Script path: `/usr/bin/put`
- Internal resolver: `10.143.0.1`
- Upstream resolver: `192.168.231.254`
- Receiver: `192.168.230.122`
- Domain: `email-19.kennedy-mendoza.info`

## Triage observations

- DNS requests used the repeatable `3x6` data marker and `3x7` completion marker.
- The traffic persisted for approximately 4.04 days at a low average rate.
- Two PCAPs overlapped; exact deduplication removed 35,786 duplicate rows.
- Thirty-one receiver objects exactly matched source objects by SHA-256.
- One additional file, `Vaughn-mcdaniel.docx`, had 128 chunks but no completion marker or receiver object.

## Triage disposition

- Overall incident: **Confirmed exfiltration**
- Completed object scope: **31 files / 2,042,802 bytes**
- Additional object: **Attempted exfiltration**
- Immediate response: isolate the source host, block the domain and receiver infrastructure, preserve volatile and disk evidence, and rotate privileged credentials associated with the host.
