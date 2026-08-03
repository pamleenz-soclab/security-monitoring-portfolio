# Processed Evidence

This directory contains the minimum sanitised evidence required to reproduce the public investigation narrative.

- Lab host, domain, user, and source-address values are replaced.
- Destination indicators are deactivated with bracket notation.
- Full Windows messages, task XML, registry data, and encoded PowerShell content are omitted.
- Record IDs, event IDs, task names, registry paths, process IDs, and timestamps are retained for local cross-checking.
- Each CSV separates direct observations from interpretation through an explicit `status` field.

The source JSON and full working exports remain under ignored local directories.

