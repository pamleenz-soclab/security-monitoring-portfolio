# Evidence Inventory

## Raw evidence retained locally

Raw evidence is retained under `evidence/raw/` and is excluded from Git.

| File | Size | Physical lines | SHA-256 |
|---|---:|---:|---|
| `windows-sysmon.log` | 20,699,440 bytes | 13,468 | `6fb7acc46cae31504b1d8fc7b731cfcbbfc61ef9819574a72d684c8ea47e9360` |
| `windows-security.log` | 21,544,480 bytes | 38,203 | `55555312391cf49c51fddbbd2c19aa09d7c1469205d0f3374bec68ad4df49a78` |
| `windows-powershell.log` | 57,064,933 bytes | 493,563 | `405c2a15b183abd9f23e22eb18ddb65b562d9b80cca7a4338ffeddc26cbb6c4c` |

Physical line counts are not event counts because several XML events contain embedded line breaks.

## Parsed event counts

| Source | Parsed events | Earliest event | Latest event |
|---|---:|---|---|
| PowerShell | 43,105 | `2026-04-24T06:09:08.5443670Z` | `2026-04-24T10:32:13.7945387Z` |
| Security | 16,946 | `2026-04-24T01:03:00.2303838Z` | `2026-04-24T10:36:59.1734273Z` |
| Sysmon | 13,462 | `2026-04-24T06:29:08.8009398Z` | `2026-04-24T10:34:55.5178180Z` |
| **Total** | **73,513** |  |  |

Parser errors: **0**

## Logical host normalisation

Short names and FQDNs were normalised as the same logical hosts:

| Logical host | Observed aliases |
|---|---|
| `EC2AMAZ-I41BETP` | `EC2AMAZ-I41BETP`, `EC2AMAZ-I41BETP.attackrange.local` |
| `EC2AMAZ-TLJH2O4` | `EC2AMAZ-TLJH2O4`, `EC2AMAZ-TLJH2O4.attackrange.local` |
| `WIN-GM4EB5GIVO0` | `WIN-GM4EB5GIVO0` |
| `WIN-QQ6SF2TB3S8` | `WIN-QQ6SF2TB3S8` |

## Derived evidence included in Git

The `evidence/processed/` directory contains:

- Rapid triage timeline.
- Impact and scope timeline.
- Host-account-file scope map.
- Process and command-line analysis.
- File-impact analysis.
- Recovery-inhibition analysis.
- Network and shared-drive analysis.
- Sanitised evidence excerpts.
- Source and hash records.

These files contain only the minimum fields required to support the published conclusions.
