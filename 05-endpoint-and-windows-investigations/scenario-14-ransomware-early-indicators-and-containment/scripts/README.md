# Analysis Scripts

## `scenario14_first_pass.py`

Purpose:

- Parses the three concatenated XML event streams.
- Creates a normalised SQLite event index.
- Produces broad process, authentication, file, network, recovery, and defence candidate tables.
- Generates `compact-first-pass.txt`.

Important limitation:

The first pass intentionally uses broad candidate tags. Keyword-only results must not be treated as confirmed findings.

## `scenario14_precise_verify.py`

Purpose:

- Normalises short and FQDN host aliases.
- Correlates the builder and payload process chains.
- Links file events by exact Process GUID.
- Extracts RDP, authentication, recovery, defence, and network candidates.
- Produces `compact-verification.txt`.

Important limitation:

The script treats the builder process and payload process as ransomware-related process candidates. Public reporting must separate the one payload-output file created by the builder from the 183 ransom notes created by the payload.

## Requirements

Python 3.10 or later is recommended. The scripts use the Python standard library only.

## Example

```bash
python3 scripts/scenario14_first_pass.py \
  --raw-dir evidence/raw \
  --working-dir evidence/working

python3 scripts/scenario14_precise_verify.py \
  --db evidence/working/scenario14-events.sqlite \
  --output-dir evidence/working
```

Raw evidence must remain local and Git-ignored.
