# Scenario 18 — Stage 2 Starter

This package creates and investigates one deterministic, explicitly synthetic cloud privilege and OAuth application-abuse event.

## Safety properties

- No connection to Microsoft Entra, Azure, Microsoft Graph, or any real tenant.
- No real tenant IDs, UPNs, application IDs, service-principal IDs, credential IDs, secrets, private keys, cookies, or tokens.
- Every UUID is generated deterministically from a documented synthetic namespace.
- All user principal names use `synthetic.example`.
- All IP addresses use RFC 5737 documentation networks.
- Credential records contain metadata only.
- The first-pass parser and correlation scripts do not read `ground-truth/`.

## Included scripts

- `scripts/generation/generate_synthetic_event.py`
- `scripts/validation/validate_synthetic_package.py`
- `scripts/parsing/first_pass_parser.py`
- `scripts/correlation/precise_cloud_privilege_correlation.py`
- `scripts/correlation/permission_risk.py`
- `scripts/validation/git_aware_validator.py`
- `scripts/validation/sanitisation_test.py`
- `scripts/safe-reproducibility-wrapper.sh`

## Expected location

Copy the package contents into:

`07-cloud-identity-and-privilege-investigations/scenario-18-cloud-privilege-and-oauth-application-abuse/`

The wrapper generates raw evidence under `evidence/raw/`, writes all investigative outputs under `evidence/working/`, and leaves `evidence/processed/` untouched.
