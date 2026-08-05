# Decoded PowerShell stager findings

The raw encoded command is intentionally not copied into tracked evidence.

- Execution user: `NT AUTHORITY\SYSTEM`
- Parent chain: `services.exe -> cmd.exe -> cmd.exe -> powershell.exe`
- PowerShell flags: `-noP -sta -w 1 -enc <redacted>`
- Observed destination: `http://10.10.10.5/login/process.php` (private lab address)
- Behaviour observed in Event ID 4104:
  - attempts to disable Script Block Logging;
  - sets the in-memory AMSI initialisation-failed flag;
  - creates a `System.Net.WebClient` using the default proxy and credentials;
  - downloads encrypted stage data over HTTP;
  - decrypts the returned data with an RC4-style routine;
  - executes the result in memory with `IEX`.
- Follow-on evidence: the same ProcessGuid `{d273d0f0-fd6c-5f66-7605-000000000800}` connects to `10.10.10.5:80` and later spawns `whoami.exe`.

The source-side dataset records `Invoke-SMBExec` being supplied a demonstration NTLM hash. This attribution is simulation ground truth; target/network telemetry independently proves successful NTLM authentication but not the credential representation. The hash is excluded from processed evidence.
