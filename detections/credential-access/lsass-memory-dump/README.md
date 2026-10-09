# LSASS memory dump via LOLBins or dumping tools

| | |
|---|---|
| **Rule** | [`rule.yaml`](rule.yaml) |
| **Data** | `DeviceProcessEvents` (Defender for Endpoint via the Defender XDR connector) |
| **ATT&CK** | T1003.001 OS Credential Dumping: LSASS Memory |
| **Severity** | High |
| **Runs** | Hourly over 1 hour (also works as-is in Defender advanced hunting) |

## Goal
Catch credential dumping from LSASS by the methods that show up in real intrusions, not just "mimikatz.exe".

## Strategy
Classify each process by **technique**, and alert on any match. `Technique` tells the analyst which branch hit:

| Technique | What it matches |
|---|---|
| comsvcs MiniDump | `rundll32 … comsvcs.dll, MiniDump <pid> <file> full` (also the `#24` ordinal), matched on original file name so a renamed rundll32 still hits |
| ProcDump | ProcDump (by original file name, so renamed copies count) with `lsass` on the command line |
| createdump | .NET `createdump.exe` with full or mini-dump flags |
| Credential tooling keywords | `sekurlsa::`, `lsadump::`, `Out-Minidump`, `MiniDumpWriteDump`, `nanodump`, `Invoke-Mimikatz` |
| Generic LSASS dump | anything else with `lsass` plus `-ma`/`/ma`/`.dmp` |

Lower-casing the command line once (`Cmd`) keeps the `has` checks simple and case-insensitive.

## Technical context
- Defender for Endpoint usually blocks or alerts on many of these by itself. This rule is still useful: it catches what's in **audit/passive mode**, on devices with tamper-protection gaps, and it hands the SOC the command line in a Sentinel incident alongside the other signals.
- Attackers often dump by **PID** instead of the name `lsass`. That's why the comsvcs branch doesn't require the word `lsass`.

## Blind spots
- Dumping without a revealing command line: direct syscalls from injected code, `PssCaptureSnapshot`-based tools, or handle duplication. That needs `DeviceEvents` with `ActionType == "OpenProcessApiCall"` on lsass (a good follow-up rule).
- Dumps via Task Manager's "Create dump file". Its command line shows nothing; it's visible as `DeviceFileEvents` creating `lsass.DMP`.
- Offline dumping: copying a VM's memory or the hiberfil.

## False positives
- Admins or support engineers using ProcDump on LSASS while troubleshooting. Rare, and they should be on a change ticket. Treat as a true positive until confirmed.
- Security tools taking memory snapshots for forensics (some EDR/IR collectors). Exclude by `InitiatingProcessFileName` + signed path.

## Validation
On an isolated lab VM with Defender in **audit** mode:
```
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump <lsass_pid> C:\Temp\x.dmp full
```
One alert, `Technique = comsvcs MiniDump`.

## Response
1. Isolate the device. Assume every credential that touched it is compromised: logged-on users, service accounts, cached domain admins.
2. Find how the attacker got admin on the host (dumping LSASS needs SeDebugPrivilege) and what came before.
3. Reset the exposed credentials, starting with privileged ones. Watch for their use elsewhere (lateral movement, new sign-ins).
