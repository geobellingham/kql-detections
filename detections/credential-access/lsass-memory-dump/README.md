# LSASS memory dump via LOLBins or dumping tools

| | |
|---|---|
| **Rule** | [`rule.yaml`](rule.yaml) |
| **Data** | `DeviceProcessEvents` (Defender for Endpoint via the Defender XDR connector) |
| **ATT&CK** | T1003.001 OS Credential Dumping: LSASS Memory |
| **Severity** | High |
| **Runs** | Hourly over 1 hour (also works as-is in Defender advanced hunting) |

## Goal
Catch credential dumping from LSASS using the methods that actually show up in intrusions. Most of them don't involve a file called mimikatz.exe.

## How it works
Each process is checked against a list of known techniques. If one matches, it alerts, and `Technique` tells the analyst which one:

| Technique | What it matches |
|---|---|
| comsvcs MiniDump | `rundll32 … comsvcs.dll, MiniDump <pid> <file> full` (also the `#24` ordinal), matched on the original file name so a renamed rundll32 still counts |
| ProcDump | ProcDump (by original file name, so renamed copies count) with `lsass` on the command line |
| createdump | .NET `createdump.exe` with full or mini dump flags |
| Credential tooling keywords | `sekurlsa::`, `lsadump::`, `Out-Minidump`, `MiniDumpWriteDump`, `nanodump`, `Invoke-Mimikatz` |
| Generic LSASS dump | anything else with `lsass` plus `-ma`, `/ma` or `.dmp` |

The command line is lower-cased once at the start, which keeps the checks simple and case-insensitive.

## Technical context
- Defender for Endpoint blocks or alerts on many of these by itself. This rule still helps on devices in audit or passive mode, on devices with tamper protection gaps, and it puts the command line into a Sentinel incident next to the other signals.
- Attackers often pass the PID of lsass, so the word `lsass` never appears. The comsvcs check doesn't require it for that reason.

## Blind spots
- Dumping with no telling command line: direct syscalls from injected code, `PssCaptureSnapshot`-based tools, or handle duplication. That needs `DeviceEvents` with `ActionType == "OpenProcessApiCall"` on lsass, which would make a good follow-up rule.
- Dumps made with Task Manager's "Create dump file". The command line shows nothing. You can see it in `DeviceFileEvents` when `lsass.DMP` is created.
- Offline dumping, like copying a VM's memory or the hibernation file.

## False positives
- Admins or support engineers running ProcDump on LSASS for troubleshooting. This is rare and should have a change ticket. Treat it as real until someone confirms it.
- Security tools taking memory snapshots for forensics. Exclude them by `InitiatingProcessFileName` and signed path.

## Validation
On an isolated lab VM with Defender in audit mode:
```
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump <lsass_pid> C:\Temp\x.dmp full
```
You should get one alert with `Technique = comsvcs MiniDump`.

## Response
1. Isolate the device. Assume every credential that touched it is compromised: logged-on users, service accounts, cached domain admins.
2. Work out how the attacker got admin rights on the host (dumping LSASS needs SeDebugPrivilege) and what happened before that.
3. Reset the exposed credentials, privileged ones first, and watch for them being used elsewhere.
