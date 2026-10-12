# Executable downloaded from a first-seen domain (Zscaler)

| | |
|---|---|
| **Rule** | [`rule.yaml`](rule.yaml) |
| **Data** | `CommonSecurityLog` (Zscaler NSS web logs via CEF) |
| **ATT&CK** | T1189 Drive-by Compromise, T1204.002 Malicious File, T1566.002 Spearphishing Link |
| **Severity** | Medium |
| **Runs** | Hourly over 14 days |

## Goal
Catch malware delivery at the download, before anything runs.

## How it works
People download executables all day from vendors everyone uses. The interesting case is an executable from a domain nobody in the company has visited before.

1. Build the list of domains seen in the Zscaler logs over the last 14 days, leaving out the current hour.
2. In the current hour, take allowed downloads where the URL path ends in a risky extension (exe, dll, msi, scripts, iso/img/vhd, lnk, OneNote and so on), or where Zscaler gave it a risky `FileType`. The second check covers files served without an extension.
3. Drop anything from a domain in the 14-day list (`leftanti` join), and anything from a short allow-list of trusted software vendors.

You get one alert per domain and source IP.

## Technical context
- The 14-day list covers the whole company. If one colleague has already been to a domain, it counts as known. That keeps the volume down, with the downside listed under blind spots.
- The root domain is taken as the last two labels, which is wrong for `co.uk`-style domains. It's fine for the allow-list, but don't use it for attribution.
- Field names depend on your NSS feed format. `FileType` has to be mapped from the Zscaler `filetype` field in the CEF feed.

## Blind spots
- Payloads on popular platforms like GitHub, Dropbox, Google Drive or the Discord CDN. Those domains are already known. A separate rule for risky downloads from file-sharing sites by users who don't normally use them would cover this.
- Payloads inside archives (`.zip`, `.7z`). They're left out to keep the noise down. Add them if Zscaler sandbox results come through in the feed.
- HTML smuggling, where the file is built in the browser and the proxy never sees an `.exe`.

## False positives
- Users installing legitimate small tools like drivers or open-source utilities. The domain and file name usually make it obvious. Allow-list what IT supports.
- A new SaaS vendor being rolled out. Lots of users downloading from the same new domain at once usually means a project.

## Validation
From a test machine behind Zscaler, download a harmless signed `.exe` from a domain you control or a new test subdomain. You should get one alert with `ExtensionList = .exe`.

## Response
1. Check the domain's age and reputation, and the file hash in Defender or VirusTotal.
2. In Defender XDR, check whether the file ran on the host by following the SHA256 from `DeviceFileEvents` to `DeviceProcessEvents`.
3. If it's malicious, block the domain in Zscaler, isolate the host if the file ran, and find out how the user got the link (email, Teams, a search ad).
