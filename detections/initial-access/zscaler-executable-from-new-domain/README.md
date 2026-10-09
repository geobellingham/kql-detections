# Executable downloaded from a first-seen domain (Zscaler)

| | |
|---|---|
| **Rule** | [`rule.yaml`](rule.yaml) |
| **Data** | `CommonSecurityLog` (Zscaler NSS web logs via CEF) |
| **ATT&CK** | T1189 Drive-by Compromise, T1204.002 Malicious File, T1566.002 Spearphishing Link |
| **Severity** | Medium |
| **Runs** | Hourly over 14 days |

## Goal
Catch malware delivery at the download step, before anything runs.

## Strategy
Executables get downloaded all day from vendors everyone uses. What stands out is one coming from a domain **the whole organisation has never visited**.

1. Build the set of domains seen in Zscaler logs over the last 14 days, excluding the current hour.
2. In the current hour, take allowed downloads whose URL path ends in a risky extension (exe, dll, msi, scripts, iso/img/vhd, lnk, OneNote…) **or** that Zscaler classified with a risky `FileType` (covers downloads served without an extension).
3. Drop anything whose domain is in the 14-day set (`leftanti` join), and drop a small allow-list of trusted software vendors by root domain.

One alert per domain + source IP.

## Technical context
- The 14-day "known" set is org-wide on purpose. If one colleague already visited a domain, it isn't new. That keeps volume low but means a site visited once by someone else won't alert (see blind spots).
- Root-domain extraction takes the last two labels, which is wrong for `co.uk`-style suffixes. Good enough for an allow-list, not for attribution.
- Field names depend on your NSS feed format. `FileType` must be mapped to the Zscaler `filetype` field in the CEF feed.

## Blind spots
- Payloads hosted on popular platforms (GitHub, Dropbox, Google Drive, Discord CDN). Those domains are "known". Cover them with a separate rule on risky downloads from file-sharing domains by users who don't normally use them.
- Payloads inside archives (`.zip`, `.7z`), which are left out to keep noise down. Add them if Zscaler sandboxing reports results into the feed.
- HTML smuggling: the file is built in the browser, so the proxy never sees an `.exe`.

## False positives
- Users installing legitimate niche tools (drivers, small open-source utilities). A quick look at the domain and file name usually settles it. Allow-list what IT supports.
- New SaaS vendor rollouts. Many users at once from the same domain points to a project, not an attack.

## Validation
From a test machine behind Zscaler, download a harmless `.exe` (for example a signed utility) from a domain you registered or a fresh test subdomain. One alert, `ExtensionList = .exe`.

## Response
1. Check the domain's age and reputation, and the file hash in Defender / VirusTotal.
2. In Defender XDR, did the file execute on the host? Look up `DeviceFileEvents` → `DeviceProcessEvents` by SHA256.
3. If it's malicious: block the domain in Zscaler, isolate the host if the file ran, and look for how the user got the link (email, Teams, search ad).
