# Periodic beaconing to a rare external destination

| | |
|---|---|
| **Rule** | [`rule.yaml`](rule.yaml) |
| **Data** | `CommonSecurityLog` (FortiGate via CEF/AMA) |
| **ATT&CK** | T1071 Application Layer Protocol, T1573 Encrypted Channel |
| **Severity** | Medium |
| **Runs** | Daily over 24 hours |

## Goal
Find implants checking in with their C2 server: traffic that is too *regular* to be a human and goes somewhere almost nobody else in the company goes.

## Strategy
Two independent filters, both needed:

1. **Rarity.** Count how many internal hosts contacted each external IP in the day. Keep destinations seen from **≤ 3** hosts. That removes Microsoft, Google, CDNs, AV update servers and so on, which is most of the periodic traffic on any network.
2. **Regularity.** For each source → destination:port flow, sort the connections in time and measure the gap between consecutive ones. A beacon has a steady gap, so the **coefficient of variation** (stdev / mean of the gaps, `Jitter`) is low. Keep flows with **≥ 30 connections**, an average gap **≥ 30s**, and `Jitter ≤ 0.2`.

`SizeJitter` (the same measure on bytes sent) is reported but not filtered on. Low values (same-sized check-ins every time) strengthen the case.

## Technical context
- C2 frameworks add jitter on purpose (Cobalt Strike's `jitter` setting, often 10–30%). `maxJitter = 0.2` catches the default and light jitter. Raise it and you buy more coverage with more noise.
- FortiGate logs at session end, so long-lived sessions (one TLS connection held open for hours) produce one event and won't look periodic. That's a blind spot below.
- `prev()` needs a serialized row set, which the `sort` gives it.

## Blind spots
- Beacons over long-lived connections or WebSockets (one session, many messages inside).
- Beacons through the web proxy: the firewall sees only the proxy. Run the same logic on Zscaler logs keyed on user + host name.
- Domain fronting or C2 hosted on popular services (Azure, Cloudflare Workers, Slack/Teams webhooks). Those fail the rarity filter by design.
- Slow beacons (once an hour or less) never reach 30 connections in a day. A 7-day variant with `minConnections` around 100 covers them.

## False positives
- Niche SaaS agents, monitoring probes, license servers, IoT and printers phoning home. Check `HostNames` and the device owner, then allow-list the destination.
- Developer machines polling a personal or test server.

## Validation
On a lab host: `while true; do curl -s https://<test-server>/ >/dev/null; sleep 60; done` for a few hours. One alert, `AvgGapSec` ≈ 60, `Jitter` close to 0.

## Response
1. Look up the destination (WHOIS, passive DNS, threat intel). Was the domain registered recently? Is the certificate self-signed?
2. On the source host (Defender XDR): which process owns the connection? Check its signature, path and parent.
3. If it's malicious: isolate the host and block the destination. Then hunt for the same destination, or the same `AvgGapSec` pattern, from other hosts over a longer lookback.
