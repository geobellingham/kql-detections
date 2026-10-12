# Periodic beaconing to a rare external destination

| | |
|---|---|
| **Rule** | [`rule.yaml`](rule.yaml) |
| **Data** | `CommonSecurityLog` (FortiGate via CEF/AMA) |
| **ATT&CK** | T1071 Application Layer Protocol, T1573 Encrypted Channel |
| **Severity** | Medium |
| **Runs** | Daily over 24 hours |

## Goal
Find malware checking in with its C2 server: traffic on a timer, going somewhere almost nobody else in the company talks to.

## How it works
The rule uses two filters and a flow has to pass both.

1. **Rare destination.** Count how many internal hosts talked to each external IP during the day, and keep destinations seen from 3 hosts or fewer. This removes Microsoft, Google, CDNs, AV updates and most other periodic traffic.
2. **Regular timing.** For each source to destination:port flow, sort the connections by time and measure the gaps between them. A beacon checks in at a steady interval, so the gaps barely vary. `Jitter` is the standard deviation of the gaps divided by their average. The rule keeps flows with at least 30 connections, an average gap of 30 seconds or more, and `Jitter` of 0.2 or less.

`SizeJitter` is the same calculation on bytes sent. It's reported for context only. If it's low as well, the check-ins are the same size every time, which makes it more likely to be a beacon.

## Technical context
- C2 frameworks add jitter on purpose. Cobalt Strike's `jitter` setting is often 10 to 30%. `maxJitter = 0.2` catches the default and light jitter. Raising it catches more and adds noise.
- FortiGate logs a session when it ends. A single TLS connection held open for hours gives one event, so it won't look periodic.
- `prev()` needs the rows in order, which the `sort` takes care of.

## Blind spots
- Beacons over one long-lived connection or a WebSocket.
- Beacons through the web proxy, where the firewall only sees the proxy. The same logic works on Zscaler logs if you group by user and host name.
- C2 hosted on popular services like Azure, Cloudflare Workers or Slack/Teams webhooks. These fail the rarity filter.
- Slow beacons, once an hour or less, never reach 30 connections in a day. A 7-day version with `minConnections` around 100 covers them.

## False positives
- Niche SaaS agents, monitoring probes, license servers, IoT devices and printers phoning home. Check `HostNames` and who owns the device, then allow-list the destination.
- Developer machines polling a personal or test server.

## Validation
On a lab host, run `while true; do curl -s https://<test-server>/ >/dev/null; sleep 60; done` for a few hours. You should get one alert with `AvgGapSec` around 60 and `Jitter` close to 0.

## Response
1. Look up the destination: WHOIS, passive DNS, threat intel. Check if the domain is new or the certificate is self-signed.
2. On the source host in Defender XDR, find the process that owns the connection and check its signature, path and parent.
3. If it's malicious, isolate the host and block the destination. Then search for the same destination, or the same `AvgGapSec` pattern, from other hosts over a longer period.
