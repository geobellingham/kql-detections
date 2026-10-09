# SSH brute force followed by successful login

| | |
|---|---|
| **Rule** | [`rule.yaml`](rule.yaml) |
| **Data** | `Syslog` (auth/authpriv from Linux hosts via AMA) |
| **ATT&CK** | T1110.001 Password Guessing, T1078 Valid Accounts |
| **Severity** | High |
| **Runs** | Hourly over 1 hour |

## Goal
Find the moment SSH brute forcing actually works.

## Strategy
A plain "N failed SSH logins" rule on an internet-facing host fires all day and teaches analysts to ignore it. This rule keeps the brute-force part as context and alerts only on the outcome:

1. Parse `sshd` auth messages into Failure / Success, plus source IP and target user. The regexes handle `Failed password for invalid user X`, `Invalid user X from`, and `Accepted password|publickey for X`.
2. Per source IP + host: count failures, and keep only sources with **≥ 20** in the hour.
3. Join to successful logins from the **same IP on the same host** that happen after the first failure.

`UserWasTargeted` says whether the account that logged in was one of the names being guessed. True means a guessed password worked. False is also interesting: an attacker who already had a key or password, scanning noisily first.

## Technical context
- Messages vary slightly across distros (`Failed password` vs `Failed publickey`; IPv6 sources). The IP regex accepts both IPv4 and IPv6.
- Hosts behind NAT or a jump box show the jump box IP. On those hosts, tune by excluding known bastion IPs.

## Blind spots
- Distributed brute force: many IPs, few attempts each. That needs a per-host variant that counts distinct sources.
- Success from a *different* IP after a failed burst (the attacker cracks the password, then logs in from fresh infrastructure). Handle that with a lookback on newly seen source IPs per user.
- Hosts not forwarding authpriv, or with `LogLevel` lowered in `sshd_config`.

## False positives
- Vulnerability scanners and config-management tools with a stale password, then a correct one after rotation. Check the source against the scanner inventory.
- A user fat-fingering a password 20+ times is unlikely, but it happens with scripted jobs that retry in loops.

## Validation
From a test box, run `hydra` (or a loop of `sshpass`) with 25 wrong passwords against a lab host, then one correct login. One alert fires with `UserWasTargeted = true`.

## Response
1. Treat as a compromised host until shown otherwise: check `last`, `~/.ssh/authorized_keys`, crontab, new users (see [linux-short-lived-account](../../persistence/linux-short-lived-account/)), and outbound connections.
2. Block the source IP, rotate the account's credentials, and move SSH to key-only auth if it isn't already.
