# SSH brute force followed by successful login

| | |
|---|---|
| **Rule** | [`rule.yaml`](rule.yaml) |
| **Data** | `Syslog` (auth/authpriv from Linux hosts via AMA) |
| **ATT&CK** | T1110.001 Password Guessing, T1078 Valid Accounts |
| **Severity** | High |
| **Runs** | Hourly over 1 hour |

## Goal
Find the moment an SSH brute force actually gets in.

## How it works
Internet-facing SSH gets hammered all day. A rule that fires on every burst of failed logins gets ignored within a week. This one uses the failures as context and only alerts when a login succeeds afterwards.

1. Parse `sshd` auth messages into failures and successes, with the source IP and the username. The regexes cover `Failed password for invalid user X`, `Invalid user X from` and `Accepted password|publickey for X`.
2. Count failures per source IP and host, and keep sources with 20 or more in the hour.
3. Join to successful logins from the same IP on the same host after the first failure.

`UserWasTargeted` tells you if the account that logged in was one of the names being guessed. If it was, a guessed password worked. If it wasn't, the attacker probably had a key or password already and was just noisy before using it. Both are bad.

## Technical context
- Message formats differ a little between distros (`Failed password` vs `Failed publickey`, IPv6 sources). The IP regex handles IPv4 and IPv6.
- Hosts behind NAT or a jump box will show the jump box IP. Exclude known bastion IPs on those hosts.

## Blind spots
- Distributed brute force, with many IPs trying a few times each. You'd need a per-host version that counts distinct sources.
- The attacker cracks the password and then logs in from a different IP. A lookback on new source IPs per user would cover it.
- Hosts that don't forward authpriv, or have a lower `LogLevel` in `sshd_config`.

## False positives
- Vulnerability scanners or config management tools using an old password, then the right one after a rotation. Check the source against your scanner list.
- Scripted jobs that retry in a loop. Rare, but it happens.

## Validation
From a test box, run `hydra` or a loop of `sshpass` with 25 wrong passwords against a lab host, then log in with the right one. You should get one alert with `UserWasTargeted = true`.

## Response
1. Treat the host as compromised until you've checked it: `last`, `~/.ssh/authorized_keys`, crontab, new users (see [linux-short-lived-account](../../persistence/linux-short-lived-account/)) and outbound connections.
2. Block the source IP, rotate the account's credentials, and switch SSH to key-only if it isn't already.
