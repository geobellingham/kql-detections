# Short-lived local account on Linux

| | |
|---|---|
| **Rule** | [`rule.yaml`](rule.yaml) |
| **Data** | `Syslog` (auth/authpriv: `useradd`, `userdel`, `sshd`) |
| **ATT&CK** | T1136.001 Create Account: Local, T1070.009 Clear Persistence |
| **Severity** | Medium (raise to High if `LoginsDuringLifetime > 0` or `Uid == 0`) |
| **Runs** | Hourly over 2 hours |

## Goal
Catch throwaway local accounts that get created, used and deleted before anyone notices.

## How it works
Accounts get created on servers all the time, so creation alone is too noisy. The same account being created and deleted on the same host within an hour is unusual.

1. Parse `useradd` ("new user: name=X, UID=N") and `userdel` ("delete user 'X'").
2. Join on host and account name and keep pairs where the delete happens within 60 minutes of the create.
3. Join SSH `Accepted` logins for that account and count the ones that happened while it existed.

The query looks back 2 hours and runs every hour, so a pair that crosses a run boundary is still caught. A pair inside the overlap can alert twice. Group alerts on `Computer` and `AccountName` to merge them.

## Technical context
- `adduser` still logs through `useradd`. Editing `/etc/passwd` directly leaves no useradd entry at all, so that needs its own detection (auditd watch on `/etc/passwd` and `/etc/shadow`).
- A new account with `UID=0` is a second root account. That's suspicious by itself.

## Blind spots
- Direct edits of `/etc/passwd`, as above.
- Accounts that are created and left in place. A "new local account on a server outside a change window" rule covers those.
- Accounts that live longer than an hour. You can raise `maxLifetime` together with the query period if your servers are quiet enough.

## False positives
- CI/CD runners, container build hosts and test harnesses that create and remove users. Add them to `excludedAccounts` or exclude the hosts.
- Admins testing a provisioning script. Check the change calendar.

## Validation
```bash
sudo useradd -m tmp_test && sleep 60 && sudo userdel -r tmp_test
```
You should get one alert with `LifetimeMinutes` around 1 and `LoginsDuringLifetime = 0`.

## Response
1. Find who ran it: `sudo` entries in the same Syslog window, or the parent session.
2. If the account logged in, go through everything that session did: bash history, auditd, new files, cron.
3. Look for how the attacker got in, for example [ssh-bruteforce-then-success](../../credential-access/ssh-bruteforce-then-success/).
