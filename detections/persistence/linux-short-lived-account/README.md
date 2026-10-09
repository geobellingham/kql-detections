# Short-lived local account on Linux

| | |
|---|---|
| **Rule** | [`rule.yaml`](rule.yaml) |
| **Data** | `Syslog` (auth/authpriv: `useradd`, `userdel`, `sshd`) |
| **ATT&CK** | T1136.001 Create Account: Local, T1070.009 Clear Persistence |
| **Severity** | Medium (raise to High if `LoginsDuringLifetime > 0` or `Uid == 0`) |
| **Runs** | Hourly over 2 hours |

## Goal
Catch throwaway local accounts: created, used, and deleted before anyone looks.

## Strategy
Account *creation* on servers is too common to alert on. Creation **plus** deletion of the same name on the same host within an hour isn't.

1. Parse `useradd` "new user: name=X, UID=N" and `userdel` "delete user 'X'".
2. Join on host + account name, keeping pairs where the delete comes within `maxLifetime` (60 min) of the create.
3. Left-join SSH `Accepted` logins for that account and count only those inside its lifetime.

The query window is 2h with an hourly schedule, so a pair that straddles a run boundary is still caught. A pair that falls entirely inside the overlap can alert twice. Alert grouping on `Computer` + `AccountName` handles that.

## Technical context
- Accounts created with `adduser` still log through `useradd`. Accounts created by editing `/etc/passwd` directly leave **no** useradd entry. That's a separate detection (auditd file-watch on `/etc/passwd` and `/etc/shadow`).
- `UID=0` on a new account is a red flag by itself: a second root.

## Blind spots
- Direct `/etc/passwd` edits, as above.
- Accounts left in place (not deleted). Cover those with a "new local account on a server outside a change window" rule.
- Lifetimes longer than 1 hour. Widen `maxLifetime` with the query period if your environment is quiet enough.

## False positives
- CI/CD runners, container build hosts and test harnesses that create and remove users. Add them to `excludedAccounts` or exclude the hosts.
- Admins testing a provisioning script. Check the change calendar.

## Validation
```bash
sudo useradd -m tmp_test && sleep 60 && sudo userdel -r tmp_test
```
One alert with `LifetimeMinutes` ≈ 1 and `LoginsDuringLifetime = 0`.

## Response
1. Find who ran it: `sudo` entries in the same Syslog window, or the parent session.
2. If the account logged in, review everything that session did: bash history, auditd, new files, cron.
3. Check for the brute-force path that led here ([ssh-bruteforce-then-success](../../credential-access/ssh-bruteforce-then-success/)).
