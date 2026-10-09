# Mailbox forwarding or inbox rule to an external address

| | |
|---|---|
| **Rule** | [`rule.yaml`](rule.yaml) |
| **Data** | `OfficeActivity` (Exchange workload) |
| **ATT&CK** | T1114.003 Email Forwarding Rule, T1020 Automated Exfiltration |
| **Severity** | Medium |
| **Runs** | Hourly over 1 hour |

## Goal
Catch mail leaving automatically: after a mailbox takeover (BEC prep) or a leaver keeping a copy.

## Strategy
1. Take Exchange admin/audit operations that can set forwarding: `New-InboxRule`, `Set-InboxRule`, `Set-Mailbox`, `UpdateInboxRules` (the Outlook-client path).
2. `Parameters` is a JSON array of `{Name, Value}`. Expand it and keep the forwarding parameters: `ForwardTo`, `ForwardAsAttachmentTo`, `RedirectTo` (inbox rules), and `ForwardingSmtpAddress`/`ForwardingAddress` (mailbox-level).
3. Split multi-recipient values (`;`, `smtp:` prefixes, brackets) and pull out the domain.
4. Alert when the domain is **not** in `internalDomains`. The rule name is carried along because attackers like names such as `.`, `..` or `RSS`.

One alert per user + external domain, so a rule forwarding to three Gmail addresses is one alert, not three.

## Technical context
- `internalDomains` must be set to your accepted domains, or every forward looks external.
- `Set-Mailbox -ForwardingSmtpAddress` is usually done by admins, so check `UserId` (the actor) against the mailbox it changed.
- Outbound spam policy can block external auto-forwarding outright. If yours does, this rule still matters: the attempt itself is the signal.

## Blind spots
- Rules that *move* or *delete* mail (hiding replies from the victim) without forwarding. Pair with a rule on inbox rules that move to RSS/Archive/Deleted Items and match keywords like "invoice" or "payment".
- Forwarding via Power Automate flows or Graph API mail-send from an OAuth app. Those show up in other logs (`CloudAppEvents`, `AuditLogs` consent).
- Forwarding through mail transport rules set by a compromised admin (`New-TransportRule`).

## False positives
- Users forwarding to their own personal address (policy violation more than attack, but still worth a conversation).
- Approved forwarding to a partner domain. Add those domains to the list.

## Validation
In Outlook on the web, create a rule "forward all mail to test@gmail.com" on a test mailbox. The alert fires within the next run (audit ingestion can take 30–60 min).

## Response
1. Was the rule created from the user's usual IP/device? An unfamiliar `ClientIPs` plus a recent risky sign-in means a compromised mailbox: disable the rule, revoke sessions, reset the password.
2. Run a message trace for what was already forwarded to `Recipients` and notify the data owners.
3. If it's a leaver ([leaver-bulk-download](../../exfiltration/leaver-bulk-download/)), involve HR.
