# Mailbox forwarding or inbox rule to an external address

| | |
|---|---|
| **Rule** | [`rule.yaml`](rule.yaml) |
| **Data** | `OfficeActivity` (Exchange workload) |
| **ATT&CK** | T1114.003 Email Forwarding Rule, T1020 Automated Exfiltration |
| **Severity** | Medium |
| **Runs** | Hourly over 1 hour |

## Goal
Catch mail being forwarded out of the company automatically. Attackers set this up after taking over a mailbox, usually to watch invoice threads for BEC. Leavers set it up to keep a copy of their mail.

## How it works
1. Take the Exchange operations that can set up forwarding: `New-InboxRule`, `Set-InboxRule`, `Set-Mailbox` and `UpdateInboxRules` (the Outlook client path).
2. `Parameters` is a JSON list of `{Name, Value}` pairs. Expand it and keep the forwarding ones: `ForwardTo`, `ForwardAsAttachmentTo` and `RedirectTo` for inbox rules, `ForwardingSmtpAddress` and `ForwardingAddress` for the mailbox.
3. Split values with several recipients (`;`, `smtp:` prefixes, brackets) and get the domain of each.
4. Alert when the domain isn't in `internalDomains`. The rule name comes along too, since attackers like names such as `.`, `..` or `RSS`.

You get one alert per user and external domain. A rule forwarding to three Gmail addresses gives you one alert.

## Technical context
- Set `internalDomains` to your accepted domains first, or every forward will look external.
- `Set-Mailbox -ForwardingSmtpAddress` is normally done by an admin, so compare `UserId` (who did it) with the mailbox that was changed.
- If your outbound spam policy blocks external auto-forwarding, the attempt is still worth knowing about.

## Blind spots
- Rules that move or delete mail to hide replies from the victim, without forwarding. Pair this with a rule on inbox rules that move mail to RSS, Archive or Deleted Items and match words like "invoice" or "payment".
- Forwarding through Power Automate flows, or through an OAuth app sending mail via Graph. Those show up in `CloudAppEvents` and in consent events in `AuditLogs`.
- Transport rules set by a compromised admin (`New-TransportRule`).

## False positives
- Users forwarding to their own personal address. More of a policy problem than an attack, but still worth a conversation.
- Approved forwarding to a partner domain. Add the domain to the list.

## Validation
In Outlook on the web, create a rule on a test mailbox that forwards all mail to test@gmail.com. It should alert on the next run. Audit logs can take 30 to 60 minutes to arrive.

## Response
1. Check if the rule was created from the user's normal IP and device. An unknown `ClientIPs` value together with a recent risky sign-in means the mailbox is compromised: remove the rule, revoke sessions and reset the password.
2. Run a message trace to see what has already gone to `Recipients`, and tell the data owners.
3. If it's a leaver (see [leaver-bulk-download](../../exfiltration/leaver-bulk-download/)), bring in HR.
