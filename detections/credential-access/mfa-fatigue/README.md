# MFA fatigue: repeated denials, possibly followed by approval

| | |
|---|---|
| **Rule** | [`rule.yaml`](rule.yaml) |
| **Data** | `SigninLogs` |
| **ATT&CK** | T1621 MFA Request Generation, T1078.004 Cloud Accounts |
| **Severity** | Medium, High if an MFA-approved sign-in follows the denials |
| **Runs** | Hourly over 1 hour |

## Goal
Catch push-spam attacks, and especially the moment a user taps Approve just to make the prompts stop.

## How it works
A failed MFA (`ResultType 500121`) means the password step already worked. So even when the user never approves, someone out there has the password.

1. Count MFA failures per user in the hour, and note any where the user reported fraud.
2. Keep users with 5 or more failures, or any fraud report.
3. Join MFA-approved sign-ins that came after the first denial. If there is one, `Outcome` becomes "Approved after repeated denials" and the alert goes to High.
4. `ApprovalFromDenialIP` shows whether the approval came from the same IP as the denials. If it did, the attacker's own session got through.

## Technical context
- Number matching in Microsoft Authenticator makes push spam much harder, but people still get talked into reading the number out over the phone. The rule also covers SMS and voice methods, and tenants that haven't turned number matching on.
- `Status.additionalDetails` has the reason, for example "MFA denied; user declined the authentication", "MFA denied; user did not respond…" or "…fraud code entered".

## Blind spots
- Attacks spread over more than an hour with only 2 or 3 prompts at a time. A 24-hour version with a lower threshold helps.
- AiTM phishing (Evilginx and similar) steals the session after MFA is done, so there are no denials to see. That needs a different detection, for example token replay or a sign-in from a new ASN right after MFA.

## False positives
- A user with a broken Authenticator app on a new phone who keeps failing, then fixes it and gets in. Same IP, same location, and often a helpdesk ticket.
- Users ignoring prompts triggered by background sync on a second device.

## Validation
With a lab account, trigger 5 sign-ins and deny each prompt, then approve the sixth. You should get one High alert with `Outcome = "Approved after repeated denials"`.

## Response
1. **Approved:** revoke sessions, reset the password, check for MFA methods added in the last day (attackers add their own), and check mailbox rules and OAuth consents.
2. **Not approved:** reset the password anyway, because the attacker knows it. Tell the user why they were getting prompts.
3. Find out where the password came from. Was the same IP in [entra-password-spray](../entra-password-spray/)? Did the user click a phishing link recently?
