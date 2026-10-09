# MFA fatigue: repeated denials, possibly followed by approval

| | |
|---|---|
| **Rule** | [`rule.yaml`](rule.yaml) |
| **Data** | `SigninLogs` |
| **ATT&CK** | T1621 MFA Request Generation, T1078.004 Cloud Accounts |
| **Severity** | Medium; **High** if an MFA-approved sign-in follows the denials |
| **Runs** | Hourly over 1 hour |

## Goal
Catch push-spam attacks, and especially the moment a user taps "Approve" to make them stop.

## Strategy
A failed MFA (`ResultType 500121`) means the **password step succeeded**. So even the "no approval" case is a confirmed credential leak, not noise.

1. Per user, count MFA failures in the hour and note any where the user reported fraud.
2. Keep users with **≥ 5** failures, or any fraud report.
3. Left-join MFA-satisfied successful sign-ins **after the first denial**. If one exists, `Outcome` = "Approved after repeated denials" and severity goes to High.
4. `ApprovalFromDenialIP` shows whether the approval came from the same IP as the denials. If it did, the attacker's own session got through.

## Technical context
- Number matching in Microsoft Authenticator makes classic push fatigue much harder, but not impossible (social engineering over the phone, "just read me the number"). The rule still covers SMS/voice methods and tenants that haven't enforced number matching.
- `Status.additionalDetails` carries the reason ("MFA denied; user declined the authentication", "MFA denied; user did not respond…", "…fraud code entered").

## Blind spots
- Attacks spread over more than an hour with only 2–3 prompts at a time. A 24h variant with a lower threshold helps.
- AiTM phishing (Evilginx and similar) steals the session *after* MFA, so there are no denials to see. That needs a different detection (token replay, sign-in from a new ASN right after MFA).

## False positives
- A user with a broken Authenticator app (new phone) who keeps getting failures, then fixes it and succeeds. Same IP, same location, often with a helpdesk ticket.
- Users ignoring prompts from their own background sync on a second device.

## Validation
From a lab account, trigger 5 sign-ins and deny each prompt, then approve the sixth. One alert, High, `Outcome = "Approved after repeated denials"`.

## Response
1. **Approved:** revoke sessions, reset the password, review MFA methods registered in the last day (attackers add their own), and check mailbox rules and OAuth consents.
2. **Not approved:** reset the password anyway, since it's known to the attacker. Tell the user why they got the prompts.
3. Check where the password came from: same IP in [entra-password-spray](../entra-password-spray/)? Recent phishing click?
