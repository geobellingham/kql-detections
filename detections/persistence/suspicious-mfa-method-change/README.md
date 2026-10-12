# Suspicious MFA / security info change (risk-scored)

| | |
|---|---|
| **Rule** | [`rule.yaml`](rule.yaml) |
| **Data** | `AuditLogs`, `SigninLogs`, `OfficeActivity`, `SecurityAlert`; `IdentityInfo` optional (UEBA) |
| **ATT&CK** | T1098.005 Device Registration, T1556.006 Modify Authentication Process: MFA |
| **Severity** | Medium, High at score 7 or more |
| **Runs** | Hourly, 14-day query period |

## Goal
Catch attackers adding their own MFA method after stealing a session or a password, without alerting on every new phone in the company.

## How it works
Security info changes happen all day: new phones, passkey rollouts, helpdesk resets. Alerting on one signal, like "method registered from a new IP", is either too noisy to leave on or too narrow to catch anything. So the rule gathers the context an analyst would normally look up by hand and adds it up into a score:

| Signal | Points | How |
|---|---|---|
| New country | 3 | Country of the sign-in behind the change isn't in the user's last 13 days |
| Risky sign-in at registration | 3 | That sign-in had medium or high Entra ID Protection risk |
| External forward or delete inbox rule (24h) | 3 | `New/Set-InboxRule` or `Set-Mailbox` forwarding outside your domains, or `DeleteMessage=True` |
| Method changed by another account | 2 | The initiator isn't the user and isn't in `allowedAdmins` |
| Spray or brute force before (24h) | 2 | 10 or more bad password / lockout failures, or failures from 3 or more countries |
| Risky sign-ins before (24h) | 2 | Any medium or high risk sign-in |
| Other alerts on the user (7d) | 2 | `SecurityAlert` entities matched on Entra object ID or `Name@UPNSuffix` |
| New IP | 1 | Not in the baseline and not a trusted egress IP |
| Unmanaged device | 1 | From `DeviceDetail.isManaged` |
| No sign-in context | 1 | No matching sign-in and no usable client IP in the audit event |
| No baseline | 1 | No successful sign-ins in the 13 days before. Dormant accounts get taken over a lot |
| Weak method from unmanaged device | 1 | Phone, SMS or OATH code added from an unmanaged device |
| Privileged account | 1 | Any assigned role in `IdentityInfo`, or matches the naming pattern |
| Method deleted and re-added | 1 | The victim's method is removed and a new one added |

The alert fires at a score of 4 or more and lists every signal that counted in `Reasons`, so the analyst can see why it fired straight away.

## Details
- Registrations are picked up by `ingestion_time()` in the last hour (going back up to a day on `TimeGenerated`), so AuditLogs events that arrive late still get checked.
- The sign-in behind the change is the last successful sign-in in the hour before the first change. The latest sign-in overall is often the new Authenticator app signing in for the first time, which tells you nothing about who made the change.
- The baseline is per user and ends where the earliest change starts, so the attacker's own sign-ins don't get counted as normal.
- Every flag is wrapped in `coalesce`. Without that, a user with no baseline would get a null score and the alert would silently disappear. With it, they get +1 for "No baseline".
- `BulkRolloutContext` says how many users registered FIDO2 keys or passkeys in the same window. During a passkey rollout the analyst can see right away that the alert is part of a wave.

## Tuning before enabling
| Parameter | What to set |
|---|---|
| `backendRanges` | Some self-service registrations log a Microsoft backend IP in `InitiatedBy.user.ipAddress`. Check your AuditLogs and add the ranges, or they'll show up as new IPs |
| `trustedIPs` | Corporate egress IPs |
| `allowedAdmins` | Helpdesk and IAM accounts that add methods for users |
| `internalDomains` | Your accepted mail domains |
| `privilegedPattern` | Admin and service account naming (only used when UEBA is off) |
| `scoreThreshold` | Backtest first. Run the query with `runEnd` set to past dates across the last 30 days, mark which results were real, and see where they land |

## Blind spots
- Quiet takeovers that score low. An attacker on a VPN in the user's own country, using a stolen session with no risk detections, adding Authenticator, scores 2 (new IP 1 + unmanaged 1). Lower the threshold for privileged accounts, or add a token replay signal (same session ID from a new ASN).
- `UpdateInboxRules` from the Outlook client often has empty `Parameters`, so rules made in the client aren't seen here. See [inbox-forwarding-external](../../collection/inbox-forwarding-external/).
- Changes made by an app through Graph, with no user as initiator, only score on the user's other signals.

## False positives
- Users setting up a new phone while travelling: new country 3 + unmanaged device 1 = 4. Check `UserAgent` and `DeviceOS` and ask the user. A quick call is the expected response.
- Helpdesk resets from accounts not yet in `allowedAdmins`.
- Passkey rollouts. Check `BulkRolloutContext`.

## Validation
In a test tenant, connect through a VPN in another country, use an unmanaged browser, sign in as a test user and add a phone number at mysignins.microsoft.com. Expect a score of 5 or more (new country 3, new IP 1, unmanaged 1, plus 1 for a weak method from an unmanaged device). To backtest, set `runEnd = datetime(...)` to a known past incident and check it scores above the threshold.

## Response
1. Contact the user another way, by Teams call or phone and not by email, and ask if they made the change.
2. If they didn't: delete the new method, revoke sessions and refresh tokens, reset the password, and check sign-ins from `ClientIP` for all users.
3. Check what the attacker already did: mailbox rules (`InboxRuleSample`), OAuth app consents, file downloads, and the other alerts in `PriorAlertNames`.
