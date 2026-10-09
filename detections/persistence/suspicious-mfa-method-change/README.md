# Suspicious MFA / security info change (risk-scored)

| | |
|---|---|
| **Rule** | [`rule.yaml`](rule.yaml) |
| **Data** | `AuditLogs`, `SigninLogs`, `OfficeActivity`, `SecurityAlert`; `IdentityInfo` optional (UEBA) |
| **ATT&CK** | T1098.005 Device Registration, T1556.006 Modify Authentication Process: MFA |
| **Severity** | Medium; **High** at score ≥ 7 |
| **Runs** | Hourly, 14-day query period |

## Goal
Catch attackers adding their own MFA method after stealing a session or password, without alerting on every phone change in the company.

## Why a score
Security-info changes happen all day: new phones, passkey rollouts, helpdesk resets. A single-signal rule ("method registered from a new IP") is either too noisy to keep enabled or too narrow to catch anything. This rule collects the context an analyst would look up by hand and **adds it up**:

| Signal | Points | How |
|---|---|---|
| New country | 3 | Country of the sign-in behind the change isn't in the user's 13-day baseline |
| Risky sign-in at registration | 3 | That sign-in had medium/high Entra ID Protection risk |
| External forward / delete inbox rule (24h) | 3 | `New/Set-InboxRule`, `Set-Mailbox` with forwarding to a non-internal domain, or `DeleteMessage=True` |
| Method changed by another account | 2 | Initiator ≠ target and not in `allowedAdmins` |
| Spray / brute force before (24h) | 2 | ≥ 10 bad-password/lockout failures, or failures from ≥ 3 countries |
| Risky sign-ins before (24h) | 2 | Any medium/high risk sign-in |
| Other alerts on the user (7d) | 2 | `SecurityAlert` entities matched on Entra object ID or `Name@UPNSuffix` |
| New IP | 1 | Not in baseline and not a trusted egress IP |
| Unmanaged device | 1 | From `DeviceDetail.isManaged` |
| No sign-in context | 1 | Neither a matching sign-in nor a usable client IP in the audit event |
| No baseline | 1 | No successful sign-ins in the 13 days before. Dormant accounts are a favourite target |
| Weak method from unmanaged device | 1 | Phone/SMS/OATH code added from an unmanaged device |
| Privileged account | 1 | Any assigned role in `IdentityInfo`, or the naming pattern |
| Method deleted and re-added | 1 | Swap pattern: remove the victim's method, add the attacker's |

The alert fires at **score ≥ 4** and lists every signal in `Reasons`, so triage starts from the explanation, not from the raw query.

## Strategy details
- **Ingestion-time selection.** Registrations are picked up by `ingestion_time()` in the last hour (with `TimeGenerated` up to 1 day back), so late-arriving AuditLogs events aren't skipped between runs.
- **The sign-in behind the change** is the **last successful sign-in in the hour before the first change**. Taking the latest sign-in *overall* would often pick the new Authenticator app's own first sign-in, which says nothing about who made the change.
- **Baseline** is per user and ends where the earliest change starts, so the attacker's own sign-ins never become "known".
- **Null-safe scoring.** Every flag is `coalesce`d. A user with no baseline (no matching row in a left join) gets +1 for "No baseline" instead of a null score that silently drops the alert.
- **`BulkRolloutContext`** says how many users registered FIDO2/passkeys in the same window. During a passkey rollout, an analyst sees immediately that the alert is part of a wave.

## Tuning before enabling
| Parameter | What to set |
|---|---|
| `backendRanges` | Some self-service registrations log a Microsoft backend IP as `InitiatedBy.user.ipAddress`. Look at your AuditLogs and add the ranges, otherwise they show up as "new IP" |
| `trustedIPs` | Corporate egress IPs |
| `allowedAdmins` | Helpdesk / IAM accounts that legitimately add methods for users |
| `internalDomains` | Accepted mail domains |
| `privilegedPattern` | Admin / service account naming (only used when UEBA isn't on) |
| `scoreThreshold` | **Backtest first.** Run the query with `runEnd` set to past dates over the last 30 days, label the results, and see where true positives land |

## Blind spots
- **Quiet takeovers that score low.** An attacker on a VPN in the user's own country, on a stolen session without risk detections, adding Authenticator: New IP (1) + Unmanaged (1) = 2. Lower the threshold for privileged accounts, or add a token-replay signal (same session ID from a new ASN).
- `UpdateInboxRules` from the Outlook client often has empty `Parameters`, so client-side rules aren't seen here. See [inbox-forwarding-external](../../collection/inbox-forwarding-external/).
- Changes through Graph API by an app (no user initiator) score only on the user's other signals.

## False positives
- Users setting up a new phone while travelling: new country + unmanaged device = 4. Look at `UserAgent`/`DeviceOS` and ask the user. A short check-in call is the intended response.
- Helpdesk resets from accounts not yet in `allowedAdmins`.
- Passkey rollouts: check `BulkRolloutContext`.

## Validation
In a test tenant: from a VPN exit in a different country, on an unmanaged browser, sign in as a test user and add a phone number at mysignins.microsoft.com. Expected: score ≥ 5 (New country 3 + New IP 1 + Unmanaged 1, +1 weak method from unmanaged device). For the backtest, set `runEnd = datetime(...)` to a known past incident and confirm it scores above the threshold.

## Response
1. Contact the user out of band (Teams call or phone, **not** email). Did they make this change?
2. If not: delete the new method, revoke sessions and refresh tokens, reset the password, and review sign-ins from `ClientIP` across all users.
3. Check what the attacker already did: mailbox rules (`InboxRuleSample`), OAuth app consents, file downloads, and any other alerts listed in `PriorAlertNames`.
