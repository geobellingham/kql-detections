# OAuth consent to a risky application

| | |
|---|---|
| **Rule** | [`rule.yaml`](rule.yaml) · test: [`tests/fixtures/oauth-illicit-consent.kql`](../../../tests/fixtures/oauth-illicit-consent.kql) |
| **Data** | `AuditLogs`, `SigninLogs` (Microsoft Entra ID connector) |
| **ATT&CK** | T1528 Steal Application Access Token, T1098 Account Manipulation |
| **Severity** | Medium, High at a score of 8 or more |
| **Runs** | Hourly, 14-day query period |

## Goal
Catch consent phishing. The victim is sent a real Microsoft consent prompt for an attacker's app and clicks Accept. No password is stolen and MFA is never challenged. The app gets a refresh token for the user's mail and files that keeps working after a password reset.

## How it works
Every `Consent to application` event in the last hour is parsed and scored. The granted scopes come from the `ConsentAction.Permissions` property, which reads `old grants => new grants`. Only the new side is used. One consent is logged once per resource API, so events are merged per user and app before scoring.

| Signal | Points | Why |
|---|---|---|
| Microsoft flagged or blocked the consent as risky | 5 | Risk-based step-up consent. Fires on its own, because the user clicked a phishing prompt even though it was stopped |
| Directory write scopes (`Directory.ReadWrite.All`, `RoleManagement.ReadWrite.Directory`…) | 3 | Tenant takeover |
| Mail scopes (`Mail.Read`, `Mail.Send`, `MailboxSettings.ReadWrite`…) | 2 | Mailbox theft and internal phishing |
| File, site or chat scopes (`Files.ReadWrite.All`, `Sites.Read.All`, `Chat.Read`…) | 2 | Data theft |
| App's service principal appeared in the tenant in the last 7 days | 2 | Phishing apps are new. Apps the tenant has used for months aren't |
| Granted for all users, with one of the scopes above | 2 | A compromised admin handing an app the whole tenant |
| `offline_access` together with one of the scopes above | 1 | Refresh token, so access outlives the session |
| Consented by a user, with one of the scopes above | 1 | Admin consent usually goes through a review |
| App name imitates a brand or lure (OneDrive, DocuSign, "secure", "upgrade"…) | 1 | Common in consent phishing |
| Consent came from an IP the user hasn't signed in from in 13 days | 1 | |

The alert fires at 5. A user granting mail access to a brand-new app scores 6. The same grant to an app that has been in the tenant for months scores 4 and stays quiet.

## Technical context
- A phishing app has no app registration in your tenant. The first consent creates its service principal, which is why `Add service principal` just before the consent is a good "new app" marker.
- When risk-based step-up consent stops a user consent, the event is logged with `Result = failure` and a `ResultReason` naming the risky-app exception. The rule keeps those events and marks them `Blocked`.
- Application permissions granted by an admin show up as `Add app role assignment to service principal`, which this rule doesn't read. See blind spots.

## Blind spots
- Tenants where user consent is turned off never log a user consent. That is the better control. The rule then only sees admin consents.
- App-only (application) permissions added directly to a service principal.
- An existing, trusted app whose publisher is compromised. Nothing changes in your tenant.
- Device code phishing and AiTM, which steal tokens for first-party apps with no consent event. The [session replay rule](../aitm-session-replay/) covers part of that.
- Apps older than the 14-day query period look "not new" even if only one person ever used them.

## False positives
- A real SaaS product being rolled out: new app, mail or file scopes, often consented tenant-wide by an admin. Add it to `allowedApps` once reviewed.
- Mail clients and note-taking tools that users connect themselves. If these are common in your tenant, raise `scoreThreshold` to 6 or restrict user consent to verified publishers.

## Validation
- **Sample data:** `node tools/render-test.js oauth-illicit-consent`. Expected: two rows, `alice` (score 8) and `carol` (score 10, blocked). `bob` and `dave` don't show up.
- **Test tenant:** register a multi-tenant app in a second tenant, request `Mail.Read offline_access`, and consent to it as a normal user in the test tenant.

## Response
1. Open the app under Enterprise applications. Check the publisher, the reply URLs and who else consented (`PriorConsenters`).
2. If it isn't a known product, disable the service principal first, then revoke its grants (`Remove-MgOauth2PermissionGrant`) and the user's refresh tokens.
3. Check what the app did: `MailItemsAccessed` and file downloads in `OfficeActivity` or `CloudAppEvents` filtered on the app's ID.
4. Find the phishing mail and who else received it. Other recipients may have consented outside this run's window.
5. A blocked consent still means the user clicked. Treat it as a reported phish and look for the same sender across mailboxes.
