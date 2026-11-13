# Sign-in session used from a second network (AiTM / token replay)

| | |
|---|---|
| **Rule** | [`rule.yaml`](rule.yaml) · test: [`tests/fixtures/aitm-session-replay.kql`](../../../tests/fixtures/aitm-session-replay.kql) |
| **Data** | `SigninLogs`, `AADNonInteractiveUserSignInLogs` (Microsoft Entra ID connector) |
| **ATT&CK** | T1557 Adversary-in-the-Middle, T1539 Steal Web Session Cookie, T1550.004 Web Session Cookie |
| **Severity** | Medium, High at a score of 7 or more when the client itself also changed |
| **Runs** | Hourly, 14-day query period |

## Goal
Catch a stolen session being used. AiTM phishing kits and infostealers take the session cookie after MFA has already been passed, so there is no failed sign-in and no MFA prompt to alert on. What does show up is one session appearing from two networks.

## How it works
1. Successful sign-ins from both tables are reduced to user, `SessionId`, IP, ASN, country, user agent and app. Sign-ins from `trustedASNs` are dropped.
2. Sessions from the last 24 hours that were seen from more than one ASN are kept. The first sign-in of the session defines the "first" network.
3. The earliest sign-in from a different ASN is the "second" network. The rule alerts once, in the run where that second network first appears.
4. Both networks are compared with the ASNs and countries the user worked from in the 13 days before.

| Signal | Points | Why |
|---|---|---|
| Second network is new for the user | 2 | |
| Country changed within 2 hours | 2 | Too fast to be travel |
| Either network is a hosting provider | 2 | Phishing proxies and replay tooling run on VPS providers |
| The first network kept using the session afterwards | 2 | Two places using one session at once. Typical for cookie theft, where the victim keeps working |
| The session also started on a network new for the user | 1 | With AiTM the proxy signs in, so the victim's real network never appears |
| Country is new for the user | 1 | |
| User agent changed | 1 | |
| The second network went to mail, the portal or security info | 1 | |

The alert fires at 5.

ASNs are compared instead of IPs because one device changes IP all the time (IPv4 and IPv6, carrier NAT) while staying on the same network.

## Technical context
- `SessionId` ties interactive sign-ins and later token refreshes to one browser or app session. A replayed cookie or refresh token keeps the SessionId.
- With an AiTM kit such as Evilginx, Entra ID only ever sees the proxy. The "first" network is the phishing server and the "second" is wherever the attacker replays the cookie from. Both are new for the user.
- With an infostealer, the first network is the user's own and the attacker's is the second. The user keeps working, which gives the "kept using the session" signal.
- `hostingASNs` is a short starter list. It is only worth 2 points and is easy to extend.

## Blind spots
- Replay from the same ASN as the victim, for example a residential proxy at the same ISP.
- Token theft where the attacker redeems a fresh session and gets a new SessionId. Device code phishing looks like this.
- Sign-ins with an empty `SessionId` or ASN.
- Sessions that started more than 24 hours before the replay. Raise `sessionWindow` at the cost of a larger query.
- Users with no sign-ins in the baseline get no "new network" points, so only fast country change, hosting, concurrent use, user agent and app can add up.

## False positives
- **Personal VPN switched on mid-session.** New ASN, new country, fast switch, often a hosting ASN. This is the main one. The user agent stays the same, which is why High also needs a changed user agent or a new first network. If staff commonly use a VPN product, add its ASNs to `trustedASNs`.
- **Corporate VPN or secure web gateway** not yet in `trustedASNs`. Add your egress ASNs before enabling the rule.
- **Roaming between Wi-Fi and a mobile carrier** the user hasn't used in two weeks. Scores 2 or 3 and stays quiet unless something else adds up.

## Validation
- **Sample data:** `node tools/render-test.js aitm-session-replay`. Expected: one row for `dana`, score 10, High. `erin` (home to mobile) and `frank` (travel, score 4) don't show up.
- **Test tenant:** sign in to `office.com` in a browser, export the `ESTSAUTH` cookies, import them into a browser on a VPS or behind a VPN in another country and open Outlook on the web.

## Response
1. Revoke the user's sessions (`Revoke-MgUserSignInSession`) and reset the password. The attacker has passed MFA already, so the reset alone doesn't end the session.
2. Check what the second network did with the session: new MFA methods (the [MFA method change rule](../../persistence/suspicious-mfa-method-change/)), inbox rules (the [mail forwarding rule](../../collection/inbox-forwarding-external/)), `MailItemsAccessed`, file downloads, OAuth consents.
3. Find the phishing mail or the infected device. For AiTM, search URL click events for the first network's IP or domain and check which other users signed in from the same IP.
4. If the first network is the user's own, treat the device as compromised (infostealer) until proven otherwise.
