# Distributed password spray against Entra ID

| | |
|---|---|
| **Rule** | [`rule.yaml`](rule.yaml) · test: [`tests/fixtures/entra-distributed-password-spray.kql`](../../../tests/fixtures/entra-distributed-password-spray.kql) |
| **Data** | `SigninLogs` (Microsoft Entra ID connector) |
| **ATT&CK** | T1110.003 Password Spraying, T1110.004 Credential Stuffing |
| **Severity** | Medium, High if one of the spraying IPs then signed in |
| **Runs** | Hourly, 14-day query period, judged over the last 24 hours |

## Goal
Catch the spray that the [single-IP rule](../entra-password-spray/) can't see. Spraying tools rotate through proxy pools so that each IP tries only a handful of accounts, and they spread the attempts over a day to stay under hourly thresholds.

## How it works
1. **Drop the IPs real users work from.** Any IP with a successful sign-in before the 24-hour window is ignored. This removes office NATs and home connections where people simply mistype.
2. **Group what's left by something the attacker can't easily vary.** Every remaining failure is counted in two groups: its user agent, and its ASN. A tool usually sends one fixed user agent through many proxies. A cheap proxy pool usually sits in one or two networks.
3. **Keep groups shaped like a spray:** 10 or more IPs, 25 or more accounts, at most 3 attempts per account (more is brute force) and at most 5 accounts per IP (more and the single-IP rule already fires).
4. **Compare with the group's own history.** The number of accounts must be at least 3 times the group's busiest day in the baseline. A large consumer ISP always has some failures, and this keeps it quiet.
5. **Look for a hit.** A successful sign-in from an IP that had already failed against two or more accounts raises the alert to High and lists the accounts.

Error codes counted: 50126 wrong password, 50053 locked or smart lockout, 50034 user doesn't exist, 50055 expired password, 50056 no password. A high `UnknownAccounts` number means the attacker is working from a guessed or outdated user list.

## Technical context
- Smart lockout tracks failures per account, and familiar locations are treated more leniently. A spray with one attempt per account from unfamiliar IPs triggers nothing on its own.
- An empty user agent is common for legacy protocols and scripted clients. It is grouped as `(empty)` and judged the same way.

## Blind spots
- A tool that rotates user agents and uses proxies spread over many networks. Neither group gets large enough. Lower `minAccounts` or add a third key, for example the target app.
- A fully distributed spray with one account per IP. The group is still detected, but a correct guess isn't marked as a compromise, because one failure followed by a success from one IP is what a typo looks like.
- Sprays from IPs your own users have signed in from, such as a shared VPN exit.
- Sprays against federated accounts, which fail at the identity provider and never reach `SigninLogs`.
- Small sprays under 25 accounts.

## False positives
- A password expiry wave or a broken app after a mass password change, if it comes from IPs with no earlier successful sign-in. Look at `Apps` and the error codes: expiry shows 50055.
- A new office, VPN exit or mobile carrier range going live. The IPs are unknown on day one and become known by the next day.
- While a spray runs, the rule fires again each hour, and the user-agent group and an ASN group can both fire for the same activity. Group alerts into one incident by IP entity.

## Validation
- **Sample data:** `node tools/render-test.js entra-distributed-password-spray`. Expected: one row grouped by user agent, 30 IPs, 60 accounts, High, with `user7@contoso.com` as the successful account.
- **Test tenant:** run a spraying tool with a fixed user agent through a pool of 10 or more proxies against 25 test accounts.

## Response
1. If `PossibleCompromise` is true, start with `SuccessfulAccounts`: revoke sessions, reset passwords, and check what the session did after the sign-in.
2. Check which targets exist. Accounts without MFA or with legacy protocols allowed are the ones the attacker needs.
3. Block the group where you can: a Conditional Access block for the user agent if it is distinctive, or for the ASNs or countries if your users never come from there. Blocking individual IPs doesn't last against a proxy pool.
4. Check the same user agent and ASNs against other sign-in sources, such as VPN and on-premises ADFS.
