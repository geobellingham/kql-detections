# Password spray against Entra ID from a single IP

| | |
|---|---|
| **Rule** | [`rule.yaml`](rule.yaml) |
| **Data** | `SigninLogs` |
| **ATT&CK** | T1110.003 Password Spraying |
| **Severity** | Medium, or High when the spraying IP also has a successful sign-in |
| **Runs** | Hourly over 1 hour |

## Goal
Tell password sprays apart from everyday failed logins, and show which accounts the spray got into.

## How it works
A spray tries one or two passwords against a lot of accounts. A brute force tries a lot of passwords against one account. The rule looks at each source IP and measures which of the two it looks like:

- **FailedAccounts ≥ 15**: different accounts with a credential failure from that IP in the hour.
- **AttemptsPerAccount ≤ 3**: average failures per account. Anything higher looks like brute force, which smart lockout and other rules already deal with.
- Successful sign-ins (`ResultType 0`) from the same IP in the same hour go into `SuccessfulAccounts`, and the alert becomes High.

Failure codes used: `50126` (wrong username or password), `50053` (smart lockout or malicious IP block), `50055` (expired password) and `50056` (no stored password). They all mean the password was tested. MFA and Conditional Access failures are left out on purpose. Those mean the password was correct, which is a more serious problem for a different rule.

## Technical context
- A lot of sprays come in over legacy protocols. `ClientApps` will show "IMAP", "SMTP", "Authenticated SMTP" or "Exchange ActiveSync" if so. Blocking legacy auth with Conditional Access shuts that route.
- Attackers now rotate through residential proxies, so a single IP may only hit 3 to 5 accounts. See blind spots.

## Blind spots
- Distributed sprays with one attempt per IP across hundreds of IPs. Grouping by the shared `UserAgent` or by ASN would catch those, and it's a good next rule for this repo.
- Slow sprays spread over many hours. A 24-hour version with a higher account threshold helps.

## False positives
- Corporate NAT or VPN egress, where lots of users mistype passwords behind one IP. Exclude known egress IPs with a watchlist, or require `AttemptsPerAccount` close to 1.
- A misconfigured app or service account looping through a list of accounts, often an old SMTP relay. `UserAgents` and `Apps` usually show a single client.

## Validation
In a test tenant, script 20 sign-ins with one wrong password against 20 test users from one IP (for example with `MSOLSpray` in a lab), then one correct sign-in. You should get one alert with `PossibleCompromise = true`.

## Response
1. For each account in `SuccessfulAccounts`: revoke sessions, reset the password, and check for MFA methods or inbox rules added after the sign-in (see [inbox-forwarding-external](../../collection/inbox-forwarding-external/)).
2. Block the IP or ASN with Conditional Access named locations.
3. Work out where the target list came from, like a staff page on the website or a breach dump. The next spray will probably use the same list.
