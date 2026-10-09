# Password spray against Entra ID from a single IP

| | |
|---|---|
| **Rule** | [`rule.yaml`](rule.yaml) |
| **Data** | `SigninLogs` |
| **ATT&CK** | T1110.003 Password Spraying |
| **Severity** | Medium, or **High** when the spraying IP also has a successful sign-in |
| **Runs** | Hourly over 1 hour |

## Goal
Separate password spraying from ordinary failed logins, and surface the accounts that fell to it.

## Strategy
A spray is *wide and shallow*: many accounts, one or two attempts each. Brute force is *narrow and deep*. The rule measures the shape per source IP:

- **FailedAccounts ≥ 15**: distinct accounts with a credential failure from the IP in the hour.
- **AttemptsPerAccount ≤ 3**: average failures per account. Above that it's brute force, which smart lockout and other rules handle.
- Successful sign-ins (`ResultType 0`) from the same IP in the same window are collected into `SuccessfulAccounts`, and severity goes up to High.

Failure codes used: `50126` (bad username/password), `50053` (smart lockout or malicious-IP block), `50055` (expired password), `50056` (no stored password). They are the codes that mean "the credential was tested". MFA and Conditional Access failures are left out on purpose: those mean the password was **right**, which belongs to a different, higher-severity story.

## Technical context
- Many sprays come through legacy protocols. `ClientApps` shows "IMAP", "SMTP", "Authenticated SMTP" or "Exchange ActiveSync" when that's the route, and blocking legacy auth with Conditional Access closes it.
- Sprayers increasingly rotate through residential proxies, so one IP may only see 3–5 accounts. See blind spots.

## Blind spots
- Distributed sprays (one attempt per IP across hundreds of IPs). Catch those by grouping on the shared `UserAgent` or on ASN instead of IP. A good next rule for this repo.
- Low-and-slow sprays spread over many hours. Run a 24h variant with a higher account threshold.

## False positives
- Corporate NAT / VPN egress: many users mistyping passwords behind one IP. Exclude known egress IPs with a watchlist, or require `AttemptsPerAccount` close to 1.
- A misconfigured app or service account looping through a list of accounts (old SMTP relay configs). `UserAgents` and `Apps` usually show a single client.

## Validation
In a test tenant, script 20 sign-ins with one wrong password across 20 test users from one IP (for example with `MSOLSpray` in a lab), then one correct sign-in. One alert, `PossibleCompromise = true`.

## Response
1. For every account in `SuccessfulAccounts`: revoke sessions, reset the password, and check for new MFA methods or inbox rules registered after the sign-in ([inbox-forwarding-external](../../collection/inbox-forwarding-external/)).
2. Block the IP / ASN at Conditional Access named locations.
3. Check whether the targets came from a public source (website staff page, a breach list). That predicts the next spray.
