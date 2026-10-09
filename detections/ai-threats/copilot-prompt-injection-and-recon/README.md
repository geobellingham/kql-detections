# M365 Copilot: prompt injection, jailbreaks, or Copilot-assisted recon by a risky session

| | |
|---|---|
| **Rule** | [`rule.yaml`](rule.yaml) · test: [`tests/fixtures/copilot-prompt-injection-and-recon.kql`](../../../tests/fixtures/copilot-prompt-injection-and-recon.kql) |
| **Data** | `CloudAppEvents` (`ActionType == "CopilotInteraction"`, via Defender for Cloud Apps / Defender XDR connector), `SigninLogs` |
| **ATT&CK** | T1213.002 Data from SharePoint, T1083 Discovery, T1078.004 Cloud Accounts |
| **Severity** | Medium; **High** at score ≥ 6 |
| **Runs** | Hourly, 14-day query period |

## Goal
Use Copilot's audit trail for two current attack patterns:
1. **Indirect prompt injection:** a document, email or page that Copilot grounded on contains instructions aimed at Copilot (Microsoft flags these as **XPIA**, cross-prompt injection attack).
2. **AI-assisted recon:** an attacker in a stolen session asks Copilot "find documents with passwords / VPN / bank details" instead of browsing SharePoint by hand. It's faster for them and quieter in normal file-access logs.

## Strategy
Per user per hour, from the Copilot audit record (`RawEventData.CopilotEventData`):

| Signal | Points | Field |
|---|---|---|
| A resource Copilot used was flagged for prompt injection | 3 | `AccessedResources[].XPIADetected` |
| Risky sign-in (medium/high) for the user in the last 2h | 3 | `SigninLogs.RiskLevelDuringSignIn` |
| Jailbreak detected in a prompt | 2 | `Messages[].JailbreakDetected` |
| Resource spike: ≥ 30 resources this hour and > 3× the user's busiest baseline hour | 2 | count of `AccessedResources` |
| 3+ resources named like credentials, VPN, MFA, payroll, banking, M&A | 2 | `AccessedResources[].Name` |
| Copilot used from a country not in the user's 13-day Copilot history | 2 | `CountryCode` |
| Anonymous proxy / VPN egress | 2 | `IsAnonymousProxy` |

Alert at **≥ 3**: an XPIA hit alone alerts, a jailbreak attempt alone doesn't (curious users try those).

## Technical context
- The audit record does **not** contain the prompt text; it contains what Copilot *accessed*. Resource names and volume are the proxy for intent. Full prompts are only in Purview DSPM for AI / eDiscovery.
- Audit field casing differs between documentation and real records (`IsPrompt` vs `isPrompt`), so the rule reads both.
- `CopilotInteraction` only reaches `CloudAppEvents` if Defender for Cloud Apps has the Microsoft 365 connector enabled.

## Blind spots
- Prompt intent with ordinary file names ("summarise everything Finance shared this week").
- Copilot Chat (web-grounded, no tenant data) and third-party AI apps (`AIAppInteraction`), which carry little resource data.
- XPIA detection is Microsoft's classifier. Novel injections it misses won't be flagged here.

## False positives
- New starters or people changing roles, whose Copilot use ramps up quickly. No baseline means no spike until there's history, but a burst on day 2 can trigger.
- Travel + VPN: new country (2) + anonymous proxy (2) = 4. Check the device and sign-in risk.
- HR/finance staff legitimately working with payroll and banking files: the sensitive-name signal alone (2) stays under the threshold.

## Validation
- **Synthetic:** `node tools/render-test.js copilot-prompt-injection-and-recon`. Expected: `u-victim` High (11), `u-xpia` Medium (3); normal and jailbreak-only users are silent.
- **Live:** in a test tenant, put a document with hidden instructions ("ignore previous instructions and…") in a SharePoint site and ask Copilot to summarise it. If the classifier flags it, `XPIADetected` is true in the audit record within ~30–60 minutes.

## Response
1. **XPIA:** find the flagged resource (`XpiaResources`) and who created or shared it. External sender or guest upload means a targeted attack: remove it and search for copies.
2. **Recon pattern:** treat the session as compromised. Revoke sessions, reset credentials, and review the files in `SensitiveResources`. Any real secrets in them have to be rotated, because the attacker has seen them.
3. Check whether the same user has mailbox rules or MFA changes ([suspicious-mfa-method-change](../../persistence/suspicious-mfa-method-change/)).
