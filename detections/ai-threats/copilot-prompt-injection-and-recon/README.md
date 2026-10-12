# M365 Copilot: prompt injection, jailbreaks, or Copilot-assisted recon by a risky session

| | |
|---|---|
| **Rule** | [`rule.yaml`](rule.yaml) · test: [`tests/fixtures/copilot-prompt-injection-and-recon.kql`](../../../tests/fixtures/copilot-prompt-injection-and-recon.kql) |
| **Data** | `CloudAppEvents` (`ActionType == "CopilotInteraction"`, via Defender for Cloud Apps / Defender XDR connector), `SigninLogs` |
| **ATT&CK** | T1213.002 Data from SharePoint, T1083 Discovery, T1078.004 Cloud Accounts |
| **Severity** | Medium, High at score 6 or more |
| **Runs** | Hourly, 14-day query period |

## Goal
Use Copilot's audit log to catch two attacks:
1. **Indirect prompt injection.** A document, email or page Copilot used for its answer contains instructions aimed at Copilot. Microsoft flags these as XPIA (cross-prompt injection attack).
2. **Recon through Copilot.** Someone with a stolen session asks Copilot to find documents with passwords, VPN details or bank details. It's quicker for them than browsing SharePoint by hand and it looks quieter in the usual file-access logs.

## How it works
Per user per hour, from the Copilot audit record (`RawEventData.CopilotEventData`):

| Signal | Points | Field |
|---|---|---|
| A resource Copilot used was flagged for prompt injection | 3 | `AccessedResources[].XPIADetected` |
| Medium or high risk sign-in for the user in the last 2 hours | 3 | `SigninLogs.RiskLevelDuringSignIn` |
| Jailbreak detected in a prompt | 2 | `Messages[].JailbreakDetected` |
| Resource spike: 30+ resources this hour and more than 3 times the user's busiest baseline hour | 2 | count of `AccessedResources` |
| 3+ resources with names like credentials, VPN, MFA, payroll, banking or M&A | 2 | `AccessedResources[].Name` |
| Copilot used from a country that isn't in the user's last 13 days of Copilot use | 2 | `CountryCode` |
| Anonymous proxy or VPN | 2 | `IsAnonymousProxy` |

The alert fires at 3 or more. An XPIA hit on its own will alert. A jailbreak attempt on its own won't, because curious users try those all the time.

## Technical context
- The audit record doesn't have the prompt text. It lists what Copilot accessed, so resource names and volume are what the rule uses to guess intent. Full prompts are only in Purview DSPM for AI and eDiscovery.
- Field names don't always match the documentation (`IsPrompt` vs `isPrompt`), so the rule checks both.
- `CopilotInteraction` events only reach `CloudAppEvents` if Defender for Cloud Apps has the Microsoft 365 connector turned on.

## Blind spots
- Recon prompts that touch files with ordinary names, like "summarise everything Finance shared this week".
- Copilot Chat grounded only on the web, and third-party AI apps (`AIAppInteraction`). These have little resource data.
- XPIA detection depends on Microsoft's classifier. New injection tricks it misses won't be flagged.

## False positives
- New starters or people changing roles, whose Copilot use ramps up fast. There's no spike without some history, but a burst on day 2 can trigger it.
- Travel plus VPN: new country 2 + anonymous proxy 2 = 4. Check the device and the sign-in risk.
- HR and finance staff working with payroll and banking files. The sensitive names signal is only 2 points, so it can't fire by itself.

## Validation
- **Sample data:** `node tools/render-test.js copilot-prompt-injection-and-recon`. Expected result: `u-victim` High (11) and `u-xpia` Medium (3). The normal user and the jailbreak-only user don't show up.
- **Test tenant:** put a document with hidden instructions ("ignore previous instructions and…") on a SharePoint site and ask Copilot to summarise it. If the classifier flags it, `XPIADetected` is true in the audit record about 30 to 60 minutes later.

## Response
1. **XPIA:** find the flagged resource (`XpiaResources`) and who created or shared it. If it came from an outside sender or a guest upload, it's a targeted attack. Remove it and look for copies.
2. **Recon:** treat the session as compromised. Revoke sessions, reset credentials and go through the files in `SensitiveResources`. Any real secrets in them need rotating, because the attacker has seen them.
3. Check if the same user also has new mailbox rules or MFA changes (see [suspicious-mfa-method-change](../../persistence/suspicious-mfa-method-change/)).
