# KQL Detections

Detection rules for Microsoft Sentinel and Defender XDR, kept as code. Each rule has a write-up in the [Alerting and Detection Strategy (ADS)](https://github.com/palantir/alerting-detection-strategy-framework) format covering what it's for, how it works, what it misses and what to do when it fires.

The rules are based on problems that come up in day-to-day SOC work: noisy rules that needed rethinking, gaps found during incidents, and attacks that a single-event rule won't catch. There's no client data or client-specific logic in here.

[![Validate detections](https://github.com/geobellingham/kql-detections/actions/workflows/validate.yml/badge.svg)](https://github.com/geobellingham/kql-detections/actions/workflows/validate.yml)

## Detections

| Detection | Data source | ATT&CK | How it works |
|---|---|---|---|
| [Leaver bulk download](detections/exfiltration/leaver-bulk-download/) | OfficeActivity + Leavers watchlist | T1530, T1213 | Compares each leaver with their own last 30 days |
| [SSH brute force → success](detections/credential-access/ssh-bruteforce-then-success/) | Syslog | T1110.001, T1078 | Alerts when a login succeeds from an IP that was just brute forcing |
| [Short-lived Linux account](detections/persistence/linux-short-lived-account/) | Syslog | T1136.001, T1070.009 | Account created and deleted within an hour, plus any SSH logins while it existed |
| [Suspicious MFA method change](detections/persistence/suspicious-mfa-method-change/) | AuditLogs + SigninLogs + OfficeActivity + SecurityAlert | T1098.005, T1556.006 | Risk score from 14 signals (new country, risky sign-in, spray before, inbox rules, other alerts…) with the reasons listed in the alert |
| [Entra ID password spray](detections/credential-access/entra-password-spray/) | SigninLogs | T1110.003 | Many accounts with 3 or fewer tries each from one IP, High if any of them signed in |
| [MFA fatigue](detections/credential-access/mfa-fatigue/) | SigninLogs | T1621 | Repeated MFA denials, and any approval that follows |
| [External mail forwarding](detections/collection/inbox-forwarding-external/) | OfficeActivity | T1114.003 | Parses inbox rule and mailbox parameters, splits recipients and checks the domains |
| [Firewall beaconing](detections/command-and-control/firewall-beaconing/) | CommonSecurityLog (FortiGate) | T1071, T1573 | Steady connection timing to a destination few other hosts talk to |
| [Executable from first-seen domain](detections/initial-access/zscaler-executable-from-new-domain/) | CommonSecurityLog (Zscaler) | T1189, T1204.002 | Executable downloads from domains nobody in the company has visited in 14 days |
| [LSASS memory dump](detections/credential-access/lsass-memory-dump/) | DeviceProcessEvents | T1003.001 | Each known dumping technique checked separately, with renamed tools caught by original file name |
| [Encoded PowerShell cradle](detections/execution/encoded-powershell-download-cradle/) | DeviceProcessEvents | T1059.001, T1027.010 | Decodes `-EncodedCommand` in the query and looks for download and IEX methods |
| [AWS logging tampering](detections/defense-evasion/aws-logging-tampering/) | AWSCloudTrail | T1562.008 | Lookup table of logging-related API calls with impact levels |
| [AWS IAM privilege escalation](detections/privilege-escalation/aws-iam-privilege-escalation/) | AWSCloudTrail | T1098.001, T1098.003 | Decodes policy documents and flags keys created for a different user |

### AI threats

Detections for attacks on and through AI systems. Each one has a test file with sample data.

| Detection | Data source | ATT&CK | How it works |
|---|---|---|---|
| [LLMjacking on AWS Bedrock](detections/ai-threats/bedrock-llmjacking/) | AWSCloudTrail | T1496, T1580, T1562.008 | Scores the usual LLMjacking steps: listing models, checking if prompts are logged, failing test calls, enabling model access, creating Bedrock API keys |
| [Azure OpenAI key theft & guardrail tampering](detections/ai-threats/azure-openai-key-abuse/) | AzureActivity + AzureDiagnostics | T1552, T1562, T1496 | Key reads by new identities and content filter changes, combined with request spikes from new IP ranges, per account |
| [AI coding agent hijack](detections/ai-threats/ai-coding-agent-hijack/) | DeviceProcessEvents | T1059, T1552.001, T1567 | Claude Code / Cursor / Copilot / Codex / Gemini CLI running commands that steal credentials or download and run code |
| [Copilot prompt injection & recon](detections/ai-threats/copilot-prompt-injection-and-recon/) | CloudAppEvents (CopilotInteraction) + SigninLogs | T1213.002, T1078.004 | Microsoft's prompt injection and jailbreak flags from the audit log, plus Copilot pulling unusual amounts of content for risky sessions |
| [Exposed self-hosted LLM servers](detections/ai-threats/exposed-llm-inference-server/) | CommonSecurityLog (FortiGate) | T1190, T1496 | Ollama / LM Studio / ComfyUI reachable from the internet, or internal hosts using someone else's |

### Hunting queries

| Query | Purpose |
|---|---|
| [Disabled accounts with prior bulk downloads](hunting/disabled-account-prior-downloads.kql) | Looks back at data downloaded in the 14 days before offboarding (no watchlist needed) |

## Repository layout

```
detections/<tactic>/<rule-name>/
    rule.yaml     Sentinel scheduled analytic rule (query, schedule, entities, ATT&CK, custom details)
    README.md     ADS write-up: goal, how it works, blind spots, false positives, validation, response
hunting/          Hunting queries
tests/            Sample data for each detection + regex tests
tools/            Validator, test renderer, table schemas
docs/             ADS template for new rules
```

## Validation

Every push runs [`tools/validate.js`](tools/validate.js) in GitHub Actions. It:

1. Checks each `rule.yaml` has the required Sentinel fields, a valid severity and a unique `id`, and that there's a README.
2. Parses and binds every query with Microsoft's KQL parser ([`Kusto.Language`](https://github.com/microsoft/Kusto-Query-Language)) against the table schemas in [`tools/schemas.json`](tools/schemas.json). This catches syntax errors, misspelled columns and type errors before a rule gets near a workspace.
3. For every detection with a file in [`tests/fixtures/`](tests/fixtures/), binds the rule against the sample tables in that file. This confirms the sample data has every column the rule needs. Each file says what result to expect in `// EXPECT:` lines.

[`tests/regex_test.py`](tests/regex_test.py) tests the regexes used in the rules (credential paths, download and execute, inference API paths…) against examples that should and shouldn't match.

### Running a detection on sample data

```bash
node tools/render-test.js bedrock-llmjacking
```

This prints a query with the sample rows and the rule together. It runs in any KQL editor without real data, for example a free [Azure Data Explorer cluster](https://dataexplorer.azure.com/freecluster), Sentinel Logs or Defender advanced hunting. Compare what you get with the `EXPECT` lines in the test file.

To run all the checks locally:

```bash
npm ci --prefix tools
node tools/validate.js
pip install pyyaml && python3 tests/regex_test.py
```

## Deploying to Sentinel

The `rule.yaml` files use the same format as the rules in [Azure/Azure-Sentinel](https://github.com/Azure/Azure-Sentinel/tree/master/Detections). To deploy them:

- **Sentinel Repositories** (Content management → Repositories): connect this repo or a fork and Sentinel deploys on every commit. Repositories needs ARM or Bicep, so convert the YAML first, for example with the `ConvertTo-ARM` approach from the Azure-Sentinel repo tooling.
- **Manually**: create a scheduled analytic rule and copy in the `query`, schedule, entity mappings and custom details.

Before turning a rule on, set the values at the top of the query for your environment (domain lists, allow-lists, thresholds). Each README says which ones matter.

## Roadmap

- Run the sample data tests in CI on a Kusto emulator (Kustainer) and check the `EXPECT` row counts
- Sample data tests for the first 13 detections
- Distributed password spray, grouped by user agent or ASN
- AiTM session theft: token replay from a new ASN right after MFA
- LSASS access through `OpenProcessApiCall`, which doesn't need a command line
- AWS escalation paths that use `PassRole`
- OAuth illicit consent grants

## License

MIT, see [LICENSE](LICENSE).
