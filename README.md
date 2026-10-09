# KQL Detections

Detection rules for **Microsoft Sentinel** and **Defender XDR**, written as code. Each rule comes with a full write-up in the [Alerting and Detection Strategy (ADS)](https://github.com/palantir/alerting-detection-strategy-framework) format: why it exists, how it works, what it misses, and how to respond.

The rules are generalised from detection problems that come up in day-to-day SOC work: noisy rules that needed re-thinking, gaps found during incidents, and attacker behaviour that single-event rules miss. No client data or client-specific logic is included.

[![Validate detections](https://github.com/geobellingham/kql-detections/actions/workflows/validate.yml/badge.svg)](https://github.com/geobellingham/kql-detections/actions/workflows/validate.yml)

## Detections

| Detection | Data source | ATT&CK | What makes it work |
|---|---|---|---|
| [Leaver bulk download](detections/exfiltration/leaver-bulk-download/) | OfficeActivity + Leavers watchlist | T1530, T1213 | Compares each leaver to **their own** 30-day baseline, not a global threshold |
| [SSH brute force → success](detections/credential-access/ssh-bruteforce-then-success/) | Syslog | T1110.001, T1078 | Alerts on the *success* after a failure burst, not the noise |
| [Short-lived Linux account](detections/persistence/linux-short-lived-account/) | Syslog | T1136.001, T1070.009 | Create + delete within 1h, plus SSH logins during the account's lifetime |
| [Entra ID password spray](detections/credential-access/entra-password-spray/) | SigninLogs | T1110.003 | Wide-and-shallow shape (many accounts, ≤3 tries each); escalates on any success |
| [MFA fatigue](detections/credential-access/mfa-fatigue/) | SigninLogs | T1621 | Repeated denials, then flags an approval that follows |
| [External mail forwarding](detections/collection/inbox-forwarding-external/) | OfficeActivity | T1114.003 | Parses inbox-rule and mailbox parameters, splits recipients, checks domains |
| [Firewall beaconing](detections/command-and-control/firewall-beaconing/) | CommonSecurityLog (FortiGate) | T1071, T1573 | Gap jitter (stdev/mean) **and** destination rarity across the estate |
| [Executable from first-seen domain](detections/initial-access/zscaler-executable-from-new-domain/) | CommonSecurityLog (Zscaler) | T1189, T1204.002 | Org-wide 14-day domain history via `leftanti` join |
| [LSASS memory dump](detections/credential-access/lsass-memory-dump/) | DeviceProcessEvents | T1003.001 | Technique-labelled branches; original-file-name matching catches renamed tools |
| [Encoded PowerShell cradle](detections/execution/encoded-powershell-download-cradle/) | DeviceProcessEvents | T1059.001, T1027.010 | **Decodes** `-EncodedCommand` in the query, then looks for download/IEX primitives |
| [AWS logging tampering](detections/defense-evasion/aws-logging-tampering/) | AWSCloudTrail | T1562.008 | Lookup table of tamper calls with impact levels; parameter-aware filtering |
| [AWS IAM privilege escalation](detections/privilege-escalation/aws-iam-privilege-escalation/) | AWSCloudTrail | T1098.001, T1098.003 | Decodes policy documents; separates "my key" from "a key for someone else" |

**Hunting queries**

| Query | Purpose |
|---|---|
| [Disabled accounts with prior bulk downloads](hunting/disabled-account-prior-downloads.kql) | Retro hunt for data taken in the 14 days before offboarding (no watchlist needed) |

## Repository layout

```
detections/<tactic>/<rule-name>/
    rule.yaml     Sentinel scheduled analytic rule (query, schedule, entities, ATT&CK, custom details)
    README.md     ADS write-up: goal, strategy, blind spots, false positives, validation, response
hunting/          Ad-hoc hunting queries
tools/            Validator + table schemas
docs/             ADS template for new rules
```

## Validation

Every push runs [`tools/validate.js`](tools/validate.js) in GitHub Actions. It:

1. checks each `rule.yaml` has the required Sentinel fields, a valid severity and a unique `id`, and that the README write-up exists;
2. parses **and binds** every query with Microsoft's own KQL parser ([`Kusto.Language`](https://github.com/microsoft/Kusto-Query-Language)) against the table schemas in [`tools/schemas.json`](tools/schemas.json). That catches syntax errors, misspelled columns, and type errors before a rule ever reaches a workspace.

Run it locally:

```bash
npm ci --prefix tools
node tools/validate.js
```

## Deploying to Sentinel

The `rule.yaml` files use the same schema as the rules in [Azure/Azure-Sentinel](https://github.com/Azure/Azure-Sentinel/tree/master/Detections). To deploy:

- **Sentinel Repositories** (Content management → Repositories): connect this repo, or a fork, and Sentinel deploys on each commit. Repositories expects ARM/Bicep, so convert the YAML first (for example with the `ConvertTo-ARM` approach used in the Azure-Sentinel repo tooling).
- **Manually**: create a scheduled analytic rule and copy the `query`, schedule, entity mappings and custom details.

Before enabling, set the environment-specific values at the top of each query (domain lists, allow-lists, thresholds). Each README says which ones matter.

## Roadmap

- Distributed password spray (grouped by user agent / ASN instead of IP)
- AiTM session theft: token replay from a new ASN right after MFA
- LSASS access via `OpenProcessApiCall` (no command line needed)
- AWS `PassRole`-based escalation paths
- OAuth illicit consent grants
- Unit-test style validation: run each query against small synthetic datasets with `datatable`

## License

MIT, see [LICENSE](LICENSE).
