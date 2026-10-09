# LLMjacking: AWS Bedrock recon and model-access abuse

| | |
|---|---|
| **Rule** | [`rule.yaml`](rule.yaml) · test: [`tests/fixtures/bedrock-llmjacking.kql`](../../../tests/fixtures/bedrock-llmjacking.kql) |
| **Data** | `AWSCloudTrail` |
| **ATT&CK** | T1496 Resource Hijacking, T1580 Cloud Infrastructure Discovery, T1562.008 Disable Cloud Logs, T1078.004 Cloud Accounts |
| **Severity** | Medium; **High** at score ≥ 8 |
| **Runs** | Hourly, 14-day query period |

## Goal
Catch stolen AWS credentials being used to run, or resell, LLM inference on Amazon Bedrock: "LLMjacking". By 2026 it's no longer just cost theft. Hijacked model access powers attackers' own agentic tooling, and the bill can reach tens of thousands of dollars a day.

## Strategy
The LLMjacking playbook leaves a clear CloudTrail trail **before** the expensive part starts:

1. **Enumerate** what's available (`ListFoundationModels`, `GetFoundationModelAvailability`, agreement offers).
2. **Check whether prompts are being logged** (`GetModelInvocationLoggingConfiguration`). Legitimate apps almost never call this; attackers do, because they don't want their prompts recorded.
3. **Probe** models with deliberately invalid calls. `ValidationException` / `AccessDeniedException` responses reveal which models the key can reach without paying for a real completion.
4. **Unlock** models (`PutUseCaseForModelAccess`, `CreateFoundationModelAgreement`, `PutFoundationModelEntitlement`), create a **Bedrock API key** (IAM `CreateServiceSpecificCredential` for `bedrock.amazonaws.com`), or **delete invocation logging**.
5. Invoke across many models and regions.

Each step adds points, per identity per hour:

| Signal | Points |
|---|---|
| Invocation logging deleted | 4 |
| Model access enabled / agreement accepted | 3 |
| Bedrock API key created | 3 |
| Checked logging configuration | 2 |
| Failing invoke probes across models | 2 |
| Identity never used Bedrock in 13 days | 2 |
| New source IP for the identity | 1 |
| 3+ models invoked · enumeration (3+ recon calls) · 3+ regions · long-term IAM user key | 1 each |

Alert at **≥ 5**. Approved application roles are excluded entirely.

## Technical context
- Bedrock Runtime calls (`InvokeModel`, `Converse` and their streaming variants) are **management events** in CloudTrail and logged by default. Agent invocations (`InvokeAgent`) are data events and need advanced event selectors.
- Calls are logged with `eventSource = bedrock.amazonaws.com`, and the model is in `requestParameters.modelId`.
- Stolen keys are usually **IAM user access keys** (`AKIA…`) from leaked repos, CI variables or compromised hosts. That's why a long-term key adds a point.

## Blind spots
- Trails that exclude **read** management events miss the recon and invoke calls. Check `ReadWriteType` on your trail.
- An attacker who already knows which models are enabled and invokes directly, from an identity that already uses Bedrock, scores low. Pair this with an AWS Budgets / Cost Anomaly alert on Bedrock spend.
- Model invocation logs (prompts and outputs) aren't used here. If you ship them to Sentinel, prompt patterns (machine-generated, jailbreak preambles) are a strong extra signal.

## False positives
- A developer starting a new GenAI project with a personal IAM user scores around 4–5 (first-time Bedrock, enumeration, new IP, IAM user). Check with the user, and move them onto an approved role.
- Infrastructure-as-code runs that enable model access for a new account. Add the deployment role to `approvedIdentities`.

## Validation
- **Synthetic:** `node tools/render-test.js bedrock-llmjacking` prints a self-contained query (sample CloudTrail rows plus the rule) that runs in any KQL editor without real data. Expected: one row for `user/ci-deploy`, score 13, High.
- **Live, sandbox account:** with a test IAM user's key, from a new IP, run `aws bedrock list-foundation-models`, `aws bedrock get-model-invocation-logging-configuration`, and an `aws bedrock-runtime invoke-model` with a bad body against two models.

## Response
1. Deactivate the access key, or revoke the role's sessions, **immediately**: spend grows by the minute.
2. Check `Operations` and `Regions`. Re-enable invocation logging if it was deleted, and remove any model access or Bedrock API keys the attacker created.
3. Find where the key leaked: git history, CI variables, container images, the host it was issued to. Rotate everything stored alongside it.
4. Review the bill (Cost Explorer by service and region) and open a case with AWS if charges are fraudulent.
