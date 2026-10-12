# LLMjacking: AWS Bedrock recon and model-access abuse

| | |
|---|---|
| **Rule** | [`rule.yaml`](rule.yaml) · test: [`tests/fixtures/bedrock-llmjacking.kql`](../../../tests/fixtures/bedrock-llmjacking.kql) |
| **Data** | `AWSCloudTrail` |
| **ATT&CK** | T1496 Resource Hijacking, T1580 Cloud Infrastructure Discovery, T1562.008 Disable Cloud Logs, T1078.004 Cloud Accounts |
| **Severity** | Medium, High at score 8 or more |
| **Runs** | Hourly, 14-day query period |

## Goal
Catch stolen AWS credentials being used to run or resell LLM inference on Amazon Bedrock, known as LLMjacking. Attackers now also use the stolen model access to run their own AI tooling, and the bill can reach tens of thousands of dollars a day.

## How it works
LLMjacking follows a pattern that shows up in CloudTrail before the expensive part starts:

1. List what models are available (`ListFoundationModels`, `GetFoundationModelAvailability`, agreement offers).
2. Check if prompts are being logged (`GetModelInvocationLoggingConfiguration`). Normal apps almost never call this. Attackers do, so their prompts don't get recorded.
3. Test models with deliberately broken calls. A `ValidationException` or `AccessDeniedException` tells them which models the key can use without paying for a real answer.
4. Unlock models (`PutUseCaseForModelAccess`, `CreateFoundationModelAgreement`, `PutFoundationModelEntitlement`), create a Bedrock API key (IAM `CreateServiceSpecificCredential` for `bedrock.amazonaws.com`), or delete invocation logging.
5. Call lots of models in lots of regions.

Each step adds points, per identity per hour:

| Signal | Points |
|---|---|
| Invocation logging deleted | 4 |
| Model access enabled or agreement accepted | 3 |
| Bedrock API key created | 3 |
| Checked the logging configuration | 2 |
| Failing test calls across models | 2 |
| Identity hasn't used Bedrock in the last 13 days | 2 |
| New source IP for the identity | 1 |
| 3+ models called, 3+ list calls, 3+ regions, or a long-term IAM user key | 1 each |

The alert fires at 5 or more. Approved application roles are excluded completely.

## Technical context
- Bedrock Runtime calls (`InvokeModel`, `Converse` and the streaming versions) are management events in CloudTrail and are logged by default. Agent calls (`InvokeAgent`) are data events and need advanced event selectors.
- The events have `eventSource = bedrock.amazonaws.com`, and the model is in `requestParameters.modelId`.
- Stolen keys are usually IAM user access keys (`AKIA…`) from leaked repos, CI variables or compromised hosts, so a long-term key adds a point.

## Blind spots
- Trails that exclude read management events will miss the list and invoke calls. Check `ReadWriteType` on your trail.
- An attacker who already knows which models are enabled and calls them directly, from an identity that already uses Bedrock, will score low. Add an AWS Budgets or Cost Anomaly alert on Bedrock spend for that case.
- Model invocation logs (prompts and outputs) aren't used here. If you send them to Sentinel, machine-generated prompts and jailbreak preambles are a strong extra signal.

## False positives
- A developer starting a new GenAI project with a personal IAM user will score around 4 or 5 (first Bedrock use, list calls, new IP, IAM user). Check with them and move them to an approved role.
- Infrastructure-as-code enabling model access in a new account. Add the deployment role to `approvedIdentities`.

## Validation
- **Sample data:** `node tools/render-test.js bedrock-llmjacking` prints a query with sample CloudTrail rows and the rule together, which runs in any KQL editor without real data. Expected result: one row for `user/ci-deploy`, score 13, High.
- **Sandbox account:** using a test IAM user's key from a new IP, run `aws bedrock list-foundation-models`, `aws bedrock get-model-invocation-logging-configuration`, and an `aws bedrock-runtime invoke-model` with a bad body against two models.

## Response
1. Disable the access key or revoke the role's sessions right away. The cost goes up every minute.
2. Check `Operations` and `Regions`. Turn invocation logging back on if it was deleted, and remove any model access or Bedrock API keys the attacker set up.
3. Find where the key leaked from: git history, CI variables, container images, or the host it was issued to. Rotate everything stored with it.
4. Check the bill in Cost Explorer by service and region, and open a case with AWS if the charges are fraudulent.
