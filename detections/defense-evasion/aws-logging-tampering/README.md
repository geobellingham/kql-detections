# AWS security logging disabled or tampered with

| | |
|---|---|
| **Rule** | [`rule.yaml`](rule.yaml) |
| **Data** | `AWSCloudTrail` (Sentinel AWS S3 connector) |
| **ATT&CK** | T1562.008 Impair Defenses: Disable or Modify Cloud Logs |
| **Severity** | High when a high-impact action succeeds, otherwise Medium |
| **Runs** | Hourly over 1 hour |

## Goal
Know straight away when someone turns off CloudTrail, GuardDuty or Config in an AWS account.

## How it works
A small lookup table (`datatable`) lists the API calls that reduce visibility, each with an impact level. Keeping them in one table makes them easy to review and add to.

| Service | Calls |
|---|---|
| CloudTrail | `StopLogging`, `DeleteTrail`, `DeleteEventDataStore` (High); `UpdateTrail`, `PutEventSelectors` (Medium, they can quietly drop data events or regions) |
| GuardDuty | `DeleteDetector`, `Disassociate…` (High); `UpdateDetector` only when it sets enable=false, `CreateFilter` only with action ARCHIVE (auto-archiving findings), `DeletePublishingDestination` |
| Config | `StopConfigurationRecorder`, `DeleteConfigurationRecorder`, `DeleteDeliveryChannel` |

Events are grouped by identity and source IP. If an attacker turns off five things at once, you get one alert that lists all five. Failed calls (where `ErrorCode` is set, e.g. `AccessDenied`) are kept as well, at Medium. Someone testing whether they're allowed to turn logging off is worth knowing about.

## Technical context
- `StopLogging` itself still gets logged, because the call is recorded before the trail stops. An organisation trail, or a second trail in a separate logging account, keeps recording after a member account's trail is stopped. It's worth recommending that setup alongside this rule.
- `UserIdentityType` tells you if it was an IAM user, an assumed role (`AssumedRole`, the session name is in the ARN) or root.

## Blind spots
- Tampering with where the logs go: S3 bucket policy changes, lifecycle rules that delete logs, disabling the KMS key. You can add `PutBucketPolicy`/`PutBucketLifecycle` on the log bucket and `DisableKey`/`ScheduleKeyDeletion` on the trail key to the table.
- Changes in accounts whose CloudTrail isn't sent to Sentinel.
- Security Hub and Detective changes, which aren't covered yet.

## False positives
- Infrastructure-as-code pipelines (Terraform, CloudFormation) updating trails or detectors. `UserAgent` shows the tool and `UserIdentityArn` the pipeline role. Exclude that role, but only for the Medium-impact calls.
- Accounts being decommissioned.

## Validation
In a sandbox AWS account, run `aws cloudtrail stop-logging --name <trail>`, then `start-logging`. You should get one High alert listing `StopLogging`.

## Response
1. Turn the logging back on straight away.
2. Treat the identity as compromised unless there's a change ticket for it. Disable its access keys or revoke the role sessions, and go through everything it did in the hour before and after, using the organisation trail if the member trail was off.
3. Look for what attackers usually do next: new IAM users or keys (see [aws-iam-privilege-escalation](../../privilege-escalation/aws-iam-privilege-escalation/)), new EC2 instances in regions you don't use, S3 data access.
