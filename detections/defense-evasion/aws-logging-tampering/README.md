# AWS security logging disabled or tampered with

| | |
|---|---|
| **Rule** | [`rule.yaml`](rule.yaml) |
| **Data** | `AWSCloudTrail` (Sentinel AWS S3 connector) |
| **ATT&CK** | T1562.008 Impair Defenses: Disable or Modify Cloud Logs |
| **Severity** | High when a high-impact action succeeds, otherwise Medium |
| **Runs** | Hourly over 1 hour |

## Goal
Know immediately when someone blinds the AWS account: CloudTrail, GuardDuty or Config.

## Strategy
A lookup table (`datatable`) lists the API calls that reduce visibility, each with an impact level. Keeping the list in one place makes it easy to review and extend.

| Service | Calls |
|---|---|
| CloudTrail | `StopLogging`, `DeleteTrail`, `DeleteEventDataStore` (High); `UpdateTrail`, `PutEventSelectors` (Medium: can quietly drop data events or regions) |
| GuardDuty | `DeleteDetector`, `Disassociate…` (High); `UpdateDetector` **only when it sets enable=false**, `CreateFilter` **only with action ARCHIVE** (auto-suppressing findings), `DeletePublishingDestination` |
| Config | `StopConfigurationRecorder`, `DeleteConfigurationRecorder`, `DeleteDeliveryChannel` |

Events get grouped per identity + source IP, so an attacker turning off five things at once makes one alert listing all five. **Failed** calls (`ErrorCode` set, e.g. `AccessDenied`) are kept too, at Medium severity. Someone probing whether they're *allowed* to turn logging off is worth knowing about.

## Technical context
- `StopLogging` is ironically still logged: the call itself is recorded before the trail stops. An organisation trail, or a second trail in a separate logging account, keeps recording after a member-account trail is stopped. Recommend that architecture alongside this rule.
- `UserIdentityType` tells you whether it was an IAM user, an assumed role (`AssumedRole`, look at the session name in the ARN), or root.

## Blind spots
- Tampering with the **destination** instead of the trail: S3 bucket policy changes, lifecycle rules deleting logs, KMS key disablement. Extend the datatable with `PutBucketPolicy`/`PutBucketLifecycle` filtered on the log bucket, and `DisableKey`/`ScheduleKeyDeletion` on the trail key.
- Changes made in an account whose CloudTrail isn't ingested into Sentinel.
- Security Hub / Detective changes (not in scope yet).

## False positives
- Infrastructure-as-code pipelines (Terraform, CloudFormation) legitimately updating trails or detectors. `UserAgent` will show the tool and `UserIdentityArn` the pipeline role. Exclude that role, but only for the Medium-impact calls.
- Account decommissioning.

## Validation
In a sandbox AWS account: `aws cloudtrail stop-logging --name <trail>`, then `start-logging`. One High alert listing `StopLogging`.

## Response
1. Re-enable the logging right away.
2. Treat the identity as compromised unless a change ticket explains it: disable its access keys / revoke role sessions, and review everything it did in the hour before and after (from the organisation trail if the member trail was off).
3. Check for the next steps attackers usually take: new IAM users/keys ([aws-iam-privilege-escalation](../../privilege-escalation/aws-iam-privilege-escalation/)), new EC2 instances in unused regions, S3 data access.
