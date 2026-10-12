# AWS IAM privilege escalation or credentials for another identity

| | |
|---|---|
| **Rule** | [`rule.yaml`](rule.yaml) |
| **Data** | `AWSCloudTrail` |
| **ATT&CK** | T1098.001 Additional Cloud Credentials, T1098.003 Additional Cloud Roles, T1078.004 Cloud Accounts |
| **Severity** | High (Medium for a plain trust-policy change) |
| **Runs** | Hourly over 1 hour |

## Goal
Catch the IAM calls that turn a small foothold into control of the whole account, or plant credentials for later.

## How it works
Most IAM write calls are routine, so the rule only alerts on specific patterns, and `Reason` says which one:

| Reason | Logic |
|---|---|
| Attached AdministratorAccess / IAMFullAccess | that managed policy ARN on `Attach{User,Role,Group}Policy` |
| Inline policy allowing Action * | `Put{User,Role,Group}Policy` where the URL-decoded document has `"Effect":"Allow"` and `"Action":"*"` (string or array) |
| Role trust policy opened to any AWS principal | `UpdateAssumeRolePolicy` with `"AWS":"*"` |
| Role trust policy changed | any other `UpdateAssumeRolePolicy` (Medium, often used to add an outside account as a backdoor) |
| CreateAccessKey / CreateLoginProfile / UpdateLoginProfile for another user | the target `userName` is someone other than the caller. Creating keys for yourself is normal. Creating them for another user is a common way to keep access |
| User added to admin group | `AddUserToGroup` where the group name contains "admin" |

Only successful calls count (`ErrorCode` is empty). Approved IaC and break-glass roles are excluded with `approvedIamAdmins`.

## Technical context
- `policyDocument` in `RequestParameters` is URL-encoded, so it gets `url_decode()`d before the regex runs.
- The caller name comes from `UserIdentityUserName` for IAM users and from the session part of the ARN for assumed roles. Comparing it with `userName` tells you whether someone made a key for themselves or for another user.
- `SessionMfaAuthenticated = false` on a High alert from a person makes it more suspicious.

## Blind spots
- Escalation paths that don't use these calls: `iam:PassRole` with `ec2:RunInstances` or `lambda:CreateFunction` using an admin role, `CreatePolicyVersion` with `--set-as-default`, `SetDefaultPolicyVersion`. These are next on the list for this repo. Rhino Security Labs' list of IAM escalation paths is the reference.
- Policies that grant `iam:*` or `s3:*` on `*` without `Action: *`. Widen the regex if your environment is tidy enough.
- SSO / Identity Center permission set changes (`sso.amazonaws.com`).

## False positives
- Platform or IaC roles creating users and keys for service accounts. Add the role ARNs to `approvedIamAdmins`.
- Admins onboarding a new engineer with a login profile. Check the ticket. The person creating it should be a known admin.

## Validation
In a sandbox account, from a test user with IAM rights, run `aws iam create-access-key --user-name other-test-user`. You should get one alert with `Reason = "CreateAccessKey for another user"`.

## Response
1. Undo the change: detach the policy, delete the new key or login profile, put the old trust policy back.
2. Treat the caller as compromised. Revoke its sessions and keys and go through its activity before and after.
3. Check whether logging was touched around the same time (see [aws-logging-tampering](../../defense-evasion/aws-logging-tampering/)), and whether the new credentials were used (`UserIdentityUserName` = the target, from a new `SourceIpAddress`).
