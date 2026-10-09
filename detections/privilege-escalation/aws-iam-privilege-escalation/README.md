# AWS IAM privilege escalation or credentials for another identity

| | |
|---|---|
| **Rule** | [`rule.yaml`](rule.yaml) |
| **Data** | `AWSCloudTrail` |
| **ATT&CK** | T1098.001 Additional Cloud Credentials, T1098.003 Additional Cloud Roles, T1078.004 Cloud Accounts |
| **Severity** | High (Medium for a generic trust-policy change) |
| **Runs** | Hourly over 1 hour |

## Goal
Catch the IAM calls that turn a limited foothold into account-wide control, or that plant credentials for later.

## Strategy
Most IAM write calls are routine. The rule only alerts on **specific shapes**, and states which one in `Reason`:

| Reason | Logic |
|---|---|
| Attached AdministratorAccess / IAMFullAccess | managed policy ARN on `Attach{User,Role,Group}Policy` |
| Inline policy allowing Action * | `Put{User,Role,Group}Policy` whose (URL-decoded) document has `"Effect":"Allow"` and `"Action":"*"` (string or array) |
| Role trust policy opened to any AWS principal | `UpdateAssumeRolePolicy` with `"AWS":"*"` |
| Role trust policy changed | any other `UpdateAssumeRolePolicy` (Medium: often a backdoor that adds an external account) |
| CreateAccessKey / CreateLoginProfile / UpdateLoginProfile for another user | the target `userName` is not the caller. Creating keys for yourself is normal; creating them for someone else is a classic persistence move |
| User added to admin group | `AddUserToGroup` where the group name contains "admin" |

Only successful calls count (`ErrorCode` empty). Approved IaC/break-glass roles are excluded through `approvedIamAdmins`.

## Technical context
- `policyDocument` in `RequestParameters` arrives URL-encoded, so it gets `url_decode()`d before regex matching.
- The caller name comes from `UserIdentityUserName` for IAM users and from the session part of the ARN for assumed roles. Comparing it with `userName` is what separates "my own key" from "a key for someone else".
- `SessionMfaAuthenticated = false` on a High alert from a human user strengthens the case.

## Blind spots
- Indirect escalation paths that don't use these calls: `iam:PassRole` + `ec2:RunInstances`/`lambda:CreateFunction` with an admin role, `CreatePolicyVersion` with `--set-as-default`, `SetDefaultPolicyVersion`. These are next on the list for this repo (Rhino Security Labs' IAM escalation paths are the reference).
- Policies that grant `iam:*` or `s3:*` on `*` rather than `Action: *`. Broaden the regex if your environment is tidy enough.
- SSO / Identity Center permission-set changes (`sso.amazonaws.com`).

## False positives
- Platform/IaC roles creating users and keys for service accounts. Add the role ARNs to `approvedIamAdmins`.
- Admins onboarding a new engineer with a login profile. Check the ticket; the creating identity should be a known admin.

## Validation
In a sandbox account, from a test user with IAM rights: `aws iam create-access-key --user-name other-test-user`. One alert, `Reason = "CreateAccessKey for another user"`.

## Response
1. Undo the change: detach the policy, delete the new key or login profile, restore the trust policy.
2. Treat the **caller** as compromised. Revoke its sessions and keys, then review its activity before and after.
3. Check whether logging was touched in the same window ([aws-logging-tampering](../../defense-evasion/aws-logging-tampering/)) and whether the new credentials were used (`UserIdentityUserName` = target, from a new `SourceIpAddress`).
