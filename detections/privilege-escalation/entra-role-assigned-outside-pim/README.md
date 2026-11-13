# Privileged Entra role assigned outside PIM or made permanent

| | |
|---|---|
| **Rule** | [`rule.yaml`](rule.yaml) · test: [`tests/fixtures/entra-role-assigned-outside-pim.kql`](../../../tests/fixtures/entra-role-assigned-outside-pim.kql) |
| **Data** | `AuditLogs` (Microsoft Entra ID connector) |
| **ATT&CK** | T1098.003 Additional Cloud Roles, T1136.003 Create Cloud Account |
| **Severity** | Medium, High at a score of 7 or more |
| **Runs** | Hourly, 14-day query period |

## Goal
Catch privileged access that goes around the approved path. In a tenant that uses PIM, people get a role by activating an eligible assignment for a few hours. An attacker holding a compromised admin wants access that doesn't expire and doesn't need an approval, so they assign the role directly, usually to an account or application they control.

## How it works
The rule reads three operations in the `RoleManagement` category:

- `Add member to role`: a direct assignment in the directory. Events written by the `MS-PIM` service principal are dropped, because that is how a normal PIM activation appears.
- `Add member to role outside of PIM (permanent)`: PIM's own record of a direct assignment.
- `Add member to role in PIM completed (permanent)`: a permanent active assignment made through PIM.

A direct assignment is logged by both the directory and PIM, in two different shapes. Both are parsed and merged into one row per target and role.

| Signal | Points |
|---|---|
| Tier-0 role (Global Administrator, Privileged Role Administrator, Application Administrator…) | 3 |
| Other privileged role (User Administrator, Exchange Administrator, Helpdesk Administrator…) | 1 |
| Assigned directly, outside PIM | 2 |
| Target is a service principal | 2 |
| Target is a guest | 2 |
| Assigner gave the role to themselves | 2 |
| Target account or app was created in the last 7 days | 2 |
| Permanent active assignment through PIM | 1 |
| Assigner hasn't assigned any role in the last 13 days | 1 |
| Assigned by an application not in `approvedAutomation` | 1 |

The alert fires at 5. A tier-0 role assigned directly is enough on its own. A lower role needs more, for example a direct assignment to an account created this week.

## Technical context
- In directory events the target is `TargetResources[0]` and the role name sits in its `modifiedProperties` as `Role.DisplayName`. In PIM events the role is a `TargetResources` entry of type `Role` and the target is a separate entry. The rule reads by type, so the position doesn't matter.
- Older events name Global Administrator "Company Administrator". Both are in the tier-0 list.
- Application Administrator and Cloud Application Administrator are tier-0 here because they can add credentials to any application, including ones that hold higher privileges.

## Blind spots
- Eligible assignments. An attacker can make an account eligible and activate later. That needs a rule on `Add eligible member to role`.
- Roles reached through a role-assignable group. Adding a member to that group is a group change with no role event.
- Custom roles and administrative-unit scoped roles that aren't in the two lists.
- A patient attacker using an account older than 7 days and an admin who assigns roles regularly still alerts for tier-0 roles, at the lowest score.

## False positives
- **Tenants without PIM** (no Entra ID P2). Every assignment is direct, so every tier-0 assignment alerts. That is still a useful alert at that volume. Raise `scoreThreshold` to 6 if you only want the ones with a second signal.
- Break-glass accounts being set up or rotated.
- Identity governance or provisioning tools assigning roles. Add their display names to `approvedAutomation` to remove the "by an application" point.
- An application that needs a directory role by design, such as a sync or reporting service. Expect one alert when it is set up.

## Validation
- **Sample data:** `node tools/render-test.js entra-role-assigned-outside-pim`. Expected: two rows, Global Administrator to a new account (score 8) and Application Administrator to a service principal (score 7). The PIM activation and the permanent Helpdesk assignment don't show up.
- **Test tenant:** create a user, then assign it Global Administrator from Entra ID → Roles and administrators, not through PIM.

## Response
1. Confirm with the assigner through a second channel. If they didn't do it, their account is compromised: revoke sessions and reset credentials before anything else.
2. Remove the assignment. If the target was created recently (`Created`, `CreatedBy`), disable it too.
3. Check what the target did since `FirstSeen`: new credentials on applications, Conditional Access changes, federation or domain changes, new accounts.
4. For a service principal target, list its credentials and who added them. A new secret on an app with a tier-0 role is a backdoor that survives password resets.
