# Azure backups, locks or recovery data removed, then resources deleted

| | |
|---|---|
| **Rule** | [`rule.yaml`](rule.yaml) · test: [`tests/fixtures/azure-recovery-inhibition.kql`](../../../tests/fixtures/azure-recovery-inhibition.kql) |
| **Data** | `AzureActivity` (Azure Activity connector) |
| **ATT&CK** | T1490 Inhibit System Recovery, T1485 Data Destruction, T1562.008 Disable or Modify Cloud Logs |
| **Severity** | Medium, High at a score of 9 or more |
| **Runs** | Hourly, 14-day query period, chain judged over the last 6 hours |

## Goal
Catch the step before cloud ransomware or sabotage. With enough rights in Azure an attacker doesn't need to encrypt anything. They delete the backups, remove whatever blocks deletion, then delete or exfiltrate the data and ask for money. The first half of that is rare in normal operations and is the part worth alerting on.

## How it works
A lookup table in the query lists control-plane operations with a stage and a weight:

| Stage | Operations | Weight |
|---|---|---|
| **Safeguard** | Backup item or backup instance deleted, Recovery Services or Backup vault deleted, soft-deleted Key Vault purged | 4 |
| | Vault security settings changed (soft delete, multi-user authorization), resource lock removed | 3 |
| | Backup policy deleted, diagnostic setting deleted | 2 |
| **Snapshot** | Disk snapshot, VM restore point or restore point collection deleted | 1 to 2 |
| **Data** | Subscription cancelled | 6 |
| | Resource group deleted | 3 |
| | Storage account, Key Vault, SQL, Cosmos DB or PostgreSQL server deleted | 2 |
| | Virtual machine or disk deleted | 1 |

Per caller, over the last 6 hours:

1. Each distinct operation counts once, so deleting 50 disks weighs the same as deleting one. The weights are summed into `OpScore`.
2. **The caller must have touched a safeguard**, or cancelled a subscription. Snapshot deletions count as a safeguard only at 10 or more. A teardown that removes VMs, disks and a resource group never alerts by itself.
3. Extra points: safeguards removed and then data deleted (3), 20 or more resources touched (2), caller hasn't run any of these operations in 13 days (2), more than one subscription (1).

The alert fires at 6. Changing vault settings and deleting backup items is 7. One backup policy deleted by an admin who does this now and then is 2.

## Technical context
- Only completed operations count. `AzureActivity` logs a Start and a Success event for most writes.
- `vaults/backupconfig/write` is the call that turns off soft delete or changes the vault's security features. With soft delete on, deleted backup items are kept for 14 days, so attackers switch it off first.
- A resource group delete also logs a delete for each resource in it under the same caller. That is why plain data deletion carries low weights and can't alert alone.
- Subscription cancellation was added after reading [itprofessor.cloud's write-up](https://www.itprofessor.cloud/would-you-know-if-someone-cancelled-your-azure-subscription/), which points out that Microsoft ships no rule for it.

## Blind spots
- Data-plane destruction: deleting blobs, emptying containers, dropping tables. None of that is in `AzureActivity`. Storage diagnostic logs are needed.
- Encryption with a customer-managed key the attacker controls, followed by removing access to the key.
- Subscriptions whose Activity log isn't exported to the workspace. Export at management group level so new subscriptions are covered.
- If the Sentinel workspace sits in a subscription that is cancelled or deleted, the alert may never be raised. Keep security tooling in its own subscription.
- An attacker using an identity in `approvedCallers`, or one that already performs these operations regularly, loses the first-time-caller points but still alerts on the chain.
- Vaults with immutability or multi-user authorization enabled block most of this outright. Failed attempts aren't counted here.

## False positives
- Decommissioning a workload that has backups: the backups go, then the resources. This is the same sequence. Expect an alert and close it against the change ticket, or add the decommissioning identity to `approvedCallers`.
- Removing a lock to delete a locked resource group on purpose.
- Backup platform migrations, where items are removed from one vault after being protected in another.
- Infrastructure-as-code pipelines that delete diagnostic settings as part of a redeploy.

## Validation
- **Sample data:** `node tools/render-test.js azure-recovery-inhibition`. Expected: one row for `mallory@contoso.com`, score 18, High. The pipeline's teardown and the single backup policy deletion don't show up.
- **Test subscription:** create a Recovery Services vault with one protected VM, turn off soft delete, stop protection with delete data, then delete the VM.

## Response
1. Contact the caller through a second channel. If the activity isn't theirs, revoke the identity's sessions and remove its role assignments at once. For a service principal, rotate its credentials.
2. Stop further loss: re-enable soft delete, put locks back, and check whether deleted backup items are still in the soft-delete retention period. They can be undeleted for 14 days if soft delete was on when they were removed.
3. Recover soft-deleted Key Vaults and storage accounts before their retention runs out.
4. Scope it: list everything the caller did in `AzureActivity` in the last days, including role assignments and new credentials, and where the caller signed in from (`CallerIPs`).
5. Check for exfiltration before deletion: storage account key listings, SAS generation and large egress in the same period.
