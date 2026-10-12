# Leaver bulk download from SharePoint/OneDrive

| | |
|---|---|
| **Rule** | [`rule.yaml`](rule.yaml) |
| **Data** | `OfficeActivity` (Microsoft 365 connector), watchlist `Leavers` |
| **ATT&CK** | T1530 Data from Cloud Storage, T1213 Data from Information Repositories |
| **Severity** | Medium |
| **Runs** | Daily over 31 days |

## Goal
Spot people taking company data during their notice period, while there's still time to do something about it.

## How it works
Some people download hundreds of files a day as part of their job, so a fixed threshold for everyone is useless. This rule only looks at people on the leavers list and compares each of them with their own history.

1. Read the `Leavers` watchlist (UPN and leave date) and keep everyone whose leave date is today or later.
2. Pull their SharePoint and OneDrive download and sync events for the last 31 days.
3. Work out each person's normal day from days 2 to 31: average and maximum files per active day.
4. Alert when the last 24 hours has at least 50 files and more than 3 times their usual average.

If someone has no history at all, their baseline is 0 and any day over 50 files alerts. A leaver who never touched SharePoint and suddenly pulls 200 files is exactly who you want to look at.

## Technical context
- `FileSyncDownloadedFull` is logged when someone adds a library to the OneDrive sync client. It's the quiet way to grab a whole site, so it's included with normal downloads.
- The rule depends on the watchlist. It's usually fed from the HR system or the offboarding tickets. If you don't have one, run the hunt in [`hunting/disabled-account-prior-downloads.kql`](../../../hunting/disabled-account-prior-downloads.kql) after the fact.

## Blind spots
- Other exit routes: mail to a personal address, USB, personal cloud storage, photos of the screen. Pair this with [inbox-forwarding-external](../../collection/inbox-forwarding-external/) and the Defender for Endpoint USB and cloud upload events.
- Someone taking a little every day, under 3 times their normal. A weekly-volume version of the rule would catch that.
- People who haven't told HR yet.

## False positives
- Handover work. A leaver exporting their own project folders for whoever takes over. Check if the files are theirs and who they're going to.
- The sync client re-syncing after a laptop rebuild. Look at `ClientIPs` and whether the files match the libraries they normally use.

## Validation
Put a test user on the `Leavers` watchlist with a future leave date and sync a SharePoint library with more than 50 files to a test device. The next run should alert with `ActiveDays` = 0.

## Response
1. Look at `SampleFiles` and `FileTypes`. Customer data and source code are a problem. Their own work usually isn't.
2. Ask the manager or HR whether it's part of a handover.
3. If it isn't, keep the audit log, revoke the user's sessions and agree an early account disable with HR and legal. Don't tip the user off before HR is involved.
