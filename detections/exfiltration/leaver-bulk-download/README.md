# Leaver bulk download from SharePoint/OneDrive

| | |
|---|---|
| **Rule** | [`rule.yaml`](rule.yaml) |
| **Data** | `OfficeActivity` (Microsoft 365 connector), watchlist `Leavers` |
| **ATT&CK** | T1530 Data from Cloud Storage, T1213 Data from Information Repositories |
| **Severity** | Medium |
| **Runs** | Daily over 31 days |

## Goal
Catch employees taking company data in their notice period, before offboarding disables the account.

## Strategy
"Lots of downloads" alone is useless as a signal: some roles download hundreds of files every day. So the rule only looks at people who are known to be leaving, and compares each of them **to their own history**:

1. Pull the `Leavers` watchlist (UPN + leave date). Keep anyone whose leave date is today or later.
2. Collect SharePoint/OneDrive download and sync events for those users over the last 31 days.
3. Build a per-user baseline from days 2–31: average and max files per active day.
4. Alert when the last 24h is **≥ 50 files** *and* **> 3× the user's own average**.

Users with no history at all get a baseline of 0, so any day above 50 files alerts. That's intended: a leaver who never used SharePoint and suddenly pulls 200 files is exactly the case.

## Technical context
- `FileSyncDownloadedFull` shows up when someone adds a library to the OneDrive sync client. It's the quiet way to take a whole site, so it's included alongside browser downloads.
- The watchlist is the dependency. In practice it gets fed from the HR system or from the IAM offboarding ticket queue. Without it, use the retro hunt in [`hunting/disabled-account-prior-downloads.kql`](../../../hunting/disabled-account-prior-downloads.kql).

## Blind spots
- Data leaving by other routes: email to a personal address, USB, personal cloud from a managed device, phone photos. Pair this with mail-forwarding ([inbox-forwarding-external](../../collection/inbox-forwarding-external/)) and Defender for Endpoint USB/cloud-upload events.
- Slow exfiltration below 3× per day across the whole notice period. A weekly-volume variant catches that.
- People who quit without HR knowing yet.

## False positives
- Handover work: a leaver exporting their own project folders for the person taking over. Check whether the files are *theirs* and whether the destination is a colleague.
- Sync client re-sync after a laptop rebuild produces a large `FileSyncDownloadedFull` burst. Check `ClientIPs`/device and whether the file set matches the user's normal libraries.

## Validation
Add a test user to the `Leavers` watchlist with a future `LeaveDate`, then sync a SharePoint library with more than 50 files to a test device. The alert fires on the next run with `ActiveDays` = 0.

## Response
1. Check `SampleFiles` and `FileTypes`. Is it customer data, source code, or their own work?
2. Confirm with the manager/HR whether the download is part of a handover.
3. If not: preserve the audit log, revoke sessions, and coordinate with HR/legal on an early account disable. Don't tip the user off before HR is involved.
