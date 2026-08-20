# App Control Insights Workbook — Changelog

## v2.0 — August 2026

### Summary

v2.0 makes script enforcement visible. It adds a Script Enforcement tab covering PowerShell and MSI activity, matches script events to the signing information that identifies their publisher, and narrows collection to the eight event IDs the workbook actually uses.

### Why

v1.x reported file and policy events only. Script activity was invisible, so there was no way to see what PowerShell Constrained Language Mode was auditing or blocking, and no way to tune a policy for scripts before turning enforcement on.

Making scripts visible required one change underneath: App Control links a script event to its signing event through a correlation identifier that the workbook's original collection path discarded. Without it, every script event appeared unsigned and no publisher could be identified. Collection now preserves that identifier, so script events carry real publisher and issuer values.

### What's new

**Script Enforcement tab.** Audit and block activity for scripts and MSI files across Windows PowerShell 5.1 and PowerShell 7.x, which share the same log. Includes activity over time, audit versus block distribution, a per-machine breakdown, the publishers seen most often, a detail log, blocked COM classes, and a CSV export.

**Publisher and issuer identification on script events.** Script events are matched to their signing event, so the Script Enforcement tab shows who signed a script rather than reporting everything as unsigned.

**Blocked COM classes.** Event `8036` is reported with the component name resolved where it is known, alongside guidance on how to read it. These blocks are usually the feature working as designed rather than a fault; the readme explains what they mean and how to allow a class you have decided to trust.

**Improved file event views.** Better publisher and issuer resolution, new publisher and issuer summaries, duplicate rows removed, and clearer audit versus block labelling.

**A focused data collection rule.** Collection covers exactly the eight event IDs the workbook reads, across two logs. Several event IDs considered during development were withdrawn before release; they are listed below with the reason.

**Faster queries and a Wizard-ready export.** Queries were rewritten for performance, and the CSV export on the File Events and Script Enforcement tabs imports directly into the App Control Policy Wizard.

### Upgrading from v1.x

- **Deploy the updated data collection rule.** v2.0 collects a second log, `Microsoft-Windows-AppLocker/MSI and Script`, which must be enabled on the target machines. Without it the Script Enforcement tab stays empty.
- **Existing history is preserved.** Events collected by v1.x remain queryable. The workbook reads both the older and the current tables and removes duplicates, so no history is lost and nothing is counted twice.
- **Check for a second collector.** If another rule already collects these same logs, the events are ingested twice. The workbook deduplicates so numbers stay correct, but the duplicate ingestion is billable and worth a deliberate decision.
- **Removing a duplicate collector loses data during the gap.** A data collection rule never backfills. The agent begins reading a log when the rule is attached and does not replay what is already on disk, so anything generated while nothing was collecting cannot be recovered afterwards.

### Data collection rule

**v1.x**

```
Microsoft-Windows-CodeIntegrity/Operational!*[System[(EventID=3076 or EventID=3077 or EventID=3089 or EventID=3099)]]
```

**v2.0**

```
Microsoft-Windows-CodeIntegrity/Operational!*[System[(EventID=3076 or EventID=3077 or EventID=3089 or EventID=3099)]]

Microsoft-Windows-AppLocker/MSI and Script!*[System[(EventID=8028 or EventID=8029 or EventID=8036 or EventID=8038)]]
```

### Event ID Reference

| EventID | Channel | Meaning | App Control Wizard usage |
|---------|---------|---------|--------|
| 3076 | CodeIntegrity/Operational | Audit - would have been blocked | Creates rules |
| 3077 | CodeIntegrity/Operational | Block - did not pass the policy | Creates rules |
| 3089 | CodeIntegrity/Operational | Signature information for a blocked or audited file | Enriches rules |
| 3099 | CodeIntegrity/Operational | Policy loaded and activated | Not used |
| 8028 | AppLocker/MSI and Script | Script host queried App Control, audit-mode policy | Creates rules |
| 8029 | AppLocker/MSI and Script | Enforcement equivalent of 8028 | Creates rules |
| 8036 | AppLocker/MSI and Script | COM class blocked, CLSID not in the approved list | Not used |
| 8038 | AppLocker/MSI and Script | Signature information correlated to 8028 or 8029 | Enriches rules |

### Events withdrawn before release

Several event IDs were evaluated during development and left out of the release. They are listed here so the choice is visible rather than silent.

| EventID | Reason |
|---------|--------|
| 3033, 3034, 3036 | These report a signing level failure, not a driver failure. `3033` fires alongside `3077` for the same block, so presenting them separately restated what the File Events tab already showed. |
| 3090, 3091, 3092 | Managed Installer and Intelligent Security Graph diagnostics. They are off by default and require a configuration change and a reboot to enable, so most deployments never produce them. |
| 8030 - 8035 | Present in the Windows event manifest but absent from the published App Control event documentation, so their meaning cannot be stated with confidence. Several are also written to a different log than the one this workbook collects. |
| 3103 | Policy refresh activity. `3099` already reports which policy is active, and the Policy Events tab is an inventory rather than an error report. |
| 8037 | Logged every time a script **passes** the policy. It is by a wide margin the highest volume App Control event, and it reports success. |
| 8002, 8003, 8004 | AppLocker executable and DLL events. Microsoft's own guidance recommends reducing or stopping collection from that log because of its volume. |

### Files

| File | Purpose |
|------|---------|
| `workbook.json` | ARM template for deployment |
| `workbook-portal.json` | Gallery template for the Workbooks Advanced Editor |
| `DCR-AppControl.json` | ARM template for the Data Collection Rule |

## v1.3 — June 2025 (Current Public)

- 4 events: 3076, 3077, 3089, 3099
- 3 tabs: File Events, Policy Events, Event and Policy Graph
- Single log source: `Microsoft-Windows-CodeIntegrity/Operational`
- CSV export with 26-column `LogAnalyticsRecord` schema
- Source: [microsoft/osconfig](https://github.com/microsoft/osconfig/tree/main/guides/How%20to%20get%20insights%20into%20App%20Control%20(WDAC)%20events)
