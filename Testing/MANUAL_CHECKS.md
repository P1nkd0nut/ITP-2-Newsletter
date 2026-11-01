# Manual checks

The pipeline checks scope, severity, PoCs, links and changes automatically. This
is how the team confirms those automated checks are actually right. Do it after
each major change, and at least once a week during the project.

## How to run

```bash
python Backend/run_manual_check.py sample --size 12        # writes Backend/data/manual_checks/manual_check_YYYYMMDD.csv
# open the CSV, fill every reviewer_* column with Y, N or NA, add notes for any N
python Backend/run_manual_check.py score Backend/data/manual_checks/manual_check_YYYYMMDD.csv
```

The sample always tries to include one item from each risky group (out of scope,
no PoC, AI vs CVSS discrepancy, marked Updated, each age tier, frozen) so the
review isn't only the easy cases. Pass `--seed 1` if two people should review the
same sample.

## What to check for each item

Open `source_url` and `nvd_url` side by side with the dashboard.

| Column | Mark Y when |
|---|---|
| `reviewer_scope_ok` | In or out of scope is correct for a web/mobile offensive team, and the WEB/MOBILE category fits the affected product. |
| `reviewer_severity_ok` | The AI severity is within about 1.5 of the official CVSS (or is reasonable if NVD has no CVSS yet), and the priority score ranks it sensibly against the others. |
| `reviewer_poc_ok` | Every listed PoC repo is really for this CVE (not a scanner, a fork of an unrelated tool or a different CVE). NA if none were found. If none were found, search GitHub for "CVE-ID poc" and mark N if a real one exists. |
| `reviewer_links_ok` | Source, NVD and reference links open and point to this CVE. A link the dashboard shows as dead really is dead. |
| `reviewer_change_ok` | New / Updated / Unchanged matches what happened. For Updated, the change summary matches a real change on NVD (CVSS, description, references). |
| `reviewer_schedule_ok` | The `recheck_schedule` matches the CVE's age: under 1 month every run, 1 to 6 months every 30 days, 6 to 12 months every 90 days, over 1 year frozen with the "Not updated" notice on the dashboard. |

## Older CVEs that change

Old CVEs do sometimes get updated (NVD re-scores, a PoC appears later). When an
item is in the 1 to 12 month tiers, compare NVD's "Last Modified" date with the
dashboard: if NVD changed after our last check and the dashboard still shows the
old data, that is expected until the next scheduled check, but note it. If it
stays stale after the next check, mark `reviewer_change_ok` N.

## Recording results

Keep each filled CSV in `Backend/data/manual_checks/`. The `score` output (percent
correct per check plus every N) is what goes into the report or the weekly update.
