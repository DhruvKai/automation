# Panorama health check (read-only, proof of concept)

This command-line tool collects firewall health data from **Panorama** and writes an **HTML report** and **CSV files**. It needs Python 3.9 or later with the standard library only; there is nothing to `pip install`.

**Every check uses the XML API.** It needs the XML API permissions Configuration, Operational Requests and Log; a read-only superuser role has all three. The XML API covers everything:

- inventory, connectivity and software/content versions
- HA, and device-group and template sync
- push jobs and log collectors
- certificate expiry
- Panorama CPU, memory, disk and NTP
- logs and security rules

**The REST API is never used by default.** It is only reached through its own menu option, **9 REST API (optional)**. That option reads security rules and device-group/template-stack membership with `GET`. `API_MODE` in `.env` is no longer read.

Each API uses its own key: `PANORAMA_XML_API_KEY` (required) and `PANORAMA_REST_API_KEY` (only for menu option 9). XML requests only ever send the XML key, and REST requests only the REST key.

> **Read-only.** Every request is checked against a hard-coded allowlist before it is sent:
> - **REST:** `GET` only, on an allowlist of endpoints. POST, PUT and DELETE are refused.
> - **XML:** `show` operational commands, config `show`/`get` reads and log queries only. Commit, set, edit, delete, `request`, `clear` and `debug` are refused.
>
> **Lab only.** The tool also refuses to run unless `PANORAMA_HOST` appears in `ALLOWED_HOSTS` in `.env`.

## What it collects

**Every run (XML API):**

| Section | API call(s) | Used for |
|---|---|---|
| `panorama` | `show system info`, `show high-availability state`, `show system resources`, `show system disk-space`, `show ntp` | Panorama version, uptime, HA state and HA config sync, management CPU and memory, disk usage, NTP sync |
| `devices` | `show devices all` (one call for every firewall) | Inventory, connectivity, software/content versions, HA state, policy sync status |
| `sync` | `show devicegroups`, `show templates` | Device-group and template sync per firewall, summarised as one status (`In Sync`, `Out of Sync`, `Commit failed`, `unknown`) |
| `jobs` | `show jobs all` (most recent `MAX_JOBS` kept) | Failed commit/push jobs |
| `collectors` | `show log-collector connected` | Log collector connectivity |
| `rules` | config `show` of shared and per-device-group pre/post security rulebases (running config) | Rule inventory; checks for any/any rules, disabled rules, missing profiles and missing logging |
| `certificates` | config `show` of Panorama, shared and per-template shared certificates | Expired certificates, and certificates expiring within 30 days. Only named fields are kept; private keys never reach the report |
| `logs` | log query: system logs with severity high or above, and config logs, over the last `LOG_WINDOW_HOURS` (capped at `MAX_LOGS`) | Critical events, recent changes |
| `targeted` (off by default) | With `target=<serial>`: `show high-availability all`, `show session info`, `show system resources`, `show running resource-monitor minute last 1`, `show logging-status`, `show system info`, `show system disk-space` | **HA details** (mode, priority, HA1/HA2 links, config and state sync, link/path monitoring), **log forwarding** (connected, to where, last forwarded, lag), **content age** (antivirus and apps & threats release dates), session-table use, management and dataplane CPU, packet buffer, disk |

**Per firewall, from data the run already has:**

- **Sync status:** device group, policy sync, template, template sync and last commit-all state.
- **Versions:** PAN-OS, apps & threats, antivirus and WildFire versions. Flagged when:
  - a firewall runs a newer PAN-OS feature release than Panorama (high; Panorama must be the same or later)
  - a firewall runs a newer maintenance release than Panorama (low)
  - an HA pair runs different versions (high)
  - content is behind the newest version in use (antivirus 3 or more releases behind: medium)
- **Antivirus in policy:** allow rules that set individual profiles but no antivirus profile (low).

All of this is in `firewall_status.csv`, and in the report's **Firewall status** section. The HA, logging and content-age details there need `--targeted`.

`show devices all` also gives each firewall's device-certificate status, which is checked too. It also gives each firewall's HA state and HA peer. Pairs are matched from that, with no extra calls, and flagged when both members are active (possible split brain, critical), neither is active (high), the peer isn't connected (medium), or the peer isn't managed by this Panorama (low).

A run (without `--targeted`) makes about 16 calls, plus 2 per device group and 1 per template.

**Menu option 9 only (REST API, `GET`):**

| Section | REST call(s) | Used for |
|---|---|---|
| `devices` | `Panorama/DeviceGroups`, `Panorama/TemplateStacks` | Which firewalls (serials) are in which device group and template stack |
| `rules` | `Policies/SecurityPreRules` and `SecurityPostRules`, for `shared` and each device group | The same rule checks, read through REST |

This makes 4 calls plus 2 per device group.

All calls go out one at a time with `REQUEST_DELAY_SEC` between them.

## How to run (step by step)

> **On macOS:**
> - Type `python3` instead of `python`.
> - Use `cp .env.example .env` instead of `copy`.
> - Open the newest report with `open "$(ls -d reports/*/ | tail -1)report.html"`.

### 1. Check that Python is installed

Open **PowerShell** or **Command Prompt** (Terminal on macOS) and run:

```
python --version
```

You need Python 3.9 or later. If `python` is not found, try `py --version`. If that works, type `py` instead of `python` in every command below. If neither works, ask IT for Python 3. Nothing else needs to be installed.

### 2. Get the files

Pick one:

- With git:

  ```
  git clone https://github.com/DhruvKai/automation.git
  cd automation
  ```

- Without git: on GitHub, click **Code > Download ZIP**, extract it, then open a terminal in the extracted folder.

Run every command below from this folder. To update later, run `git pull`.

### 3. Get an API key (lab Panorama)

- **XML API key (required):** the role needs, on its **XML API** tab: **Configuration**, **Operational Requests** and **Log**. A read-only superuser role covers all of them.
- **REST API key (optional, only for menu option 9):** the role needs, on its **REST API** tab:
  - **Policies > Security Pre Rules** and **Security Post Rules**
  - **Panorama > Device Groups** and **Template Stacks**

  The REST tab only has enable/disable, not read-only, but this tool only ever sends `GET`.

Put each key on its own line in `.env`.

### 4. Create `.env`

- **Cloned from git:** `.env` is not in the repo, so copy the example:

  ```
  copy .env.example .env
  ```

- **Downloaded the ZIP:** also copy `.env.example` to `.env`.

Open `.env` in a text editor and fill in:

```
PANORAMA_HOST=10.26.254.218
ALLOWED_HOSTS=10.26.254.218
PANORAMA_XML_API_KEY=<paste the XML API key here>
PANORAMA_REST_API_KEY=<optional: the REST API key, for menu option 9>
```

`PANORAMA_API_KEY` still works as a fallback for whichever of the two is empty.

If you use menu option 9, `REST_VERSION` must match the version in your working REST URL, for example `v11.0` in `/restapi/v11.0/...`. An old `API_MODE=rest` line is ignored, with a note when you run the script.

Leave everything else as it is. `.env` is git-ignored; never commit it or share it.

### 5. Test access

```
python pano_healthcheck.py --diagnose
```

This sends a few small read-only calls and prints `PASS` or `FAIL` for each. A `FAIL` line names the exact permission that is missing; see [Troubleshooting](#troubleshooting).

### 6. Preview the calls (optional)

```
python pano_healthcheck.py --dry-run
```

This prints every API call a full run would make. It sends nothing to Panorama.

### 7. Run the health check

#### The menu (easiest)

```
python pano_healthcheck.py
```

With no options, the script opens an interactive menu. It loads the firewalls, device groups and templates from Panorama (3 read-only calls), then fills the menus with them:

| Key | Option | What it does |
|---|---|---|
| `1` | Full health check | Every section, every device group. Shows the estimated number of API calls |
| `2` | Quick health check | Shared + the first 2 device groups (and 2 templates) |
| `3` | Custom health check | Wizard: pick sections, device groups, the firewalls for live checks, and report formats. Then run it, or preview the exact calls first |
| `4` | Browse Panorama (live) | Firewalls (details, live HA/sessions/CPU/disk per firewall), device groups and templates (members, sync; collect one group's rules), an HA & sync overview, recent jobs, log collectors, Panorama status |
| `5` | Diagnose API access | Same as `--diagnose` |
| `6` | Preview API calls | Dry run of a full check; sends nothing |
| `7` | Past reports | Earlier runs with their finding counts; open the HTML, view findings, open the folder, delete one, or **clear all reports**. Deleting asks you to type `DELETE`, and only removes timestamped report folders in `OUTPUT_DIR` |
| `8` | Session settings | Report formats, request delay, log window and limits, for this session only |
| `9` | REST API (optional) | The only place the REST API is used: security rules and membership via REST, a preview of those calls, and a REST access check. Disabled when there is no REST key |

After each run, a results screen shows the severity counts and top findings. From there you can open the HTML report, page through all findings, rule findings and collection errors, or open the report folder.

**Keys:** `↑`/`↓` (`PgUp`/`PgDn`, `Home`/`End`) move, `Enter` selects, a menu's key letter or number jumps straight to it, and `Esc` goes back. In lists, typing filters by any text. In checklists, `Space` toggles, `+` selects all and `-` selects none. `Ctrl+C` cancels a running check and returns to the menu.

Where arrow keys can't work (input piped, `TERM=dumb`, some Git Bash windows), the menu falls back to numbered prompts. In Git Bash, either use `winpty python pano_healthcheck.py`, or add `--menu` for the numbered version.

Menu settings can only make a run *lighter* than `.env`. The request delay can't go below `REQUEST_DELAY_SEC`, and the live-check firewall count can't go above `MAX_TARGETED_FIREWALLS`.

#### Command line

Every option also works without the menu. Any option skips the menu.

For a fast proof-of-concept run, start with `--quick`. It collects rules for shared plus only the first 2 device groups, which is about 8 calls:

```
python pano_healthcheck.py --quick
```

To pick the device groups yourself (names are case-sensitive and must match Panorama exactly):

```
python pano_healthcheck.py --device-groups "US,VOOR"
```

For the full report, covering every device group:

```
python pano_healthcheck.py
```

A limited run says so at the top of the report, so it can't be mistaken for a full one. Progress is printed for each rule call, as `[n/total] device group, rulebase, rule count, time`. At the end, the script prints the report folder, for example:

```
Done: 8 read-only API calls, 6 firewalls, 9 findings (critical 0, high 2, medium 3).
Report: /Users/.../automation/reports/20261029-101500
```

### 8. Open the report

Open the report folder and open `report.html` in your browser. Open the CSV files in Excel.

- **Windows (PowerShell):**

  ```
  start (Get-ChildItem reports | Sort-Object Name | Select-Object -Last 1).FullName
  ```

- **macOS:**

  ```
  open "$(ls -d reports/*/ | tail -1)report.html"
  ```

### Other options

```
python pano_healthcheck.py --format csv                 # CSV only, no HTML
python pano_healthcheck.py --format html                # HTML only
python pano_healthcheck.py --sections rules             # only some sections
python pano_healthcheck.py --env /path/to/other.env     # use a different settings file
python pano_healthcheck.py --firewalls 0079010001,0079010002   # live checks for these firewalls only
python pano_healthcheck.py --menu                       # menu, even when options are given
python pano_healthcheck.py --help                       # list all options
```

- `--sections` choices: `panorama`, `devices`, `sync`, `jobs`, `collectors`, `rules`, `certificates`, `logs`, `targeted`.
- The command line always uses the XML API. The REST API is only in the menu.
- `--targeted` checks up to `MAX_TARGETED_FIREWALLS` firewalls (5 by default), with 7 extra calls per firewall. Use `--firewalls <serials>` to pick which ones. Raise `MAX_TARGETED_FIREWALLS` in `.env` to cover more.
- `--quick` also limits certificate checks to the first 2 templates.

## Output

Output goes to `reports/<YYYYMMDD-HHMMSS>/`:

- `report.html`
- `findings.csv`
- `inventory.csv`
- `security_rules.csv` (every rule, every field)
- `rule_findings.csv`
- `collection_errors.csv`
- `panorama.csv`
- `sync_status.csv`
- `jobs.csv`
- `log_collectors.csv`
- `firewall_status.csv` (one row per firewall: versions, sync, HA, logging)
- `ha_pairs.csv` (firewall HA pairs, their status and any version mismatch)
- `certificates.csv` (soonest expiry first)
- `disk_usage.csv` (Panorama, plus targeted firewalls)
- `system_logs.csv`
- `config_logs.csv`
- `firewall_resources.csv` (with `--targeted`)

A REST run from menu option 9 writes only `inventory.csv` (membership), the rule files, `findings.csv` and `report.html`.

If one section fails, for example because a permission is missing, the run continues. The failure is listed under **Collection errors** in the report.

## Troubleshooting

`--diagnose` explains each failure.

**REST API (menu option 9):**

| Error | Meaning | Usual fix |
|---|---|---|
| 401 / 403 on one endpoint | The role does not allow that REST endpoint | Enable it on the role's **REST API** tab (the error names it), or skip that section |
| 404 | The endpoint was not found at this version path | Set `REST_VERSION` to match your working REST URL. The full endpoint list is at `https://<panorama>/restapi-doc` |
| "could not list device groups" | `Panorama/DeviceGroups` is not readable | Set `DEVICE_GROUPS=<dg1>,<dg2>` in `.env`, using the names from the Panorama GUI. Rules are then still collected |

**XML API:**

| Code | Meaning | Usual fix |
|---|---|---|
| 403 "Type [op/config/log] not authorized for user role" | The key is **valid**, but the role lacks that XML API permission | **Panorama > Admin Roles > *role* > XML API**: enable it and commit. If every check fails, check that `PANORAMA_XML_API_KEY` holds the XML key, not the REST one |
| 17 / 18 / 1 | Invalid, malformed or unknown command | The command is not valid on this PAN-OS version |
| 22 | Session timed out | Generate a new key |

**Both APIs:**

| Error | Meaning | Usual fix |
|---|---|---|
| "response was not XML/JSON" | A proxy or the wrong host answered | Check `PANORAMA_HOST`; keep `BYPASS_PROXY=true` |
| SSL certificate error | `VERIFY_TLS=true` with a self-signed certificate | Set `CA_BUNDLE` to the CA certificate, or `VERIFY_TLS=false` in the lab |

## Notes and limits

- The API key is always sent in the `X-PAN-KEY` header (the XML API can use the POST body instead). It is never put in a URL, so it doesn't end up in web server logs.
- Every run reads rules from the **running** config. Menu option 9 reads them through the REST API, which may include candidate (uncommitted) changes.
- Log query times use the clock of the machine running the script. If that clock is in a different timezone from Panorama, the log window is offset by the difference.
- Health thresholds are in `evaluate()` and `evaluate_rule()` in `pano_healthcheck.py`:

  | Setting | Value |
  |---|---|
  | `LOAD_LIMITS` | CPU, memory, session and packet-buffer limits |
  | `DISK_LIMITS` | 90% high, 80% medium |
  | `CERT_WARN_DAYS` | 30 |
  | `AV_MAX_AGE_DAYS` | 3 |
  | `APP_MAX_AGE_DAYS` | 30 |
  | `LOG_LAG_MINUTES` | 60 |
- The `/opt/panlogs` log partition is not flagged when it is full. PAN-OS keeps it full by design and purges the oldest logs.
- `show logging-status` comes back as text, and its layout varies by PAN-OS version. If log forwarding shows blank for a firewall, the text did not match; the raw lines are not stored.
- Licenses and available software/content updates are not checked: their XML commands are `<request>` commands, which this tool never sends.

## Tests

```
python -m unittest discover -s tests -v
```

The tests use a fake Panorama and make no network calls.
