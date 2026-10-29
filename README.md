# Panorama health check (read-only, proof of concept)

This command-line tool collects firewall health data from **Panorama** and writes an **HTML report** and **CSV files**. It needs Python 3.9 or later with the standard library only; there is nothing to `pip install`.

It works with either Panorama API. Set the mode with `API_MODE` in `.env`:

| `API_MODE` | Needs | Collects |
|---|---|---|
| `rest` (default) | REST API permissions: Policies > Security Pre/Post Rules, Panorama > Device Groups and Template Stacks | Firewall inventory (by device group and template stack), and security rules with rule findings |
| `xml` | XML API permissions: Configuration, Operational Requests, Log | Everything in `rest`, plus connectivity, software/content versions, HA, device-group and template sync, push jobs, log collectors and logs |

The REST API has no operational endpoints. Connectivity, HA, sync status, jobs and logs are only available in `xml` mode.

> **Read-only.** Every request is checked against a hard-coded allowlist before it is sent:
> - **REST:** `GET` only, on an allowlist of endpoints. POST, PUT and DELETE are refused.
> - **XML:** `show` operational commands, config `show`/`get` reads and log queries only. Commit, set, edit, delete, `request`, `clear` and `debug` are refused.
>
> **Lab only.** The tool also refuses to run unless `PANORAMA_HOST` appears in `ALLOWED_HOSTS` in `.env`.

## What it collects

**REST mode** (`API_MODE=rest`):

| Section | REST call(s), all `GET` | Used for |
|---|---|---|
| `devices` | `Panorama/DeviceGroups`, `Panorama/TemplateStacks` | Which firewalls (serials) are in which device group and template stack |
| `rules` | `Policies/SecurityPreRules` and `SecurityPostRules`, for `shared` and each device group | Rule inventory; checks for any/any rules, disabled rules, missing profiles and missing logging |

A REST run makes 4 calls plus 2 per device group.

**XML mode** (`API_MODE=xml`):

| Section | API call(s) | Used for |
|---|---|---|
| `panorama` | `show system info`, `show high-availability state` | Panorama version, uptime, HA |
| `devices` | `show devices all` (one call for every firewall) | Inventory, connectivity, software/content versions, HA state, policy sync status |
| `sync` | `show devicegroups`, `show templates` | Device-group and template sync per firewall |
| `jobs` | `show jobs all` (most recent `MAX_JOBS` kept) | Failed commit/push jobs |
| `collectors` | `show log-collector connected` | Log collector connectivity |
| `rules` | config `show` of shared and per-device-group pre/post security rulebases (running config) | Same rule checks as REST mode |
| `logs` | log query: system logs with severity high or above, and config logs, over the last `LOG_WINDOW_HOURS` (capped at `MAX_LOGS`) | Critical events, recent changes |
| `targeted` (off by default) | `show high-availability state`, `show session info`, `show system resources` with `target=<serial>` | Live HA, session-table use, management CPU and memory |

An XML run (without `--targeted`) makes about 10 calls plus 2 per device group.

In both modes, calls go out one at a time with `REQUEST_DELAY_SEC` between them.

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

- **REST mode:** the admin role needs, on its **REST API** tab:
  - **Policies > Security Pre Rules** and **Security Post Rules**
  - **Panorama > Device Groups** and **Template Stacks**

  The REST tab only has enable/disable, not read-only, but this tool only ever sends `GET`.
- **XML mode:** the role needs, on its **XML API** tab: **Configuration**, **Operational Requests** and **Log**.

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
PANORAMA_API_KEY=<paste the key here>
```

Also check these two:

- `API_MODE`: `rest` by default.
- `REST_VERSION`: must match the version in your working REST URL, for example `v11.0` in `/restapi/v11.0/...`.

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

```
python pano_healthcheck.py
```

Progress is printed per section. At the end, the script prints the report folder, for example:

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
python pano_healthcheck.py --help                       # list all options
```

- `--sections` choices: `panorama`, `devices`, `sync`, `jobs`, `collectors`, `rules`, `logs`, `targeted`.
- In REST mode, only `devices` and `rules` produce data.
- `--targeted` (XML mode only) checks up to `MAX_TARGETED_FIREWALLS` firewalls, with 3 extra calls per firewall.

## Output

Output goes to `reports/<YYYYMMDD-HHMMSS>/`:

- `report.html`
- `findings.csv`
- `inventory.csv`
- `security_rules.csv` (every rule, every field)
- `rule_findings.csv`
- `collection_errors.csv`

In XML mode only:

- `panorama.csv`
- `sync_status.csv`
- `jobs.csv`
- `log_collectors.csv`
- `system_logs.csv`
- `config_logs.csv`
- `firewall_resources.csv` (with `--targeted`)

If one section fails, for example because a permission is missing, the run continues. The failure is listed under **Collection errors** in the report.

## Troubleshooting

`--diagnose` explains each failure.

**REST mode:**

| Error | Meaning | Usual fix |
|---|---|---|
| 401 / 403 on one endpoint | The role does not allow that REST endpoint | Enable it on the role's **REST API** tab (the error names it), or skip that section |
| 404 | The endpoint was not found at this version path | Set `REST_VERSION` to match your working REST URL. The full endpoint list is at `https://<panorama>/restapi-doc` |
| "could not list device groups" | `Panorama/DeviceGroups` is not readable | Set `DEVICE_GROUPS=<dg1>,<dg2>` in `.env`, using the names from the Panorama GUI. Rules are then still collected |

**XML mode:**

| Code | Meaning | Usual fix |
|---|---|---|
| 403 "Type [op/config/log] not authorized for user role" | The key is **valid**, but the role lacks that XML API permission | **Panorama > Admin Roles > *role* > XML API**: enable it and commit. If every XML check fails but REST works, use `API_MODE=rest` |
| 17 / 18 / 1 | Invalid, malformed or unknown command | The command is not valid on this PAN-OS version |
| 22 | Session timed out | Generate a new key |

**Both modes:**

| Error | Meaning | Usual fix |
|---|---|---|
| "response was not XML/JSON" | A proxy or the wrong host answered | Check `PANORAMA_HOST`; keep `BYPASS_PROXY=true` |
| SSL certificate error | `VERIFY_TLS=true` with a self-signed certificate | Set `CA_BUNDLE` to the CA certificate, or `VERIFY_TLS=false` in the lab |

## Notes and limits

- The API key is always sent in the `X-PAN-KEY` header (XML mode can use the POST body instead). It is never put in a URL, so it doesn't end up in web server logs.
- REST mode reads rules through the REST API, which may include candidate (uncommitted) changes. XML mode reads the **running** config.
- In XML mode, log query times use the clock of the machine running the script. If that clock is in a different timezone from Panorama, the log window is offset by the difference.
- Health thresholds are in `evaluate()` and `evaluate_rule()` in `pano_healthcheck.py`.

## Tests

```
python -m unittest discover -s tests -v
```

The tests use a fake Panorama and make no network calls.
