# Panorama health check (read-only, proof of concept)

This command-line tool collects firewall health data from **Panorama** through the PAN-OS XML API and writes an **HTML report** and **CSV files**. It needs Python 3.9 or later with the standard library only; there is nothing to `pip install`.

> **Read-only.** Every request is checked against a hard-coded allowlist before it is sent:
> - `show` operational commands
> - config `show`/`get` reads
> - log queries
>
> Anything else is refused before it reaches the network, including commit, set, edit, delete, `request`, `clear` and `debug`.
>
> **Lab only.** The tool also refuses to run unless `PANORAMA_HOST` appears in `ALLOWED_HOSTS` in `.env`.

## What it collects

| Section | API call(s) | Used for |
|---|---|---|
| `panorama` | `show system info`, `show high-availability state` | Panorama version, uptime, HA |
| `devices` | `show devices all` (one call for every firewall) | inventory, connectivity, software/content versions, HA state, policy sync status |
| `sync` | `show devicegroups`, `show templates` | device-group and template sync per firewall |
| `jobs` | `show jobs all` (most recent `MAX_JOBS` kept) | failed commit/push jobs |
| `collectors` | `show log-collector connected` | log collector connectivity |
| `rules` | config `show` of shared and per-device-group pre/post security rulebases (running config) | rule inventory, any/any rules, disabled rules, missing profiles or logging |
| `logs` | log query: system logs with severity high or above, and config logs, over the last `LOG_WINDOW_HOURS` (capped at `MAX_LOGS`) | critical events, recent changes |
| `targeted` (off by default) | `show high-availability state`, `show session info`, `show system resources` with `target=<serial>` | live HA, session-table use, management CPU and memory |

The default run (without `--targeted`) makes about 10 calls, plus 2 per device group. Calls go out one at a time with `REQUEST_DELAY_SEC` between them.

## How to run (step by step)

### 1. Check that Python is installed

Open **PowerShell** or **Command Prompt** and run:

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

- Without git: on GitHub, click **Code > Download ZIP**, extract it, then open PowerShell in the extracted folder:

  ```
  cd C:\path\to\automation
  ```

Run every command below from this folder.

### 3. Create the API admin role and key (one time, lab Panorama)

1. On the **lab** Panorama, go to **Panorama > Admin Roles** and create a role.
2. On the role's **XML API** tab, enable **Operational Requests**, **Configuration** and **Log**.
3. Disable everything else on that tab: Commit, Import, Export, User-ID Agent, Report and so on.
4. If the account is for automation only, disable the Web UI and REST API tabs too.
5. Create an admin account that uses this role.
6. Generate an API key for that admin.

### 4. Create `.env`

- **Cloned from git:** `.env` is not in the repo, so copy the example:

  ```
  copy .env.example .env
  ```

- **Downloaded the ZIP:** also copy `.env.example` to `.env`.

Open `.env` in Notepad and fill in:

```
PANORAMA_HOST=10.26.254.218
ALLOWED_HOSTS=10.26.254.218
PANORAMA_API_KEY=<paste the key here>
```

Leave the other settings as they are for the first run. `.env` is git-ignored; never commit it or share it.

### 5. Test access

```
python pano_healthcheck.py --diagnose
```

This sends 4 small read-only calls and prints `PASS` or `FAIL` for each. A `FAIL` line includes the error code and which role permission to enable; see [Troubleshooting](#troubleshooting). Fix any failures before going on.

### 6. Preview the calls (optional)

```
python pano_healthcheck.py --dry-run
```

This prints every API call a full run would make. It sends nothing to Panorama.

### 7. Run the health check

```
python pano_healthcheck.py
```

Progress is printed per section. A full run takes about 1–2 minutes; the log queries are the slowest part. At the end, the script prints the report folder, for example:

```
Done: 14 read-only API calls, 6 firewalls, 9 findings (critical 1, high 3, medium 5).
Report: C:\...\automation\reports\20261029-101500
```

### 8. Open the report

Open the report folder and double-click `report.html` to view it in your browser. Open the CSV files in Excel. To open the newest report from PowerShell:

```
start (Get-ChildItem reports | Sort-Object Name | Select-Object -Last 1).FullName
```

### Other options

```
python pano_healthcheck.py --format csv                 # CSV only, no HTML
python pano_healthcheck.py --format html                # HTML only
python pano_healthcheck.py --sections devices,sync,jobs # only some sections
python pano_healthcheck.py --targeted                   # add live per-firewall checks
python pano_healthcheck.py --env C:\path\to\other.env   # use a different settings file
python pano_healthcheck.py --help                       # list all options
```

- `--sections` choices: `panorama`, `devices`, `sync`, `jobs`, `collectors`, `rules`, `logs`, `targeted`.
- `--targeted` checks up to `MAX_TARGETED_FIREWALLS` firewalls, with 3 extra calls per firewall.

## Output

Output goes to `reports/<YYYYMMDD-HHMMSS>/`:

- `report.html`
- `findings.csv`
- `inventory.csv`
- `sync_status.csv`
- `jobs.csv`
- `log_collectors.csv`
- `security_rules.csv`
- `rule_findings.csv`
- `system_logs.csv`
- `config_logs.csv`
- `panorama.csv`
- `collection_errors.csv`
- `firewall_resources.csv` (only with `--targeted`)

If one section fails, for example because the role is missing a permission, the run continues. The failure is listed under **Collection errors** in the report.

## Troubleshooting

`--diagnose` explains each failure. The XML API error codes are:

| Code | Meaning | Usual fix |
|---|---|---|
| 16 / 403 | Not authorised | Enable the matching **XML API** permission on the admin role (Operational Requests, Configuration or Log), or check the key |
| 17 / 18 / 1 | Invalid, malformed or unknown command | The command is not valid on this PAN-OS version |
| 22 | Session timed out | Generate a new key |
| "response was not XML" | A proxy or the wrong host answered | Check `PANORAMA_HOST`; keep `BYPASS_PROXY=true` |
| SSL certificate error | `VERIFY_TLS=true` with a self-signed certificate | Set `CA_BUNDLE` to the CA certificate, or `VERIFY_TLS=false` in the lab |

Operational commands must be **nested XML**. For example, `show devices all` becomes `<show><devices><all></all></devices></show>`.

To check by hand with curl:

```
curl.exe -k -G "https://<panorama>/api/" -H "X-PAN-KEY: <key>" --data-urlencode "type=op" --data-urlencode "cmd=<show><devices><all></all></devices></show>"
```

## Notes and limits

- Log query times use the clock of the machine running the script. If that clock is in a different timezone from Panorama, the log window is offset by the difference.
- `show system resources` reports the **management plane** only. Dataplane load needs other commands that are not included yet.
- Health thresholds are in `evaluate()` and `evaluate_rule()` in `pano_healthcheck.py`:
  - session table 80%
  - management CPU 85%
  - management memory 90%
- The `rules` section reads the **running** config (`action=show`), not the candidate config.

## Tests

```
python -m unittest discover -s tests -v
```

The tests use a fake Panorama and make no network calls.
