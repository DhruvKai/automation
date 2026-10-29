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

## Setup

1. Create an admin role on the **lab** Panorama: **Panorama > Admin Roles > XML API**.
   - Enable **Operational Requests**, **Configuration** and **Log**.
   - Disable everything else: Commit, Import, Export, User-ID Agent, Report and so on.
   - Disable the Web UI and REST API tabs too if the account is for automation only.
2. Generate an API key for an admin that uses this role.
3. Put the key in `.env` as `PANORAMA_API_KEY=...`. `.env` is git-ignored; never commit it.

## Run

```
python pano_healthcheck.py --diagnose     # check access and permissions with 4 small calls
python pano_healthcheck.py --dry-run      # list the calls that would be made; send nothing
python pano_healthcheck.py                # full collection, writes HTML and CSV
python pano_healthcheck.py --format csv   # CSV only
python pano_healthcheck.py --sections devices,sync,jobs
python pano_healthcheck.py --targeted     # add per-firewall live checks (up to MAX_TARGETED_FIREWALLS)
```

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
