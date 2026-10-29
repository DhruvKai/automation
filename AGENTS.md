# AGENTS.md: rules for AI/code agents working in this repo

This repo is a **read-only** Palo Alto Panorama health-check collector. It is used for firewall health reporting. Your top priority is keeping it read-only and low-load.

## Hard rules (do not break)

1. **Read-only only.** Never add code that changes Panorama or firewall state. That covers:
   - commit, commit-all and push
   - config `set`/`edit`/`delete`/`rename`/`clone`/`move`/`override`
   - `import`/`export`
   - `user-id`
   - op `<request>`, `<clear>`, `<set>`, `<debug>`, `<test>` or `<commit-all>`
   - anything that creates, deletes or modifies objects
2. **All requests go through `PanoramaClient.request()` and therefore through `guard()`.**
   - Never call urllib or HTTP directly anywhere else.
   - Never weaken `guard()`.
   - To add a new command, add the exact XML to `OP_COMMANDS`. Only `<show>` commands are allowed.
   - Add a test for the new command in `tests/test_pano_healthcheck.py`.
   - `cmd` must never be built from user input or free-form strings.
3. **Lab only.**
   - Do not change `ALLOWED_HOSTS` handling. It is read from `.env` only, never from environment variables.
   - Do not add production hosts.
   - Development and testing happen against the lab Panorama only.
4. **Secrets.**
   - Never print, log, write to reports or commit the API key.
   - `.env` is git-ignored; keep it that way.
   - The key goes in the `X-PAN-KEY` header, or in the POST body. Never put it in URLs.
5. **Low load.**
   - Requests run one at a time with `REQUEST_DELAY_SEC` between them. Do not add threads or parallel requests.
   - Prefer one Panorama-wide aggregate call, such as `show devices all`, over per-firewall calls.
   - Per-firewall (`target=`) calls stay opt-in and capped by `MAX_TARGETED_FIREWALLS`.
   - Log queries stay capped by `MAX_LOGS` and `LOG_WINDOW_HOURS`.
   - Keep the one network retry. Do not add retry loops.
6. **Standard library only.** The tool must run on a locked-down corp machine with no `pip install`.

## Layout

The whole tool is one file, `pano_healthcheck.py`. Its sections, in order:

- **Settings:** `.env` loader and `load_settings()`, which applies the lab-host lock.
- **Guard:** `OP_COMMANDS` (the allowlist), `guard()` and `ReadOnlyViolation`.
- **API client:** `PanoramaClient`, which handles TLS, proxy bypass, throttling, error-code mapping and the log-job polling.
- **XML helpers:** `flatten()` turns PAN-OS XML into `{path: text}`; `top_entries()`.
- **Collectors:** a `Collector.collect_<section>()` method for each section in `SECTIONS`. A section that fails is recorded in `data["errors"]` and the run continues.
- **Health findings:** `evaluate()` (device, sync, job and resource rules) and `evaluate_rule()` (security-rule checks).
- **Reports:** CSV via `write_csv()`/`csv_tables()`, and a self-contained HTML page via `write_html()`.
- **CLI:** `main()` with `--diagnose`, `--dry-run`, `--sections`, `--targeted` and `--format`.

Other files:

- `tests/test_pano_healthcheck.py`: guard, settings, client, parser and end-to-end tests, using a `FakePanorama` transport.

## Working here

- Run the tests with `python -m unittest discover -s tests -v`. They must pass before any commit.
- Use `python pano_healthcheck.py --dry-run` to see exactly which calls a change would make.
- PAN-OS response shapes vary by version.
  - Parse defensively with `flatten()`, `.get()` and `findtext()`.
  - Record failures as collection errors instead of crashing.
  - When you add a parser, add a sample-XML fixture to the tests.
- New report columns: add them to the matching `*_COLS` list. CSVs include every collected field automatically.
