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
2. **All requests go through the guarded client methods.**
   - XML requests go through `PanoramaClient.request()`, which calls `guard()`. REST requests go through `PanoramaClient.rest_get()`, which calls `guard_rest()`.
   - Never call urllib or HTTP directly anywhere else.
   - Never weaken either guard.
   - To add an XML command, add the exact XML to `OP_COMMANDS`. Only `<show>` commands are allowed. `cmd` must never be built from user input or free-form strings.
   - To add a REST endpoint, add it to `REST_ENDPOINTS`. REST is `GET` only: never POST, PUT or DELETE, and never rename, move or edit parameters.
   - Add a test for every new command or endpoint in `tests/test_pano_healthcheck.py`.
3. **Lab only.**
   - Do not change `ALLOWED_HOSTS` handling. It is read from `.env` only, never from environment variables.
   - Do not add production hosts.
   - Development and testing happen against the lab Panorama only.
4. **Secrets.**
   - Never print, log, write to reports or commit the API key.
   - `.env` is git-ignored; keep it that way.
   - The key goes in the `X-PAN-KEY` header, or in the POST body (XML only). Never put it in URLs; `load_settings()` rejects `HTTP_METHOD=GET` with `KEY_IN_HEADER=false`.
5. **Low load.**
   - Requests run one at a time with `REQUEST_DELAY_SEC` between them. Do not add threads or parallel requests.
   - Prefer one Panorama-wide aggregate call, such as `show devices all`, over per-firewall calls.
   - Per-firewall (`target=`) calls stay opt-in and capped by `MAX_TARGETED_FIREWALLS`.
   - Log queries stay capped by `MAX_LOGS` and `LOG_WINDOW_HOURS`.
   - Keep the one network retry. Do not add retry loops.
6. **Standard library only.** The tool must run on a locked-down corp machine with no `pip install`.

## Layout

The whole tool is one file, `pano_healthcheck.py`. Its sections, in order:

- **Settings:** `.env` loader and `load_settings()`, which applies the lab-host lock and reads `API_MODE` (`rest`, the default, or `xml`).
- **Guards:**
  - XML: `OP_COMMANDS` (the allowlist), `guard()`.
  - REST: `REST_ENDPOINTS` (the allowlist), `guard_rest()`.
  - Both raise `ReadOnlyViolation`.
- **API client:** `PanoramaClient`.
  - `_send()` handles throttling and the single retry.
  - `request()` sends XML requests; `rest_get()` sends REST requests.
  - It also handles TLS, proxy bypass, error-code mapping and the log-job polling.
- **XML helpers:**
  - `flatten()` turns PAN-OS XML into `{path: text}`.
  - `json_to_element()` turns REST JSON into the same XML shape, so the parsers and health rules are shared.
  - `top_entries()`.
- **Collectors:** `Collector.collect_<section>()` for XML mode and `collect_<section>_rest()` for REST mode, one per section in `SECTIONS`.
  - A section with no REST method is listed in `data["unavailable"]`.
  - A section that fails is recorded in `data["errors"]`, and the run continues.
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
