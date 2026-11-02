#!/usr/bin/env python3
"""Read-only Panorama health-check collector (proof of concept).

Collects firewall health data from Panorama through the PAN-OS XML API and
writes an HTML report and/or CSV files. The REST API is only used when it is
chosen from the interactive menu. Python standard library only.

Every request passes a guard before anything is sent. XML: only allowlisted
`show` operational commands, config `show`/`get` reads and log queries
(guard()). REST: only GET on allowlisted endpoints (guard_rest()). Anything
else raises ReadOnlyViolation.

Usage:
    python pano_healthcheck.py                 (interactive menu)
    python pano_healthcheck.py --diagnose
    python pano_healthcheck.py --dry-run
    python pano_healthcheck.py [--sections devices,sync] [--format html,csv] [--targeted]
"""
from __future__ import annotations

import argparse
import csv
import html
import json
import os
import re
import shutil
import socket
import ssl
import sys
import textwrap
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from collections import Counter
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent

# --------------------------------------------------------------------------
# Settings
# --------------------------------------------------------------------------

DEFAULTS = {
    "PANORAMA_HOST": "",
    "PANORAMA_PORT": "443",
    "PANORAMA_API_KEY": "",
    "PANORAMA_XML_API_KEY": "",
    "PANORAMA_REST_API_KEY": "",
    "ALLOWED_HOSTS": "",
    "REST_VERSION": "v11.0",
    "DEVICE_GROUPS": "",
    "VERIFY_TLS": "false",
    "CA_BUNDLE": "",
    "BYPASS_PROXY": "true",
    "KEY_IN_HEADER": "true",
    "HTTP_METHOD": "POST",
    "REQUEST_DELAY_SEC": "1",
    "TIMEOUT_SEC": "60",
    "LOG_WINDOW_HOURS": "24",
    "MAX_LOGS": "100",
    "MAX_JOBS": "50",
    "ENABLE_TARGETED": "false",
    "MAX_TARGETED_FIREWALLS": "5",
    "OUTPUT_DIR": "reports",
}

# ALLOWED_HOSTS is read from the .env file only, so an environment variable
# cannot widen the lab-host lock.
FILE_ONLY_KEYS = {"ALLOWED_HOSTS"}

# Each API has its own key; PANORAMA_API_KEY is the fallback for either.
API_KEY_VARS = {"xml": "PANORAMA_XML_API_KEY", "rest": "PANORAMA_REST_API_KEY"}


class ConfigError(Exception):
    pass


@dataclass
class Settings:
    host: str
    port: int
    xml_api_key: str
    rest_api_key: str
    allowed_hosts: list
    verify_tls: bool
    ca_bundle: str
    bypass_proxy: bool
    key_in_header: bool
    request_delay: float
    timeout: float
    log_window_hours: int
    max_logs: int
    max_jobs: int
    enable_targeted: bool
    max_targeted: int
    output_dir: Path
    key_sources: dict = field(default_factory=dict)  # api mode -> where its key came from
    http_method: str = "POST"
    api_mode: str = "xml"  # always xml, except for the menu's REST API option
    rest_version: str = "v11.0"
    device_groups: list = field(default_factory=list)

    @property
    def api_key(self):
        """The key for the API this run uses."""
        return self.rest_api_key if self.api_mode == "rest" else self.xml_api_key

    def key_label(self):
        """Masked key description, for comparing with the key used in curl."""
        key = self.api_key
        if not key:
            return f"no {self.api_mode.upper()} API key"
        if self.api_mode == "rest":
            sent = "REST GET, X-PAN-KEY header"
        else:
            sent = f"XML {self.http_method}, " + ("X-PAN-KEY header" if self.key_in_header else "POST body")
        source = self.key_sources.get(self.api_mode, "")
        return (f"{self.api_mode.upper()} API key ...{key[-4:]} ({len(key)} chars"
                f"{', from ' + source if source else ''}), sent via {sent}")


def load_env_file(path):
    values = {}
    path = Path(path)
    if not path.exists():
        return values
    for raw in path.read_text(encoding="utf-8-sig").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
            value = value[1:-1]
        values[key.strip()] = value
    return values


def _bool(value):
    return str(value).strip().lower() in ("1", "true", "yes", "on")


def load_settings(env_path, environ=None, require_key=True):
    environ = os.environ if environ is None else environ
    values = dict(DEFAULTS)
    values.update(load_env_file(env_path))
    sources = {name: f"{env_path} {name}" for name in ("PANORAMA_API_KEY", *API_KEY_VARS.values())}
    for key in DEFAULTS:
        if key not in FILE_ONLY_KEYS and environ.get(key):
            values[key] = environ[key]
            if key in sources:
                sources[key] = f"environment variable {key}"

    keys, key_sources = {}, {}
    for mode, var in API_KEY_VARS.items():
        name = var if values[var].strip() else "PANORAMA_API_KEY"
        keys[mode] = values[name].strip()
        key_sources[mode] = sources[name]

    host = values["PANORAMA_HOST"].strip()
    allowed = [h.strip().lower() for h in values["ALLOWED_HOSTS"].split(",") if h.strip()]
    if not host:
        raise ConfigError("PANORAMA_HOST is empty in .env")
    if host.lower() not in allowed:
        raise ConfigError(
            f"PANORAMA_HOST '{host}' is not listed in ALLOWED_HOSTS. "
            "This tool is locked to the lab Panorama; refusing to run."
        )
    http_method = values["HTTP_METHOD"].strip().upper()
    if http_method not in ("POST", "GET"):
        raise ConfigError("HTTP_METHOD must be POST or GET")
    if http_method == "GET" and not _bool(values["KEY_IN_HEADER"]):
        raise ConfigError("HTTP_METHOD=GET needs KEY_IN_HEADER=true; the key is never put in a URL")
    if require_key and not keys["xml"]:
        raise ConfigError(f"{API_KEY_VARS['xml']} is empty. Put the lab XML API key in .env.")
    rest_version = values["REST_VERSION"].strip()
    if not re.fullmatch(r"v\d+\.\d+", rest_version):
        raise ConfigError("REST_VERSION must look like v11.0 (your Panorama's major.minor version)")

    output_dir = Path(values["OUTPUT_DIR"])
    if not output_dir.is_absolute():
        output_dir = SCRIPT_DIR / output_dir

    try:
        return Settings(
            host=host,
            port=int(values["PANORAMA_PORT"]),
            xml_api_key=keys["xml"],
            rest_api_key=keys["rest"],
            allowed_hosts=allowed,
            verify_tls=_bool(values["VERIFY_TLS"]),
            ca_bundle=values["CA_BUNDLE"].strip(),
            bypass_proxy=_bool(values["BYPASS_PROXY"]),
            key_in_header=_bool(values["KEY_IN_HEADER"]),
            request_delay=float(values["REQUEST_DELAY_SEC"]),
            timeout=float(values["TIMEOUT_SEC"]),
            log_window_hours=int(values["LOG_WINDOW_HOURS"]),
            max_logs=min(int(values["MAX_LOGS"]), 5000),
            max_jobs=int(values["MAX_JOBS"]),
            enable_targeted=_bool(values["ENABLE_TARGETED"]),
            max_targeted=int(values["MAX_TARGETED_FIREWALLS"]),
            output_dir=output_dir,
            key_sources=key_sources,
            http_method=http_method,
            rest_version=rest_version,
            device_groups=[g.strip() for g in values["DEVICE_GROUPS"].split(",") if g.strip()],
        )
    except ValueError as exc:
        raise ConfigError(f"Invalid number in .env: {exc}") from None


# --------------------------------------------------------------------------
# Read-only guard
# --------------------------------------------------------------------------

class ReadOnlyViolation(Exception):
    pass


# The only operational commands this tool can ever send.
OP_COMMANDS = {
    "system_info": "<show><system><info></info></system></show>",
    "ha_state": "<show><high-availability><state></state></high-availability></show>",
    "devices_all": "<show><devices><all></all></devices></show>",
    "devicegroups": "<show><devicegroups></devicegroups></show>",
    "templates": "<show><templates></templates></show>",
    "jobs_all": "<show><jobs><all></all></jobs></show>",
    "log_collectors": "<show><log-collector><connected></connected></log-collector></show>",
    "session_info": "<show><session><info></info></session></show>",
    "system_resources": "<show><system><resources></resources></system></show>",
    "disk_space": "<show><system><disk-space></disk-space></system></show>",
    "ntp": "<show><ntp></ntp></show>",
    # Per firewall (target=<serial>): HA mode, links and config sync, and log forwarding to Panorama/collectors.
    "ha_all": "<show><high-availability><all></all></high-availability></show>",
    "logging_status": "<show><logging-status></logging-status></show>",
    # Firewall dataplane CPU and packet buffers, last 1 minute.
    "dp_resources": "<show><running><resource-monitor><minute><last>1</last></minute></resource-monitor></running></show>",
}
ALLOWED_OP = frozenset(OP_COMMANDS.values())
# Commands that may be proxied to a managed firewall with target=<serial>.
TARGETED_OP = frozenset(OP_COMMANDS[n] for n in ("system_info", "ha_all", "session_info", "system_resources",
                                                 "disk_space", "ntp", "dp_resources", "logging_status"))

ALLOWED_PARAMS = {
    "op": {"type", "cmd", "target"},
    "config": {"type", "action", "xpath"},
    "log": {"type", "log-type", "query", "nlogs", "dir", "action", "job-id"},
}
ALLOWED_LOG_TYPES = {"system", "config"}
SERIAL_RE = re.compile(r"[A-Za-z0-9_-]{1,64}")


def guard(params):
    """Raise ReadOnlyViolation unless `params` is a permitted read-only call."""
    req_type = params.get("type")
    if req_type not in ALLOWED_PARAMS:
        raise ReadOnlyViolation(f"request type '{req_type}' is not allowed (read-only tool)")
    extra = set(params) - ALLOWED_PARAMS[req_type]
    if extra:
        raise ReadOnlyViolation(f"parameters not allowed for type={req_type}: {sorted(extra)}")

    if req_type == "op":
        cmd = params.get("cmd", "")
        if cmd not in ALLOWED_OP:
            raise ReadOnlyViolation(f"operational command not in allowlist: {cmd!r}")
        target = params.get("target")
        if target is not None:
            if cmd not in TARGETED_OP:
                raise ReadOnlyViolation("this command may not be sent to a firewall target")
            if not SERIAL_RE.fullmatch(target):
                raise ReadOnlyViolation(f"invalid target serial: {target!r}")

    elif req_type == "config":
        if params.get("action") not in ("show", "get"):
            raise ReadOnlyViolation(f"config action '{params.get('action')}' is not allowed")
        if not str(params.get("xpath", "")).startswith("/config/"):
            raise ReadOnlyViolation("config xpath must start with /config/")

    elif req_type == "log":
        action = params.get("action")
        if action is None:
            if params.get("log-type") not in ALLOWED_LOG_TYPES:
                raise ReadOnlyViolation(f"log-type '{params.get('log-type')}' is not allowed")
            nlogs = str(params.get("nlogs", "20"))
            if not nlogs.isdigit() or not 1 <= int(nlogs) <= 5000:
                raise ReadOnlyViolation("nlogs must be between 1 and 5000")
        elif action == "get":
            if not str(params.get("job-id", "")).isdigit():
                raise ReadOnlyViolation("log action=get needs a numeric job-id")
            if set(params) - {"type", "action", "job-id"}:
                raise ReadOnlyViolation("log action=get takes only job-id")
        else:
            raise ReadOnlyViolation(f"log action '{action}' is not allowed")


# The only REST endpoints this tool can ever call, and only with GET.
REST_ENDPOINTS = frozenset({
    "Policies/SecurityPreRules",
    "Policies/SecurityPostRules",
    "Panorama/DeviceGroups",
    "Panorama/TemplateStacks",
})
REST_QUERY_KEYS = {"location", "device-group"}
REST_LOCATIONS = {"shared", "device-group", "panorama"}
DEVICE_GROUP_RE = re.compile(r"[^\x00-\x1f\x7f]{1,63}")


def guard_rest(method, endpoint, query):
    """Raise ReadOnlyViolation unless this is a GET on an allowlisted REST endpoint."""
    if method != "GET":
        raise ReadOnlyViolation(f"REST method '{method}' is not allowed (read-only tool, GET only)")
    if endpoint not in REST_ENDPOINTS:
        raise ReadOnlyViolation(f"REST endpoint not in allowlist: {endpoint!r}")
    extra = set(query) - REST_QUERY_KEYS
    if extra:
        raise ReadOnlyViolation(f"REST query parameters not allowed: {sorted(extra)}")
    location = query.get("location")
    if location is not None and location not in REST_LOCATIONS:
        raise ReadOnlyViolation(f"REST location '{location}' is not allowed")
    if (location == "device-group") != ("device-group" in query):
        raise ReadOnlyViolation("device-group must be given exactly when location=device-group")
    if "device-group" in query and not DEVICE_GROUP_RE.fullmatch(query["device-group"]):
        raise ReadOnlyViolation(f"invalid device-group name: {query['device-group']!r}")


# --------------------------------------------------------------------------
# API client
# --------------------------------------------------------------------------

API_ERROR_CODES = {
    "1": "Unknown command",
    "2": "Internal error", "3": "Internal error", "4": "Internal error", "5": "Internal error",
    "6": "Bad xpath",
    "7": "Object not present",
    "8": "Object not unique",
    "10": "Reference count not zero",
    "11": "Internal error",
    "12": "Invalid object",
    "13": "Object not found",
    "14": "Operation not possible",
    "15": "Operation denied",
    "16": "Unauthorized - the admin role lacks access to this request type",
    "17": "Invalid command",
    "18": "Malformed command",
    "19": "Success", "20": "Success",
    "21": "Internal error",
    "22": "Session timed out",
    "400": "Bad request",
    "401": "Unauthorized - invalid API key",
    "403": "Forbidden - invalid API key or insufficient admin rights",
    "404": "Not found",
}

ROLE_PERMISSION = {"op": "Operational Requests", "config": "Configuration", "log": "Log"}


def error_hint(code, req_type, message=""):
    if req_type.startswith("rest:"):
        endpoint = req_type[5:]
        if code in ("401", "403", "16"):
            return (f"The admin role does not allow REST API '{endpoint}'. On Panorama: Panorama > Admin "
                    f"Roles > <role> > REST API tab > {endpoint.replace('/', ' > ')} (this tool only sends GET).")
        if code == "404":
            return f"'{endpoint}' was not found; check REST_VERSION in .env and https://<panorama>/restapi-doc."
        return ""
    perm = ROLE_PERMISSION.get(req_type, "the matching")
    if code in ("16", "403"):
        if "not authorized for user role" in message:
            hint = (f"The key is valid, but its admin role does not allow '{perm}'. On Panorama: "
                    f"Panorama > Admin Roles > <role> > XML API tab > enable '{perm}', then commit "
                    "on Panorama.")
            if req_type != "config":
                hint += " Each XML API permission is separate, so config queries can work while this one is denied."
            return hint
        return (f"Check the API key, and that its admin role has XML API > '{perm}' enabled "
                "(Panorama > Admin Roles).")
    if code in ("1", "17", "18"):
        return "Panorama did not accept the command syntax; it may not exist on this PAN-OS version."
    if code == "22":
        return "Generate a new API key."
    return ""


class ApiError(Exception):
    def __init__(self, message, code="", req_type=""):
        self.code = code
        self.req_type = req_type
        meaning = API_ERROR_CODES.get(code, "")
        text = message
        if code:
            text = f"[code {code}{': ' + meaning if meaning else ''}] {message}"
        hint = error_hint(code, req_type, message)
        if hint:
            text += f" -> {hint}"
        super().__init__(text)


def _response_message(root):
    parts = []
    for msg in root.iter("msg"):
        text = " ".join(t.strip() for t in msg.itertext() if t.strip())
        if text:
            parts.append(text)
    return "; ".join(parts) or "no message"


class PanoramaClient:
    """Sends throttled, guarded, one-at-a-time requests to the XML or REST API."""

    def __init__(self, settings, dry_run=False, transport=None, log=print):
        self.settings = settings
        self.dry_run = dry_run
        self.log = log
        self.calls = []
        self._last_request = 0.0
        self._transport = transport or self._urllib_transport()

    def _urllib_transport(self):
        s = self.settings
        if s.verify_tls:
            context = ssl.create_default_context(cafile=s.ca_bundle or None)
        else:
            context = ssl._create_unverified_context()
        handlers = [urllib.request.HTTPSHandler(context=context)]
        if s.bypass_proxy:
            handlers.append(urllib.request.ProxyHandler({}))
        opener = urllib.request.build_opener(*handlers)
        base = f"https://{s.host}:{s.port}"

        def send(path, query, headers, method="POST"):
            """Return (http_status, body). The key is only ever in headers or the POST body."""
            if method == "GET":
                req = urllib.request.Request(f"{base}{path}?{query}", headers=headers, method="GET")
            else:
                req = urllib.request.Request(f"{base}{path}", data=query.encode(), headers=headers,
                                             method="POST")
            try:
                with opener.open(req, timeout=s.timeout) as resp:
                    return resp.status, resp.read()
            except urllib.error.HTTPError as exc:
                # PAN-OS sends an XML/JSON error body with 4xx codes.
                return exc.code, exc.read()

        return send

    def _send(self, path, query, headers, method):
        """Throttle, send once, retry once on network errors only. Returns (status, body)."""
        wait = self.settings.request_delay - (time.monotonic() - self._last_request)
        if wait > 0:
            time.sleep(wait)
        for attempt in (1, 2):
            try:
                return self._transport(path, query, headers, method)
            except (urllib.error.URLError, socket.timeout, ConnectionError) as exc:
                if attempt == 2:
                    reason = getattr(exc, "reason", exc)
                    raise ApiError(f"cannot reach {self.settings.host}: {reason}") from None
                time.sleep(max(self.settings.request_delay, 2))
            finally:
                self._last_request = time.monotonic()

    def request(self, params, label):
        """XML API request. Returns the <result> element."""
        guard(params)
        self.calls.append(label)
        if self.dry_run:
            self.log(f"  [dry-run] {label}")
            return ET.Element("result")

        body_params = dict(params)
        method = self.settings.http_method
        headers = {"Content-Type": "application/x-www-form-urlencoded"} if method == "POST" else {}
        if self.settings.key_in_header:
            headers["X-PAN-KEY"] = self.settings.xml_api_key
        else:
            body_params["key"] = self.settings.xml_api_key  # POST body only; load_settings forbids GET here
        status, payload = self._send("/api/", urllib.parse.urlencode(body_params), headers, method)

        try:
            root = ET.fromstring(payload)
        except ET.ParseError:
            snippet = payload[:120].decode("utf-8", "replace").replace("\n", " ")
            if status >= 400:
                raise ApiError(f"HTTP {status}: {snippet!r}", code=str(status), req_type=params["type"]) from None
            raise ApiError(f"response was not XML (proxy or wrong host?): {snippet!r}") from None

        if root.get("status") != "success":
            raise ApiError(_response_message(root), code=root.get("code", ""), req_type=params["type"])
        result = root.find("result")
        return result if result is not None else ET.Element("result")

    def op(self, name, target=None):
        params = {"type": "op", "cmd": OP_COMMANDS[name]}
        label = f"op {name}"
        if target:
            params["target"] = target
            label += f" target={target}"
        return self.request(params, label)

    def config_show(self, xpath):
        return self.request({"type": "config", "action": "show", "xpath": xpath}, f"config show {xpath}")

    def rest_get(self, endpoint, query):
        """REST API GET. Returns the list of entry dicts."""
        guard_rest("GET", endpoint, query)
        qs = urllib.parse.urlencode(query)
        label = f"rest GET {endpoint}" + (f"?{qs}" if qs else "")
        self.calls.append(label)
        if self.dry_run:
            self.log(f"  [dry-run] {label}")
            return []

        req_type = f"rest:{endpoint}"
        headers = {"X-PAN-KEY": self.settings.rest_api_key, "Accept": "application/json"}
        status, payload = self._send(f"/restapi/{self.settings.rest_version}/{endpoint}", qs, headers, "GET")
        try:
            doc = json.loads(payload)
        except ValueError:
            snippet = payload[:120].decode("utf-8", "replace").replace("\n", " ")
            raise ApiError(f"HTTP {status}, response was not JSON: {snippet!r}",
                           code=str(status) if status >= 400 else "", req_type=req_type) from None
        if not isinstance(doc, dict):
            doc = {}
        if status >= 400 or str(doc.get("@status", "")).lower() != "success":
            message = doc.get("message") or doc.get("msg") or str(doc)[:200]
            code = str(status) if status >= 400 else str(doc.get("code", doc.get("@code", "")))
            raise ApiError(f"{endpoint}: {message}", code=code, req_type=req_type)
        result = doc.get("result") or {}
        entries = result.get("entry", []) if isinstance(result, dict) else []
        return entries if isinstance(entries, list) else [entries]

    def log_query(self, log_type, query, nlogs):
        """Enqueue a log query, poll the job, and return the <entry> elements."""
        params = {"type": "log", "log-type": log_type, "nlogs": str(nlogs), "dir": "backward"}
        if query:
            params["query"] = query
        result = self.request(params, f"log query {log_type} nlogs={nlogs} {query}".rstrip())
        if self.dry_run:
            self.log(f"  [dry-run] log get job-id=<id>  (polled until finished)")
            return []
        job_id = (result.findtext("job") or "").strip()
        if not job_id.isdigit():
            raise ApiError(f"log query returned no job id: {_response_message(result)}")

        for delay in (2, 2, 3, 3, 5, 5, 5, 10, 10, 10):
            time.sleep(delay)
            got = self.request({"type": "log", "action": "get", "job-id": job_id},
                               f"log get job-id={job_id}")
            if (got.findtext("job/status") or "").strip().upper() == "FIN":
                return got.findall("./log/logs/entry")
        raise ApiError(f"log query job {job_id} did not finish in time")


# --------------------------------------------------------------------------
# XML helpers
# --------------------------------------------------------------------------

def _add(out, key, value):
    if key in out and out[key] != "":
        if value != "":
            out[key] = f"{out[key]}; {value}"
    else:
        out[key] = value


def flatten(elem, prefix=""):
    """Turn an element tree into {path: text}. <entry name=X> becomes X, member lists are joined."""
    out = {}
    for child in elem:
        part = child.get("name") if child.tag == "entry" and child.get("name") else child.tag
        key = f"{prefix}/{part}" if prefix else part
        if len(child):
            if all(c.tag == "member" for c in child):
                _add(out, key, ", ".join((c.text or "").strip() for c in child))
            else:
                for k, v in flatten(child, key).items():
                    _add(out, k, v)
        else:
            _add(out, key, (child.text or "").strip())
    return out


def json_to_element(tag, value):
    """Convert a REST API JSON object to the equivalent XML element ('@x' keys become attributes)."""
    el = ET.Element(tag)
    if isinstance(value, dict):
        for key, child in value.items():
            if key.startswith("@"):
                el.set(key[1:], str(child))
            elif key == "#text":
                el.text = str(child)
            else:
                for item in child if isinstance(child, list) else [child]:
                    el.append(json_to_element(key, item))
    elif value is not None:
        el.text = str(value)
    return el


def top_entries(elem):
    """Return the shallowest list of <entry> children below `elem`."""
    level = [elem]
    while level:
        for node in level:
            entries = node.findall("entry")
            if entries:
                return entries
        level = [c for n in level for c in n]
    return []


# --------------------------------------------------------------------------
# Collectors
# --------------------------------------------------------------------------

PANORAMA_DEVICE_XPATH = "/config/devices/entry[@name='localhost.localdomain']"
SECTIONS = ["panorama", "devices", "sync", "jobs", "collectors", "rules", "certificates", "logs", "targeted"]


QUICK_DEVICE_GROUPS = 2  # --quick: rules for shared + this many device groups


class Collector:
    def __init__(self, client, settings, only_groups=None, max_groups=None, only_serials=None):
        self.only_groups = only_groups or []    # --device-groups: collect rules for these only
        self.max_groups = max_groups            # --quick: cap on device groups
        self.only_serials = only_serials or []  # --firewalls: live checks for these only
        self.client = client
        self.settings = settings
        self.data = {
            "panorama": {}, "panorama_ha": {}, "panorama_resources": {}, "panorama_ntp": {},
            "devices": [], "sync": [], "jobs": [], "log_collectors": [], "rules": [], "certificates": [],
            "system_logs": [], "config_logs": [], "resources": [], "disk": [],
            "errors": [], "unavailable": [], "scope_note": "",
        }
        self._device_groups = None
        self._templates = None
        self._dg_entries = None  # REST: device-group entry dicts
        self._panorama_query = {"location": "panorama"}  # REST: query form that worked for Panorama/*

    def run(self, sections):
        rest = self.settings.api_mode == "rest"
        for name in SECTIONS:
            if name not in sections:
                continue
            collect = getattr(self, f"collect_{name}_rest" if rest else f"collect_{name}", None)
            if collect is None:
                self.data["unavailable"].append(name)
                continue
            print(f"Collecting: {name}")
            try:
                collect()
            except ReadOnlyViolation:
                raise
            except ApiError as exc:
                self._error(name, exc)
        if self.data["unavailable"]:
            print(f"Skipped (not available through the REST API): {', '.join(self.data['unavailable'])}. "
                  "The default XML API run collects them.")
        return self.data

    def _error(self, section, exc):
        print(f"  ! {section}: {exc}")
        self.data["errors"].append({"section": section, "error": str(exc)})

    def collect_panorama(self):
        info = self.client.op("system_info")
        system = info.find("system")
        self.data["panorama"] = flatten(system if system is not None else info)
        hostname = self.data["panorama"].get("hostname") or "Panorama"
        serial = self.data["panorama"].get("serial", "")
        for label, name, store in (
            ("HA", "ha_state", lambda r: self.data.update(panorama_ha=flatten(r))),
            ("resources", "system_resources", lambda r: self.data.update(panorama_resources=parse_resources(r))),
            ("disk", "disk_space", lambda r: self.data["disk"].extend(parse_disk_space(r, hostname, serial))),
            ("NTP", "ntp", lambda r: self.data.update(panorama_ntp=parse_ntp(r))),
        ):
            try:
                store(self.client.op(name))
            except ApiError as exc:
                self._error(f"panorama ({label})", exc)

    def collect_devices(self):
        result = self.client.op("devices_all")
        entries = result.findall("./devices/entry") or top_entries(result)
        rows = []
        for entry in entries:
            row = flatten(entry)
            row.setdefault("serial", entry.get("name", ""))
            rows.append(row)
        self.data["devices"] = rows

    def collect_sync(self):
        rows = []
        dg_result = self.client.op("devicegroups")
        dg_entries = dg_result.findall("./devicegroups/entry")
        self._device_groups = [e.get("name") for e in dg_entries if e.get("name")]
        rows += self._sync_rows("device-group", dg_entries)
        try:
            tpl_result = self.client.op("templates")
            tpl_entries = tpl_result.findall("./templates/entry")
            self._templates = [e.get("name") for e in tpl_entries if e.get("name")]
            rows += self._sync_rows("template", tpl_entries)
        except ApiError as exc:
            self._error("sync (templates)", exc)
        self.data["sync"] = rows

    @staticmethod
    def _sync_rows(kind, group_entries):
        rows = []
        for group in group_entries:
            for dev in group.findall("./devices/entry"):
                flat = flatten(dev)
                row = {
                    "type": kind,
                    "group": group.get("name", ""),
                    "hostname": flat.get("hostname", ""),
                    "serial": flat.get("serial", dev.get("name", "")),
                    "connected": flat.get("connected", ""),
                }
                for key, value in flat.items():
                    if "status" in key or "sync" in key or "last-commit" in key:
                        row[key] = value
                row["status"] = sync_status(row)
                rows.append(row)
        return rows

    def collect_jobs(self):
        result = self.client.op("jobs_all")
        rows = []
        for job in result.findall("./job"):
            row = {c.tag: (c.text or "").strip() for c in job if len(c) == 0}
            details = job.find("details")
            if details is not None:
                row["details"] = " ".join(t.strip() for t in details.itertext() if t.strip())[:500]
            devices = job.findall("./devices/entry")
            if devices:
                failed = [d for d in devices if (d.findtext("result") or "").upper() == "FAIL"]
                row["devices_total"] = str(len(devices))
                row["devices_failed"] = str(len(failed))
                row["failed_devices"] = ", ".join(
                    d.findtext("devicename") or d.findtext("serial-no") or d.get("name", "") for d in failed)
            rows.append(row)
        rows.sort(key=lambda r: int(r.get("id", "0") or 0), reverse=True)
        self.data["jobs"] = rows[: self.settings.max_jobs]

    def collect_collectors(self):
        result = self.client.op("log_collectors")
        rows = []
        for entry in top_entries(result):
            row = flatten(entry)
            row.setdefault("serial", entry.get("name", ""))
            rows.append(row)
        self.data["log_collectors"] = rows

    def collect_rules(self):
        if self._device_groups is None:
            # Read device-group names from config so this section only needs the
            # 'Configuration' XML API permission.
            names = self.client.request(
                {"type": "config", "action": "get",
                 "xpath": f"{PANORAMA_DEVICE_XPATH}/device-group/entry/@name"},
                "config get device-group names")
            self._device_groups = [e.get("name") for e in top_entries(names) if e.get("name")]
        locations = [("shared", "/config/shared")]
        locations += [(dg, f"{PANORAMA_DEVICE_XPATH}/device-group/entry[@name='{dg}']")
                      for dg in self._select_groups(self._device_groups)]
        if self.client.dry_run and not self._device_groups:
            print("  [dry-run] + 2 config show calls per device group (pre/post rulebase)")

        rows = []
        total = len(locations) * 2
        step = 0
        for location, base in locations:
            for rulebase in ("pre-rulebase", "post-rulebase"):
                step += 1
                started = time.monotonic()
                try:
                    result = self.client.config_show(f"{base}/{rulebase}/security/rules")
                except ApiError as exc:
                    if exc.code in ("7", "13"):  # rulebase not configured
                        continue
                    raise
                rules_el = next(result.iter("rules"), result)
                entries = rules_el.findall("entry")
                for position, entry in enumerate(entries, start=1):
                    rows.append(rule_row(location, rulebase, position, entry))
                self._progress(step, total, location, rulebase, len(entries), started)
        self.data["rules"] = rows

    # ---- REST API mode: only configuration data exists in the REST API ----

    def _rest_device_groups(self):
        """Device-group entries from Panorama/DeviceGroups, else names from DEVICE_GROUPS in .env."""
        if self._dg_entries is not None:
            return self._dg_entries
        last = None
        for query in ({"location": "panorama"}, {}):
            try:
                self._dg_entries = self.client.rest_get("Panorama/DeviceGroups", query)
                self._panorama_query = query
                return self._dg_entries
            except ApiError as exc:
                last = exc
                if exc.code in ("401", "403", "16"):
                    break  # a permission problem; another query form will not help
        if self.settings.device_groups:
            self._error("device groups", last)
            print(f"  using DEVICE_GROUPS from .env: {', '.join(self.settings.device_groups)}")
            self._dg_entries = [{"@name": name} for name in self.settings.device_groups]
            return self._dg_entries
        self._dg_entries = []
        raise ApiError(f"could not list device groups ({last}). "
                       "Set DEVICE_GROUPS=<dg1>,<dg2> in .env to collect device-group rules anyway.")

    def collect_devices_rest(self):
        rows = {}

        def add(serial, column, group):
            row = rows.setdefault(serial, {"serial": serial, "device-group": "", "template-stack": ""})
            row[column] = f"{row[column]}, {group}" if row[column] else group

        for dg in self._rest_device_groups():
            group = json_to_element("entry", dg)
            for dev in group.findall("./devices/entry"):
                add(dev.get("name", ""), "device-group", group.get("name", ""))
        try:
            for stack in self.client.rest_get("Panorama/TemplateStacks", self._panorama_query):
                group = json_to_element("entry", stack)
                for dev in group.findall("./devices/entry"):
                    add(dev.get("name", ""), "template-stack", group.get("name", ""))
        except ApiError as exc:
            self._error("devices (template stacks)", exc)
        self.data["devices"] = list(rows.values())

    def collect_rules_rest(self):
        try:
            names = [e.get("@name") for e in self._rest_device_groups() if e.get("@name")]
        except ApiError as exc:
            self._error("rules (device groups)", exc)
            names = []
        names = self._select_groups(names)
        locations = [("shared", {"location": "shared"})]
        locations += [(name, {"location": "device-group", "device-group": name}) for name in names]
        if self.client.dry_run and not names:
            print("  [dry-run] + 2 REST GET calls per device group (pre/post rules)")

        rows = []
        denied = set()
        total = len(locations) * 2
        step = 0
        for location, query in locations:
            for rulebase, endpoint in (("pre-rulebase", "Policies/SecurityPreRules"),
                                       ("post-rulebase", "Policies/SecurityPostRules")):
                step += 1
                if endpoint in denied:
                    continue
                started = time.monotonic()
                try:
                    entries = self.client.rest_get(endpoint, query)
                except ApiError as exc:
                    if exc.code in ("401", "403", "16"):
                        denied.add(endpoint)  # don't repeat a denied call for every device group
                    self._error(f"rules ({location} {rulebase})", exc)
                    continue
                before = len(rows)
                for position, entry in enumerate(entries, start=1):
                    if entry.get("@location") and entry["@location"] != query["location"]:
                        continue  # inherited from another location; collected there
                    rows.append(rule_row(location, rulebase, position, json_to_element("entry", entry)))
                self._progress(step, total, location, rulebase, len(rows) - before, started)
        self.data["rules"] = rows

    def _select_groups(self, names):
        """Apply --device-groups and --quick to the device groups whose rules are collected."""
        selected = list(names)
        if self.only_groups:
            missing = [g for g in self.only_groups if names and g not in names]
            if missing:
                self._error("rules (device groups)",
                            ApiError(f"device group(s) not found on Panorama: {', '.join(missing)}"))
            selected = [g for g in self.only_groups if not names or g in names]
        if self.max_groups is not None:
            selected = selected[: self.max_groups]
        if selected != list(names):
            self._limit_note(f"security rules for shared + {len(selected)} of {len(names)} device groups "
                             f"({', '.join(selected) or 'none'})")
        return selected

    def _limit_note(self, text):
        """Record that this run collected less than a full run would; shown at the top of the report."""
        note = self.data["scope_note"]
        self.data["scope_note"] = f"{note}; {text}" if note else f"Limited run: {text}"
        print(f"  Limited run: {text}")

    def _progress(self, step, total, location, rulebase, count, started):
        if not self.client.dry_run:
            print(f"  [{step}/{total}] {location} {rulebase}: {count} rules ({time.monotonic() - started:.1f}s)",
                  flush=True)

    def collect_certificates(self):
        """Certificate expiry: Panorama's own, shared, and each template's shared certificates."""
        if self._templates is None:
            names = self.client.request(
                {"type": "config", "action": "get",
                 "xpath": f"{PANORAMA_DEVICE_XPATH}/template/entry/@name"},
                "config get template names")
            self._templates = [e.get("name") for e in top_entries(names) if e.get("name")]
        templates = list(self._templates)
        if self.max_groups is not None and len(templates) > self.max_groups:
            self._limit_note(f"certificates for {self.max_groups} of {len(templates)} templates")
            templates = templates[: self.max_groups]
        if self.client.dry_run and not templates:
            print("  [dry-run] + 1 config show call per template")

        locations = [("panorama", "/config/panorama/certificate"), ("shared", "/config/shared/certificate")]
        locations += [(f"template {t}", f"{PANORAMA_DEVICE_XPATH}/template/entry[@name='{t}']/config/shared/certificate")
                      for t in templates]
        rows = []
        for location, xpath in locations:
            try:
                result = self.client.config_show(xpath)
            except ApiError as exc:
                if exc.code not in ("7", "13"):  # 7/13: no certificates at this location
                    self._error(f"certificates ({location})", exc)
                continue
            rows += [certificate_row(location, entry) for entry in top_entries(result)]
        self.data["certificates"] = rows

    def collect_logs(self):
        since = (datetime.now() - timedelta(hours=self.settings.log_window_hours)).strftime("%Y/%m/%d %H:%M:%S")
        time_q = f"( receive_time geq '{since}' )"
        for key, log_type, query in (
            ("system_logs", "system", f"( severity geq high ) and {time_q}"),
            ("config_logs", "config", time_q),
        ):
            try:
                entries = self.client.log_query(log_type, query, self.settings.max_logs)
                self.data[key] = [flatten(e) for e in entries]
            except ApiError as exc:
                self._error(f"logs ({log_type})", exc)

    def collect_targeted(self):
        serials = [d.get("serial", "") for d in self.data["devices"] if d.get("connected") == "yes"]
        if self.only_serials:
            # Without inventory data (devices section skipped) trust the list; the guard checks each serial.
            serials = [s for s in self.only_serials if not self.data["devices"] or s in serials]
        if self.client.dry_run and not serials:
            serials = ["<serial>"]
            print(f"  [dry-run] up to {self.settings.max_targeted} connected firewalls, "
                  f"{len(TARGETED_CALLS)} calls each:")
        rows = []
        for serial in serials[: self.settings.max_targeted]:
            if serial == "<serial>":
                for name in TARGETED_CALLS:
                    print(f"  [dry-run] op {name} target=<serial>")
                continue
            row = {"serial": serial}
            dev = next((d for d in self.data["devices"] if d.get("serial") == serial), {})
            row["hostname"] = dev.get("hostname", "")
            errors = []
            for name in TARGETED_CALLS:
                try:
                    result = self.client.op(name, target=serial)
                except ApiError as exc:
                    errors.append(f"{name}: {exc}")
                    if exc.code not in ("1", "17", "18"):
                        break  # unreachable or denied: the remaining calls would fail the same way
                    continue
                if name == "disk_space":
                    disks = parse_disk_space(result, row["hostname"] or serial, serial)
                    self.data["disk"] += disks
                    row["disk_max_pct"] = max((d["use_pct"] for d in disks), key=float, default="")
                else:
                    row.update(TARGETED_CALLS[name](result))
            if errors:
                row["error"] = "; ".join(errors)
            rows.append(row)
        self.data["resources"] = rows


def rule_row(location, rulebase, position, entry):
    flat = flatten(entry)
    profiles = flat.get("profile-setting/group", "")
    if not profiles:
        profiles = ", ".join(f"{k.rsplit('/', 1)[-1]}={v}" for k, v in flat.items()
                             if k.startswith("profile-setting/profiles/") and v)
    target = ", ".join(k.split("/")[2] for k in flat if k.startswith("target/devices/"))
    return {
        "location": location,
        "rulebase": rulebase,
        "position": position,
        "name": entry.get("name", ""),
        "uuid": entry.get("uuid", ""),
        "action": flat.get("action", ""),
        "disabled": flat.get("disabled", "no") or "no",
        "from": flat.get("from", ""),
        "to": flat.get("to", ""),
        "source": flat.get("source", ""),
        "destination": flat.get("destination", ""),
        "source-user": flat.get("source-user", ""),
        "application": flat.get("application", ""),
        "service": flat.get("service", ""),
        "category": flat.get("category", ""),
        "profiles": profiles,
        "log-start": flat.get("log-start", "no") or "no",
        "log-end": flat.get("log-end", "yes") or "yes",
        "log-setting": flat.get("log-setting", ""),
        "target": target,
        "negate-source": flat.get("negate-source", "no") or "no",
        "negate-destination": flat.get("negate-destination", "no") or "no",
        "tag": flat.get("tag", ""),
        "description": flat.get("description", ""),
    }


def _ends(flat, suffix):
    return next((v for k, v in flat.items() if k == suffix or k.endswith("/" + suffix)), "")


def parse_ha(result):
    """show high-availability all (or state): mode, states, links, config sync and monitoring."""
    flat = flatten(result)
    return {
        "ha_enabled": _ends(flat, "enabled"),
        "ha_mode": _ends(flat, "group/mode") or _ends(flat, "mode"),
        "ha_local_state": _ends(flat, "local-info/state"),
        "ha_peer_state": _ends(flat, "peer-info/state"),
        "ha_peer_conn": _ends(flat, "peer-info/conn-status"),
        "ha_priority": _ends(flat, "local-info/priority"),
        "ha_preemptive": _ends(flat, "local-info/preemptive"),
        "ha1_status": _ends(flat, "peer-info/conn-ha1/conn-status"),
        "ha2_status": _ends(flat, "peer-info/conn-ha2/conn-status"),
        "ha_config_sync": _ends(flat, "running-sync"),
        "ha_state_sync": _ends(flat, "local-info/state-sync"),
        "ha_link_monitoring": _ends(flat, "link-monitoring/enabled"),
        "ha_path_monitoring": _ends(flat, "path-monitoring/enabled"),
    }


def parse_session_info(result):
    flat = flatten(result)
    row = {k: flat.get(k, "") for k in ("num-active", "num-max", "cps", "pps", "kbps")}
    try:
        row["session_util_pct"] = f"{100 * int(row['num-active']) / int(row['num-max']):.1f}"
    except (ValueError, ZeroDivisionError):
        row["session_util_pct"] = ""
    return row


def parse_resources(result):
    """Parse management-plane CPU/memory from the `top` text in show system resources."""
    text = "".join(result.itertext())
    row = {"mgmt_cpu_pct": "", "mgmt_mem_pct": ""}
    cpu = re.search(r"Cpu\(s\):.*?([\d.]+)\s*%?\s*id", text)
    if cpu:
        row["mgmt_cpu_pct"] = f"{100 - float(cpu.group(1)):.1f}"
    mem = re.search(r"Mem\s*:\s*([\d.]+)\s*total,\s*([\d.]+)\s*free,\s*([\d.]+)\s*used", text)
    if mem:
        total, used = float(mem.group(1)), float(mem.group(3))
        row["mgmt_mem_pct"] = f"{100 * used / total:.1f}" if total else ""
    else:
        old = re.search(r"Mem:\s*(\d+)k total,\s*(\d+)k used", text)
        if old and int(old.group(1)):
            row["mgmt_mem_pct"] = f"{100 * int(old.group(2)) / int(old.group(1)):.1f}"
    return row


def _numbers(text):
    return [float(n) for n in re.findall(r"\d+(?:\.\d+)?", text or "")]


def parse_dp_resources(result):
    """Dataplane CPU (average over cores, busiest dataplane) and packet-buffer use from resource-monitor."""
    cpu = []
    for avg in result.iter("cpu-load-average"):
        values = [n for e in avg.findall("entry") for n in _numbers(e.findtext("value"))]
        if values:
            cpu.append(sum(values) / len(values))
    buffers = [n for e in result.iter("entry")
               if (e.findtext("name") or "").strip().lower().startswith("packet buffer")
               for n in _numbers(e.findtext("value"))]
    return {"dp_cpu_pct": f"{max(cpu):.1f}" if cpu else "",
            "packet_buffer_pct": f"{max(buffers):.1f}" if buffers else ""}


def parse_disk_space(result, device, serial=""):
    """Parse the `df -h` text in show system disk-space into one row per /dev filesystem."""
    rows = []
    for line in "".join(result.itertext()).splitlines():
        m = re.match(r"(/\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\d+)%\s+(\S+)$", line.strip())
        if m:
            rows.append({"device": device, "serial": serial, "filesystem": m.group(1), "size": m.group(2),
                         "used": m.group(3), "avail": m.group(4), "use_pct": m.group(5), "mount": m.group(6)})
    return rows


def parse_ntp(result):
    """show ntp: which server the clock is synched to ('LOCAL' = none) and each server's status."""
    flat = flatten(result)
    if "synched" not in flat:
        return {}
    servers = []
    for key in sorted(k for k in flat if k.endswith("/name")):
        prefix = key[: -len("/name")]
        servers.append(f"{flat[key]} ({flat.get(prefix + '/status', '?')}, "
                       f"reachable={flat.get(prefix + '/reachable', '?')})")
    return {"ntp_synched": flat["synched"], "ntp_servers": "; ".join(servers)}


def _epoch(value):
    """Seconds since 1970 for epoch digits or a PAN-OS date string (time zone names ignored); None if unparseable."""
    text = " ".join(str(value or "").split())
    if text.isdigit():
        return int(text)
    text = re.sub(r"\s+[A-Z]{2,5}$", "", text)
    for fmt in ("%b %d %H:%M:%S %Y", "%Y/%m/%d %H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y/%m/%d", "%Y-%m-%d"):
        try:
            return (datetime.strptime(text, fmt) - datetime(1970, 1, 1)).total_seconds()
        except ValueError:
            pass
    return None


def days_left(value, now=None):
    """Whole days until a date given as epoch seconds or a PAN-OS date string; '' if unparseable."""
    expiry = _epoch(value)
    now = time.time() if now is None else now
    return "" if expiry is None else str(int((expiry - now) // 86400))


def days_old(value, now=None):
    """Whole days since a date; '' if unparseable."""
    then = _epoch(value)
    now = time.time() if now is None else now
    return "" if then is None else str(int((now - then) // 86400))


def parse_content(result, now=None):
    """Content release dates and ages from a firewall's show system info."""
    system = result.find("system")
    flat = flatten(system if system is not None else result)
    row = {}
    for kind in ("av", "app", "wildfire"):
        date = flat.get(f"{kind}-release-date", "")
        row[f"{kind}_release_date"] = date
        row[f"{kind}_age_days"] = days_old(date, now) if date else ""
    return row


LOG_TYPES = {"traffic", "threat", "system", "config", "url", "wildfire", "hipmatch", "userid", "auth", "data",
             "gtp", "tunnel", "decryption", "globalprotect", "iptag", "sctp"}
LOG_TIME = r"(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}|Not Available)"


def parse_logging_status(result):
    """show logging-status text: is the firewall forwarding logs, to where, and how far behind."""
    text = "\n".join(result.itertext())
    row = {"log_forwarding": "", "log_destination": "", "last_log_forwarded": "", "log_fwd_lag_min": ""}
    connected = re.search(r"is active and connected to\s+([\w.:\[\]-]+)", text)
    if connected:
        row["log_forwarding"], row["log_destination"] = "connected", connected.group(1)
    elif re.search(r"not connected|is not active|disconnected", text, re.I):
        row["log_forwarding"] = "not connected"
    lags = []
    for m in re.finditer(rf"^\s*([a-z-]+)\s+{LOG_TIME}\s+{LOG_TIME}", text, re.M):
        kind, created, forwarded = m.groups()
        if kind not in LOG_TYPES or created == "Not Available":
            continue
        if forwarded != "Not Available":
            row["last_log_forwarded"] = max(row["last_log_forwarded"], forwarded)
            lags.append((_epoch(created) - _epoch(forwarded)) / 60)
    if lags:
        row["log_fwd_lag_min"] = f"{max(0, max(lags)):.0f}"
    return row


CERT_FIELDS = ("common-name", "subject", "issuer", "not-valid-before", "not-valid-after", "expiry-epoch",
               "algorithm", "ca")


def certificate_row(location, entry, now=None):
    # Named fields only: a certificate entry also holds the (encrypted) private key, which must
    # never reach a report, so this deliberately does not flatten() the entry.
    row = {"location": location, "name": entry.get("name", "")}
    for name in CERT_FIELDS:
        row[name] = (entry.findtext(name) or "").strip()
    row["has-private-key"] = "yes" if entry.find("private-key") is not None else "no"
    row["days_left"] = days_left(row["expiry-epoch"] or row["not-valid-after"], now)
    return row


SYNC_ID_KEYS = ("type", "group", "hostname", "serial", "connected", "status")


def _out_of_sync(value):
    low = value.lower()
    return "out of sync" in low or "out-of-sync" in low


def sync_status(row):
    """One status for a device-group/template member: 'Out of Sync', 'Commit failed', 'In Sync' or 'unknown'."""
    values = [v for k, v in row.items() if k not in SYNC_ID_KEYS and v]
    if any(_out_of_sync(v) for v in values):
        return "Out of Sync"
    if any("fail" in v.lower() for v in values):
        return "Commit failed"
    if any("in sync" in v.lower() or "in-sync" in v.lower() for v in values):
        return "In Sync"
    return "unknown"


def ha_pairs(devices):
    """HA pairs from show devices all (ha/state, ha/peer/serial): one row per pair or lone HA member."""
    by_serial = {d.get("serial", ""): d for d in devices}
    rows, seen = [], set()
    for dev in devices:
        serial, state = dev.get("serial", ""), dev.get("ha/state", "").lower()
        peer_serial = dev.get("ha/peer/serial", "")
        if serial in seen or (not peer_serial and state in ("", "disabled")):
            continue
        peer = by_serial.get(peer_serial)
        seen |= {serial, peer_serial}
        peer_state = (peer or {}).get("ha/state", "").lower()
        if not peer_serial:
            status = "no peer reported"
        elif peer is None:
            status = "peer not managed by Panorama"
        elif peer.get("connected") != "yes":
            status = "peer not connected"
        elif state == "active" and peer_state == "active":
            status = "both active (possible split brain)"
        elif state == "passive" and peer_state == "passive":
            status = "no active member"
        elif state not in HEALTHY_HA_STATES or peer_state not in HEALTHY_HA_STATES:
            status = "degraded"
        else:
            status = "ok"
        mismatch = "; ".join(f"{f} {dev.get(f, '')} vs {peer.get(f, '')}" for f in HA_VERSION_FIELDS
                             if peer and dev.get(f) and peer.get(f) and dev.get(f) != peer.get(f))
        rows.append({
            "firewall": dev.get("hostname") or serial, "serial": serial, "state": state or "-",
            "peer": (peer or {}).get("hostname") or peer_serial or "-", "peer_serial": peer_serial,
            "peer_state": peer_state or "-", "peer_connected": (peer or {}).get("connected", "-"), "status": status,
            "version_mismatch": mismatch,
        })
    return rows


def _version(text):
    m = re.match(r"(\d+)\.(\d+)\.(\d+)", text or "")
    return tuple(int(n) for n in m.groups()) if m else None


def _content(text):
    m = re.match(r"(\d+)", text or "")
    return int(m.group(1)) if m else None


HA_VERSION_FIELDS = ("sw-version", "app-version", "av-version")


def firewall_status(devices, sync_rows, resources=()):
    """One row per firewall: versions, device-group/template sync, HA and logging, from data already collected."""
    pairs = {}
    for pair in ha_pairs(devices):
        pairs[pair["serial"]] = (pair["peer"], pair["status"])
        if pair["peer_serial"]:
            pairs[pair["peer_serial"]] = (pair["firewall"], pair["status"])
    live = {r.get("serial"): r for r in resources}
    rows = []
    for dev in devices:
        serial = dev.get("serial", "")
        member = [r for r in sync_rows if r.get("serial") == serial]
        r = live.get(serial, {})
        peer, pair_status = pairs.get(serial, ("", ""))

        def joined(kind, key):
            return ", ".join(m[key] for m in member if m["type"] == kind)

        rows.append({
            "hostname": dev.get("hostname", ""), "serial": serial, "model": dev.get("model", ""),
            "connected": dev.get("connected", ""), "sw-version": dev.get("sw-version", ""),
            "app-version": dev.get("app-version", ""), "av-version": dev.get("av-version", ""),
            "wildfire-version": dev.get("wildfire-version", ""),
            "url-filtering-version": dev.get("url-filtering-version", ""),
            "device-group": joined("device-group", "group"), "policy_sync": joined("device-group", "status"),
            "template": joined("template", "group"), "template_sync": joined("template", "status"),
            "last_commit": ", ".join(v for k, v in dev.items() if "last-commit-all" in k and v),
            "ha_state": dev.get("ha/state", ""), "ha_peer": peer, "ha_pair": pair_status,
            "ha_mode": r.get("ha_mode", ""), "ha_config_sync": r.get("ha_config_sync", ""),
            "ha_links": ", ".join(f"{k} {r[k]}" for k in ("ha1_status", "ha2_status") if r.get(k)).replace("_status", ""),
            "log_forwarding": r.get("log_forwarding", ""), "log_destination": r.get("log_destination", ""),
            "last_log_forwarded": r.get("last_log_forwarded", ""), "av_age_days": r.get("av_age_days", ""),
        })
    return rows


HA_PAIR_SEVERITY = {"both active (possible split brain)": "critical", "no active member": "high",
                    "peer not connected": "medium", "peer not managed by Panorama": "low",
                    "no peer reported": "low"}


# Per-firewall calls for --targeted, in order, with their parsers (disk_space is handled separately).
TARGETED_CALLS = {
    "ha_all": parse_ha,
    "session_info": parse_session_info,
    "system_resources": parse_resources,
    "dp_resources": parse_dp_resources,
    "logging_status": parse_logging_status,
    "system_info": parse_content,
    "disk_space": None,
}


# --------------------------------------------------------------------------
# Health findings
# --------------------------------------------------------------------------

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
HEALTHY_HA_STATES = {"", "active", "passive", "active-primary", "active-secondary", "disabled"}
BAD_DEVICE_CERT = {"none", "no", "expired", "invalid", "not present"}
CERT_WARN_DAYS = 30
# (field, label, limit %) for management plane and dataplane load.
LOAD_LIMITS = (("session_util_pct", "Session table utilisation", 80),
               ("mgmt_cpu_pct", "Management CPU", 85),
               ("mgmt_mem_pct", "Management memory", 90),
               ("dp_cpu_pct", "Dataplane CPU", 80),
               ("packet_buffer_pct", "Packet buffer", 80))
DISK_LIMITS = (("high", 90), ("medium", 80))
AV_MAX_AGE_DAYS = 3        # antivirus content is released daily
APP_MAX_AGE_DAYS = 30      # applications & threats content
LOG_LAG_MINUTES = 60       # log forwarding behind by this much is flagged
CONTENT_FIELDS = (("app-version", "Applications & Threats content"), ("av-version", "Antivirus content"),
                  ("wildfire-version", "WildFire content"))


def _finding(findings, severity, area, target, finding, detail=""):
    findings.append({"severity": severity, "area": area, "target": target,
                     "finding": finding, "detail": detail})


def evaluate_rule(rule):
    issues = []
    allow = rule["action"] == "allow"
    is_any = lambda field: rule[field].strip().lower() in ("any", "")
    if rule["disabled"] == "yes":
        issues.append(("info", "Rule is disabled"))
    if allow and is_any("source") and is_any("destination") and is_any("application"):
        issues.append(("high", "Allow rule with source, destination and application all 'any'"))
    elif allow and is_any("application") and rule["service"].strip().lower() == "any":
        issues.append(("medium", "Allow rule with application 'any' and service 'any'"))
    if allow and not rule["profiles"]:
        issues.append(("medium", "Allow rule without security profiles"))
    elif allow and "=" in rule["profiles"] and "virus=" not in rule["profiles"]:
        issues.append(("low", "Allow rule without an antivirus profile"))  # individual profiles, no group
    if rule["log-end"] == "no":
        issues.append(("medium", "Logging at session end is disabled"))
    if allow and not rule["log-setting"]:
        issues.append(("low", "No log forwarding profile"))
    return issues


def evaluate(data):
    findings = []
    devices = data["devices"]

    for dev in devices:
        name = dev.get("hostname") or dev.get("serial", "")
        if "connected" in dev and dev["connected"] != "yes":
            _finding(findings, "critical", "connectivity", name, "Firewall not connected to Panorama",
                     f"serial {dev.get('serial', '')}, ip {dev.get('ip-address', '')}")
        if dev.get("deactivated") == "yes":
            _finding(findings, "info", "inventory", name, "Firewall is deactivated in Panorama")
        if dev.get("unsupported-version") == "yes":
            _finding(findings, "medium", "versions", name, "Firewall runs a version Panorama flags as unsupported",
                     dev.get("sw-version", ""))
        ha_state = dev.get("ha/state", "").lower()
        if ha_state not in HEALTHY_HA_STATES:
            _finding(findings, "high", "high-availability", name, f"HA state is '{ha_state}'")
        if dev.get("connected") == "yes":
            cert = dev.get("device-cert-present", "")
            left = days_left(dev.get("device-cert-expiry-date", ""))
            if cert.lower() in BAD_DEVICE_CERT:
                _finding(findings, "medium", "certificates", name, f"Device certificate is '{cert}'",
                         "needed for cloud services such as WildFire, URL filtering and telemetry")
            elif left and int(left) <= CERT_WARN_DAYS:
                _finding(findings, "medium", "certificates", name,
                         f"Device certificate {'expired' if int(left) < 0 else f'expires in {left} days'}",
                         dev.get("device-cert-expiry-date", ""))
        for key, value in dev.items():
            low = value.lower()
            if "status" in key and ("out of sync" in low or "out-of-sync" in low):
                _finding(findings, "high", "sync", name, f"{key} is '{value}'")
            elif "commit" in key and "fail" in low:
                _finding(findings, "high", "sync", name, f"{key} is '{value}'")

    for pair in ha_pairs(devices):
        severity = HA_PAIR_SEVERITY.get(pair["status"])
        if severity:
            _finding(findings, severity, "high-availability", f"{pair['firewall']} / {pair['peer']}",
                     f"HA pair: {pair['status']}", f"states {pair['state']} / {pair['peer_state']}")
        if pair["version_mismatch"]:
            _finding(findings, "high", "high-availability", f"{pair['firewall']} / {pair['peer']}",
                     "HA peers run different versions", pair["version_mismatch"])

    for row in data["sync"]:
        for key, value in row.items():
            if key in SYNC_ID_KEYS:
                continue
            low = value.lower()
            if "out of sync" in low or "out-of-sync" in low or "fail" in low:
                _finding(findings, "high", "sync", row["hostname"] or row["serial"],
                         f"{row['type']} '{row['group']}': {key} is '{value}'")

    connected = [d for d in devices if d.get("connected") == "yes"]
    versions = Counter(d.get("sw-version", "") for d in connected if d.get("sw-version"))
    if len(versions) > 1:
        majority = versions.most_common(1)[0][0]
        for d in connected:
            if d.get("sw-version") and d["sw-version"] != majority:
                _finding(findings, "info", "versions", d.get("hostname") or d.get("serial", ""),
                         "PAN-OS version differs from fleet majority", f"{d['sw-version']} vs {majority}")

    # Content: compare each firewall with the newest version in use (fleet and Panorama).
    for field, label in CONTENT_FIELDS:
        known = [(d, _content(d.get(field))) for d in connected]
        newest = max([v for _, v in known if v is not None] + [_content(data["panorama"].get(field)) or 0])
        for d, v in known:
            if v is not None and v < newest:
                behind = newest - v
                severity = "medium" if field == "av-version" and behind >= AV_MAX_AGE_DAYS else "low"
                detail = f"{d[field]}; newest in use starts {newest}"
                if field == "av-version":
                    detail += f" ({behind} releases behind)"
                _finding(findings, severity, "versions", d.get("hostname") or d.get("serial", ""),
                         f"{label} is behind the newest in use", detail)

    # Panorama must run the same or a later PAN-OS than every managed firewall.
    panorama_version = _version(data["panorama"].get("sw-version"))
    for d in devices if panorama_version else ():
        fw_version = _version(d.get("sw-version"))
        if fw_version and fw_version[:2] > panorama_version[:2]:
            _finding(findings, "high", "versions", d.get("hostname") or d.get("serial", ""),
                     "Firewall runs a newer PAN-OS feature release than Panorama",
                     f"{d['sw-version']} vs Panorama {data['panorama']['sw-version']}; Panorama must be the same or later")
        elif fw_version and fw_version > panorama_version:
            _finding(findings, "low", "versions", d.get("hostname") or d.get("serial", ""),
                     "Firewall runs a newer maintenance release than Panorama",
                     f"{d['sw-version']} vs Panorama {data['panorama']['sw-version']}")

    ha = data["panorama_ha"]
    if ha.get("enabled") == "yes":
        conn = _ends(ha, "peer-info/conn-status")
        if conn and conn.lower() != "up":
            _finding(findings, "high", "panorama", "Panorama", f"Panorama HA peer connection is '{conn}'")
        local = _ends(ha, "local-info/state").lower()
        if local and "active" not in local and "passive" not in local:
            _finding(findings, "high", "panorama", "Panorama", f"Panorama HA local state is '{local}'")
        sync = _ends(ha, "running-sync")
        if sync and sync.lower() != "synchronized" and _ends(ha, "running-sync-enabled") != "no":
            _finding(findings, "medium", "panorama", "Panorama", f"Panorama HA running config is '{sync}'",
                     "the HA peers have different running configurations")

    for field, label, limit in LOAD_LIMITS:
        try:
            if float(data["panorama_resources"].get(field, "")) >= limit:
                _finding(findings, "high", "panorama", "Panorama",
                         f"{label} at {data['panorama_resources'][field]}%")
        except ValueError:
            pass
    ntp = data["panorama_ntp"]
    if ntp and ntp["ntp_synched"].strip().lower() in ("", "local"):
        _finding(findings, "medium", "panorama", "Panorama", "Clock is not synchronised to an NTP server",
                 ntp["ntp_servers"] or "no NTP servers configured")

    for disk in data["disk"]:
        if "panlogs" in disk["mount"]:
            continue  # log storage is kept full by design; PAN-OS purges the oldest logs
        for severity, limit in DISK_LIMITS:
            if int(disk["use_pct"]) >= limit:
                _finding(findings, severity, "disk", disk["device"], f"{disk['mount']} is {disk['use_pct']}% full",
                         f"{disk['used']} of {disk['size']} used, {disk['avail']} free")
                break

    for cert in data["certificates"]:
        if cert["days_left"] and int(cert["days_left"]) <= CERT_WARN_DAYS:
            expired = int(cert["days_left"]) < 0
            _finding(findings, "high" if expired else "medium", "certificates",
                     f"{cert['location']}: {cert['name']}",
                     "Certificate expired" if expired else f"Certificate expires in {cert['days_left']} days",
                     f"not valid after {cert['not-valid-after']}; CN {cert['common-name'] or '-'}")

    for lc in data["log_collectors"]:
        if lc.get("connected", "yes") != "yes":
            _finding(findings, "high", "log-collector", lc.get("host-name") or lc.get("serial", ""),
                     "Log collector not connected")

    for job in data["jobs"]:
        if job.get("result", "").upper() == "FAIL" or job.get("devices_failed", "0") not in ("", "0"):
            _finding(findings, "high", "jobs", f"job {job.get('id', '')}",
                     f"{job.get('type', 'Job')} failed",
                     f"finished {job.get('tfin', '')}; failed devices: {job.get('failed_devices', '') or 'n/a'}")

    rule_counts = Counter()
    for rule in data["rules"]:
        for severity, issue in evaluate_rule(rule):
            rule_counts[(severity, issue)] += 1
    for (severity, issue), count in rule_counts.items():
        _finding(findings, severity, "security-policy", f"{count} rule(s)", issue, "see Rule findings")

    crit = [e for e in data["system_logs"] if e.get("severity", "").lower() == "critical"]
    if crit:
        _finding(findings, "medium", "system-logs", "Panorama/firewalls",
                 f"{len(crit)} critical system log event(s) in the log window")
    if data["config_logs"]:
        _finding(findings, "info", "config-logs", "Panorama/firewalls",
                 f"{len(data['config_logs'])} configuration change(s) in the log window")

    for row in data["resources"]:
        name = row.get("hostname") or row["serial"]
        if row.get("error"):
            _finding(findings, "medium", "resources", name, "Per-firewall query failed", row["error"])
        for field, label, limit in LOAD_LIMITS:
            try:
                if float(row.get(field, "")) >= limit:
                    _finding(findings, "high", "resources", name, f"{label} at {row[field]}%")
            except ValueError:
                pass
        if row.get("ha_peer_conn") and row["ha_peer_conn"].lower() != "up":
            _finding(findings, "high", "high-availability", name, f"HA peer connection is '{row['ha_peer_conn']}'")
        for link in ("ha1", "ha2"):
            status = row.get(f"{link}_status", "")
            if status and status.lower() != "up":
                _finding(findings, "high", "high-availability", name, f"{link.upper()} link is '{status}'")
        if row.get("ha_enabled") == "yes" and row.get("ha_config_sync", "").lower() not in ("", "synchronized"):
            _finding(findings, "medium", "high-availability", name,
                     f"HA config is not synchronised with the peer ('{row['ha_config_sync']}')")
        if row.get("log_forwarding") == "not connected":
            _finding(findings, "high", "logging", name, "Firewall is not forwarding logs",
                     "no connection to Panorama or a log collector (show logging-status)")
        if row.get("log_fwd_lag_min") and int(row["log_fwd_lag_min"]) >= LOG_LAG_MINUTES:
            _finding(findings, "medium", "logging", name,
                     f"Log forwarding is {row['log_fwd_lag_min']} minutes behind",
                     f"last forwarded {row.get('last_log_forwarded', '')} to {row.get('log_destination', '') or '?'}")
        for kind, label, limit in (("av", "Antivirus", AV_MAX_AGE_DAYS), ("app", "Applications & Threats", APP_MAX_AGE_DAYS)):
            age = row.get(f"{kind}_age_days", "")
            if age and int(age) >= limit:
                _finding(findings, "medium", "versions", name, f"{label} content is {age} days old",
                         f"released {row.get(f'{kind}_release_date', '')}")

    for err in data["errors"]:
        _finding(findings, "medium", "collection", err["section"], "Section could not be collected", err["error"])
    if data.get("unavailable"):
        _finding(findings, "info", "collection", ", ".join(data["unavailable"]),
                 "Not checked: the REST API has no data for these sections",
                 "The default run (XML API) collects them")

    findings.sort(key=lambda f: SEVERITY_ORDER[f["severity"]])
    return findings


def rule_findings(rules):
    rows = []
    for rule in rules:
        for severity, issue in evaluate_rule(rule):
            rows.append({"severity": severity, "location": rule["location"], "rulebase": rule["rulebase"],
                         "position": rule["position"], "name": rule["name"], "finding": issue})
    rows.sort(key=lambda r: SEVERITY_ORDER[r["severity"]])
    return rows


# --------------------------------------------------------------------------
# Reports
# --------------------------------------------------------------------------

INVENTORY_COLS = ["hostname", "serial", "model", "family", "ip-address", "connected", "deactivated",
                  "sw-version", "app-version", "threat-version", "av-version", "wildfire-version",
                  "url-filtering-version", "ha/state", "ha/peer/serial", "uptime", "multi-vsys",
                  "operational-mode", "unsupported-version", "device-cert-present",
                  "device-cert-expiry-date", "connected-at"]
FINDING_COLS = ["severity", "area", "target", "finding", "detail"]
SYNC_COLS = ["type", "group", "hostname", "serial", "connected", "status"]
HA_COLS = ["firewall", "serial", "state", "peer", "peer_serial", "peer_state", "peer_connected", "status",
           "version_mismatch"]
FW_STATUS_COLS = ["hostname", "serial", "connected", "sw-version", "app-version", "av-version", "wildfire-version",
                  "device-group", "policy_sync", "template", "template_sync", "last_commit", "ha_state", "ha_peer",
                  "ha_pair", "ha_mode", "ha_links", "ha_config_sync", "log_forwarding", "last_log_forwarded",
                  "av_age_days"]
JOB_COLS = ["id", "type", "status", "result", "user", "tenq", "tfin", "progress",
            "devices_total", "devices_failed", "failed_devices", "description", "details"]
RULE_COLS = ["location", "rulebase", "position", "name", "action", "disabled", "from", "to", "source",
             "destination", "source-user", "application", "service", "category", "profiles",
             "log-start", "log-end", "log-setting", "target", "negate-source", "negate-destination",
             "tag", "description", "uuid"]
RULE_FINDING_COLS = ["severity", "location", "rulebase", "position", "name", "finding"]
SYSLOG_COLS = ["receive_time", "time_generated", "device_name", "serial", "severity", "subtype",
               "eventid", "opaque"]
CONFIGLOG_COLS = ["receive_time", "admin", "client", "cmd", "path", "result", "device_name", "serial"]
RESOURCE_COLS = ["hostname", "serial", "ha_enabled", "ha_local_state", "ha_peer_state", "ha_peer_conn",
                 "num-active", "num-max", "session_util_pct", "cps", "pps", "kbps",
                 "mgmt_cpu_pct", "mgmt_mem_pct", "dp_cpu_pct", "packet_buffer_pct", "disk_max_pct",
                 "ha_mode", "ha1_status", "ha2_status", "ha_config_sync", "log_forwarding", "log_destination",
                 "last_log_forwarded", "log_fwd_lag_min", "av_release_date", "av_age_days", "error"]
DISK_COLS = ["device", "serial", "mount", "use_pct", "size", "used", "avail", "filesystem"]
CERT_COLS = ["location", "name", "days_left", "not-valid-after", "common-name", "issuer", "subject",
             "not-valid-before", "algorithm", "ca", "has-private-key", "expiry-epoch"]


def by_expiry(certs):
    return sorted(certs, key=lambda c: int(c["days_left"]) if c["days_left"] else 10**9)


def columns_for(rows, preferred, include_extra=True):
    present = {k for r in rows for k in r}
    cols = [c for c in preferred if c in present]
    if include_extra:
        cols += sorted(present - set(cols))
    return cols or list(preferred)


def write_csv(path, rows, preferred):
    cols = columns_for(rows, preferred)
    with open(path, "w", newline="", encoding="utf-8-sig") as fh:
        writer = csv.DictWriter(fh, fieldnames=cols, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow({c: row.get(c, "") for c in cols})


def csv_tables(data, findings):
    panorama = [{"field": k, "value": v} for k, v in data["panorama"].items()]
    panorama += [{"field": f"ha/{k}", "value": v} for k, v in data["panorama_ha"].items()]
    panorama += [{"field": k, "value": v} for k, v in {**data["panorama_resources"], **data["panorama_ntp"]}.items()]
    tables = {
        "findings.csv": (findings, FINDING_COLS),
        "panorama.csv": (panorama, ["field", "value"]),
        "inventory.csv": (data["devices"], INVENTORY_COLS),
        "sync_status.csv": (data["sync"], SYNC_COLS),
        "jobs.csv": (data["jobs"], JOB_COLS),
        "log_collectors.csv": (data["log_collectors"], ["serial", "host-name", "connected"]),
        "security_rules.csv": (data["rules"], RULE_COLS),
        "rule_findings.csv": (rule_findings(data["rules"]), RULE_FINDING_COLS),
        "certificates.csv": (by_expiry(data["certificates"]), CERT_COLS),
        "system_logs.csv": (data["system_logs"], SYSLOG_COLS),
        "config_logs.csv": (data["config_logs"], CONFIGLOG_COLS),
        "collection_errors.csv": (data["errors"], ["section", "error"]),
    }
    if any("connected" in d for d in data["devices"]):  # XML inventory; REST has no HA data
        tables["ha_pairs.csv"] = (ha_pairs(data["devices"]), HA_COLS)
        tables["firewall_status.csv"] = (firewall_status(data["devices"], data["sync"], data["resources"]),
                                         FW_STATUS_COLS)
    if data["resources"]:
        tables["firewall_resources.csv"] = (data["resources"], RESOURCE_COLS)
    if data["disk"]:
        tables["disk_usage.csv"] = (data["disk"], DISK_COLS)
    csv_section = {"panorama.csv": "panorama", "sync_status.csv": "sync", "jobs.csv": "jobs",
                   "log_collectors.csv": "collectors", "certificates.csv": "certificates",
                   "system_logs.csv": "logs", "config_logs.csv": "logs"}
    unavailable = set(data.get("unavailable", []))
    return {name: t for name, t in tables.items() if csv_section.get(name) not in unavailable}


def _table(rows, cols, empty="No data collected."):
    if not rows:
        return f'<p class="empty">{html.escape(empty)}</p>'
    head = "".join(f"<th>{html.escape(c)}</th>" for c in cols)
    body = []
    for row in rows:
        cells = []
        for c in cols:
            value = str(row.get(c, ""))
            cls = f' class="sev-{value}"' if c == "severity" and value in SEVERITY_ORDER else ""
            cells.append(f"<td{cls}>{html.escape(value)}</td>")
        body.append("<tr>" + "".join(cells) + "</tr>")
    return f'<div class="scroll"><table><thead><tr>{head}</tr></thead><tbody>{"".join(body)}</tbody></table></div>'


HTML_STYLE = """
:root { --bg:#f7f7f5; --fg:#1d1d1b; --muted:#6b6b66; --card:#fff; --line:#e2e2dc;
  --crit:#b3261e; --high:#c4540a; --med:#9a7b00; --low:#2f6db5; --info:#6b6b66; }
@media (prefers-color-scheme: dark) { :root { --bg:#161615; --fg:#ececea; --muted:#a0a09a;
  --card:#1f1f1d; --line:#33332f; --crit:#ff8a80; --high:#ffb070; --med:#e6c84a; --low:#8ab4f8; --info:#a0a09a; } }
* { box-sizing:border-box; }
body { margin:0; padding:24px 16px 64px; background:var(--bg); color:var(--fg);
  font:14px/1.45 system-ui,-apple-system,"Segoe UI",sans-serif; }
main { max-width:1400px; margin:0 auto; }
h1 { font-size:22px; margin:0 0 4px; } h2 { font-size:17px; margin:32px 0 8px; }
.meta { color:var(--muted); margin-bottom:16px; }
nav a { color:var(--fg); margin-right:12px; font-size:13px; }
.tiles { display:flex; flex-wrap:wrap; gap:10px; margin:16px 0; }
.tile { background:var(--card); border:1px solid var(--line); border-radius:8px; padding:10px 14px; min-width:120px; }
.tile b { display:block; font-size:22px; font-variant-numeric:tabular-nums; }
.tile span { color:var(--muted); font-size:12px; }
.scroll { overflow-x:auto; border:1px solid var(--line); border-radius:8px; background:var(--card); }
table { border-collapse:collapse; width:100%; font-size:12.5px; }
th, td { text-align:left; padding:6px 10px; border-bottom:1px solid var(--line); vertical-align:top; white-space:nowrap; }
td { max-width:420px; overflow:hidden; text-overflow:ellipsis; }
th { position:sticky; top:0; background:var(--card); font-weight:600; }
.sev-critical { color:var(--crit); font-weight:700; } .sev-high { color:var(--high); font-weight:700; }
.sev-medium { color:var(--med); font-weight:600; } .sev-low { color:var(--low); } .sev-info { color:var(--info); }
.empty { color:var(--muted); font-style:italic; }
.scope { border-left:3px solid var(--med); padding:6px 10px; background:var(--card); }
details summary { cursor:pointer; color:var(--muted); margin-top:8px; }
"""


def sync_html(rows):
    counts = Counter((r["type"], r.get("status", "unknown")) for r in rows)
    summary = ", ".join(f"{kind} {status}: {n}" for (kind, status), n in sorted(counts.items()))
    order = {"Out of Sync": 0, "Commit failed": 1, "unknown": 2, "In Sync": 3}
    rows = sorted(rows, key=lambda r: (order.get(r.get("status"), 2), r["type"], r["group"]))
    head = f'<p class="meta">{html.escape(summary)}</p>' if summary else ""
    return head + _table(rows, columns_for(rows, SYNC_COLS))


def fw_status_html(data):
    rows = firewall_status(data["devices"], data["sync"], data["resources"])
    note = ("" if data["resources"] else '<p class="meta">HA mode, HA links, HA config sync and log forwarding '
            "come from the per-firewall checks (--targeted).</p>")
    return note + _table(rows, columns_for(rows, FW_STATUS_COLS, include_extra=False))


def ha_html(data):
    ha = data["panorama_ha"]
    pano = ""
    if ha:
        pano = _table([{"Panorama HA": ha.get("enabled", ""), "local state": _ends(ha, "local-info/state"),
                        "peer state": _ends(ha, "peer-info/state"),
                        "peer connection": _ends(ha, "peer-info/conn-status"),
                        "running config": _ends(ha, "running-sync")}],
                      ["Panorama HA", "local state", "peer state", "peer connection", "running config"])
    pairs = ha_pairs(data["devices"])
    return pano + "<h3>Firewall HA pairs</h3>" + _table(pairs, HA_COLS, "No firewalls report an HA peer.")


def write_html(path, data, findings, settings, calls, started):
    devices = data["devices"]
    sev = Counter(f["severity"] for f in findings)
    tiles = [(len(devices), "managed firewalls")]
    if any("connected" in d for d in devices):
        connected = sum(1 for d in devices if d.get("connected") == "yes")
        tiles += [(connected, "connected"), (len(devices) - connected, "not connected")]
    tiles += [
        (sev["critical"], "critical findings"),
        (sev["high"], "high findings"),
        (sev["medium"], "medium findings"),
        (len(data["rules"]), "security rules"),
    ]
    tiles_html = "".join(f'<div class="tile"><b>{v}</b><span>{html.escape(l)}</span></div>' for v, l in tiles)

    pano = data["panorama"]
    pano_rows = [{"field": k, "value": pano.get(k, "")} for k in
                 ("hostname", "ip-address", "model", "serial", "sw-version", "uptime", "system-mode",
                  "app-version", "av-version", "wildfire-version", "time") if k in pano]
    ha = data["panorama_ha"]
    if ha:
        pano_rows += [{"field": "HA enabled", "value": ha.get("enabled", "")},
                      {"field": "HA local state", "value": _ends(ha, "local-info/state")},
                      {"field": "HA peer state", "value": _ends(ha, "peer-info/state")},
                      {"field": "HA peer connection", "value": _ends(ha, "peer-info/conn-status")},
                      {"field": "HA running config", "value": _ends(ha, "running-sync")}]
    for key, label in (("mgmt_cpu_pct", "Management CPU %"), ("mgmt_mem_pct", "Management memory %"),
                       ("ntp_synched", "NTP synched to"), ("ntp_servers", "NTP servers")):
        value = data["panorama_resources"].get(key) or data["panorama_ntp"].get(key)
        if value:
            pano_rows.append({"field": label, "value": value})

    status_cols = sorted({k for d in devices for k in d
                          if "policy-status" in k or "template-status" in k or "last-commit-all" in k})
    inv_cols = columns_for(devices, INVENTORY_COLS[:2] + ["device-group", "template-stack"]
                           + INVENTORY_COLS[2:16] + status_cols, include_extra=False)
    unavailable = set(data.get("unavailable", []))

    rule_summary = Counter((r["location"], r["rulebase"]) for r in data["rules"])
    rule_summary_rows = [{"location": loc, "rulebase": rb, "rules": n,
                          "disabled": sum(1 for r in data["rules"] if r["location"] == loc
                                          and r["rulebase"] == rb and r["disabled"] == "yes")}
                         for (loc, rb), n in sorted(rule_summary.items())]

    inventory_title = ("Firewall inventory (device-group / template-stack membership)"
                       if settings.api_mode == "rest" else "Firewall inventory & connectivity")
    # (html id, title, content, SECTIONS name it depends on)
    candidates = [
        ("findings", "Health findings", _table(findings, FINDING_COLS, "No findings."), None),
        ("panorama", "Panorama", _table(pano_rows, ["field", "value"]), "panorama"),
        ("inventory", inventory_title, _table(devices, inv_cols), "devices"),
        ("fwstatus", "Firewall status (versions, sync, HA, logging)", fw_status_html(data),
         "devices" if any("connected" in d for d in devices) else "sync"),
        ("sync", "Sync status (device groups & templates)", sync_html(data["sync"]), "sync"),
        # XML inventory only: REST device data has no HA fields.
        ("ha", "High availability", ha_html(data), "devices" if any("connected" in d for d in devices) else "sync"),
        ("jobs", f"Recent Panorama jobs (last {settings.max_jobs})",
         _table(data["jobs"], columns_for(data["jobs"], JOB_COLS[:12], include_extra=False)), "jobs"),
        ("collectors", "Log collectors", _table(data["log_collectors"],
                                                columns_for(data["log_collectors"], ["serial", "host-name", "connected"])),
         "collectors"),
        ("rules", "Security rules", _table(rule_summary_rows, ["location", "rulebase", "rules", "disabled"])
         + "<h3>Rule findings</h3>" + _table(rule_findings(data["rules"]), RULE_FINDING_COLS, "No rule findings."),
         "rules"),
        ("certificates", f"Certificates (expiring within {CERT_WARN_DAYS} days first)",
         _table(by_expiry(data["certificates"]), CERT_COLS[:8]), "certificates"),
        ("syslogs", f"System logs, severity high+ (last {settings.log_window_hours}h)",
         _table(data["system_logs"], columns_for(data["system_logs"], SYSLOG_COLS, include_extra=False)), "logs"),
        ("configlogs", f"Configuration logs (last {settings.log_window_hours}h)",
         _table(data["config_logs"], columns_for(data["config_logs"], CONFIGLOG_COLS, include_extra=False)), "logs"),
    ]
    sections = [(sid, title, content) for sid, title, content, needs in candidates if needs not in unavailable]
    if unavailable:
        items = "".join(f"<li>{html.escape(n)}</li>" for n in SECTIONS if n in unavailable)
        sections.append(("not-collected", "Not collected",
                         "<p>The REST API has no endpoints for these sections; the default run, which uses "
                         f"the XML API, collects them:</p><ul>{items}</ul>"))
    if data["resources"]:
        sections.append(("resources", "Per-firewall live status (HA, sessions, CPU, memory)",
                         _table(data["resources"], columns_for(data["resources"], RESOURCE_COLS))))
    if data["disk"]:
        disks = sorted(data["disk"], key=lambda d: -int(d["use_pct"]))
        sections.append(("disk", "Disk usage", _table(disks, DISK_COLS)))
    if data["errors"]:
        sections.append(("errors", "Collection errors", _table(data["errors"], ["section", "error"])))

    nav = "".join(f'<a href="#{sid}">{html.escape(title)}</a>' for sid, title, _ in sections)
    body = "".join(f'<section id="{sid}"><h2>{html.escape(title)}</h2>{content}</section>'
                   for sid, title, content in sections)
    calls_html = "".join(f"<li>{html.escape(c)}</li>" for c in calls)

    doc = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Panorama Health Check</title><style>{HTML_STYLE}</style></head>
<body><main>
<h1>Panorama Health Check</h1>
<div class="meta">Panorama {html.escape(settings.host)} &middot; collected {started:%Y-%m-%d %H:%M:%S}
 &middot; {settings.api_mode.upper()} API &middot; {len(calls)} read-only API calls</div>
{f'<p class="scope"><b>{html.escape(data["scope_note"])}.</b> Run without --quick/--device-groups for the full report.</p>' if data.get("scope_note") else ""}
<nav>{nav}</nav>
<div class="tiles">{tiles_html}</div>
{body}
<details><summary>API calls made ({len(calls)})</summary><ol>{calls_html}</ol></details>
</main></body></html>"""
    Path(path).write_text(doc, encoding="utf-8")


# --------------------------------------------------------------------------
# Diagnose
# --------------------------------------------------------------------------

REST_CHECKS = [
    ("Policies/SecurityPreRules (shared)", "Policies/SecurityPreRules", {"location": "shared"}),
    ("Policies/SecurityPostRules (shared)", "Policies/SecurityPostRules", {"location": "shared"}),
]


def diagnose(client, mode=None):
    """Check API access: the XML API by default, the REST API when mode='rest' (menu only)."""
    s = replace(client.settings, api_mode=mode or client.settings.api_mode)
    print(f"Diagnosing {s.api_mode.upper()} API access to {s.host} (read-only checks)")
    print(f"Using {s.key_label()}\n")
    return diagnose_rest(client) if s.api_mode == "rest" else diagnose_xml(client)


def diagnose_rest(client):
    ok = True
    for label, endpoint, query in REST_CHECKS:
        try:
            entries = client.rest_get(endpoint, query)
            print(f"  PASS  {label} ({len(entries)} entries)")
        except ApiError as exc:
            ok = False
            print(f"  FAIL  {label}\n        {exc}")

    collector = Collector(client, client.settings)
    try:
        with_query = collector._rest_device_groups()
        names = ", ".join(e.get("@name", "") for e in with_query) or "none"
        print(f"  PASS  Panorama/DeviceGroups ({len(with_query)}: {names})")
        stacks = client.rest_get("Panorama/TemplateStacks", collector._panorama_query)
        print(f"  PASS  Panorama/TemplateStacks ({len(stacks)} entries)")
    except ApiError as exc:
        ok = False
        print(f"  FAIL  Panorama/DeviceGroups or TemplateStacks\n        {exc}")

    print("\nThe REST API covers configuration only: inventory by device group, and security rules.")
    print("Connectivity, HA, sync, jobs and logs come from the XML API, which every default run uses.")
    print("\nAll checks passed." if ok else "\nSome checks failed; the report will include what passed.")
    return 0 if ok else 1


def diagnose_xml(client):
    checks = [
        ("Operational request: show system info", lambda: client.op("system_info")),
        ("Operational request: show devices all", lambda: client.op("devices_all")),
        ("Configuration read: Panorama hostname",
         lambda: client.config_show(f"{PANORAMA_DEVICE_XPATH}/deviceconfig/system/hostname")),
        ("Log read: 1 system log", lambda: client.log_query("system", "", 1)),
    ]
    ok = True
    denied = False
    for label, call in checks:
        try:
            result = call()
            extra = ""
            if label.endswith("show devices all") and result is not None:
                extra = f" ({len(result.findall('./devices/entry'))} firewalls)"
            print(f"  PASS  {label}{extra}")
        except ApiError as exc:
            ok = False
            denied = denied or exc.code in ("16", "403")
            print(f"  FAIL  {label}\n        {exc}")
    if denied:
        compare_key_methods(client)
    print("\nAll checks passed." if ok else "\nSome checks failed; see the hints above.")
    return 0 if ok else 1


KEY_METHODS = [
    ("X-PAN-KEY header, POST", {"key_in_header": True, "http_method": "POST"}),
    ("X-PAN-KEY header, GET", {"key_in_header": True, "http_method": "GET"}),
    ("key in POST body", {"key_in_header": False, "http_method": "POST"}),
]


def compare_key_methods(client):
    """Repeat one small config read with each way of sending the key."""
    print("\nAccess was denied. Trying the same config read with each way of sending the key:")
    xpath = f"{PANORAMA_DEVICE_XPATH}/deviceconfig/system/hostname"
    working = []
    for label, changes in KEY_METHODS:
        probe = PanoramaClient(replace(client.settings, **changes), transport=client._transport, log=client.log)
        try:
            probe.config_show(xpath)
            accepted = True
        except ApiError as exc:
            accepted = exc.code not in ("16", "403")  # any other error means the key got through
            if not accepted:
                print(f"  FAIL  {label}: code {exc.code}")
        if accepted:
            working.append(changes)
            print(f"  PASS  {label}")
        client.calls += probe.calls
    current = {"key_in_header": client.settings.key_in_header, "http_method": client.settings.http_method}
    if current in working:
        print("\n  -> The current method works for config reads; the failures above are role permissions.")
    elif working:
        best = working[0]
        print("\n  -> Panorama accepts the key another way. Set these in .env and run --diagnose again:")
        print(f"       KEY_IN_HEADER={'true' if best['key_in_header'] else 'false'}")
        print(f"       HTTP_METHOD={best['http_method']}")
    else:
        print("\n  -> Every method was denied: the role has no XML API access. Check that PANORAMA_XML_API_KEY")
        print("     is the XML key, and enable Panorama > Admin Roles > <role> > XML API.")


# --------------------------------------------------------------------------
# Interactive menu
# --------------------------------------------------------------------------

SEV_STYLE = {"critical": "1;31", "high": "1;38;5;208", "medium": "33", "low": "36", "info": "2"}
SECTION_INFO = {
    "panorama": "Panorama version, HA, CPU/memory, disk, NTP",
    "devices": "firewall inventory, connectivity, versions, device certificates",
    "sync": "device-group and template sync status",
    "jobs": "failed commit and push jobs",
    "collectors": "log collector connectivity",
    "rules": "security rule checks",
    "certificates": "certificate expiry (Panorama, shared, templates)",
    "logs": "high-severity system logs and config changes",
    "targeted": "live per-firewall HA, sessions, CPU, packet buffer, disk",
}
REST_SECTIONS = [s for s in SECTIONS if hasattr(Collector, f"collect_{s}_rest")]
REPORT_DIR_RE = re.compile(r"\d{8}-\d{6}")


def estimate_calls(mode, sections, groups=0, templates=0, firewalls=0):
    """Minimum number of API calls a run makes (each log query adds at least one poll)."""
    if mode == "rest":
        calls = 2 if "devices" in sections else 0
        if "rules" in sections:
            calls += 2 * (1 + groups) + (0 if "devices" in sections else 1)
        return calls
    per_section = {"panorama": 5, "devices": 1, "sync": 2, "jobs": 1, "collectors": 1, "logs": 4}
    calls = sum(per_section.get(s, 0) for s in sections)
    if "rules" in sections:
        calls += 2 * (1 + groups) + (0 if "sync" in sections else 1)
    if "certificates" in sections:
        calls += 2 + templates + (0 if "sync" in sections else 1)
    if "targeted" in sections:
        calls += len(TARGETED_CALLS) * firewalls
    return calls


@dataclass
class MenuItem:
    key: str
    label: str
    hint: str = ""
    style: str = ""
    disabled: bool = False


def _enable_ansi():
    """Turn on ANSI escape handling in the Windows console; True if colors and redraws will work."""
    if os.name != "nt":
        return True
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        handle = kernel32.GetStdHandle(-11)
        mode = ctypes.c_uint32()
        return bool(kernel32.GetConsoleMode(handle, ctypes.byref(mode))
                    and kernel32.SetConsoleMode(handle, mode.value | 0x0004))
    except (AttributeError, OSError):
        return False


WIN_KEYS = {"H": "up", "P": "down", "K": "left", "M": "right", "I": "pgup", "Q": "pgdn", "G": "home", "O": "end"}
ANSI_KEYS = {"[A": "up", "[B": "down", "[C": "right", "[D": "left", "[5~": "pgup", "[6~": "pgdn",
             "[H": "home", "[F": "end", "OH": "home", "OF": "end", "[1~": "home", "[4~": "end"}
NAMED_KEYS = {"\r": "enter", "\n": "enter", "\x1b": "esc", "\x08": "backspace", "\x7f": "backspace",
              " ": "space", "\t": "tab"}


def read_key():
    """Read one keypress: a named key ('up', 'enter', 'esc', ...) or the character typed."""
    if os.name == "nt":
        import msvcrt
        ch = msvcrt.getwch()
        if ch in ("\x00", "\xe0"):
            return WIN_KEYS.get(msvcrt.getwch(), "")
    else:
        import select
        import termios
        import tty
        fd = sys.stdin.fileno()
        old = termios.tcgetattr(fd)
        try:
            tty.setraw(fd)
            ch = os.read(fd, 1).decode(errors="ignore")
            if ch == "\x1b":
                seq = ""
                while len(seq) < 3 and seq not in ANSI_KEYS and select.select([fd], [], [], 0.03)[0]:
                    seq += os.read(fd, 1).decode(errors="ignore")
                if seq:
                    return ANSI_KEYS.get(seq, "")
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old)
    if ch == "\x03":
        raise KeyboardInterrupt
    return NAMED_KEYS.get(ch, ch)


def _open_path(path):
    """Open a report file or folder with the desktop's default application."""
    if os.name == "nt":
        os.startfile(str(path))
    else:
        import webbrowser
        webbrowser.open(Path(path).resolve().as_uri())


def _read_csv(path):
    try:
        with open(path, newline="", encoding="utf-8-sig") as fh:
            return list(csv.DictReader(fh))
    except OSError:
        return []


class Tui:
    """Terminal UI: arrow-key menus on a real terminal, numbered prompts otherwise (pipes, dumb terminals, tests)."""

    def __init__(self, out=None, read_line=None, keys=None):
        self.out = out or sys.stdout
        terminal = self.out.isatty() and sys.stdin.isatty() and os.environ.get("TERM") != "dumb"
        self.color = bool(terminal and not os.environ.get("NO_COLOR") and _enable_ansi())
        self.arrows = keys is not None or (self.color and read_line is None)
        self.read_line = read_line or input
        if keys is not None:
            keys = iter(keys)
            self.read_key = lambda: next(keys)
        else:
            self.read_key = read_key
        self.header = lambda: []
        try:
            "▸─·✓↑↓…".encode(getattr(self.out, "encoding", None) or "ascii")
            self.g = {"cursor": "▸", "rule": "─", "dot": "·", "on": "✓", "updown": "↑↓", "more": "…"}
        except (UnicodeEncodeError, LookupError):
            self.g = {"cursor": ">", "rule": "-", "dot": "|", "on": "x", "updown": "up/down", "more": "~"}

    # ---- output ----

    def s(self, text, code):
        return f"\033[{code}m{text}\033[0m" if self.color and code else str(text)

    def write(self, text=""):
        print(text, file=self.out, flush=True)

    @property
    def width(self):
        return max(40, shutil.get_terminal_size((100, 30)).columns - 1)

    @property
    def height(self):
        return max(12, shutil.get_terminal_size((100, 30)).lines)

    def screen(self, title=""):
        if self.arrows:
            self.out.write("\033[H\033[2J\033[3J")
        for line in self.header():
            self.write(line)
        if title:
            self.write("\n " + self.s(title, "1"))
        self.write()

    def message(self, text, code="33"):
        self.write("  " + self.s(text, code))

    def pause(self, text="Press any key to continue"):
        if self.arrows:
            self.write(self.s(f"\n  {text}", "2"))
            self.read_key()
        else:
            self.read_line(f"\n  {text.replace('any key', 'Enter')} ")

    def prompt(self, label, default=""):
        suffix = f" [{default}]" if str(default) != "" else ""
        text = self.read_line(f"  {label}{suffix}: ").strip()
        return text or str(default)

    def fit(self, text, width):
        text = str(text).replace("\n", " ")
        return text if len(text) <= width else text[: max(0, width - 1)] + self.g["more"]

    def format_table(self, rows, cols, width=None):
        """Aligned plain-text table: (header line, [row lines]), shrunk to fit the terminal."""
        width = (width or self.width) - 8
        widths = {c: min(36, max([len(c)] + [len(str(r.get(c, ""))) for r in rows])) for c in cols}
        while sum(widths.values()) + 2 * len(cols) > width and max(widths.values()) > 6:
            widest = max(widths, key=widths.get)
            widths[widest] -= 1

        def line(values):
            return "  ".join(self.fit(v, widths[c]).ljust(widths[c]) for c, v in zip(cols, values)).rstrip()

        return line(cols), [line([r.get(c, "") for c in cols]) for r in rows]

    def table_items(self, rows, cols, style=None):
        head, lines = self.format_table(rows, cols)
        items = [MenuItem(str(n), text, style=style(row) if style else "")
                 for n, (row, text) in enumerate(zip(rows, lines), 1)]
        return head, items

    def table_lines(self, rows, cols, style=None):
        head, lines = self.format_table(rows, cols)
        return ["  " + self.s(head, "1")] + ["  " + self.s(text, style(row) if style else "")
                                              for row, text in zip(rows, lines)]

    # ---- input ----

    def select(self, title, items, intro=(), head="", filterable=False, show_keys=True):
        """Pick one item; returns its key, or None for Esc/back."""
        return self._list(title, items, intro, head, False, (), None, filterable, show_keys)

    def checklist(self, title, items, selected=(), limit=None, intro=(), head="", filterable=False):
        """Pick any number of items; returns their keys in list order, or None if cancelled."""
        return self._list(title, items, intro, head, True, selected, limit, filterable, False)

    @staticmethod
    def _filter(items, query):
        words = query.lower().split()
        return [i for i in items if all(w in f"{i.label} {i.hint}".lower() for w in words)]

    def _list(self, title, items, intro, head, multi, selected, limit, filterable, show_keys):
        chosen = {k for k in selected if any(i.key == k for i in items)}
        if not self.arrows:
            return self._plain_list(title, items, intro, head, multi, chosen, limit, filterable)
        query, cursor, top, note = "", 0, 0, ""
        while True:
            shown = self._filter(items, query)
            cursor = max(0, min(cursor, len(shown) - 1))
            self.screen(title)
            for line in intro:
                self.write(line)
            if intro:
                self.write()
            if filterable:
                self.write(f"  {self.s('Filter:', '2')} {query}{self.s('_', '5')}   "
                           + self.s(f"{len(shown)} of {len(items)}", "2"))
            key_width = max([len(i.key) for i in items] + [1]) if show_keys else 0
            indent = " " * (3 + (4 if multi else 0) + (key_width + 2 if key_width else 0))
            if head:
                self.write(self.s(indent + head, "1"))
            rows = max(3, self.height - len(self.header()) - len(intro) - (10 if filterable else 8))
            if cursor < top:
                top = cursor
            elif cursor >= top + rows:
                top = cursor - rows + 1
            top = max(0, min(top, max(0, len(shown) - rows)))
            if top:
                self.write(self.s(f"{indent}{self.g['updown'][0]} {top} more", "2"))
            label_width = min(40, max([len(i.label) for i in items if i.hint] + [0]))
            for idx in range(top, min(len(shown), top + rows)):
                item = shown[idx]
                self.write(self._item_line(item, idx == cursor, multi, item.key in chosen, key_width, label_width))
            if not shown:
                self.write(self.s(f"{indent}(nothing matches '{query}')", "2"))
            if top + rows < len(shown):
                self.write(self.s(f"{indent}{self.g['updown'][-1]} {len(shown) - top - rows} more", "2"))
            help_text = f"{self.g['updown']} move"
            if multi:
                help_text += " · Space toggle · + all · - none · Enter confirm"
                help_text += f" · {len(chosen)} selected" + (f" (max {limit})" if limit else "")
            else:
                help_text += " · Enter select" + (" · type a key" if show_keys and not filterable else "")
            help_text += " · type to filter" if filterable else ""
            self.write("\n  " + self.s(help_text + " · Esc back", "2"))
            if note:
                self.write("  " + self.s(note, "33"))
                note = ""

            key = self.read_key()
            if key in ("up", "down", "pgup", "pgdn", "home", "end") and shown:
                step = {"up": -1, "down": 1, "pgup": -rows, "pgdn": rows}.get(key)
                if step in (-1, 1):
                    cursor = (cursor + step) % len(shown)
                elif step:
                    cursor = max(0, min(len(shown) - 1, cursor + step))
                else:
                    cursor = 0 if key == "home" else len(shown) - 1
            elif key == "enter":
                if multi:
                    return [i.key for i in items if i.key in chosen]
                if shown:
                    if shown[cursor].disabled:
                        note = f"Not available: {shown[cursor].hint}"
                        continue
                    return shown[cursor].key
            elif key in ("esc", "left"):
                return None
            elif multi and key == "space" and shown:
                k = shown[cursor].key
                if k in chosen:
                    chosen.discard(k)
                elif limit and len(chosen) >= limit:
                    note = f"At most {limit} can be selected (MAX_TARGETED_FIREWALLS)."
                else:
                    chosen.add(k)
            elif multi and key == "+":
                for item in shown:
                    if not limit or len(chosen) < limit:
                        chosen.add(item.key)
            elif multi and key == "-":
                chosen.clear()
            elif key == "backspace" and filterable:
                query = query[:-1]
            elif len(key) == 1 and key.isprintable():
                if filterable:
                    query, cursor, top = query + key, 0, 0
                    continue
                match = next((i for i in items if i.key.lower() == key.lower()), None)
                if match and not multi:
                    if match.disabled:
                        note = f"Not available: {match.hint}"
                        continue
                    return match.key
                if key.lower() == "q":
                    return None

    def _item_line(self, item, current, multi, on, key_width, label_width=0):
        mark = self.s(self.g["cursor"], "1;36") if current else " "
        box = (self.s(f"[{self.g['on']}] ", "32") if on else "[ ] ") if multi else ""
        key = self.s(f"{item.key:>{key_width}}  ", "36") if key_width else ""
        room = self.width - 3 - (4 if multi else 0) - (key_width + 2 if key_width else 0)
        label = self.fit(item.label, room)
        if item.hint:
            label = label.ljust(label_width)
        hint = self.fit(item.hint, room - len(label) - 3) if item.hint and room - len(label) > 8 else ""
        style = "2" if item.disabled else ("1" if current else item.style)
        if current and item.style and not item.disabled:
            style = f"1;{item.style}"
        text = self.s(label, style) + (self.s(f"   {hint}", "2") if hint else "")
        return f" {mark} {box}{key}{text}"

    def _plain_list(self, title, items, intro, head, multi, chosen, limit, filterable):
        query = ""
        while True:
            shown = self._filter(items, query)
            self.screen(title)
            for line in intro:
                self.write(line)
            if head:
                self.write((" " * 11 if multi else " " * 7) + head)
            label_width = min(40, max([len(i.label) for i in shown if i.hint] + [0]))
            for n, item in enumerate(shown, 1):
                hint = f"{' ' * (label_width - len(item.label))}   {item.hint}" if item.hint else ""
                if multi:
                    self.write(f"  {n:>3}) [{'x' if item.key in chosen else ' '}] {item.label}{hint}")
                else:
                    self.write(f"  {item.key:>3}) {item.label}{hint}{'  (not available)' if item.disabled else ''}")
            if multi:
                tip = "numbers or ranges toggle (1,3-5), a all, n none, Enter confirm, q cancel"
            else:
                tip = "type a key, Enter for back"
            if filterable:
                tip += ", /text filters"
            answer = self.read_line(f"  {tip}\n  > ").strip()
            if filterable and answer.startswith("/"):
                query = answer[1:]
                continue
            if multi:
                if not answer:
                    return [i.key for i in items if i.key in chosen]
                if answer.lower() == "q":
                    return None
                if answer.lower() in ("a", "+"):
                    chosen |= {i.key for i in shown[: limit or None]}
                elif answer.lower() in ("n", "-"):
                    chosen.clear()
                else:
                    for n in self._parse_numbers(answer, len(shown)):
                        k = shown[n - 1].key
                        if k in chosen:
                            chosen.discard(k)
                        elif not limit or len(chosen) < limit:
                            chosen.add(k)
                        else:
                            self.message(f"At most {limit} can be selected.")
                if limit and len(chosen) > limit:
                    chosen = set(sorted(chosen, key=[i.key for i in items].index)[:limit])
                continue
            if not answer:
                return None
            match = next((i for i in items if i.key.lower() == answer.lower()), None)
            if match and not match.disabled:
                return match.key
            self.message(f"Not available: {match.hint}" if match else f"Unknown choice: {answer}")

    @staticmethod
    def _parse_numbers(text, count):
        numbers = []
        for part in re.split(r"[,\s]+", text):
            m = re.fullmatch(r"(\d+)(?:-(\d+))?", part)
            if m:
                lo, hi = int(m.group(1)), int(m.group(2) or m.group(1))
                numbers += [n for n in range(lo, hi + 1) if 1 <= n <= count]
        return numbers

    def view(self, title, lines):
        """Scrollable text view."""
        lines = list(lines) or ["  (nothing to show)"]
        if not self.arrows:
            self.screen(title)
            for line in lines:
                self.write(line)
            self.pause()
            return
        top = 0
        while True:
            self.screen(title)
            rows = max(3, self.height - len(self.header()) - 6)
            top = max(0, min(top, len(lines) - rows))
            for line in lines[top: top + rows]:
                self.write(line)
            where = f"lines {top + 1}-{min(len(lines), top + rows)} of {len(lines)} · " if len(lines) > rows else ""
            self.write("\n  " + self.s(f"{where}{self.g['updown']} scroll · Esc back", "2"))
            key = self.read_key()
            moves = {"up": -1, "down": 1, "pgup": -rows, "pgdn": rows, "space": rows,
                     "home": -len(lines), "end": len(lines)}
            if key in moves:
                top += moves[key]
            elif key in ("esc", "enter", "left", "backspace", "q"):
                return


class MenuApp:
    """Menu-driven front end. Every Panorama call still goes through PanoramaClient and its guards."""

    def __init__(self, settings, transport=None, tui=None):
        self.settings = settings
        self.env = replace(settings)  # values from .env: the menu can make runs lighter, never heavier
        self.transport = transport
        self.tui = tui or Tui()
        self.tui.header = self.header_lines
        self.client = PanoramaClient(settings, transport=transport, log=self.tui.write)
        self.formats = ["html", "csv"]
        self.cache = None
        self.cache_errors = {}
        self.last_run = ""

    # ---- inventory that populates the menus (cached; refresh on request) ----

    def load_inventory(self, force=False):
        if self.cache is not None and not force:
            return
        self.cache, self.cache_errors = {"devices": [], "groups": [], "templates": []}, {}
        self.tui.write(self.tui.s("  Loading inventory from Panorama (read-only)...", "2"))
        fetches = [("devices", self._xml_devices), ("groups", lambda: self._xml_groups("devicegroups")),
                   ("templates", lambda: self._xml_groups("templates"))]
        for key, fetch in fetches:
            try:
                self.cache[key] = fetch()
            except ApiError as exc:
                self.cache_errors[key] = str(exc)

    def _xml_devices(self):
        collector = Collector(self.client, self.settings)
        collector.collect_devices()
        return collector.data["devices"]

    def _xml_groups(self, kind):
        try:
            result = self.client.op(kind)
            return [(e.get("name"), e) for e in result.findall(f"./{kind}/entry") if e.get("name")]
        except ApiError as exc:
            if exc.code not in ("16", "403"):
                raise
        # No 'Operational Requests' permission: read the names from the config instead.
        node = "device-group" if kind == "devicegroups" else "template"
        names = self.client.request({"type": "config", "action": "get",
                                     "xpath": f"{PANORAMA_DEVICE_XPATH}/{node}/entry/@name"},
                                    f"config get {node} names")
        return [(e.get("name"), None) for e in top_entries(names) if e.get("name")]

    def group_names(self):
        return [name for name, _ in self.cache["groups"]]

    def cached_sync_rows(self):
        return [row for kind, sync_kind in (("groups", "device-group"), ("templates", "template"))
                for _, el in self.cache[kind] if el is not None for row in Collector._sync_rows(sync_kind, [el])]

    def connected(self):
        return [d for d in self.cache["devices"] if d.get("connected") == "yes"]

    @staticmethod
    def mode_sections():
        return list(SECTIONS)

    def estimate(self, sections, groups=None, templates=None, firewalls=0):
        groups = len(self.cache["groups"]) if groups is None else groups
        templates = len(self.cache["templates"]) if templates is None else templates
        return estimate_calls("xml", sections, groups, templates, firewalls)

    # ---- layout ----

    def header_lines(self):
        t, s = self.tui, self.settings
        dot = f" {t.g['dot']} "
        rule = t.s(t.g["rule"] * min(t.width, 96), "2")
        key = f"key ...{s.api_key[-4:]}" if s.api_key else t.s("no key", "31")
        lines = [rule, " " + t.s("PANORAMA HEALTH CHECK", "1;36") + t.s("   read-only", "2"),
                 " " + dot.join([s.host, "XML API", key])]
        if self.cache is not None:
            parts = []
            if self.cache["devices"]:
                down = len(self.cache["devices"]) - len(self.connected())
                parts.append(f"{len(self.cache['devices'])} firewalls "
                             + (t.s(f"({down} not connected)", "31") if down else t.s("(all connected)", "32")))
            parts.append(f"{len(self.cache['groups'])} device groups")
            parts.append(f"{len(self.cache['templates'])} templates")
            lines.append(" " + dot.join(parts))
            if self.cache_errors:
                lines.append(" " + t.s(f"Could not read: {', '.join(self.cache_errors)} (see Diagnose)", "33"))
        if self.last_run:
            lines.append(" " + self.last_run)
        lines.append(rule)
        return lines

    def _safe(self, action, *args):
        """Run a menu action; API errors and Ctrl+C return to the menu instead of exiting."""
        try:
            action(*args)
        except ApiError as exc:
            self.tui.write()
            for line in textwrap.wrap(str(exc), self.tui.width - 4):
                self.tui.message(line, "31")
            self.tui.pause()
        except KeyboardInterrupt:
            self.tui.write()
            self.tui.message("Cancelled.")
            self.tui.pause()

    # ---- main menu ----

    def run(self):
        try:
            self.load_inventory()
        except KeyboardInterrupt:
            pass
        actions = {"1": self.full_check, "2": self.quick_check, "3": self.custom_check, "4": self.browse,
                   "5": self.run_diagnose, "6": self.preview, "7": self.reports, "8": self.settings_menu,
                   "9": self.rest_menu, "r": lambda: self.load_inventory(force=True)}
        while True:
            try:
                choice = self.tui.select("Main menu", self.main_items())
            except KeyboardInterrupt:
                choice = None
            if choice in (None, "q"):
                self.tui.write("\n  Bye.")
                return 0
            self._safe(actions[choice])

    def main_items(self):
        full = [s for s in self.mode_sections() if s != "targeted"]
        groups, templates = len(self.cache["groups"]), len(self.cache["templates"])
        dot = f" {self.tui.g['dot']} "
        reports = self._report_dirs()
        devices = self.cache["devices"]
        s = self.settings
        return [
            MenuItem("1", "Full health check",
                     dot.join([f"{len(full)} sections", f"{groups} device groups", f"~{self.estimate(full)} calls"])),
            MenuItem("2", "Quick health check",
                     dot.join([f"shared + first {QUICK_DEVICE_GROUPS} device groups",
                               f"~{self.estimate(full, min(groups, QUICK_DEVICE_GROUPS), min(templates, QUICK_DEVICE_GROUPS))} calls"])),
            MenuItem("3", "Custom health check...", "choose sections, device groups, firewalls and formats"),
            MenuItem("4", "Browse Panorama (live)",
                     f"{len(devices)} firewalls, {groups} device groups, HA & sync, jobs, Panorama status"),
            MenuItem("5", "Diagnose API access", "test each permission and how the key is sent"),
            MenuItem("6", "Preview API calls", "dry run of a full check; sends nothing"),
            MenuItem("7", "Past reports", f"{len(reports)} in {s.output_dir}"),
            MenuItem("8", "Session settings",
                     dot.join([f"delay {s.request_delay:g}s", f"logs {s.log_window_hours}h",
                               ",".join(self.formats)])),
            MenuItem("9", "REST API (optional)",
                     "security rules and membership via REST; never used otherwise" if s.rest_api_key
                     else f"{API_KEY_VARS['rest']} is empty in .env", disabled=not s.rest_api_key),
            MenuItem("r", "Refresh inventory", "re-read firewalls and groups (3 calls)"),
            MenuItem("q", "Quit"),
        ]

    # ---- health checks ----

    def full_check(self):
        self.execute("Full health check", [s for s in self.mode_sections() if s != "targeted"])

    def quick_check(self):
        self.execute("Quick health check", [s for s in self.mode_sections() if s != "targeted"],
                     max_groups=QUICK_DEVICE_GROUPS)

    def preview(self):
        self.execute("Preview: full health check", [s for s in self.mode_sections() if s != "targeted"], dry=True)

    def execute(self, title, sections, dry=False, settings=None, **scope):
        self.tui.screen(title + (" (dry run, nothing is sent)" if dry else ""))
        if not dry:
            self.tui.message("Ctrl+C cancels.", "2")
        client = PanoramaClient(self.settings, dry_run=True, transport=self.transport,
                                log=self.tui.write) if dry else self.client
        started = time.monotonic()
        first = len(client.calls)
        data, findings, out_dir = run_health_check(client, settings or self.settings, sections, self.formats,
                                                   **scope)
        calls = len(client.calls) - first
        if dry:
            self.tui.write(f"\n  Preview complete: {calls} calls listed, nothing sent.")
            self.tui.pause()
            return
        sev = Counter(f["severity"] for f in findings)
        self.last_run = self.tui.s(f"Last run {out_dir.name}: ", "2") + "  ".join(
            self.tui.s(f"{name} {sev[name]}", SEV_STYLE[name]) for name in ("critical", "high", "medium") if sev[name]
        ) if findings else ""
        self.results(data, findings, out_dir, calls, time.monotonic() - started)

    def results(self, data, findings, out_dir, calls, elapsed):
        t = self.tui
        dot = f" {t.g['dot']} "
        sev = Counter(f["severity"] for f in findings)
        intro = ["  " + t.s("Health check complete", "1;32") + dot + dot.join(
                     [f"{calls} read-only calls", f"{elapsed:.0f}s", f"{len(data['devices'])} firewalls"]),
                 "  " + t.s(f"Report: {out_dir}", "2"), "",
                 "  " + "   ".join(t.s(f"{name.upper()} {sev[name]}", SEV_STYLE[name] if sev[name] else "2")
                                   for name in SEVERITY_ORDER)]
        if data.get("scope_note"):
            intro.append("  " + t.s(data["scope_note"], "33"))
        if data["errors"]:
            intro.append("  " + t.s(f"{len(data['errors'])} part(s) could not be collected; see collection errors",
                                    "33"))
        top = [f for f in findings if f["severity"] != "info"][:8]
        if top:
            intro += ["", "  " + t.s("Top findings", "1")]
            intro += ["  " + t.s(f"{f['severity']:<9}", SEV_STYLE[f["severity"]])
                      + t.fit(f"{t.fit(f['target'], 24):<24}  {f['finding']}", t.width - 14) for f in top]
        rules = rule_findings(data["rules"])
        html_path = out_dir / "report.html"
        while True:
            items = [
                MenuItem("o", "Open HTML report", str(html_path) if html_path.exists() else "HTML format was off",
                         disabled=not html_path.exists()),
                MenuItem("f", f"View all findings ({len(findings)})"),
                MenuItem("r", f"View rule findings ({len(rules)})", disabled=not rules, hint="" if rules else "none"),
                MenuItem("e", f"View collection errors ({len(data['errors'])})", disabled=not data["errors"],
                         hint="" if data["errors"] else "none"),
                MenuItem("d", "Open report folder"),
                MenuItem("b", "Back to main menu"),
            ]
            choice = t.select("Results", items, intro=intro)
            if choice in (None, "b"):
                return
            if choice == "o":
                _open_path(html_path)
            elif choice == "f":
                t.view("All findings", t.table_lines(findings, FINDING_COLS, self._sev_style))
            elif choice == "r":
                t.view("Rule findings", t.table_lines(rules, RULE_FINDING_COLS, self._sev_style))
            elif choice == "e":
                t.view("Collection errors", self._error_lines(data["errors"]))
            elif choice == "d":
                _open_path(out_dir)

    @staticmethod
    def _sev_style(row):
        return SEV_STYLE.get(row.get("severity", ""), "")

    def _error_lines(self, errors):
        lines = []
        for err in errors:
            lines.append("  " + self.tui.s(err["section"], "1;31"))
            lines += ["    " + part for part in textwrap.wrap(err["error"], self.tui.width - 6)] + [""]
        return lines

    def custom_check(self):
        t = self.tui
        available = self.mode_sections()
        items = [MenuItem(s, f"{s:<13}", SECTION_INFO[s]) for s in available]
        sections = t.checklist("Custom health check 1/4: sections", items,
                               selected=[s for s in available if s != "targeted"])
        if not sections:
            return
        scope = {}
        groups, templates, firewalls = len(self.cache["groups"]), len(self.cache["templates"]), 0
        if "rules" in sections and self.cache["groups"]:
            names = self.group_names()
            members = {name: len(el.findall("./devices/entry")) for name, el in self.cache["groups"] if el is not None}
            picked = t.checklist(
                "Custom health check 2/4: device groups for security rules (shared is always included)",
                [MenuItem(n, n, f"{members[n]} firewalls" if n in members else "") for n in names],
                selected=names, filterable=True)
            if picked is None:
                return
            if len(picked) < len(names):
                scope["only_groups"], scope["max_groups"] = picked, len(picked)
            groups = len(picked)
        if "targeted" in sections:
            connected = self.connected()
            if not connected:
                t.message("No connected firewalls are known, so live per-firewall checks are skipped.")
                t.pause()
                sections.remove("targeted")
            else:
                cap = self.settings.max_targeted
                head, fw_items = t.table_items(connected, ["hostname", "serial", "model", "sw-version", "ha/state"])
                for item, dev in zip(fw_items, connected):
                    item.key = dev.get("serial", "")
                picked = t.checklist(f"Custom health check 3/4: firewalls for live checks (max {cap}, "
                                     f"{len(TARGETED_CALLS)} calls each)", fw_items,
                                     selected=[d.get("serial", "") for d in connected[:cap]], limit=cap,
                                     head=head, filterable=True)
                if picked is None:
                    return
                if picked:
                    scope["only_serials"], firewalls = picked, len(picked)
                else:
                    sections.remove("targeted")
        formats = t.checklist("Custom health check 4/4: report formats",
                              [MenuItem("html", "HTML report", "report.html, one self-contained page"),
                               MenuItem("csv", "CSV files", "one file per table, for Excel")],
                              selected=self.formats)
        if not formats:
            return
        estimate = self.estimate(sections, groups, templates, firewalls)
        dot = f" {t.g['dot']} "
        groups_text = (", ".join(scope["only_groups"]) or "shared only") if "only_groups" in scope else "all"
        rows = [("Sections", ", ".join(sections)),
                ("Device groups", groups_text if "rules" in sections else ""),
                ("Firewalls", ", ".join(scope.get("only_serials", [])) if "targeted" in sections else ""),
                ("Formats", ", ".join(formats)),
                ("Estimate", f"~{estimate} read-only API calls{dot}{self.settings.request_delay:g}s apart{dot}"
                             f"~{estimate * max(self.settings.request_delay, 0.5):.0f}s or more")]
        intro = [f"  {t.s(f'{label:<14}', '2')} {value}" for label, value in rows if value]
        saved, self.formats = self.formats, formats
        try:
            while True:
                choice = t.select("Custom health check: ready", [
                    MenuItem("r", "Run now"), MenuItem("p", "Preview the exact calls (dry run)"),
                    MenuItem("b", "Cancel")], intro=intro)
                if choice == "p":
                    self.execute("Preview: custom health check", list(sections), dry=True, **scope)
                    continue
                if choice == "r":
                    self.execute("Custom health check", list(sections), **scope)
                return
        finally:
            self.formats = saved

    def run_diagnose(self, mode=None):
        self.tui.screen(f"Diagnose {(mode or 'xml').upper()} API access")
        diagnose(self.client, mode)
        self.tui.pause()

    # ---- REST API: only ever used from here ----

    def rest_menu(self):
        t = self.tui
        intro = [f"  {t.s('Using', '2')} {replace(self.settings, api_mode='rest').key_label()}",
                 "  " + t.s("Every other check uses the XML API only. Nothing here runs unless you pick it.", "2")]
        while True:
            estimate = estimate_calls("rest", REST_SECTIONS, len(self.cache["groups"]))
            choice = t.select("REST API (optional, GET only)", [
                MenuItem("r", "Security rules and membership via REST",
                         f"~{estimate} REST GET calls; device groups, template stacks, pre/post rules"),
                MenuItem("p", "Preview the REST calls", "dry run; sends nothing"),
                MenuItem("d", "Diagnose REST API access", "Policies, Panorama/DeviceGroups, TemplateStacks"),
                MenuItem("b", "Back")], intro=intro)
            if choice in (None, "b"):
                return
            if choice == "d":
                self._safe(self.run_diagnose, "rest")
            else:
                # A per-run copy: the REST setting never outlives this run, and session limits still apply.
                self._safe(self.execute, "REST API: security rules and membership", list(REST_SECTIONS),
                           choice == "p", replace(self.settings, api_mode="rest"))

    # ---- browse (live, read-only) ----

    def browse(self):
        while True:
            devices, dot = self.cache["devices"], f" {self.tui.g['dot']} "
            down = len(devices) - len(self.connected())
            items = [
                MenuItem("f", f"Firewalls ({len(devices)})", f"{down} not connected" if down else "all connected",
                         style="31" if down else ""),
                MenuItem("g", f"Device groups ({len(self.cache['groups'])})", "members and policy sync; collect rules"),
                MenuItem("t", f"Templates ({len(self.cache['templates'])})", "members and template sync"),
                MenuItem("h", "HA & sync overview", "HA pairs, out-of-sync firewalls (no extra calls)"),
                MenuItem("j", "Recent jobs", f"last {self.settings.max_jobs} commit/push jobs (1 call)"),
                MenuItem("l", "Log collectors", "connectivity (1 call)"),
                MenuItem("p", "Panorama status", "version, HA, CPU, memory, disk, NTP (5 calls)"),
                MenuItem("r", "Refresh inventory", "3 calls"),
                MenuItem("b", "Back"),
            ]
            choice = self.tui.select("Browse Panorama (live, read-only)", items)
            if choice in (None, "b"):
                return
            action = {"f": self.browse_firewalls, "g": lambda: self.browse_groups("groups"),
                      "t": lambda: self.browse_groups("templates"), "h": self.ha_sync_overview,
                      "j": self.browse_jobs,
                      "l": self.browse_collectors, "p": self.panorama_status,
                      "r": lambda: self.load_inventory(force=True)}[choice]
            self._safe(action)

    def browse_firewalls(self):
        t = self.tui
        devices = self.cache["devices"]
        if not devices:
            t.message(self.cache_errors.get("devices", "No firewalls found."))
            t.pause()
            return
        rows = firewall_status(devices, self.cached_sync_rows())
        cols = ["hostname", "serial", "connected", "sw-version", "av-version", "policy_sync", "template_sync",
                "ha_state", "ha_pair"]

        def style(row):
            if row["connected"] != "yes":
                return "31"
            bad = ("Out of Sync", "Commit failed")
            return "33" if row["policy_sync"] in bad or row["template_sync"] in bad or row["ha_pair"] not in ("", "ok") else ""

        head, items = t.table_items(rows, cols, style=style)
        while True:
            choice = t.select(f"Firewalls ({len(devices)})", items, head=head, filterable=True, show_keys=False)
            if choice is None:
                return
            self._safe(self.firewall_detail, devices[int(choice) - 1])

    def firewall_detail(self, dev):
        t = self.tui
        name = dev.get("hostname") or dev.get("serial", "")
        fields = [c for c in INVENTORY_COLS if dev.get(c)]
        fields += sorted(k for k in dev if "policy-status" in k or "template-status" in k)
        pad = min(40, max(len(c) for c in fields)) if fields else 0
        intro = [f"  {t.s(f'{c:<{pad}}', '2')}  {t.s(dev[c], '31' if c == 'connected' and dev[c] != 'yes' else '')}"
                 for c in fields]
        status = next((r for r in firewall_status(self.cache["devices"], self.cached_sync_rows())
                       if r["serial"] == dev.get("serial")), {})
        status_lines = [(label, status.get(key, "")) for key, label in (
            ("device-group", "Device group"), ("policy_sync", "Policy sync"), ("template", "Template"),
            ("template_sync", "Template sync"), ("last_commit", "Last commit-all"), ("ha_peer", "HA peer"),
            ("ha_pair", "HA pair"))]
        intro += ["", "  " + t.s("Sync and HA", "1")]
        intro += [f"  {t.s(f'{label:<{max(pad, 16)}}', '2')}  "
                  + t.s(value or "-", "33" if value in ("Out of Sync", "Commit failed") else "")
                  for label, value in status_lines]
        # Evaluate with the whole fleet (HA peers, newest content) and keep this firewall's findings.
        data = Collector(None, self.settings).data
        data["devices"] = self.cache["devices"]
        found = [f for f in evaluate(data) if name in f["target"].split(" / ")]
        if found:
            intro += ["", "  " + t.s("Findings", "1")]
            intro += ["  " + t.s(f"{f['severity']:<9}", SEV_STYLE[f["severity"]]) + f["finding"] for f in found]
        connected = dev.get("connected") == "yes"
        while True:
            choice = t.select(f"Firewall {name}", [
                MenuItem("l", "Live status", f"{len(TARGETED_CALLS)} read-only calls through Panorama"
                         if connected else "the firewall is not connected", disabled=not connected),
                MenuItem("a", f"All fields ({len(dev)})"),
                MenuItem("b", "Back")], intro=intro)
            if choice in (None, "b"):
                return
            if choice == "a":
                t.view(f"Firewall {name}: all fields",
                       [f"  {t.s(t.fit(k, 40).ljust(40), '2')} {v}" for k, v in sorted(dev.items())])
            else:
                self._safe(self.live_status, dev)

    def live_status(self, dev):
        t = self.tui
        serial, name = dev.get("serial", ""), dev.get("hostname") or dev.get("serial", "")
        t.screen(f"Live status: {name}")
        collector = Collector(self.client, self.settings, only_serials=[serial])
        collector.data["devices"] = self.cache["devices"]
        collector.collect_targeted()
        data = Collector(None, self.settings).data
        data["resources"], data["disk"] = collector.data["resources"], collector.data["disk"]
        row = data["resources"][0] if data["resources"] else {}
        limits = {f: limit for f, _, limit in LOAD_LIMITS}
        labels = [("ha_enabled", "HA enabled"), ("ha_mode", "HA mode"), ("ha_local_state", "HA local state"),
                  ("ha_peer_state", "HA peer state"), ("ha_peer_conn", "HA peer connection"),
                  ("ha1_status", "HA1 link"), ("ha2_status", "HA2 link"), ("ha_config_sync", "HA config sync"),
                  ("ha_state_sync", "HA state sync"), ("ha_priority", "HA priority"),
                  ("ha_preemptive", "HA preemptive"), ("ha_link_monitoring", "Link monitoring"),
                  ("ha_path_monitoring", "Path monitoring"),
                  ("log_forwarding", "Log forwarding"), ("log_destination", "Logs sent to"),
                  ("last_log_forwarded", "Last log forwarded"), ("log_fwd_lag_min", "Forwarding lag (min)"),
                  ("av_release_date", "Antivirus released"), ("av_age_days", "Antivirus age (days)"),
                  ("app_release_date", "Apps & Threats released"), ("app_age_days", "Apps & Threats age (days)"),
                  ("num-active", "Active sessions"), ("num-max", "Session capacity"),
                  ("session_util_pct", "Session table %"), ("cps", "Connections/s"), ("kbps", "Throughput kbps"),
                  ("mgmt_cpu_pct", "Management CPU %"), ("mgmt_mem_pct", "Management memory %"),
                  ("dp_cpu_pct", "Dataplane CPU %"), ("packet_buffer_pct", "Packet buffer %")]
        limits.update({"log_fwd_lag_min": LOG_LAG_MINUTES, "av_age_days": AV_MAX_AGE_DAYS,
                       "app_age_days": APP_MAX_AGE_DAYS})
        bad_values = {"down", "not connected", "unknown"}
        lines = []
        for field_name, label in labels:
            value = row.get(field_name, "")
            style = ""
            try:
                if field_name in limits:
                    style = "1;31" if float(value) >= limits[field_name] else "32"
            except ValueError:
                pass
            if value.lower() in bad_values:
                style = "1;31"
            lines.append(f"  {t.s(f'{label:<26}', '2')} {t.s(value or '-', style)}")
        if data["disk"]:
            lines += ["", "  " + t.s("Disk", "1")]
            lines += t.table_lines(data["disk"], ["mount", "use_pct", "size", "used", "avail"],
                                   lambda d: "31" if int(d["use_pct"]) >= 90 and "panlogs" not in d["mount"] else "")
        found = evaluate(data)
        if found:
            lines += ["", "  " + t.s("Findings", "1")]
            lines += ["  " + t.s(f"{f['severity']:<9}", SEV_STYLE[f["severity"]]) + t.fit(f["finding"], t.width - 14)
                      for f in found]
        if row.get("error"):
            lines += [""] + self._error_lines([{"section": "errors", "error": row["error"]}])
        t.view(f"Live status: {name}", lines)

    def browse_groups(self, kind):
        t = self.tui
        label = "Device groups" if kind == "groups" else "Templates"
        sync_kind = "device-group" if kind == "groups" else "template"
        entries = self.cache[kind]
        if not entries:
            t.message(self.cache_errors.get(kind, f"No {label.lower()} found."))
            t.pause()
            return
        rows = []
        for name, el in entries:
            members = Collector._sync_rows(sync_kind, [el]) if el is not None else None
            rows.append({"name": name, "members": members,
                         "firewalls": "?" if members is None else len(members),
                         "connected": "?" if members is None else sum(1 for m in members if m["connected"] == "yes"),
                         "out of sync": "?" if members is None else sum(1 for m in members if self._out_of_sync(m))})
        head, items = t.table_items(rows, ["name", "firewalls", "connected", "out of sync"],
                                    style=lambda r: "33" if r["out of sync"] not in (0, "?") else "")
        while True:
            choice = t.select(f"{label} ({len(rows)})", items, head=head, filterable=True, show_keys=False)
            if choice is None:
                return
            self._safe(self.group_detail, rows[int(choice) - 1], kind)

    @staticmethod
    def _out_of_sync(member):
        return any("out of sync" in v.lower() or "out-of-sync" in v.lower() for k, v in member.items()
                   if k not in ("type", "group", "hostname", "serial", "connected"))

    def group_detail(self, row, kind):
        t = self.tui
        members = row["members"] or []
        status_cols = sorted({k for m in members for k in m if "status" in k})
        member_lines = t.table_lines(members, ["hostname", "serial", "connected"] + status_cols,
                                     lambda m: "31" if m["connected"] != "yes" else ("33" if self._out_of_sync(m) else ""))
        items = [MenuItem("m", f"Members ({len(members)})", disabled=not members,
                          hint="" if members else "membership needs 'Operational Requests'")]
        if kind == "groups":
            items.append(MenuItem("r", "Collect security rules for this device group",
                                  "2 calls, report written like any other run"))
        items.append(MenuItem("b", "Back"))
        intro = member_lines[:8] + ([f"  {t.s(f'... {len(members) - 7} more', '2')}"] if len(members) > 7 else [])
        while True:
            choice = t.select(f"{'Device group' if kind == 'groups' else 'Template'} {row['name']}", items, intro=intro)
            if choice in (None, "b"):
                return
            if choice == "m":
                t.view(f"Members of {row['name']}", member_lines)
            else:
                self.execute(f"Security rules: {row['name']}", ["rules"], only_groups=[row["name"]], max_groups=1)

    def ha_sync_overview(self):
        t = self.tui
        pairs = ha_pairs(self.cache["devices"])
        sync = self.cached_sync_rows()
        lines = ["  " + t.s("Firewall HA pairs", "1")]
        if pairs:
            lines += t.table_lines(pairs, ["firewall", "state", "peer", "peer_state", "peer_connected", "status",
                                           "version_mismatch"],
                                   lambda r: SEV_STYLE.get(HA_PAIR_SEVERITY.get(r["status"], ""), "")
                                   or ("32" if r["status"] == "ok" else "33"))
        else:
            lines.append("  " + t.s("No firewalls report an HA peer.", "2"))
        counts = Counter(r["status"] for r in sync)
        lines += ["", "  " + t.s("Sync status", "1") + "   " + "   ".join(
            t.s(f"{status} {n}", "32" if status == "In Sync" else "33") for status, n in sorted(counts.items()))]
        problems = [r for r in sync if r["status"] != "In Sync"]
        if problems:
            lines += t.table_lines(problems, ["type", "group", "hostname", "serial", "connected", "status"],
                                   lambda r: "31" if r["status"] in ("Out of Sync", "Commit failed") else "2")
        elif sync:
            lines.append("  " + t.s("Every firewall is in sync.", "32"))
        else:
            lines.append("  " + t.s(self.cache_errors.get("groups", "No sync data."), "2"))
        t.view("HA & sync overview", lines)

    def browse_jobs(self):
        t = self.tui
        t.screen("Recent jobs")
        collector = Collector(self.client, self.settings)
        collector.collect_jobs()
        jobs = collector.data["jobs"]
        if not jobs:
            t.message("No jobs.")
            t.pause()
            return

        def failed(job):
            return job.get("result", "").upper() == "FAIL" or job.get("devices_failed", "0") not in ("", "0")

        head, items = t.table_items(jobs, ["id", "type", "status", "result", "tfin", "user", "devices_failed"],
                                    style=lambda j: "31" if failed(j) else "")
        while True:
            choice = t.select(f"Recent jobs ({len(jobs)}, {sum(map(failed, jobs))} failed)", items, head=head,
                              filterable=True, show_keys=False)
            if choice is None:
                return
            job = jobs[int(choice) - 1]
            lines = []
            for k, v in job.items():
                wrapped = textwrap.wrap(str(v), t.width - 26) or [""]
                lines.append(f"  {t.s(f'{k:<20}', '2')} {wrapped[0]}")
                lines += [" " * 23 + part for part in wrapped[1:]]
            t.view(f"Job {job.get('id', '')}", lines)

    def browse_collectors(self):
        t = self.tui
        t.screen("Log collectors")
        collector = Collector(self.client, self.settings)
        collector.collect_collectors()
        rows = collector.data["log_collectors"]
        t.view(f"Log collectors ({len(rows)})",
               t.table_lines(rows, columns_for(rows, ["serial", "host-name", "connected"])[:8],
                             lambda r: "31" if r.get("connected", "yes") != "yes" else ""))

    def panorama_status(self):
        t = self.tui
        t.screen("Panorama status")
        collector = Collector(self.client, self.settings)
        collector.collect_panorama()
        data = collector.data
        pano, ha = data["panorama"], data["panorama_ha"]
        lines = [f"  {t.s(f'{k:<22}', '2')} {pano[k]}" for k in
                 ("hostname", "ip-address", "model", "serial", "sw-version", "uptime", "system-mode",
                  "app-version", "av-version", "wildfire-version", "time") if pano.get(k)]
        extra = [("HA enabled", ha.get("enabled", "")), ("HA local state", _ends(ha, "local-info/state")),
                 ("HA peer state", _ends(ha, "peer-info/state")), ("HA peer connection", _ends(ha, "peer-info/conn-status")),
                 ("HA running config", _ends(ha, "running-sync")),
                 ("Management CPU %", data["panorama_resources"].get("mgmt_cpu_pct", "")),
                 ("Management memory %", data["panorama_resources"].get("mgmt_mem_pct", "")),
                 ("NTP synched to", data["panorama_ntp"].get("ntp_synched", "")),
                 ("NTP servers", data["panorama_ntp"].get("ntp_servers", ""))]
        lines += [f"  {t.s(f'{k:<22}', '2')} {v}" for k, v in extra if v]
        if data["disk"]:
            lines += ["", "  " + t.s("Disk", "1")]
            lines += t.table_lines(data["disk"], ["mount", "use_pct", "size", "used", "avail"],
                                   lambda d: "31" if int(d["use_pct"]) >= 90 and "panlogs" not in d["mount"] else "")
        found = [f for f in evaluate(data) if f["area"] in ("panorama", "disk")]
        lines += ["", "  " + t.s("Findings", "1")]
        lines += ["  " + t.s(f"{f['severity']:<9}", SEV_STYLE[f["severity"]]) + t.fit(f["finding"], t.width - 14)
                  for f in found] or ["  " + t.s("No Panorama findings.", "32")]
        if data["errors"]:
            lines += [""] + self._error_lines(data["errors"])
        t.view("Panorama status", lines)

    # ---- past reports ----

    def _report_dirs(self):
        root = self.settings.output_dir
        if not root.is_dir():
            return []
        return sorted((p for p in root.iterdir() if p.is_dir() and REPORT_DIR_RE.fullmatch(p.name)), reverse=True)

    def reports(self):
        t = self.tui
        runs = self._report_dirs()[:100]
        if not runs:
            t.message(f"No reports yet in {self.settings.output_dir}.")
            t.pause()
            return
        rows = []
        for path in runs:
            sev = Counter(r.get("severity", "") for r in _read_csv(path / "findings.csv"))
            rows.append({"when": datetime.strptime(path.name, "%Y%m%d-%H%M%S").strftime("%Y-%m-%d %H:%M:%S"),
                         "firewalls": len(_read_csv(path / "inventory.csv")), "critical": sev["critical"],
                         "high": sev["high"], "medium": sev["medium"], "low": sev["low"],
                         "html": "yes" if (path / "report.html").exists() else "no"})
        head, items = t.table_items(rows, ["when", "firewalls", "critical", "high", "medium", "low", "html"],
                                    style=lambda r: "31" if r["critical"] else ("38;5;208" if r["high"] else ""))
        items.append(MenuItem("x", f"Clear all reports ({len(self._report_dirs())} folders)",
                              f"deletes every report folder in {self.settings.output_dir}", style="31"))
        choice = t.select(f"Past reports ({len(rows)}, newest first)", items, head=head, filterable=True,
                          show_keys=False)
        if choice == "x":
            self.clear_reports()
        elif choice is not None:
            self.report_actions(runs[int(choice) - 1])
            self.reports()  # re-list: the report may have been deleted

    def report_actions(self, path):
        t = self.tui
        html_path = path / "report.html"
        findings = _read_csv(path / "findings.csv")
        while True:
            choice = t.select(f"Report {path.name}", [
                MenuItem("o", "Open HTML report", "" if html_path.exists() else "no HTML in this run",
                         disabled=not html_path.exists()),
                MenuItem("f", f"View findings ({len(findings)})"),
                MenuItem("d", "Open report folder", str(path)),
                MenuItem("x", "Delete this report", "asks first", style="31"),
                MenuItem("b", "Back")])
            if choice in (None, "b"):
                return
            if choice == "o":
                _open_path(html_path)
            elif choice == "f":
                t.view(f"Findings {path.name}", t.table_lines(findings, FINDING_COLS, self._sev_style))
            elif choice == "x":
                if self._delete_reports([path], f"report {path.name}"):
                    return
            else:
                _open_path(path)

    def clear_reports(self):
        runs = self._report_dirs()
        if runs:
            self._delete_reports(runs, f"all {len(runs)} report folders in {self.settings.output_dir}")

    def _delete_reports(self, paths, what):
        """Delete report folders after a typed confirmation. Only timestamped folders in OUTPUT_DIR qualify."""
        t = self.tui
        root = self.settings.output_dir.resolve()
        paths = [p for p in paths if p.parent.resolve() == root and REPORT_DIR_RE.fullmatch(p.name)
                 and p.is_dir() and not p.is_symlink()]
        if not paths:
            return False
        t.write()
        t.message(f"This permanently deletes {what}.", "1;31")
        if t.prompt("Type DELETE to confirm, anything else cancels") != "DELETE":
            t.message("Cancelled; nothing was deleted.")
            t.pause()
            return False
        failed = []
        for path in paths:
            try:
                shutil.rmtree(path)
            except OSError as exc:
                failed.append(f"{path.name}: {exc.strerror or exc}")
        t.message(f"Deleted {len(paths) - len(failed)} report folder(s).", "32")
        for line in failed:
            t.message(f"Could not delete {line}", "31")
        if self.last_run and not self._report_dirs():
            self.last_run = ""
        t.pause()
        return True

    # ---- session settings ----

    def settings_menu(self):
        t, s, env = self.tui, self.settings, self.env
        while True:
            items = [
                MenuItem("f", f"Report formats: {', '.join(self.formats)}"),
                MenuItem("d", f"Request delay: {s.request_delay:g}s", f"minimum {env.request_delay:g}s from .env"),
                MenuItem("w", f"Log window: {s.log_window_hours}h", "1-168 hours"),
                MenuItem("l", f"Max logs per query: {s.max_logs}", f"1-{env.max_logs}"),
                MenuItem("j", f"Max jobs kept: {s.max_jobs}", "1-500"),
                MenuItem("t", f"Max firewalls for live checks: {s.max_targeted}", f"1-{env.max_targeted} (.env cap)"),
                MenuItem("i", "Connection details", "host, TLS, proxy, keys"),
                MenuItem("b", "Back"),
            ]
            choice = t.select("Session settings (this session only; edit .env to keep them)", items)
            if choice in (None, "b"):
                return
            if choice == "f":
                picked = t.checklist("Report formats", [MenuItem("html", "HTML report"), MenuItem("csv", "CSV files")],
                                     selected=self.formats)
                if picked:
                    self.formats = picked
            elif choice == "d":
                s.request_delay = self._ask_number("Request delay in seconds", s.request_delay,
                                                   env.request_delay, 30, float)
            elif choice == "w":
                s.log_window_hours = self._ask_number("Log window in hours", s.log_window_hours, 1, 168)
            elif choice == "l":
                s.max_logs = self._ask_number("Max logs per query", s.max_logs, 1, env.max_logs)
            elif choice == "j":
                s.max_jobs = self._ask_number("Max jobs kept", s.max_jobs, 1, 500)
            elif choice == "t":
                s.max_targeted = self._ask_number("Max firewalls for live checks", s.max_targeted,
                                                  1, max(1, env.max_targeted))
            else:
                t.view("Connection details", self._connection_lines())

    def _ask_number(self, label, current, lo, hi, cast=int):
        text = self.tui.prompt(f"{label} ({lo:g}-{hi:g})", f"{current:g}")
        try:
            value = cast(text)
        except ValueError:
            value = None
        if value is None or not lo <= value <= hi:
            self.tui.message(f"Must be a number from {lo:g} to {hi:g}; kept {current:g}.")
            self.tui.pause()
            return current
        return value

    def _connection_lines(self):
        t, s = self.tui, self.settings
        rows = [("Panorama", f"https://{s.host}:{s.port}"), ("Allowed hosts (.env)", ", ".join(s.allowed_hosts)),
                ("TLS verification", "on" if s.verify_tls else t.s("off (lab only)", "33")),
                ("CA bundle", s.ca_bundle or "-"), ("Bypass proxy", "yes" if s.bypass_proxy else "no"),
                ("REST version", s.rest_version),
                ("XML key", replace(s, api_mode="xml").key_label()),
                ("REST key", replace(s, api_mode="rest").key_label()),
                ("Output folder", str(s.output_dir)), ("Calls this session", str(len(self.client.calls)))]
        lines = []
        for label, value in rows:
            wrapped = textwrap.wrap(value, t.width - 28) or [""]
            lines.append(f"  {t.s(f'{label:<24}', '2')} {wrapped[0]}")
            lines += [" " * 27 + part for part in wrapped[1:]]
        return lines


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def parse_args(argv):
    p = argparse.ArgumentParser(description="Read-only Panorama health-check collector (proof of concept). "
                                            "Run with no options for the interactive menu.")
    p.add_argument("--env", default=str(SCRIPT_DIR / ".env"), help="path to the .env file")
    p.add_argument("--menu", action="store_true", help="open the interactive menu (default when run with no options)")
    p.add_argument("--dry-run", action="store_true", help="print the API calls that would be made; send nothing")
    p.add_argument("--diagnose", action="store_true", help="test API access and permissions, then exit")
    p.add_argument("--sections", default=",".join(SECTIONS),
                   help=f"comma-separated sections to collect (default: all). Choices: {','.join(SECTIONS)}")
    p.add_argument("--targeted", action="store_true",
                   help="also query each connected firewall through Panorama (overrides ENABLE_TARGETED)")
    p.add_argument("--firewalls", default="",
                   help="comma-separated serials for the live per-firewall checks (implies --targeted)")
    p.add_argument("--format", default="html,csv", help="html, csv or html,csv (default)")
    p.add_argument("--output-dir", help="override OUTPUT_DIR")
    p.add_argument("--quick", action="store_true",
                   help=f"fast proof-of-concept run: rules for shared + the first {QUICK_DEVICE_GROUPS} device groups")
    p.add_argument("--device-groups", default="",
                   help="comma-separated device groups to collect rules for (default: all)")
    return p.parse_args(argv)


def run_health_check(client, settings, sections, formats, only_groups=None, max_groups=None, only_serials=None):
    """Collect, evaluate and write the report. Returns (data, findings, out_dir); out_dir is None on a dry run."""
    started = datetime.now()
    first_call = len(client.calls)
    collector = Collector(client, settings, only_groups=only_groups, max_groups=max_groups, only_serials=only_serials)
    data = collector.run(sections)
    if client.dry_run:
        return data, [], None

    findings = evaluate(data)
    out_dir = settings.output_dir / started.strftime("%Y%m%d-%H%M%S")
    out_dir.mkdir(parents=True, exist_ok=True)
    if "csv" in formats:
        for filename, (rows, cols) in csv_tables(data, findings).items():
            write_csv(out_dir / filename, rows, cols)
    if "html" in formats:
        write_html(out_dir / "report.html", data, findings, settings, client.calls[first_call:], started)
    return data, findings, out_dir


def main(argv=None, transport=None):
    if argv is None:
        argv = sys.argv[1:]
    args = parse_args(argv)
    try:
        settings = load_settings(args.env, require_key=not args.dry_run)
    except ConfigError as exc:
        print(f"Config error: {exc}", file=sys.stderr)
        return 2
    if args.output_dir:
        settings.output_dir = Path(args.output_dir)
    if load_env_file(args.env).get("API_MODE", "").strip().lower() == "rest":
        print("Note: API_MODE in .env is no longer used. Every run uses the XML API; the REST API is only an "
              "option in the menu (python pano_healthcheck.py, option 9).", file=sys.stderr)

    if args.menu and (args.dry_run or args.diagnose):
        # The menu talks to Panorama as soon as it opens; never let it run when asked for a dry run.
        print("--menu cannot be combined with --dry-run or --diagnose (both are options inside the menu)",
              file=sys.stderr)
        return 2
    if args.menu or (not argv and sys.stdin.isatty() and sys.stdout.isatty()):
        return MenuApp(settings, transport=transport).run()

    sections = [s.strip() for s in args.sections.split(",") if s.strip()]
    unknown = set(sections) - set(SECTIONS)
    if unknown:
        print(f"Unknown sections: {', '.join(sorted(unknown))}", file=sys.stderr)
        return 2
    only_serials = [s.strip() for s in args.firewalls.split(",") if s.strip()]
    if "targeted" in sections and not (args.targeted or only_serials or settings.enable_targeted):
        sections.remove("targeted")
    formats = {f.strip().lower() for f in args.format.split(",") if f.strip()}
    if not formats or formats - {"html", "csv"}:
        print("--format must be html, csv or html,csv", file=sys.stderr)
        return 2

    if not args.dry_run:
        print(f"Panorama {settings.host}, using {settings.key_label()}")
        if not settings.verify_tls:
            print("Warning: TLS certificate verification is off (VERIFY_TLS=false). Lab use only.")
        print()

    client = PanoramaClient(settings, dry_run=args.dry_run, transport=transport)

    if args.diagnose:
        return diagnose(client)

    if args.dry_run:
        print(f"Dry run against {settings.host}: planned read-only calls\n")

    only_groups = [g.strip() for g in args.device_groups.split(",") if g.strip()]
    data, findings, out_dir = run_health_check(
        client, settings, sections, formats, only_groups=only_groups,
        max_groups=QUICK_DEVICE_GROUPS if args.quick else None, only_serials=only_serials)

    if args.dry_run:
        print(f"\nDry run complete: {len(client.calls)} calls listed, nothing sent, no report written.")
        return 0

    sev = Counter(f["severity"] for f in findings)
    print(f"\nDone: {len(client.calls)} read-only API calls, {len(data['devices'])} firewalls, "
          f"{len(findings)} findings (critical {sev['critical']}, high {sev['high']}, medium {sev['medium']}).")
    if data["scope_note"]:
        print(data["scope_note"] + ".")
    print(f"Report: {out_dir}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
