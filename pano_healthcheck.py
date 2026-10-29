#!/usr/bin/env python3
"""Read-only Panorama health-check collector (proof of concept).

Collects firewall health data from Panorama through the PAN-OS REST API
(API_MODE=rest, the default) or XML API (API_MODE=xml) and writes an HTML
report and/or CSV files. Python standard library only.

Every request passes a guard before anything is sent. XML: only allowlisted
`show` operational commands, config `show`/`get` reads and log queries
(guard()). REST: only GET on allowlisted endpoints (guard_rest()). Anything
else raises ReadOnlyViolation.

Usage:
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
import socket
import ssl
import sys
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
    "ALLOWED_HOSTS": "",
    "API_MODE": "rest",
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


class ConfigError(Exception):
    pass


@dataclass
class Settings:
    host: str
    port: int
    api_key: str
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
    key_source: str = ""
    http_method: str = "POST"
    api_mode: str = "xml"
    rest_version: str = "v11.0"
    device_groups: list = field(default_factory=list)

    def key_label(self):
        """Masked key description, for comparing with the key used in curl."""
        if not self.api_key:
            return "no API key"
        if self.api_mode == "rest":
            sent = "REST GET, X-PAN-KEY header"
        else:
            sent = f"XML {self.http_method}, " + ("X-PAN-KEY header" if self.key_in_header else "POST body")
        return f"API key ...{self.api_key[-4:]} ({len(self.api_key)} chars, from {self.key_source}), sent via {sent}"


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
    key_source = f"{env_path}"
    for key in DEFAULTS:
        if key not in FILE_ONLY_KEYS and environ.get(key):
            values[key] = environ[key]
            if key == "PANORAMA_API_KEY":
                key_source = "environment variable PANORAMA_API_KEY"

    host = values["PANORAMA_HOST"].strip()
    allowed = [h.strip().lower() for h in values["ALLOWED_HOSTS"].split(",") if h.strip()]
    if not host:
        raise ConfigError("PANORAMA_HOST is empty in .env")
    if host.lower() not in allowed:
        raise ConfigError(
            f"PANORAMA_HOST '{host}' is not listed in ALLOWED_HOSTS. "
            "This tool is locked to the lab Panorama; refusing to run."
        )
    if require_key and not values["PANORAMA_API_KEY"].strip():
        raise ConfigError("PANORAMA_API_KEY is empty. Put the lab API key in .env.")

    http_method = values["HTTP_METHOD"].strip().upper()
    if http_method not in ("POST", "GET"):
        raise ConfigError("HTTP_METHOD must be POST or GET")
    if http_method == "GET" and not _bool(values["KEY_IN_HEADER"]):
        raise ConfigError("HTTP_METHOD=GET needs KEY_IN_HEADER=true; the key is never put in a URL")
    api_mode = values["API_MODE"].strip().lower()
    if api_mode not in ("rest", "xml"):
        raise ConfigError("API_MODE must be rest or xml")
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
            api_key=values["PANORAMA_API_KEY"].strip(),
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
            key_source=key_source,
            http_method=http_method,
            api_mode=api_mode,
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
}
ALLOWED_OP = frozenset(OP_COMMANDS.values())
# Commands that may be proxied to a managed firewall with target=<serial>.
TARGETED_OP = frozenset(OP_COMMANDS[n] for n in ("system_info", "ha_state", "session_info", "system_resources"))

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
    "Objects/Addresses",            # diagnose baseline (the call known to work)
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
            headers["X-PAN-KEY"] = self.settings.api_key
        else:
            body_params["key"] = self.settings.api_key  # POST body only; load_settings forbids GET here
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
        headers = {"X-PAN-KEY": self.settings.api_key, "Accept": "application/json"}
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
SECTIONS = ["panorama", "devices", "sync", "jobs", "collectors", "rules", "logs", "targeted"]


class Collector:
    def __init__(self, client, settings):
        self.client = client
        self.settings = settings
        self.data = {
            "panorama": {}, "panorama_ha": {}, "devices": [], "sync": [], "jobs": [],
            "log_collectors": [], "rules": [], "system_logs": [], "config_logs": [],
            "resources": [], "errors": [], "unavailable": [],
        }
        self._device_groups = None
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
            print(f"Skipped (not available through the REST API): {', '.join(self.data['unavailable'])}")
        return self.data

    def _error(self, section, exc):
        print(f"  ! {section}: {exc}")
        self.data["errors"].append({"section": section, "error": str(exc)})

    def collect_panorama(self):
        info = self.client.op("system_info")
        system = info.find("system")
        self.data["panorama"] = flatten(system if system is not None else info)
        try:
            self.data["panorama_ha"] = flatten(self.client.op("ha_state"))
        except ApiError as exc:
            self._error("panorama (HA)", exc)

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
            rows += self._sync_rows("template", tpl_result.findall("./templates/entry"))
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
                    if "status" in key or "sync" in key:
                        row[key] = value
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
                      for dg in self._device_groups]
        if self.client.dry_run and not self._device_groups:
            print("  [dry-run] + 2 config show calls per device group (pre/post rulebase)")

        rows = []
        for location, base in locations:
            for rulebase in ("pre-rulebase", "post-rulebase"):
                try:
                    result = self.client.config_show(f"{base}/{rulebase}/security/rules")
                except ApiError as exc:
                    if exc.code in ("7", "13"):  # rulebase not configured
                        continue
                    raise
                rules_el = next(result.iter("rules"), result)
                for position, entry in enumerate(rules_el.findall("entry"), start=1):
                    rows.append(rule_row(location, rulebase, position, entry))
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
        locations = [("shared", {"location": "shared"})]
        locations += [(name, {"location": "device-group", "device-group": name}) for name in names]
        if self.client.dry_run and not names:
            print("  [dry-run] + 2 REST GET calls per device group (pre/post rules)")

        rows = []
        denied = set()
        for location, query in locations:
            for rulebase, endpoint in (("pre-rulebase", "Policies/SecurityPreRules"),
                                       ("post-rulebase", "Policies/SecurityPostRules")):
                if endpoint in denied:
                    continue
                try:
                    entries = self.client.rest_get(endpoint, query)
                except ApiError as exc:
                    if exc.code in ("401", "403", "16"):
                        denied.add(endpoint)  # don't repeat a denied call for every device group
                    self._error(f"rules ({location} {rulebase})", exc)
                    continue
                for position, entry in enumerate(entries, start=1):
                    if entry.get("@location") and entry["@location"] != query["location"]:
                        continue  # inherited from another location; collected there
                    rows.append(rule_row(location, rulebase, position, json_to_element("entry", entry)))
        self.data["rules"] = rows

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
        if self.client.dry_run and not serials:
            serials = ["<serial>"]
            print(f"  [dry-run] up to {self.settings.max_targeted} connected firewalls, 3 calls each:")
        rows = []
        for serial in serials[: self.settings.max_targeted]:
            if serial == "<serial>":
                for name in ("ha_state", "session_info", "system_resources"):
                    print(f"  [dry-run] op {name} target=<serial>")
                continue
            row = {"serial": serial}
            dev = next((d for d in self.data["devices"] if d.get("serial") == serial), {})
            row["hostname"] = dev.get("hostname", "")
            try:
                row.update(parse_ha(self.client.op("ha_state", target=serial)))
                row.update(parse_session_info(self.client.op("session_info", target=serial)))
                row.update(parse_resources(self.client.op("system_resources", target=serial)))
            except ApiError as exc:
                row["error"] = str(exc)
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
    flat = flatten(result)
    return {
        "ha_enabled": _ends(flat, "enabled"),
        "ha_local_state": _ends(flat, "local-info/state"),
        "ha_peer_state": _ends(flat, "peer-info/state"),
        "ha_peer_conn": _ends(flat, "peer-info/conn-status"),
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


# --------------------------------------------------------------------------
# Health findings
# --------------------------------------------------------------------------

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
HEALTHY_HA_STATES = {"", "active", "passive", "active-primary", "active-secondary", "disabled"}


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
        for key, value in dev.items():
            low = value.lower()
            if "status" in key and ("out of sync" in low or "out-of-sync" in low):
                _finding(findings, "high", "sync", name, f"{key} is '{value}'")
            elif "commit" in key and "fail" in low:
                _finding(findings, "high", "sync", name, f"{key} is '{value}'")

    for row in data["sync"]:
        for key, value in row.items():
            if key in ("type", "group", "hostname", "serial", "connected"):
                continue
            low = value.lower()
            if "out of sync" in low or "out-of-sync" in low or "fail" in low:
                _finding(findings, "high", "sync", row["hostname"] or row["serial"],
                         f"{row['type']} '{row['group']}': {key} is '{value}'")

    connected = [d for d in devices if d.get("connected") == "yes"]
    for field, label in (("app-version", "Applications & Threats content"),
                         ("av-version", "Antivirus content"),
                         ("sw-version", "PAN-OS version")):
        values = Counter(d.get(field, "") for d in connected if d.get(field))
        if len(values) > 1:
            majority = values.most_common(1)[0][0]
            for d in connected:
                if d.get(field) and d.get(field) != majority:
                    sev = "info" if field == "sw-version" else "low"
                    _finding(findings, sev, "versions", d.get("hostname") or d.get("serial", ""),
                             f"{label} differs from fleet majority", f"{d[field]} vs {majority}")

    ha = data["panorama_ha"]
    if ha.get("enabled") == "yes":
        conn = _ends(ha, "peer-info/conn-status")
        if conn and conn.lower() != "up":
            _finding(findings, "high", "panorama", "Panorama", f"Panorama HA peer connection is '{conn}'")

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
            continue
        for field, label, limit in (("session_util_pct", "Session table utilisation", 80),
                                    ("mgmt_cpu_pct", "Management CPU", 85),
                                    ("mgmt_mem_pct", "Management memory", 90)):
            try:
                if float(row.get(field, "")) >= limit:
                    _finding(findings, "high", "resources", name, f"{label} at {row[field]}%")
            except ValueError:
                pass
        if row.get("ha_peer_conn") and row["ha_peer_conn"].lower() != "up":
            _finding(findings, "high", "high-availability", name, f"HA peer connection is '{row['ha_peer_conn']}'")

    for err in data["errors"]:
        _finding(findings, "medium", "collection", err["section"], "Section could not be collected", err["error"])
    if data.get("unavailable"):
        _finding(findings, "info", "collection", ", ".join(data["unavailable"]),
                 "Not checked: the REST API has no operational data (connectivity, HA, sync, jobs, logs)",
                 "These need XML API access (API_MODE=xml)")

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
SYNC_COLS = ["type", "group", "hostname", "serial", "connected"]
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
                 "mgmt_cpu_pct", "mgmt_mem_pct", "error"]


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
    tables = {
        "findings.csv": (findings, FINDING_COLS),
        "panorama.csv": (panorama, ["field", "value"]),
        "inventory.csv": (data["devices"], INVENTORY_COLS),
        "sync_status.csv": (data["sync"], SYNC_COLS),
        "jobs.csv": (data["jobs"], JOB_COLS),
        "log_collectors.csv": (data["log_collectors"], ["serial", "host-name", "connected"]),
        "security_rules.csv": (data["rules"], RULE_COLS),
        "rule_findings.csv": (rule_findings(data["rules"]), RULE_FINDING_COLS),
        "system_logs.csv": (data["system_logs"], SYSLOG_COLS),
        "config_logs.csv": (data["config_logs"], CONFIGLOG_COLS),
        "collection_errors.csv": (data["errors"], ["section", "error"]),
    }
    if data["resources"]:
        tables["firewall_resources.csv"] = (data["resources"], RESOURCE_COLS)
    csv_section = {"panorama.csv": "panorama", "sync_status.csv": "sync", "jobs.csv": "jobs",
                   "log_collectors.csv": "collectors", "system_logs.csv": "logs", "config_logs.csv": "logs"}
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
details summary { cursor:pointer; color:var(--muted); margin-top:8px; }
"""


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
                      {"field": "HA peer connection", "value": _ends(ha, "peer-info/conn-status")}]

    status_cols = sorted({k for d in devices for k in d if "policy-status" in k or "template-status" in k})
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
        ("sync", "Device-group & template sync", _table(data["sync"], columns_for(data["sync"], SYNC_COLS)), "sync"),
        ("jobs", f"Recent Panorama jobs (last {settings.max_jobs})",
         _table(data["jobs"], columns_for(data["jobs"], JOB_COLS[:12], include_extra=False)), "jobs"),
        ("collectors", "Log collectors", _table(data["log_collectors"],
                                                columns_for(data["log_collectors"], ["serial", "host-name", "connected"])),
         "collectors"),
        ("rules", "Security rules", _table(rule_summary_rows, ["location", "rulebase", "rules", "disabled"])
         + "<h3>Rule findings</h3>" + _table(rule_findings(data["rules"]), RULE_FINDING_COLS, "No rule findings."),
         "rules"),
        ("syslogs", f"System logs, severity high+ (last {settings.log_window_hours}h)",
         _table(data["system_logs"], columns_for(data["system_logs"], SYSLOG_COLS, include_extra=False)), "logs"),
        ("configlogs", f"Configuration logs (last {settings.log_window_hours}h)",
         _table(data["config_logs"], columns_for(data["config_logs"], CONFIGLOG_COLS, include_extra=False)), "logs"),
    ]
    sections = [(sid, title, content) for sid, title, content, needs in candidates if needs not in unavailable]
    if unavailable:
        items = "".join(f"<li>{html.escape(n)}</li>" for n in SECTIONS if n in unavailable)
        sections.append(("not-collected", "Not collected",
                         "<p>The REST API has no endpoints for these sections; they need XML API access "
                         f"(API_MODE=xml):</p><ul>{items}</ul>"))
    if data["resources"]:
        sections.append(("resources", "Per-firewall live status (management plane)",
                         _table(data["resources"], columns_for(data["resources"], RESOURCE_COLS))))
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
    ("Objects/Addresses (shared): your known-working call", "Objects/Addresses", {"location": "shared"}),
    ("Policies/SecurityPreRules (shared)", "Policies/SecurityPreRules", {"location": "shared"}),
    ("Policies/SecurityPostRules (shared)", "Policies/SecurityPostRules", {"location": "shared"}),
]


def diagnose(client):
    print(f"Diagnosing {client.settings.api_mode.upper()} API access to {client.settings.host} (read-only checks)")
    print(f"Using {client.settings.key_label()}\n")
    if client.settings.api_mode == "rest":
        return diagnose_rest(client)
    return diagnose_xml(client)


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
    print("Connectivity, HA, sync, jobs and logs are not available through REST.")
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
        print("\n  -> Every method was denied: the role has no XML API access. If your key works with")
        print("     the REST API (/restapi/...), set API_MODE=rest in .env.")


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def parse_args(argv):
    p = argparse.ArgumentParser(description="Read-only Panorama health-check collector (proof of concept).")
    p.add_argument("--env", default=str(SCRIPT_DIR / ".env"), help="path to the .env file")
    p.add_argument("--dry-run", action="store_true", help="print the API calls that would be made; send nothing")
    p.add_argument("--diagnose", action="store_true", help="test API access and permissions, then exit")
    p.add_argument("--sections", default=",".join(SECTIONS),
                   help=f"comma-separated sections to collect (default: all). Choices: {','.join(SECTIONS)}")
    p.add_argument("--targeted", action="store_true",
                   help="also query each connected firewall through Panorama (overrides ENABLE_TARGETED)")
    p.add_argument("--format", default="html,csv", help="html, csv or html,csv (default)")
    p.add_argument("--output-dir", help="override OUTPUT_DIR")
    return p.parse_args(argv)


def main(argv=None, transport=None):
    args = parse_args(argv)
    try:
        settings = load_settings(args.env, require_key=not args.dry_run)
    except ConfigError as exc:
        print(f"Config error: {exc}", file=sys.stderr)
        return 2
    if args.output_dir:
        settings.output_dir = Path(args.output_dir)

    sections = [s.strip() for s in args.sections.split(",") if s.strip()]
    unknown = set(sections) - set(SECTIONS)
    if unknown:
        print(f"Unknown sections: {', '.join(sorted(unknown))}", file=sys.stderr)
        return 2
    if "targeted" in sections and not (args.targeted or settings.enable_targeted):
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

    started = datetime.now()
    data = Collector(client, settings).run(sections)

    if args.dry_run:
        print(f"\nDry run complete: {len(client.calls)} calls listed, nothing sent, no report written.")
        return 0

    findings = evaluate(data)
    out_dir = settings.output_dir / started.strftime("%Y%m%d-%H%M%S")
    out_dir.mkdir(parents=True, exist_ok=True)
    if "csv" in formats:
        for filename, (rows, cols) in csv_tables(data, findings).items():
            write_csv(out_dir / filename, rows, cols)
    if "html" in formats:
        write_html(out_dir / "report.html", data, findings, settings, client.calls, started)

    sev = Counter(f["severity"] for f in findings)
    print(f"\nDone: {len(client.calls)} read-only API calls, {len(data['devices'])} firewalls, "
          f"{len(findings)} findings (critical {sev['critical']}, high {sev['high']}, medium {sev['medium']}).")
    print(f"Report: {out_dir}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
