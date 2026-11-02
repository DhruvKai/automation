import contextlib
import io
import json
import sys
import re
import tempfile
import time
import unittest
import urllib.parse
import xml.etree.ElementTree as ET
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import pano_healthcheck as ph  # noqa: E402

LAB_HOST = "192.0.2.10"

DEVICES_ALL = """<response status="success"><result><devices>
<entry name="001"><serial>001</serial><connected>yes</connected><hostname>fw-a</hostname>
 <ip-address>192.0.2.21</ip-address><model>PA-VM</model><family>vm</family><sw-version>10.2.10</sw-version>
 <app-version>8800-8000</app-version><av-version>4800-5300</av-version><unsupported-version>no</unsupported-version>
 <ha><state>active</state><peer><serial>002</serial></peer></ha>
 <vsys><entry name="vsys1"><display-name>vsys1</display-name><shared-policy-status>In Sync</shared-policy-status></entry></vsys>
</entry>
<entry name="002"><serial>002</serial><connected>yes</connected><hostname>fw-b</hostname>
 <ip-address>192.0.2.22</ip-address><model>PA-VM</model><family>vm</family><sw-version>10.2.10</sw-version>
 <app-version>8700-7900</app-version><av-version>4800-5300</av-version>
 <ha><state>suspended</state></ha>
 <vsys><entry name="vsys1"><display-name>vsys1</display-name><shared-policy-status>Out of Sync</shared-policy-status></entry></vsys>
</entry>
<entry name="003"><serial>003</serial><connected>no</connected><hostname>fw-c</hostname>
 <ip-address>192.0.2.23</ip-address><model>PA-440</model><sw-version>11.1.4</sw-version></entry>
</devices></result></response>"""

SYSTEM_INFO = """<response status="success"><result><system><hostname>pano-lab</hostname>
<sw-version>11.1.4</sw-version><model>Panorama</model><uptime>3 days</uptime></system></result></response>"""

HA_STATE = """<response status="success"><result><enabled>no</enabled></result></response>"""

DEVICEGROUPS = """<response status="success"><result><devicegroups>
<entry name="DG-Branch"><devices><entry name="001"><serial>001</serial><connected>yes</connected>
<hostname>fw-a</hostname><shared-policy-status>In Sync</shared-policy-status></entry></devices></entry>
</devicegroups></result></response>"""

TEMPLATES = """<response status="success"><result><templates>
<entry name="TPL-Branch"><devices><entry name="001"><serial>001</serial><connected>yes</connected>
<hostname>fw-a</hostname><template-status>Out of Sync</template-status></entry></devices></entry>
</templates></result></response>"""

JOBS = """<response status="success"><result>
<job><id>41</id><type>CommitAll</type><status>FIN</status><result>OK</result><tfin>2026/10/28 10:00:00</tfin></job>
<job><id>42</id><type>CommitAll</type><status>FIN</status><result>FAIL</result><tfin>2026/10/28 11:00:00</tfin>
 <devices><entry name="002"><serial-no>002</serial-no><devicename>fw-b</devicename><result>FAIL</result></entry></devices></job>
</result></response>"""

LOG_COLLECTORS = """<response status="success"><result><log-collector>
<entry name="LC1"><host-name>lc-1</host-name><connected>no</connected></entry>
</log-collector></result></response>"""

RULES_DG = """<response status="success"><result><rules>
<entry name="allow-any" uuid="u1"><from><member>any</member></from><to><member>any</member></to>
 <source><member>any</member></source><destination><member>any</member></destination>
 <application><member>any</member></application><service><member>any</member></service><action>allow</action></entry>
<entry name="web-out" uuid="u2"><from><member>trust</member></from><to><member>untrust</member></to>
 <source><member>10.0.0.0/8</member></source><destination><member>any</member></destination>
 <application><member>web-browsing</member></application><service><member>application-default</member></service>
 <action>allow</action><profile-setting><group><member>default</member></group></profile-setting>
 <log-setting>to-panorama</log-setting></entry>
<entry name="old" uuid="u3"><from><member>any</member></from><to><member>any</member></to>
 <source><member>any</member></source><destination><member>any</member></destination>
 <application><member>any</member></application><service><member>any</member></service>
 <action>deny</action><disabled>yes</disabled><log-end>no</log-end></entry>
</rules></result></response>"""

DG_NAMES = """<response status="success"><result total-count="1" count="1">
<entry name="DG-Branch"/></result></response>"""

OP_DENIED = """<response status="error" code="403"><result><msg>Type [op] not authorized for user role.</msg>
</result></response>"""

NOT_PRESENT ="""<response status="error" code="7"><msg><line>No such node</line></msg></response>"""

LOG_ENQUEUE = """<response status="success"><result><msg><line>query job enqueued with jobid 7</line></msg>
<job>7</job></result></response>"""

SYSTEM_LOGS = """<response status="success"><result><job><status>FIN</status></job><log><logs count="1">
<entry logid="1"><receive_time>2026/10/28 09:00:00</receive_time><severity>critical</severity>
<opaque>disk full</opaque><device_name>fw-a</device_name></entry></logs></log></result></response>"""

TOP_TEXT = """<response status="success"><result><![CDATA[top - 10:00:00 up 3 days
%Cpu(s):  7.5 us,  2.5 sy,  0.0 ni, 90.0 id,  0.0 wa
MiB Mem :   8000.0 total,   1000.0 free,   6000.0 used,   1000.0 buff/cache
]]></result></response>"""

SESSION_INFO = """<response status="success"><result><num-max>100000</num-max><num-active>85000</num-active>
<cps>120</cps></result></response>"""

DISK_SPACE = """<response status="success"><result><![CDATA[Filesystem      Size  Used Avail Use% Mounted on
/dev/root       6.9G  6.3G  0.3G  95% /
none            2.0G   40K  2.0G   1% /dev
/dev/sda5        16G  9.6G  5.2G  65% /opt/pancfg
/dev/sda8       200G  196G  4.0G  98% /opt/panlogs
]]></result></response>"""

NTP = """<response status="success"><result><synched>LOCAL</synched>
<ntp-server-1><status>rejected</status><authentication-type>none</authentication-type><reachable>no</reachable>
<name>192.0.2.123</name></ntp-server-1></result></response>"""

DP_RESOURCES = """<response status="success"><result><resource-monitor><data-processors><dp0><minute>
<cpu-load-average><entry><coreid>0</coreid><value>0</value></entry><entry><coreid>1</coreid><value>90</value></entry>
<entry><coreid>2</coreid><value>94</value></entry></cpu-load-average>
<resource-utilization><entry><name>session</name><value>3</value></entry>
<entry><name>packet buffer</name><value>12</value></entry><entry><name>packet descriptor</name><value>5</value></entry>
</resource-utilization></minute></dp0></data-processors></resource-monitor></result></response>"""

HA_DEGRADED = """<response status="success"><result><enabled>yes</enabled><group><mode>Active-Passive</mode>
<local-info><state>primary-suspended</state></local-info><peer-info><conn-status>down</conn-status>
<state>secondary-active</state></peer-info><running-sync>not synchronized</running-sync>
<running-sync-enabled>yes</running-sync-enabled></group></result></response>"""

SHARED_CERTS = """<response status="success"><result total-count="1" count="1"><certificate>
<entry name="old-ca"><common-name>Lab CA</common-name><issuer>Lab CA</issuer>
 <not-valid-after>Jan  1 00:00:00 2020 GMT</not-valid-after><expiry-epoch>1577836800</expiry-epoch><ca>yes</ca>
 <algorithm>RSA</algorithm><private-key>-----BEGIN ENCRYPTED PRIVATE KEY-----PRIVATEBLOB</private-key>
 <public-key>PUBLICBLOB</public-key></entry>
<entry name="pano-web"><common-name>pano.lab</common-name><not-valid-after>Jan  1 00:00:00 2099 GMT</not-valid-after>
 </entry>
</certificate></result></response>"""

TEMPLATE_CERTS = f"""<response status="success"><result total-count="1" count="1"><certificate>
<entry name="gp-portal"><common-name>vpn.lab</common-name><expiry-epoch>{int(time.time()) + 10 * 86400 + 3600}</expiry-epoch>
 <private-key>PRIVATEBLOB</private-key></entry></certificate></result></response>"""


HA_ALL = """<response status="success"><result><enabled>yes</enabled><group><mode>Active-Passive</mode>
<local-info><state>active</state><priority>100</priority><preemptive>no</preemptive><state-sync>Complete</state-sync>
</local-info><peer-info><conn-status>up</conn-status><state>passive</state>
<conn-ha1><conn-status>up</conn-status></conn-ha1><conn-ha2><conn-status>down</conn-status></conn-ha2></peer-info>
<link-monitoring><enabled>yes</enabled></link-monitoring><path-monitoring><enabled>no</enabled></path-monitoring>
<running-sync>not synchronized</running-sync><running-sync-enabled>yes</running-sync-enabled></group>
</result></response>"""

_NOW = time.time()
_STAMP = lambda seconds_ago: time.strftime("%Y/%m/%d %H:%M:%S", time.gmtime(_NOW - seconds_ago))  # noqa: E731

LOGGING_STATUS = f"""<response status="success"><result><![CDATA[
>Log Collection Service
'Log Collection log forwarding agent' is active and connected to 192.0.2.50

   -----------------------------------------------------------------------------------------------------
        Type      Last Log Created        Last Log Fwded       Last Seq Num Fwded  Last Seq Num Acked
   -----------------------------------------------------------------------------------------------------
      config   {_STAMP(600)}    {_STAMP(600)}          100        100
      system   {_STAMP(300)}    {_STAMP(300 + 90 * 60)}          200        200
     traffic   Not Available          Not Available                 0          0
]]></result></response>"""

LOGGING_DOWN = """<response status="success"><result><![CDATA[
>Log Collection Service
'Log Collection log forwarding agent' is not active.
]]></result></response>"""

FW_SYSTEM_INFO = f"""<response status="success"><result><system><hostname>fw-a</hostname>
<sw-version>10.2.10</sw-version><av-version>4800-5300</av-version>
<av-release-date>{_STAMP(10 * 86400 + 3600)} PDT</av-release-date>
<app-version>8800-8000</app-version><app-release-date>{_STAMP(2 * 86400 + 3600)} PDT</app-release-date>
</system></result></response>"""

REST_DEVICE_GROUPS = {"@status": "success", "@code": "19", "result": {"@count": "1", "entry": [
    {"@name": "DG-Branch", "devices": {"entry": [{"@name": "001"}, {"@name": "002"}]}},
    {"@name": "DG-DC"}, {"@name": "DG-Lab"}]}}

REST_TEMPLATE_STACKS = {"@status": "success", "result": {"entry": [
    {"@name": "TS-Branch", "devices": {"entry": [{"@name": "001"}]}}]}}

REST_PRE_RULES_DG = {"@status": "success", "@code": "19", "result": {"@count": "2", "entry": [
    {"@name": "allow-any", "@uuid": "u1", "@location": "device-group", "@device-group": "DG-Branch",
     "from": {"member": ["any"]}, "to": {"member": ["any"]}, "source": {"member": ["any"]},
     "destination": {"member": ["any"]}, "application": {"member": ["any"]}, "service": {"member": ["any"]},
     "action": "allow"},
    {"@name": "web-out", "@uuid": "u2", "@location": "device-group", "@device-group": "DG-Branch",
     "from": {"member": ["trust"]}, "to": {"member": ["untrust"]}, "source": {"member": ["10.0.0.0/8"]},
     "destination": {"member": ["any"]}, "application": {"member": ["web-browsing"]},
     "service": {"member": ["application-default"]}, "action": "allow",
     "profile-setting": {"group": {"member": ["default"]}}, "log-setting": "to-panorama"},
]}}

REST_EMPTY = {"@status": "success", "@code": "19", "result": {"@count": "0", "@total-count": "0"}}
REST_DENIED = {"code": 16, "message": "Unauthorized request"}


class FakePanorama:
    """Transport stand-in: answers by request parameters, records what was sent."""

    def __init__(self):
        self.sent = []

    def __call__(self, path, query, headers, method="POST"):
        params = dict(urllib.parse.parse_qsl(query))
        self.sent.append((params, headers))
        if path.startswith("/restapi/"):
            assert method == "GET", "REST calls must be GET"
            return self.rest(path.split("/", 3)[3], params)
        return 200, self.xml(params)

    def rest(self, endpoint, params):
        if endpoint == "Panorama/DeviceGroups":
            doc = REST_DEVICE_GROUPS
        elif endpoint == "Panorama/TemplateStacks":
            doc = REST_TEMPLATE_STACKS
        elif endpoint == "Policies/SecurityPreRules" and params.get("device-group") == "DG-Branch":
            doc = REST_PRE_RULES_DG
        else:
            doc = REST_EMPTY
        return 200, json.dumps(doc).encode()

    def xml(self, params):
        t = params["type"]
        if t == "op":
            name = next(k for k, v in ph.OP_COMMANDS.items() if v == params["cmd"])
            if params.get("target") and name == "system_info":
                return FW_SYSTEM_INFO.encode()
            return {
                "ha_all": HA_ALL, "logging_status": LOGGING_STATUS,
                "system_info": SYSTEM_INFO, "ha_state": HA_STATE, "devices_all": DEVICES_ALL,
                "devicegroups": DEVICEGROUPS, "templates": TEMPLATES, "jobs_all": JOBS,
                "log_collectors": LOG_COLLECTORS, "session_info": SESSION_INFO,
                "system_resources": TOP_TEXT, "disk_space": DISK_SPACE, "ntp": NTP,
                "dp_resources": DP_RESOURCES,
            }[name].encode()
        if t == "config":
            if params["xpath"].endswith("/device-group/entry/@name"):
                return DG_NAMES.encode()
            if params["xpath"].endswith("/deviceconfig/system/hostname"):
                return b'<response status="success"><result><hostname>pano-lab</hostname></result></response>'
            if params["xpath"] == "/config/shared/certificate":
                return SHARED_CERTS.encode()
            if "TPL-Branch" in params["xpath"] and params["xpath"].endswith("/certificate"):
                return TEMPLATE_CERTS.encode()
            if "DG-Branch" in params["xpath"] and "pre-rulebase" in params["xpath"]:
                return RULES_DG.encode()
            return NOT_PRESENT.encode()
        if t == "log":
            if params.get("action") == "get":
                return SYSTEM_LOGS.encode()
            return LOG_ENQUEUE.encode()
        raise AssertionError(f"unexpected request {params}")


class ThreeGroupPanorama(FakePanorama):
    """Panorama whose config lists three device groups."""

    def xml(self, params):
        if params["type"] == "config" and params["xpath"].endswith("/device-group/entry/@name"):
            return (b'<response status="success"><result><entry name="DG-Branch"/><entry name="DG-DC"/>'
                    b'<entry name="DG-Lab"/></result></response>')
        return super().xml(params)


def make_settings(**overrides):
    values = dict(
        host=LAB_HOST, port=443, xml_api_key="SECRET-KEY", rest_api_key="REST-KEY", allowed_hosts=[LAB_HOST],
        verify_tls=False,
        ca_bundle="", bypass_proxy=True, key_in_header=True, request_delay=0, timeout=5,
        log_window_hours=24, max_logs=100, max_jobs=50, enable_targeted=False, max_targeted=5,
        output_dir=Path(tempfile.gettempdir()),
    )
    values.update(overrides)
    return ph.Settings(**values)


class GuardTests(unittest.TestCase):
    def test_allowlisted_op_commands_pass(self):
        for cmd in ph.OP_COMMANDS.values():
            ph.guard({"type": "op", "cmd": cmd})

    def test_write_request_types_rejected(self):
        for req_type in ("commit", "import", "export", "user-id", "report", "keygen", "version", None):
            with self.assertRaises(ph.ReadOnlyViolation, msg=req_type):
                ph.guard({"type": req_type, "cmd": "<commit></commit>"})

    def test_config_write_actions_rejected(self):
        for action in ("set", "edit", "delete", "rename", "clone", "move", "override", "multi-move",
                       "multi-clone", "complete", None):
            with self.assertRaises(ph.ReadOnlyViolation, msg=action):
                ph.guard({"type": "config", "action": action, "xpath": "/config/shared"})

    def test_config_element_param_rejected(self):
        with self.assertRaises(ph.ReadOnlyViolation):
            ph.guard({"type": "config", "action": "show", "xpath": "/config/shared", "element": "<x/>"})

    def test_config_xpath_must_be_under_config(self):
        with self.assertRaises(ph.ReadOnlyViolation):
            ph.guard({"type": "config", "action": "show", "xpath": "/"})

    def test_non_allowlisted_op_commands_rejected(self):
        for cmd in (
            "<request><restart><system></system></restart></request>",
            "<clear><session><all></all></session></clear>",
            "<set><system><setting><target-vsys>vsys1</target-vsys></setting></system></set>",
            "<debug><software><restart></restart></software></debug>",
            "<commit-all><shared-policy></shared-policy></commit-all>",
            "<show><devices><all/></devices></show>",  # same command, different spelling: still not allowlisted
            "show devices all",
        ):
            with self.assertRaises(ph.ReadOnlyViolation, msg=cmd):
                ph.guard({"type": "op", "cmd": cmd})

    def test_target_only_on_targeted_commands(self):
        ph.guard({"type": "op", "cmd": ph.OP_COMMANDS["session_info"], "target": "0079010001"})
        ph.guard({"type": "op", "cmd": ph.OP_COMMANDS["dp_resources"], "target": "0079010001"})
        with self.assertRaises(ph.ReadOnlyViolation):
            ph.guard({"type": "op", "cmd": ph.OP_COMMANDS["devices_all"], "target": "0079010001"})
        with self.assertRaises(ph.ReadOnlyViolation):
            ph.guard({"type": "op", "cmd": ph.OP_COMMANDS["session_info"], "target": "x&type=commit"})

    def test_log_rules(self):
        ph.guard({"type": "log", "log-type": "system", "nlogs": "100", "query": "(severity geq high)"})
        ph.guard({"type": "log", "action": "get", "job-id": "12"})
        for params in (
            {"type": "log", "action": "finish", "job-id": "12"},
            {"type": "log", "log-type": "traffic", "nlogs": "10"},
            {"type": "log", "log-type": "system", "nlogs": "999999"},
            {"type": "log", "action": "get", "job-id": "12; drop"},
        ):
            with self.assertRaises(ph.ReadOnlyViolation, msg=params):
                ph.guard(params)

    def test_client_never_sends_a_rejected_request(self):
        fake = FakePanorama()
        client = ph.PanoramaClient(make_settings(), transport=fake, log=lambda *_: None)
        with self.assertRaises(ph.ReadOnlyViolation):
            client.request({"type": "config", "action": "delete", "xpath": "/config/shared"}, "bad")
        with self.assertRaises(ph.ReadOnlyViolation):
            client.rest_get("Objects/Tags", {"location": "shared"})
        self.assertEqual(fake.sent, [])

    def test_rest_guard(self):
        ph.guard_rest("GET", "Policies/SecurityPreRules", {"location": "shared"})
        ph.guard_rest("GET", "Policies/SecurityPreRules", {"location": "device-group", "device-group": "DG 1"})
        ph.guard_rest("GET", "Panorama/DeviceGroups", {})
        for method in ("POST", "PUT", "DELETE", "PATCH"):
            with self.assertRaises(ph.ReadOnlyViolation, msg=method):
                ph.guard_rest(method, "Policies/SecurityPreRules", {"location": "shared"})
        for endpoint, query in (
            ("Objects/Tags", {"location": "shared"}),                         # not allowlisted
            ("Policies/SecurityPreRules", {"location": "shared", "name": "x"}),       # extra parameter
            ("Policies/SecurityPreRules", {"location": "shared", "newname": "y"}),    # rename parameter
            ("Policies/SecurityPreRules", {"location": "vsys"}),                      # unknown location
            ("Policies/SecurityPreRules", {"location": "device-group"}),      # missing device-group
            ("Policies/SecurityPreRules", {"location": "shared", "device-group": "DG"}),
            ("Policies/SecurityPreRules", {"location": "device-group", "device-group": "a\nb"}),
        ):
            with self.assertRaises(ph.ReadOnlyViolation, msg=(endpoint, query)):
                ph.guard_rest("GET", endpoint, query)


class SettingsTests(unittest.TestCase):
    def _env(self, text):
        tmp = tempfile.NamedTemporaryFile("w", suffix=".env", delete=False, encoding="utf-8")
        tmp.write(text)
        tmp.close()
        self.addCleanup(Path(tmp.name).unlink)
        return tmp.name

    def test_host_must_be_in_allowlist(self):
        path = self._env("PANORAMA_HOST=10.9.9.9\nALLOWED_HOSTS=192.0.2.10\nPANORAMA_API_KEY=k\n")
        with self.assertRaises(ph.ConfigError):
            ph.load_settings(path, environ={})

    def test_env_var_cannot_widen_allowlist(self):
        path = self._env("PANORAMA_HOST=192.0.2.10\nALLOWED_HOSTS=192.0.2.10\nPANORAMA_API_KEY=k\n")
        with self.assertRaises(ph.ConfigError):
            ph.load_settings(path, environ={"PANORAMA_HOST": "10.9.9.9", "ALLOWED_HOSTS": "10.9.9.9"})

    def test_empty_key_rejected_unless_dry_run(self):
        path = self._env("PANORAMA_HOST=192.0.2.10\nALLOWED_HOSTS=192.0.2.10\nPANORAMA_API_KEY=\n")
        with self.assertRaises(ph.ConfigError):
            ph.load_settings(path, environ={})
        self.assertEqual(ph.load_settings(path, environ={}, require_key=False).host, "192.0.2.10")

    def test_key_never_allowed_in_url(self):
        path = self._env("PANORAMA_HOST=192.0.2.10\nALLOWED_HOSTS=192.0.2.10\nPANORAMA_API_KEY=k\n"
                         "HTTP_METHOD=GET\nKEY_IN_HEADER=false\n")
        with self.assertRaises(ph.ConfigError):
            ph.load_settings(path, environ={})

    def test_separate_xml_and_rest_keys(self):
        path = self._env("PANORAMA_HOST=192.0.2.10\nALLOWED_HOSTS=192.0.2.10\nPANORAMA_API_KEY=old\n"
                         "PANORAMA_XML_API_KEY=xml-key\nPANORAMA_REST_API_KEY=rest-key\nAPI_MODE=xml\n")
        settings = ph.load_settings(path, environ={})
        self.assertEqual((settings.xml_api_key, settings.rest_api_key), ("xml-key", "rest-key"))
        self.assertEqual(settings.api_key, "xml-key")
        self.assertIn("PANORAMA_XML_API_KEY", settings.key_label())
        self.assertNotIn("xml-key", settings.key_label())

    def test_legacy_key_is_fallback_for_both(self):
        path = self._env("PANORAMA_HOST=192.0.2.10\nALLOWED_HOSTS=192.0.2.10\nPANORAMA_API_KEY=old\n"
                         "PANORAMA_REST_API_KEY=rest-key\n")
        settings = ph.load_settings(path, environ={})
        self.assertEqual((settings.xml_api_key, settings.rest_api_key), ("old", "rest-key"))

    def test_key_for_current_mode_is_required(self):
        path = self._env("PANORAMA_HOST=192.0.2.10\nALLOWED_HOSTS=192.0.2.10\nPANORAMA_REST_API_KEY=k\n"
                         "API_MODE=xml\n")
        with self.assertRaises(ph.ConfigError) as ctx:
            ph.load_settings(path, environ={})
        self.assertIn("PANORAMA_XML_API_KEY", str(ctx.exception))

    def test_xml_is_the_only_default_mode(self):
        path = self._env("PANORAMA_HOST=192.0.2.10\nALLOWED_HOSTS=192.0.2.10\nPANORAMA_API_KEY=k\nAPI_MODE=rest\n")
        settings = ph.load_settings(path, environ={"API_MODE": "rest"})
        self.assertEqual((settings.api_mode, settings.rest_version), ("xml", "v11.0"))


class ClientTests(unittest.TestCase):
    def test_key_goes_in_header_not_body(self):
        fake = FakePanorama()
        client = ph.PanoramaClient(make_settings(), transport=fake, log=lambda *_: None)
        client.op("system_info")
        params, headers = fake.sent[0]
        self.assertEqual(headers["X-PAN-KEY"], "SECRET-KEY")
        self.assertNotIn("key", params)

    def test_each_api_uses_its_own_key(self):
        fake = FakePanorama()
        client = ph.PanoramaClient(make_settings(), transport=fake, log=lambda *_: None)
        client.op("system_info")
        client.rest_get("Panorama/DeviceGroups", {})
        self.assertEqual([h["X-PAN-KEY"] for _, h in fake.sent], ["SECRET-KEY", "REST-KEY"])

    def test_xml_key_in_post_body(self):
        fake = FakePanorama()
        client = ph.PanoramaClient(make_settings(key_in_header=False), transport=fake, log=lambda *_: None)
        client.op("system_info")
        params, headers = fake.sent[0]
        self.assertEqual(params["key"], "SECRET-KEY")
        self.assertNotIn("X-PAN-KEY", headers)

    def test_error_response_maps_code_and_hint(self):
        denied = b'<response status="error" code="16"><msg><line>Unauthorized request</line></msg></response>'
        client = ph.PanoramaClient(make_settings(), transport=lambda p, q, h, m: (200, denied),
                                   log=lambda *_: None)
        with self.assertRaises(ph.ApiError) as ctx:
            client.op("devices_all")
        self.assertEqual(ctx.exception.code, "16")
        self.assertIn("Operational Requests", str(ctx.exception))

    def test_diagnose_finds_working_key_method(self):
        config_denied = (b'<response status="error" code="403"><result><msg>Type [config] not authorized '
                         b'for user role.</msg></result></response>')
        fake = FakePanorama()

        def header_denied(path, query, headers, method="POST"):
            if "X-PAN-KEY" in headers:
                return 403, config_denied
            return fake(path, query, headers, method)

        client = ph.PanoramaClient(make_settings(), transport=header_denied, log=lambda *_: None)
        with contextlib.redirect_stdout(io.StringIO()) as out, mock.patch.object(ph.time, "sleep"):
            code = ph.diagnose(client)
        self.assertEqual(code, 1)
        self.assertIn("PASS  key in POST body", out.getvalue())
        self.assertIn("KEY_IN_HEADER=false", out.getvalue())

    def test_non_xml_response_is_reported(self):
        client = ph.PanoramaClient(make_settings(), transport=lambda p, q, h, m: (200, b"<html>proxy</html>x"),
                                   log=lambda *_: None)
        with self.assertRaises(ph.ApiError):
            client.op("system_info")

    def test_rest_get_sends_key_in_header_only(self):
        fake = FakePanorama()
        client = ph.PanoramaClient(make_settings(api_mode="rest"), transport=fake, log=lambda *_: None)
        entries = client.rest_get("Panorama/DeviceGroups", {"location": "panorama"})
        params, headers = fake.sent[0]
        self.assertEqual(entries[0]["@name"], "DG-Branch")
        self.assertEqual(headers["X-PAN-KEY"], "REST-KEY")
        self.assertEqual(params, {"location": "panorama"})

    def test_rest_permission_error_has_hint(self):
        client = ph.PanoramaClient(make_settings(api_mode="rest"),
                                   transport=lambda p, q, h, m: (403, json.dumps(REST_DENIED).encode()),
                                   log=lambda *_: None)
        with self.assertRaises(ph.ApiError) as ctx:
            client.rest_get("Policies/SecurityPreRules", {"location": "shared"})
        self.assertEqual(ctx.exception.code, "403")
        self.assertIn("REST API tab > Policies > SecurityPreRules", str(ctx.exception))


class ParserTests(unittest.TestCase):
    def test_flatten_devices(self):
        result = ET.fromstring(DEVICES_ALL).find("result")
        row = ph.flatten(result.find("devices/entry"))
        self.assertEqual(row["hostname"], "fw-a")
        self.assertEqual(row["ha/state"], "active")
        self.assertEqual(row["vsys/vsys1/shared-policy-status"], "In Sync")

    def test_parse_resources_and_sessions(self):
        res = ph.parse_resources(ET.fromstring(TOP_TEXT).find("result"))
        self.assertEqual(res, {"mgmt_cpu_pct": "10.0", "mgmt_mem_pct": "75.0"})
        ses = ph.parse_session_info(ET.fromstring(SESSION_INFO).find("result"))
        self.assertEqual(ses["session_util_pct"], "85.0")

    def test_ha_pairs(self):
        devices = [
            {"serial": "1", "hostname": "a1", "connected": "yes", "ha/state": "active", "ha/peer/serial": "2"},
            {"serial": "2", "hostname": "a2", "connected": "yes", "ha/state": "active", "ha/peer/serial": "1"},
            {"serial": "3", "hostname": "b1", "connected": "yes", "ha/state": "passive", "ha/peer/serial": "4"},
            {"serial": "4", "hostname": "b2", "connected": "yes", "ha/state": "passive", "ha/peer/serial": "3"},
            {"serial": "5", "hostname": "c1", "connected": "yes", "ha/state": "active", "ha/peer/serial": "6"},
            {"serial": "6", "hostname": "c2", "connected": "no", "ha/state": "passive", "ha/peer/serial": "5"},
            {"serial": "7", "hostname": "d1", "connected": "yes", "ha/state": "active", "ha/peer/serial": "99"},
            {"serial": "8", "hostname": "e1", "connected": "yes", "ha/state": "active-primary", "ha/peer/serial": "9"},
            {"serial": "9", "hostname": "e2", "connected": "yes", "ha/state": "active-secondary", "ha/peer/serial": "8"},
            {"serial": "10", "hostname": "solo", "connected": "yes"},
        ]
        status = {r["firewall"]: r["status"] for r in ph.ha_pairs(devices)}
        self.assertEqual(status, {"a1": "both active (possible split brain)", "b1": "no active member",
                                  "c1": "peer not connected", "d1": "peer not managed by Panorama", "e1": "ok"})
        data = ph.Collector(None, make_settings()).data
        data["devices"] = devices
        severities = {f["finding"]: f["severity"] for f in ph.evaluate(data) if f["finding"].startswith("HA pair")}
        self.assertEqual(severities["HA pair: both active (possible split brain)"], "critical")
        self.assertEqual(severities["HA pair: no active member"], "high")

    def test_sync_status(self):
        self.assertEqual(ph.sync_status({"type": "template", "template-status": "Out of Sync"}), "Out of Sync")
        self.assertEqual(ph.sync_status({"vsys/vsys1/shared-policy-status": "In Sync"}), "In Sync")
        self.assertEqual(ph.sync_status({"last-commit-all-state-sp": "commit failed",
                                         "shared-policy-status": "In Sync"}), "Commit failed")
        self.assertEqual(ph.sync_status({"connected": "yes"}), "unknown")

    def test_parse_disk_space(self):
        rows = ph.parse_disk_space(ET.fromstring(DISK_SPACE).find("result"), "pano-lab", "P1")
        self.assertEqual([(r["mount"], r["use_pct"]) for r in rows],
                         [("/", "95"), ("/opt/pancfg", "65"), ("/opt/panlogs", "98")])

    def test_parse_ntp(self):
        ntp = ph.parse_ntp(ET.fromstring(NTP).find("result"))
        self.assertEqual(ntp["ntp_synched"], "LOCAL")
        self.assertEqual(ntp["ntp_servers"], "192.0.2.123 (rejected, reachable=no)")
        self.assertEqual(ph.parse_ntp(ET.Element("result")), {})

    def test_parse_dp_resources(self):
        row = ph.parse_dp_resources(ET.fromstring(DP_RESOURCES).find("result"))
        self.assertEqual(row, {"dp_cpu_pct": "61.3", "packet_buffer_pct": "12.0"})

    def test_certificate_row_never_keeps_private_key(self):
        entry = ET.fromstring(SHARED_CERTS).find("result/certificate/entry")
        row = ph.certificate_row("shared", entry)
        self.assertEqual(row["has-private-key"], "yes")
        self.assertLess(int(row["days_left"]), 0)
        self.assertNotIn("PRIVATEBLOB", json.dumps(row))
        self.assertNotIn("PUBLICBLOB", json.dumps(row))

    def test_days_left(self):
        now = 1_000_000_000  # 2001-09-09 01:46:40 UTC
        self.assertEqual(ph.days_left(str(now + 5 * 86400), now), "5")
        self.assertEqual(ph.days_left("Sep 19 01:46:40 2001 GMT", now), "10")
        self.assertEqual(ph.days_left("2001/09/07 01:46:40", now), "-2")
        self.assertEqual(ph.days_left("N/A", now), "")

    def test_panorama_ha_and_load_findings(self):
        data = ph.Collector(None, make_settings()).data
        data["panorama_ha"] = ph.flatten(ET.fromstring(HA_DEGRADED).find("result"))
        data["panorama_resources"] = {"mgmt_cpu_pct": "97.0", "mgmt_mem_pct": "40.0"}
        data["resources"] = [{"serial": "001", "hostname": "fw-a", "dp_cpu_pct": "88.0", "packet_buffer_pct": "1"}]
        found = [f["finding"] for f in ph.evaluate(data)]
        for text in ("Panorama HA peer connection is 'down'", "Panorama HA local state is 'primary-suspended'",
                     "Panorama HA running config is 'not synchronized'", "Management CPU at 97.0%",
                     "Dataplane CPU at 88.0%"):
            self.assertIn(text, found)
        self.assertFalse(any("memory" in f or "Packet buffer" in f for f in found))

    def test_device_certificate_findings(self):
        data = ph.Collector(None, make_settings()).data
        soon = time.strftime("%Y/%m/%d %H:%M:%S", time.gmtime(time.time() + 5 * 86400))
        data["devices"] = [
            {"serial": "1", "hostname": "fw-a", "connected": "yes", "device-cert-present": "None"},
            {"serial": "2", "hostname": "fw-b", "connected": "yes", "device-cert-present": "Valid",
             "device-cert-expiry-date": soon},
            {"serial": "3", "hostname": "fw-c", "connected": "yes", "device-cert-present": "Valid",
             "device-cert-expiry-date": "2099/01/01 00:00:00"},
        ]
        found = {(f["target"], f["finding"]) for f in ph.evaluate(data) if f["area"] == "certificates"}
        self.assertIn(("fw-a", "Device certificate is 'None'"), found)
        self.assertTrue(any(t == "fw-b" and "expires in" in f for t, f in found))
        self.assertFalse(any(t == "fw-c" for t, _ in found))

    def test_parse_ha_details(self):
        row = ph.parse_ha(ET.fromstring(HA_ALL).find("result"))
        self.assertEqual((row["ha_mode"], row["ha_local_state"], row["ha_peer_state"]),
                         ("Active-Passive", "active", "passive"))
        self.assertEqual((row["ha1_status"], row["ha2_status"], row["ha_config_sync"]), ("up", "down", "not synchronized"))
        self.assertEqual((row["ha_priority"], row["ha_state_sync"], row["ha_link_monitoring"]), ("100", "Complete", "yes"))

    def test_parse_logging_status(self):
        row = ph.parse_logging_status(ET.fromstring(LOGGING_STATUS).find("result"))
        self.assertEqual((row["log_forwarding"], row["log_destination"], row["log_fwd_lag_min"]),
                         ("connected", "192.0.2.50", "90"))
        self.assertEqual(row["last_log_forwarded"], _STAMP(600))
        down = ph.parse_logging_status(ET.fromstring(LOGGING_DOWN).find("result"))
        self.assertEqual(down["log_forwarding"], "not connected")
        self.assertEqual(ph.parse_logging_status(ET.Element("result"))["log_forwarding"], "")

    def test_parse_content_age(self):
        row = ph.parse_content(ET.fromstring(FW_SYSTEM_INFO).find("result"), now=_NOW)
        self.assertEqual((row["av_age_days"], row["app_age_days"], row["wildfire_age_days"]), ("10", "2", ""))

    def test_version_findings(self):
        data = ph.Collector(None, make_settings()).data
        data["panorama"] = {"sw-version": "10.2.8", "av-version": "4805-5310"}
        data["devices"] = [
            {"serial": "1", "hostname": "new", "connected": "yes", "sw-version": "11.1.2", "av-version": "4805-5310"},
            {"serial": "2", "hostname": "maint", "connected": "yes", "sw-version": "10.2.9", "av-version": "4801-5306"},
            {"serial": "3", "hostname": "ok", "connected": "yes", "sw-version": "10.2.8-h3", "av-version": "4804-5309"},
        ]
        found = {(f["target"], f["finding"]): f["severity"] for f in ph.evaluate(data) if f["area"] == "versions"}
        self.assertEqual(found[("new", "Firewall runs a newer PAN-OS feature release than Panorama")], "high")
        self.assertEqual(found[("maint", "Firewall runs a newer maintenance release than Panorama")], "low")
        self.assertEqual(found[("maint", "Antivirus content is behind the newest in use")], "medium")  # 4 behind
        self.assertEqual(found[("ok", "Antivirus content is behind the newest in use")], "low")
        self.assertNotIn(("ok", "Firewall runs a newer maintenance release than Panorama"), found)

    def test_firewall_status_rows(self):
        dev_rows =[dict(ph.flatten(e), serial=e.get("name"))
                    for e in ET.fromstring(DEVICES_ALL).find("result").findall("devices/entry")]
        sync = (ph.Collector._sync_rows("device-group", ET.fromstring(DEVICEGROUPS).findall("result/devicegroups/entry"))
                + ph.Collector._sync_rows("template", ET.fromstring(TEMPLATES).findall("result/templates/entry")))
        rows = {r["hostname"]: r for r in ph.firewall_status(dev_rows, sync)}
        self.assertEqual((rows["fw-a"]["device-group"], rows["fw-a"]["policy_sync"]), ("DG-Branch", "In Sync"))
        self.assertEqual((rows["fw-a"]["template"], rows["fw-a"]["template_sync"]), ("TPL-Branch", "Out of Sync"))
        self.assertEqual((rows["fw-a"]["ha_peer"], rows["fw-b"]["ha_peer"]), ("fw-b", "fw-a"))
        self.assertEqual(rows["fw-c"]["policy_sync"], "")

    def test_antivirus_profile_check(self):
        rule = {"action": "allow", "disabled": "no", "source": "10.0.0.0/8", "destination": "any",
                "application": "web-browsing", "service": "application-default", "log-end": "yes",
                "log-setting": "fwd", "profiles": "spyware=strict, vulnerability=strict"}
        self.assertIn(("low", "Allow rule without an antivirus profile"), ph.evaluate_rule(rule))
        rule["profiles"] = "virus=default, spyware=strict"
        self.assertEqual(ph.evaluate_rule(rule), [])
        rule["profiles"] = "best-practice"  # a profile group: contents unknown, not flagged
        self.assertEqual(ph.evaluate_rule(rule), [])

    def test_rule_evaluation(self):
        rules = ET.fromstring(RULES_DG).find("result/rules").findall("entry")
        rows = [ph.rule_row("DG", "pre-rulebase", i, e) for i, e in enumerate(rules, 1)]
        issues = {r["name"]: [i for _, i in ph.evaluate_rule(r)] for r in rows}
        self.assertTrue(any("all 'any'" in i for i in issues["allow-any"]))
        self.assertEqual(issues["web-out"], [])
        self.assertIn("Rule is disabled", issues["old"])
        self.assertIn("Logging at session end is disabled", issues["old"])


class EndToEndTests(unittest.TestCase):
    def run_main(self, *args, mode="xml", xml_key=True, fake=None):
        fake = fake or FakePanorama()
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        env = Path(tmp.name) / ".env"
        env.write_text(f"PANORAMA_HOST={LAB_HOST}\nALLOWED_HOSTS={LAB_HOST}\n"
                       + ("PANORAMA_XML_API_KEY=SECRET-KEY\n" if xml_key else "")
                       + "PANORAMA_REST_API_KEY=REST-KEY\n"
                       f"REQUEST_DELAY_SEC=0\nAPI_MODE={mode}\n", encoding="utf-8")
        out = io.StringIO()
        with contextlib.redirect_stdout(out), mock.patch.object(ph.time, "sleep"):  # skip log-poll waits
            code = ph.main(["--env", str(env), "--output-dir", tmp.name, *args], transport=fake)
        return code, fake, Path(tmp.name), out.getvalue()

    def test_full_run_writes_html_and_csv(self):
        code, fake, out_dir, stdout = self.run_main("--targeted")
        self.assertEqual(code, 0, stdout)
        report_dir = next(p for p in out_dir.iterdir() if p.is_dir())
        names = {p.name for p in report_dir.iterdir()}
        for expected in ("report.html", "inventory.csv", "sync_status.csv", "security_rules.csv",
                         "rule_findings.csv", "findings.csv", "jobs.csv", "system_logs.csv",
                         "firewall_resources.csv", "certificates.csv", "disk_usage.csv", "firewall_status.csv"):
            self.assertIn(expected, names)

        findings = (report_dir / "findings.csv").read_text(encoding="utf-8-sig")
        for text in ("Firewall not connected", "HA state is 'suspended'", "Out of Sync",
                     "CommitAll failed", "Log collector not connected", "Session table utilisation",
                     "Clock is not synchronised to an NTP server", "/ is 95% full",
                     "shared: old-ca,Certificate expired",
                     "template TPL-Branch: gp-portal,Certificate expires in 10 days",
                     "HA2 link is 'down'", "HA config is not synchronised with the peer",
                     "Log forwarding is 90 minutes behind", "Antivirus content is 10 days old",
                     "HA peers run different versions,app-version 8800-8000 vs 8700-7900",
                     "Applications & Threats content is behind the newest in use"):
            self.assertIn(text, findings)
        self.assertNotIn("panlogs", findings)  # log partition is full by design

        status = (report_dir / "firewall_status.csv").read_text(encoding="utf-8-sig")
        self.assertIn("fw-a,001,yes,10.2.10,8800-8000,4800-5300", status)
        self.assertIn("DG-Branch,In Sync,TPL-Branch,Out of Sync", status)
        self.assertIn("Active-Passive", status)
        disk = (report_dir / "disk_usage.csv").read_text(encoding="utf-8-sig")
        self.assertIn("pano-lab", disk)
        self.assertIn("fw-b", disk)  # targeted firewalls' disks too
        resources = (report_dir / "firewall_resources.csv").read_text(encoding="utf-8-sig")
        self.assertIn("61.3", resources)  # dataplane CPU

        for path in report_dir.iterdir():
            text = path.read_text(encoding="utf-8-sig")
            for secret in ("SECRET-KEY", "REST-KEY", "PRIVATEBLOB"):
                self.assertNotIn(secret, text, path.name)
        html_text = (report_dir / "report.html").read_text(encoding="utf-8")
        self.assertIn("fw-a", html_text)
        for params, headers in fake.sent:
            self.assertIn(params["type"], ("op", "config", "log"))
            self.assertEqual(headers["X-PAN-KEY"], "SECRET-KEY")  # XML key only

    def test_api_mode_rest_in_env_never_hits_rest(self):
        with contextlib.redirect_stderr(io.StringIO()) as err:
            code, fake, out_dir, stdout = self.run_main(mode="rest")
        self.assertEqual(code, 0, stdout)
        self.assertIn("API_MODE in .env is no longer used", err.getvalue())
        self.assertTrue(all("type" in p for p, _ in fake.sent), "a REST call was made")
        self.assertTrue(all(h["X-PAN-KEY"] == "SECRET-KEY" for _, h in fake.sent))

        report_dir = next(p for p in out_dir.iterdir() if p.is_dir())
        sync = (report_dir / "sync_status.csv").read_text(encoding="utf-8-sig")
        self.assertIn("template,TPL-Branch,fw-a,001,yes,Out of Sync", sync)
        self.assertIn("device-group,DG-Branch,fw-a,001,yes,In Sync", sync)
        ha = (report_dir / "ha_pairs.csv").read_text(encoding="utf-8-sig")
        self.assertIn("fw-a,001,active,fw-b,002,suspended,yes,degraded", ha)
        html_text = (report_dir / "report.html").read_text(encoding="utf-8")
        self.assertIn("XML API", html_text)
        self.assertIn("Firewall HA pairs", html_text)
        self.assertNotIn("Not collected", html_text)

    @staticmethod
    def rule_calls(fake):
        calls = []
        for p, _ in fake.sent:
            m = re.search(r"(?:entry\[@name='([^']+)'\]|/config/shared)/(?:pre|post)-rulebase", p.get("xpath", ""))
            if m:
                calls.append(m.group(1) or "shared")
        return calls

    def test_quick_limits_device_groups(self):
        code, fake, out_dir, stdout = self.run_main("--quick", "--sections", "rules", fake=ThreeGroupPanorama())
        self.assertEqual(code, 0, stdout)
        self.assertEqual(self.rule_calls(fake), ["shared", "shared", "DG-Branch", "DG-Branch", "DG-DC", "DG-DC"])
        self.assertIn("Limited run: security rules for shared + 2 of 3 device groups", stdout)
        report_dir = next(p for p in out_dir.iterdir() if p.is_dir())
        self.assertIn("Limited run", (report_dir / "report.html").read_text(encoding="utf-8"))

    def test_device_groups_option(self):
        code, fake, _, stdout = self.run_main("--device-groups", "DG-Lab,Nope", "--sections", "rules",
                                              fake=ThreeGroupPanorama())
        self.assertEqual(code, 0, stdout)
        self.assertEqual(self.rule_calls(fake), ["shared", "shared", "DG-Lab", "DG-Lab"])
        self.assertIn("not found on Panorama: Nope", stdout)

    def test_rest_diagnose(self):
        fake = FakePanorama()
        client = ph.PanoramaClient(make_settings(), transport=fake, log=lambda *_: None)
        with contextlib.redirect_stdout(io.StringIO()) as out:
            code = ph.diagnose(client, "rest")
        self.assertTrue(all("type" not in p and h["X-PAN-KEY"] == "REST-KEY" for p, h in fake.sent))
        self.assertEqual(code, 0, out.getvalue())
        self.assertIn("PASS  Panorama/DeviceGroups (3: DG-Branch, DG-DC, DG-Lab)", out.getvalue())

    def test_rules_collected_when_op_is_denied(self):
        fake = FakePanorama()

        def op_denied(path, query, headers, method="POST"):
            if "type=op" in query:
                fake.sent.append((dict(urllib.parse.parse_qsl(query)), headers))
                return 403, OP_DENIED.encode()
            return fake(path, query, headers, method)

        client = ph.PanoramaClient(make_settings(), transport=op_denied, log=lambda *_: None)
        with contextlib.redirect_stdout(io.StringIO()) as out, mock.patch.object(ph.time, "sleep"):
            data = ph.Collector(client, make_settings()).run(["devices", "rules", "logs"])
        self.assertEqual(len(data["rules"]), 3)
        self.assertEqual(len(data["system_logs"]), 1)
        self.assertEqual([e["section"] for e in data["errors"]], ["devices"])
        self.assertIn("does not allow 'Operational Requests'", out.getvalue())

    def test_menu_refuses_dry_run_and_diagnose(self):
        for flag in ("--dry-run", "--diagnose"):
            with contextlib.redirect_stderr(io.StringIO()):
                code, fake, _, _ = self.run_main("--menu", flag)
            self.assertEqual((code, fake.sent), (2, []), flag)

    def test_firewalls_option_limits_live_checks(self):
        code, fake, _, stdout = self.run_main("--firewalls", "002", "--sections", "devices,targeted")
        self.assertEqual(code, 0, stdout)
        targets = {p.get("target") for p, _ in fake.sent if p.get("target")}
        self.assertEqual(targets, {"002"})

    def test_dry_run_sends_nothing(self):
        code, fake, out_dir, stdout = self.run_main("--dry-run", "--targeted")
        self.assertEqual(code, 0)
        self.assertEqual(fake.sent, [])
        for call in ("op devices_all", "op disk_space", "op ntp", "config show /config/shared/certificate",
                     "op dp_resources target=<serial>"):
            self.assertIn(call, stdout)
        self.assertEqual(list(out_dir.glob("2*")), [])


class MenuTests(unittest.TestCase):
    """Drive the interactive menu with scripted input (numbered mode) or keypresses (arrow mode)."""

    def make_app(self, inputs, **overrides):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.out_dir = Path(tmp.name)
        script = iter(inputs)

        def read_line(prompt=""):
            try:
                return next(script)
            except StopIteration:
                raise AssertionError("menu asked for more input than the test scripted") from None

        self.fake = FakePanorama()
        self.screen = io.StringIO()
        settings = make_settings(output_dir=self.out_dir, **overrides)
        return ph.MenuApp(settings, transport=self.fake, tui=ph.Tui(out=self.screen, read_line=read_line))

    def run_app(self, app):
        with contextlib.redirect_stdout(io.StringIO()), mock.patch.object(ph.time, "sleep"):
            self.assertEqual(app.run(), 0)
        return self.screen.getvalue()

    def op_calls(self):
        return [(next(k for k, v in ph.OP_COMMANDS.items() if v == p["cmd"]), p.get("target"))
                for p, _ in self.fake.sent if p.get("type") == "op"]

    def test_menu_is_populated_from_panorama(self):
        screen = self.run_app(self.make_app(["q"]))
        self.assertEqual(self.op_calls(), [("devices_all", None), ("devicegroups", None), ("templates", None)])
        self.assertTrue(all("type" in p for p, _ in self.fake.sent), "the menu hit the REST API by default")
        for text in ("3 firewalls (1 not connected)", "1 device groups", "1 templates",
                     "Full health check", "~21 calls", "Bye."):
            self.assertIn(text, screen)

    def test_quick_check_writes_report_and_shows_results(self):
        screen = self.run_app(self.make_app(["2", "f", "", "b", "q"]))
        self.assertIn("Health check complete", screen)
        self.assertIn("Top findings", screen)
        self.assertIn("Firewall not connected to Panorama", screen)
        report = next(p for p in self.out_dir.iterdir() if p.is_dir())
        self.assertTrue((report / "report.html").exists())
        self.assertNotIn("SECRET-KEY", (report / "report.html").read_text(encoding="utf-8"))

    def test_custom_check_uses_picked_sections_and_firewalls(self):
        # sections: none, then rules (6) + targeted (9); all device groups; firewalls capped at 1:
        # trying to add fw-b (2) is refused; both formats; run; back; quit.
        app = self.make_app(["3", "n", "6,9", "", "", "2", "", "", "r", "b", "q"], max_targeted=1)
        screen = self.run_app(app)
        self.assertIn("At most 1 can be selected", screen)
        targeted = {target for _, target in self.op_calls() if target}
        self.assertEqual(targeted, {"001"})
        xpaths = [p.get("xpath", "") for p, _ in self.fake.sent if p.get("type") == "config"]
        self.assertTrue(any("DG-Branch" in x and "pre-rulebase" in x for x in xpaths))
        self.assertFalse(any("certificate" in x for x in xpaths))

    def test_browse_firewall_live_status(self):
        screen = self.run_app(self.make_app(["4", "f", "1", "l", "", "b", "", "b", "q"]))
        self.assertIn("Live status: fw-a", screen)
        self.assertIn("Dataplane CPU %", screen)
        self.assertIn("61.3", screen)
        for text in ("Policy sync", "Template sync", "HA2 link", "Log forwarding", "192.0.2.50",
                     "Antivirus age (days)", "HA peers run different versions"):
            self.assertIn(text, screen)
        self.assertEqual({t for _, t in self.op_calls() if t}, {"001"})

    def test_browse_device_group_and_jobs(self):
        screen = self.run_app(self.make_app(["4", "g", "1", "m", "", "b", "", "j", "2", "", "", "b", "q"]))
        self.assertIn("Device group DG-Branch", screen)
        self.assertIn("Recent jobs (2, 1 failed)", screen)
        self.assertIn("Job 41", screen)

    def test_browse_ha_and_sync(self):
        screen = self.run_app(self.make_app(["4", "h", "", "b", "q"]))
        for text in ("XML API", "HA & sync overview", "Firewall HA pairs", "degraded", "Out of Sync 1", "TPL-Branch"):
            self.assertIn(text, screen)

    def test_rest_only_through_its_menu_option(self):
        # REST option -> run -> back from results -> back from the REST menu -> quit
        screen = self.run_app(self.make_app(["9", "r", "b", "b", "q"]))
        self.assertIn("REST API (optional, GET only)", screen)
        rest = [(p, h) for p, h in self.fake.sent if "type" not in p]
        self.assertTrue(rest)
        self.assertTrue(all(h["X-PAN-KEY"] == "REST-KEY" for _, h in rest))
        self.assertTrue(all("type" in p for p, _ in self.fake.sent[:3]))  # inventory before it was XML
        report = next(p for p in self.out_dir.iterdir() if p.is_dir())
        self.assertIn("001,DG-Branch,TS-Branch", (report / "inventory.csv").read_text(encoding="utf-8-sig"))
        rules = (report / "security_rules.csv").read_text(encoding="utf-8-sig")
        self.assertIn("allow-any", rules)
        self.assertIn("REST API", (report / "report.html").read_text(encoding="utf-8"))
        self.assertNotIn("REST-KEY", (report / "report.html").read_text(encoding="utf-8"))

    def test_rest_option_disabled_without_rest_key(self):
        screen = self.run_app(self.make_app(["9", "q"], rest_api_key=""))
        self.assertIn("Not available: PANORAMA_REST_API_KEY is empty in .env", screen)
        self.assertTrue(all("type" in p for p, _ in self.fake.sent))

    def test_settings_never_exceed_env_limits(self):
        app = self.make_app(["8", "t", "50", "", "d", "0.2", "", "w", "48", "b", "q"], request_delay=1.0)
        self.run_app(app)
        self.assertEqual((app.settings.max_targeted, app.settings.request_delay), (5, 1.0))
        self.assertEqual(app.settings.log_window_hours, 48)

    def make_reports(self):
        for name in ("20260101-000000", "20260102-000000", "keep-me"):
            (self.out_dir / name).mkdir()
            (self.out_dir / name / "findings.csv").write_text("severity\nhigh\n", encoding="utf-8")
        (self.out_dir / "notes.txt").write_text("not a report", encoding="utf-8")

    def remaining(self):
        return sorted(p.name for p in self.out_dir.iterdir())

    def test_clear_all_reports_needs_confirmation(self):
        app = self.make_app(["7", "x", "no", "", "q"])
        self.make_reports()
        screen = self.run_app(app)
        self.assertIn("Cancelled; nothing was deleted", screen)
        self.assertEqual(self.remaining(), ["20260101-000000", "20260102-000000", "keep-me", "notes.txt"])

        app = self.make_app(["7", "x", "DELETE", "", "q"])
        self.make_reports()
        screen = self.run_app(app)
        self.assertIn("Deleted 2 report folder(s)", screen)
        self.assertEqual(self.remaining(), ["keep-me", "notes.txt"])  # only timestamped report folders go

    def test_delete_one_report(self):
        app = self.make_app(["7", "1", "x", "DELETE", "", "", "q"])
        self.make_reports()
        self.run_app(app)
        self.assertEqual(self.remaining(), ["20260101-000000", "keep-me", "notes.txt"])  # newest was deleted

    def test_past_reports(self):
        screen = self.run_app(self.make_app(["2", "b", "7", "1", "f", "", "b", "", "q"]))
        self.assertIn("Past reports (1, newest first)", screen)
        self.assertIn("Findings 2", screen)  # report folder names start with the year

    def test_estimate_matches_a_real_run(self):
        sections = [s for s in ph.SECTIONS if s != "targeted"]
        fake = FakePanorama()
        client = ph.PanoramaClient(make_settings(), transport=fake, log=lambda *_: None)
        with contextlib.redirect_stdout(io.StringIO()), mock.patch.object(ph.time, "sleep"):
            ph.Collector(client, make_settings()).run(sections)
        self.assertEqual(len(fake.sent), ph.estimate_calls("xml", sections, groups=1, templates=1))
        self.assertEqual(ph.estimate_calls("rest", ["devices", "rules"], groups=3), 10)


class TuiKeyTests(unittest.TestCase):
    items = [ph.MenuItem("a", "fw-a"), ph.MenuItem("b", "fw-b"), ph.MenuItem("c", "fw-c", disabled=True, hint="off")]

    def tui(self, keys):
        return ph.Tui(out=io.StringIO(), keys=keys)

    def test_arrow_select_and_hotkey(self):
        self.assertEqual(self.tui(["down", "enter"]).select("t", self.items), "b")
        self.assertEqual(self.tui(["up", "up", "enter"]).select("t", self.items), "b")  # wraps around
        self.assertEqual(self.tui(["b"]).select("t", self.items), "b")
        self.assertIsNone(self.tui(["esc"]).select("t", self.items))
        tui = self.tui(["c", "a"])  # a disabled item is refused; the next key still works
        self.assertEqual(tui.select("t", self.items), "a")
        self.assertIn("Not available: off", tui.out.getvalue())

    def test_type_to_filter(self):
        self.assertEqual(self.tui(["f", "w", "-", "b", "enter"]).select("t", self.items, filterable=True), "b")

    def test_checklist_toggle_all_none_and_limit(self):
        self.assertEqual(self.tui(["space", "down", "space", "enter"]).checklist("t", self.items), ["a", "b"])
        self.assertEqual(self.tui(["+", "enter"]).checklist("t", self.items), ["a", "b", "c"])
        self.assertEqual(self.tui(["-", "enter"]).checklist("t", self.items, selected=["a"]), [])
        tui = self.tui(["space", "down", "space", "enter"])
        self.assertEqual(tui.checklist("t", self.items, limit=1), ["a"])
        self.assertIn("At most 1", tui.out.getvalue())

    def test_plain_number_ranges(self):
        answers = iter(["1-2", ""])
        tui = ph.Tui(out=io.StringIO(), read_line=lambda prompt="": next(answers))
        self.assertEqual(tui.checklist("t", self.items), ["a", "b"])


if __name__ == "__main__":
    unittest.main()
