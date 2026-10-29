import contextlib
import io
import sys
import tempfile
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


class FakePanorama:
    """Transport stand-in: answers by request parameters, records what was sent."""

    def __init__(self):
        self.sent = []

    def __call__(self, body, headers, method="POST"):
        params = dict(urllib.parse.parse_qsl(body.decode()))
        self.sent.append((params, headers))
        t = params["type"]
        if t == "op":
            name = next(k for k, v in ph.OP_COMMANDS.items() if v == params["cmd"])
            return {
                "system_info": SYSTEM_INFO, "ha_state": HA_STATE, "devices_all": DEVICES_ALL,
                "devicegroups": DEVICEGROUPS, "templates": TEMPLATES, "jobs_all": JOBS,
                "log_collectors": LOG_COLLECTORS, "session_info": SESSION_INFO,
                "system_resources": TOP_TEXT,
            }[name].encode()
        if t == "config":
            if params["xpath"].endswith("/device-group/entry/@name"):
                return DG_NAMES.encode()
            if "DG-Branch" in params["xpath"] and "pre-rulebase" in params["xpath"]:
                return RULES_DG.encode()
            return NOT_PRESENT.encode()
        if t == "log":
            if params.get("action") == "get":
                return SYSTEM_LOGS.encode()
            return LOG_ENQUEUE.encode()
        raise AssertionError(f"unexpected request {params}")


def make_settings(**overrides):
    values = dict(
        host=LAB_HOST, port=443, api_key="SECRET-KEY", allowed_hosts=[LAB_HOST], verify_tls=False,
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
        self.assertEqual(fake.sent, [])


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


class ClientTests(unittest.TestCase):
    def test_key_goes_in_header_not_body(self):
        fake = FakePanorama()
        client = ph.PanoramaClient(make_settings(), transport=fake, log=lambda *_: None)
        client.op("system_info")
        params, headers = fake.sent[0]
        self.assertEqual(headers["X-PAN-KEY"], "SECRET-KEY")
        self.assertNotIn("key", params)

    def test_error_response_maps_code_and_hint(self):
        denied = b'<response status="error" code="16"><msg><line>Unauthorized request</line></msg></response>'
        client = ph.PanoramaClient(make_settings(), transport=lambda b, h, m: denied, log=lambda *_: None)
        with self.assertRaises(ph.ApiError) as ctx:
            client.op("devices_all")
        self.assertEqual(ctx.exception.code, "16")
        self.assertIn("Operational Requests", str(ctx.exception))

    def test_diagnose_finds_working_key_method(self):
        config_denied = (b'<response status="error" code="403"><result><msg>Type [config] not authorized '
                         b'for user role.</msg></result></response>')
        fake = FakePanorama()

        def header_denied(body, headers, method="POST"):
            if "X-PAN-KEY" in headers or method == "POST":
                return config_denied
            return fake(body, headers, method)

        client = ph.PanoramaClient(make_settings(), transport=header_denied, log=lambda *_: None)
        with contextlib.redirect_stdout(io.StringIO()) as out, mock.patch.object(ph.time, "sleep"):
            code = ph.diagnose(client)
        self.assertEqual(code, 1)
        self.assertIn("PASS  key in URL query, GET", out.getvalue())
        self.assertIn("KEY_IN_HEADER=false", out.getvalue())
        self.assertIn("HTTP_METHOD=GET", out.getvalue())

    def test_get_sends_key_only_in_query(self):
        fake = FakePanorama()
        client = ph.PanoramaClient(make_settings(key_in_header=False, http_method="GET"), transport=fake,
                                   log=lambda *_: None)
        client.op("system_info")
        params, headers = fake.sent[0]
        self.assertEqual(params["key"], "SECRET-KEY")
        self.assertNotIn("X-PAN-KEY", headers)

    def test_non_xml_response_is_reported(self):
        client = ph.PanoramaClient(make_settings(), transport=lambda b, h, m: b"<html>proxy</html>x",
                                   log=lambda *_: None)
        with self.assertRaises(ph.ApiError):
            client.op("system_info")


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

    def test_rule_evaluation(self):
        rules = ET.fromstring(RULES_DG).find("result/rules").findall("entry")
        rows = [ph.rule_row("DG", "pre-rulebase", i, e) for i, e in enumerate(rules, 1)]
        issues = {r["name"]: [i for _, i in ph.evaluate_rule(r)] for r in rows}
        self.assertTrue(any("all 'any'" in i for i in issues["allow-any"]))
        self.assertEqual(issues["web-out"], [])
        self.assertIn("Rule is disabled", issues["old"])
        self.assertIn("Logging at session end is disabled", issues["old"])


class EndToEndTests(unittest.TestCase):
    def run_main(self, *args):
        fake = FakePanorama()
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        env = Path(tmp.name) / ".env"
        env.write_text(f"PANORAMA_HOST={LAB_HOST}\nALLOWED_HOSTS={LAB_HOST}\nPANORAMA_API_KEY=SECRET-KEY\n"
                       "REQUEST_DELAY_SEC=0\n", encoding="utf-8")
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
                         "firewall_resources.csv"):
            self.assertIn(expected, names)

        findings = (report_dir / "findings.csv").read_text(encoding="utf-8-sig")
        for text in ("Firewall not connected", "HA state is 'suspended'", "Out of Sync",
                     "CommitAll failed", "Log collector not connected", "Session table utilisation"):
            self.assertIn(text, findings)

        html_text = (report_dir / "report.html").read_text(encoding="utf-8")
        self.assertIn("fw-a", html_text)
        self.assertNotIn("SECRET-KEY", html_text)
        for params, _ in fake.sent:
            self.assertIn(params["type"], ("op", "config", "log"))

    def test_rules_collected_when_op_is_denied(self):
        fake = FakePanorama()

        def op_denied(body, headers, method="POST"):
            if b"type=op" in body:
                fake.sent.append((dict(urllib.parse.parse_qsl(body.decode())), headers))
                return OP_DENIED.encode()
            return fake(body, headers)

        client = ph.PanoramaClient(make_settings(), transport=op_denied, log=lambda *_: None)
        with contextlib.redirect_stdout(io.StringIO()) as out, mock.patch.object(ph.time, "sleep"):
            data = ph.Collector(client, make_settings()).run(["devices", "rules", "logs"])
        self.assertEqual(len(data["rules"]), 3)
        self.assertEqual(len(data["system_logs"]), 1)
        self.assertEqual([e["section"] for e in data["errors"]], ["devices"])
        self.assertIn("does not allow 'Operational Requests'", out.getvalue())

    def test_dry_run_sends_nothing(self):
        code, fake, out_dir, stdout = self.run_main("--dry-run")
        self.assertEqual(code, 0)
        self.assertEqual(fake.sent, [])
        self.assertIn("op devices_all", stdout)
        self.assertEqual(list(out_dir.glob("2*")), [])


if __name__ == "__main__":
    unittest.main()
