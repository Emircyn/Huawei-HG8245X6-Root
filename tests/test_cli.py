"""End-to-end CLI checks against a loopback fake ONT; never contacts a router."""
import json
import base64
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit


ROOT = Path(__file__).resolve().parents[1]
CLI = Path(os.environ.get("HUAWEI_CLI", ROOT / "src/publish/huawei"))


def js(name, fields):
    return "new " + name + "(" + ",".join(json.dumps(x) for x in fields) + ");"


class FakeOnt(BaseHTTPRequestHandler):
    dns = "192.0.2.53,192.0.2.54"
    posts = []
    deny = False
    token = "fresh-token"
    ignore_writes = False
    missing_wifi = False
    config = b'<InternetGatewayDevice><DeviceInfo ModelName="Mock"/><!--' + b'x' * 600 + b'--></InternetGatewayDevice>'

    def log_message(self, *args):
        pass

    def reply(self, body, status=200, cookie=False):
        body = body.encode() if isinstance(body, str) else body
        self.send_response(status)
        if cookie:
            self.send_header("Set-Cookie", "Cookie=sid=mock; Path=/")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        data = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        fields = parse_qs(data.decode(errors="replace"))
        type(self).posts.append((self.path, fields))
        path = urlsplit(self.path).path
        if path == "/asp/GetRandCount.asp":
            self.reply("auth-token")
        elif path == "/login.cgi":
            self.reply("index.asp", cookie=True)
        elif path == "/cfgfiledown.cgi":
            self.reply(self.config)
        elif path == "/cfgfileupload.cgi":
            self.reply("success: reset")
        elif path == "/set.cgi":
            if "z.X_HW_DNSList" in fields and not self.ignore_writes:
                type(self).dns = fields["z.X_HW_DNSList"][0]
            self.reply("ok")
        else:
            self.reply("ok")

    def do_GET(self):
        path = urlsplit(self.path).path
        if path.endswith("GetRandToken.asp"):
            return self.reply(self.token)
        if path == "/missing":
            return self.reply("missing", 404)
        if path == "/raw":
            return self.reply("raw-device-data")
        if path.endswith("deviceinfo.asp"):
            if self.deny:
                return self.reply('<input id="txt_Username">' + "x" * 200)
            body = js("stDeviceInfo", ["InternetGatewayDevice.DeviceInfo", "MOCK001", "HW", "SW", "HG8245X6", "vendor", "time", "00:11:22:33:44:55"])
        elif path.endswith("dhcp2.asp"):
            fields = [""] * 20
            fields[0], fields[16] = "InternetGatewayDevice.LANDevice.1.LANHostConfigManagement", self.dns
            body = js("dhcpmainst", fields)
        elif path.endswith("wan_list_cache_wan.asp"):
            fields = [""] * 41
            fields[0], fields[8], fields[12], fields[14], fields[19] = "InternetGatewayDevice.WANDevice.1.WANConnectionDevice.1.WANPPPConnection.1", "INTERNET", "Connected", "192.0.2.1", "user@isp"
            body = js("WanPPP", fields)
        elif path.endswith("WlanBasic.asp"):
            if self.missing_wifi:
                return self.reply("Unavailable", 403)
            domain = "InternetGatewayDevice.LANDevice.1.WLANConfiguration.1"
            body = js("stWlanWifi", [domain, "wifi", "1", "TestSSID", "n", "6"])
            fields = [""] * 17
            fields[0], fields[4], fields[7], fields[16] = domain, "1", "11i", "AES"
            body += js("stWlan", fields) + js("stPreSharedKey", [domain + ".PreSharedKey.1", "PrivateWifi123", ""])
        elif path.endswith("alg.asp"):
            body = js("stAlg", ["InternetGatewayDevice.X_HW_ALG"] + ["0"] * 10)
        elif path.endswith("firewalllevel.asp"):
            body = "var FltsecLevelx='Low'; var AdvancedLevelValue='InternetGatewayDevice.X_HW_Security.Firewall.Level.1';"
        elif path.endswith("tr069.asp"):
            body = js("stCWMP", ["InternetGatewayDevice.ManagementServer", "1", "1", "300", "", "http://acs.example"])
        elif path.endswith("ontstate.asp"):
            body = "var PonMode='ge';"
        else:
            body = ""
        self.reply(body + " " * 100)


class CliTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), FakeOnt)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.host = "127.0.0.1:" + str(cls.server.server_port)

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.dir = Path(self.temp.name)
        FakeOnt.posts = []
        FakeOnt.deny = False
        FakeOnt.dns = "192.0.2.53,192.0.2.54"
        FakeOnt.token = "fresh-token"
        FakeOnt.ignore_writes = False
        FakeOnt.missing_wifi = False

    def run_cli(self, *args, code=0, env=None, offline=False):
        environment = dict(os.environ, HUAWEI_PASSWORD="MockPassword123", TEST_NEW="UpdatedValue123")
        environment.update(env or {})
        argv = [str(CLI), *args]
        if not offline:
            argv += ["--host", self.host]
        p = subprocess.run(argv, capture_output=True, text=True, env=environment, timeout=20)
        self.assertEqual(p.returncode, code, p.stdout + p.stderr)
        self.assertNotIn("MockPassword123", p.stdout + p.stderr)
        return json.loads(p.stdout)

    def test_self_checks(self):
        self.assertTrue(self.run_cli("self-test", offline=True)["data"]["passed"])

    def test_read_wifi_masks_password_by_default(self):
        result = self.run_cli("wifi", "get")
        self.assertEqual(result["data"][0]["Psk"], "***")
        result = self.run_cli("wifi", "get", "--show-secrets")
        self.assertEqual(result["data"][0]["Psk"], "PrivateWifi123")

    def test_dns_write_is_read_back(self):
        result = self.run_cli("dns", "set", "--primary", "198.51.100.53", "--secondary", "198.51.100.54")
        self.assertEqual(result["state"], "verified")
        self.assertEqual(FakeOnt.dns, "198.51.100.53,198.51.100.54")

    def test_invalid_dns_does_not_write(self):
        self.run_cli("dns", "set", "--primary", "1.1.1.1&x.Enable=0", code=2)
        self.assertFalse(any(p.startswith("/set.cgi") for p, _ in FakeOnt.posts))

    def test_generic_post_encodes_values_and_uses_fresh_token(self):
        path = self.dir / "fields.json"
        path.write_text(json.dumps({"x.SSID": "a&b=c", "x.X_HW_Token": "stale"}))
        result = self.run_cli("http", "post", "--path", "set.cgi?x=InternetGatewayDevice.Test", "--file", str(path), code=5)
        self.assertEqual(result["state"], "submitted")
        self.assertEqual(FakeOnt.posts[-1][1]["x.SSID"], ["a&b=c"])
        self.assertEqual(FakeOnt.posts[-1][1]["x.X_HW_Token"], ["fresh-token"])

    def test_raw_read_and_http_error(self):
        self.assertEqual(self.run_cli("http", "get", "--path", "raw")["data"]["body"], "raw-device-data")
        self.run_cli("http", "get", "--path", "missing", code=4)

    def test_login_page_is_not_authenticated(self):
        FakeOnt.deny = True
        self.run_cli("http", "get", "--path", "raw", code=3)

    def test_unknown_duplicate_and_missing_options(self):
        for args in [("info", "--bogus", "1"), ("info", "--host", "a", "--host", "b"), ("info", "--timeout")]:
            self.run_cli(*args, code=2, offline=True)
        self.assertEqual(FakeOnt.posts, [])

    def test_default_credentials_and_invalid_host(self):
        self.run_cli("http", "get", "--path", "raw", env={"HUAWEI_PASSWORD": ""})
        login = next(fields for path, fields in FakeOnt.posts if path == "/login.cgi")
        self.assertEqual(login["UserName"], ["admin"])
        self.assertEqual(base64.b64decode(login["PassWord"][0]).decode(), "superonline")
        FakeOnt.posts = []
        self.run_cli("info", "--host", "user:pass@127.0.0.1/path", code=2, offline=True)
        self.assertEqual(FakeOnt.posts, [])

    def test_backup_private_and_no_clobber(self):
        path = self.dir / "backup.cfg"
        self.run_cli("backup", "config", "--output", str(path))
        self.assertEqual(path.read_bytes(), FakeOnt.config)
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.run_cli("backup", "config", "--output", str(path), code=4)
        self.assertEqual(path.read_bytes(), FakeOnt.config)

    def test_profile_backup_contains_reusable_wifi_secret(self):
        path = self.dir / "profile.json"
        self.run_cli("backup", "profile", "--output", str(path))
        self.assertEqual(json.loads(path.read_text())["Wifi"][0]["Psk"], "PrivateWifi123")
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

    def test_invalid_restore_never_authenticates_or_uploads(self):
        path = self.dir / "bad.cfg"
        path.write_bytes(b"not-a-config" * 100)
        self.run_cli("restore", "config", "--file", str(path), code=2)
        self.assertEqual(FakeOnt.posts, [])

    def test_config_edit_preserves_original(self):
        source = self.dir / "source.xml"
        source.write_bytes(FakeOnt.config)
        output = self.dir / "changed.xml"
        self.run_cli("config", "edit", "--file", str(source), "--xpath", "//DeviceInfo", "--attribute", "ModelName", "--value-env", "TEST_NEW", "--output", str(output), offline=True)
        self.assertEqual(source.read_bytes(), FakeOnt.config)
        self.assertIn(b'ModelName="UpdatedValue123"', output.read_bytes())
        self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)

    def test_config_rejects_dtd(self):
        source = self.dir / "external.xml"
        source.write_text('<!DOCTYPE x [<!ENTITY a SYSTEM "file:///etc/passwd">]><InternetGatewayDevice>&a;</InternetGatewayDevice>')
        self.run_cli("config", "get", "--file", str(source), "--xpath", "//*", code=2, offline=True)

    def test_ignored_dns_write_is_not_success(self):
        FakeOnt.ignore_writes = True
        result = self.run_cli("dns", "set", "--primary", "198.51.100.99", code=5)
        self.assertEqual(result["state"], "submitted")
        self.assertEqual(FakeOnt.dns, "192.0.2.53,192.0.2.54")

    def test_missing_token_prevents_generic_write(self):
        FakeOnt.token = ""
        path = self.dir / "fields.json"
        path.write_text('{"x.Enable":"0"}')
        self.run_cli("http", "post", "--path", "set.cgi", "--file", str(path), code=4)
        self.assertFalse(any(p.startswith("/set.cgi") for p, _ in FakeOnt.posts))

    def test_partial_read_does_not_claim_complete(self):
        FakeOnt.missing_wifi = True
        result = self.run_cli("info", code=5)
        self.assertEqual(result["state"], "partial")
        self.assertTrue(result["warnings"])

    def test_partial_data_cannot_be_saved_as_full_profile(self):
        FakeOnt.missing_wifi = True
        path = self.dir / "incomplete.json"
        self.run_cli("backup", "profile", "--output", str(path), code=4)
        self.assertFalse(path.exists())

    def test_foreign_urls_and_header_injection_are_rejected(self):
        for path in ["https://example.com", "//example.com", "raw\r\nX-Test: injected", "raw#fragment", "\\example.com"]:
            with self.subTest(path=path):
                self.run_cli("http", "get", "--path", path, code=2)

    def test_invalid_generic_payloads_never_write(self):
        for payload in ['null', '[]', '{"x.Enable":true}', '{"x.Enable":null}', '{broken']:
            with self.subTest(payload=payload):
                path = self.dir / "fields.json"
                path.write_text(payload)
                self.run_cli("http", "post", "--path", "set.cgi", "--file", str(path), code=2)
        self.assertFalse(any(p.startswith("/set.cgi") for p, _ in FakeOnt.posts))

    def test_invalid_write_parameters(self):
        cases = [
            ("wifi", "set", "--band", "99", "--ssid", "new"),
            ("wifi", "set", "--band", "1", "--ssid", "x" * 33),
            ("wifi", "set", "--band", "1", "--ssid", "ğ" * 17),
            ("wifi", "set", "--band", "1", "--hidden", "yes"),
            ("wifi", "set", "--band", "1", "--psk-env", "ABSENT_TEST_SECRET"),
            ("firewall", "set", "--level", "ultra"),
            ("tr069", "set", "--enabled", "maybe"),
            ("dns", "set", "--primary", "1.1.1.1", "--secondary", "invalid"),
            ("dns", "set", "--primary", "1.1.1.1", "--side", "unknown"),
        ]
        for args in cases:
            with self.subTest(args=args):
                self.run_cli(*args, code=2, env={"ABSENT_TEST_SECRET": ""})
        self.assertFalse(any(p.startswith("/set.cgi") for p, _ in FakeOnt.posts))

    def test_unchanged_firewall_is_not_verified(self):
        self.assertEqual(self.run_cli("firewall", "set", "--level", "high", code=5)["state"], "submitted")

    def test_unchanged_alg_is_not_verified(self):
        path = self.dir / "alg.json"
        path.write_text('{"SIP":true}')
        self.assertEqual(self.run_cli("alg", "set", "--file", str(path), code=5)["state"], "submitted")

    def test_unchanged_tr069_is_not_verified(self):
        self.assertEqual(self.run_cli("tr069", "set", "--enabled", "false", code=5)["state"], "submitted")

    def test_unknown_alg_key_never_writes(self):
        path = self.dir / "alg.json"
        path.write_text('{"NOT_REAL":true}')
        self.run_cli("alg", "set", "--file", str(path), code=2)
        self.assertFalse(any(p.startswith("/set.cgi") for p, _ in FakeOnt.posts))

    def test_config_edit_ambiguous_or_missing_target(self):
        source = self.dir / "source.xml"
        source.write_text('<InternetGatewayDevice><Item Key="1"/><Item Key="2"/></InternetGatewayDevice>')
        for xpath, attribute in [("//Item", "Key"), ("//Missing", "Key"), ("//Item[1]", "Missing")]:
            output = self.dir / "must-not-exist.xml"
            self.run_cli("config", "edit", "--file", str(source), "--xpath", xpath, "--attribute", attribute, "--value-env", "TEST_NEW", "--output", str(output), code=2, offline=True)
            self.assertFalse(output.exists())

    def test_config_secret_attributes_masked(self):
        source = self.dir / "source.xml"
        source.write_text('<InternetGatewayDevice><Account Password="VerySecret123"/></InternetGatewayDevice>')
        result = self.run_cli("config", "get", "--file", str(source), "--xpath", "//Account", offline=True)
        self.assertEqual(result["data"][0]["attributes"]["Password"], "***")

    def test_invalid_timeout_values_before_network(self):
        for value in ["0", "-1", "3601", "abc", "1.5"]:
            self.run_cli("info", "--timeout", value, code=2)
        self.assertEqual(FakeOnt.posts, [])

    def test_password_file_authentication(self):
        path = self.dir / "password"
        path.write_text("MockPassword123\n")
        self.run_cli("http", "get", "--path", "raw", "--password-file", str(path), env={"HUAWEI_PASSWORD": ""})

    def test_explicit_credentials_override_defaults(self):
        self.run_cli("http", "get", "--path", "raw", "--user", "sUser")
        login = next(fields for path, fields in FakeOnt.posts if path == "/login.cgi")
        self.assertEqual(login["UserName"], ["sUser"])
        self.assertEqual(base64.b64decode(login["PassWord"][0]).decode(), "MockPassword123")

    def test_password_file_overrides_environment_and_empty_file_fails(self):
        path = self.dir / "password"
        path.write_text("FilePassword456\n")
        self.run_cli("http", "get", "--path", "raw", "--password-file", str(path))
        login = next(fields for name, fields in FakeOnt.posts if name == "/login.cgi")
        self.assertEqual(base64.b64decode(login["PassWord"][0]).decode(), "FilePassword456")
        FakeOnt.posts = []
        path.write_text("\n")
        self.run_cli("info", "--password-file", str(path), code=2)
        self.assertEqual(FakeOnt.posts, [])

    def test_symlink_output_does_not_overwrite_target(self):
        target = self.dir / "original"
        target.write_text("untouched")
        link = self.dir / "link"
        link.symlink_to(target)
        self.run_cli("backup", "config", "--output", str(link), code=4)
        self.assertEqual(target.read_text(), "untouched")


if __name__ == "__main__":
    unittest.main()
