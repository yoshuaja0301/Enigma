"""Tests for the Nmap and WhatWeb output parsers."""

import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout

from enigma.agent.tools import (
    NmapParseError,
    PARSERS,
    ToolFindingAdapter,
    parse_nmap,
    parse_whatweb,
)
from enigma.cli import main
from enigma.controller import AssessmentController
from enigma.core.assessment import (
    Assessment,
    AssessmentProfile,
    Authorization,
    AuthorizationStatus,
    Scope,
)
from enigma.core.target import Target
from enigma.findings.model import Verdict
from enigma.findings.normalizer import KNOWN_CHECKS
from enigma.verification.http import FakeTransport, HttpResponse

NMAP_XML = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" version="7.94">
  <host>
    <status state="up"/>
    <address addr="93.184.216.34" addrtype="ipv4"/>
    <hostnames><hostname name="target.example" type="user"/></hostnames>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open" reason="syn-ack"/>
        <service name="http" product="nginx" version="1.18.0" method="probe"/>
        <script id="http-methods" output="Supported Methods: GET HEAD POST OPTIONS TRACE"/>
      </port>
      <port protocol="tcp" portid="443">
        <state state="open"/>
        <service name="https" product="nginx" version="1.18.0" tunnel="ssl"/>
        <script id="http-security-headers" output="Content-Security-Policy header is missing"/>
      </port>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="8.2p1"/>
      </port>
      <port protocol="tcp" portid="3306">
        <state state="closed"/>
        <service name="mysql"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""

WHATWEB_JSONL = "\n".join([
    json.dumps({
        "target": "http://target.example/",
        "http_status": 200,
        "plugins": {
            "HTTPServer": {"string": ["nginx/1.18.0 (Ubuntu)"], "os": ["Ubuntu"]},
            "X-Powered-By": {"string": ["PHP/7.4.3"]},
            "Title": {"string": ["Example Site"]},
            "Country": {"string": ["INDONESIA"], "module": ["ID"]},
            "IP": {"string": ["93.184.216.34"]},
            "Bootstrap": {"string": ["bootstrap"]},
        },
    }),
    json.dumps({
        "target": "http://target.example/admin",
        "plugins": {"Apache": {"version": ["2.4.41"], "string": ["Apache/2.4.41"]}},
    }),
])


class NmapParserTests(unittest.TestCase):
    def setUp(self):
        self.findings = parse_nmap(NMAP_XML)

    def test_closed_ports_are_ignored(self):
        ports = {f["tool"]["port"] for f in self.findings}
        self.assertNotIn("3306", ports)
        self.assertEqual(ports, {"80", "443", "22"})

    def test_open_port_recorded_but_not_verifiable(self):
        open_ports = [f for f in self.findings if f["category"] == "open-port"]
        self.assertEqual(len(open_ports), 3)      # 80, 443, 22
        for f in open_ports:
            self.assertNotIn("check", f)          # Enigma cannot verify a port over HTTP
            self.assertEqual(f["target"]["host"], "target.example")

    def test_http_service_banner_maps_to_server_version(self):
        banners = [f for f in self.findings
                   if f["category"] == "version-disclosure" and "nginx" in f["title"]]
        self.assertTrue(banners)
        for f in banners:
            self.assertEqual(f["check"], "server_version")

    def test_non_http_service_banner_is_not_an_http_check(self):
        # OpenSSH on 22 must NOT become an HTTP server_version check.
        ssh = [f for f in self.findings if f["tool"]["port"] == "22"]
        self.assertEqual(len(ssh), 1)             # only the open-port record
        self.assertNotIn("check", ssh[0])

    def test_nse_http_methods_flags_risky_method(self):
        trace = [f for f in self.findings if f.get("parameters", {}).get("method") == "TRACE"]
        self.assertEqual(len(trace), 1)
        self.assertEqual(trace[0]["check"], "http_method")
        # GET/POST are not risky and must not be emitted
        methods = {f.get("parameters", {}).get("method") for f in self.findings}
        self.assertNotIn("GET", methods)

    def test_nse_security_headers_infers_header(self):
        headers = [f for f in self.findings if f["category"] == "security-headers"]
        self.assertEqual(len(headers), 1)
        self.assertEqual(headers[0]["check"], "security_header")
        self.assertEqual(headers[0]["parameters"]["header"], "Content-Security-Policy")

    def test_rejects_entity_declaration(self):
        malicious = NMAP_XML.replace("<!DOCTYPE nmaprun>",
                                     '<!DOCTYPE nmaprun [<!ENTITY a "aaaa">]>')
        with self.assertRaises(NmapParseError):
            parse_nmap(malicious)

    def test_rejects_non_nmap_xml(self):
        with self.assertRaises(NmapParseError):
            parse_nmap("<other><x/></other>")

    def test_rejects_malformed_xml(self):
        with self.assertRaises(NmapParseError):
            parse_nmap("<nmaprun><host>")

    def test_empty_input(self):
        self.assertEqual(parse_nmap(""), [])


class WhatWebParserTests(unittest.TestCase):
    def setUp(self):
        self.findings = parse_whatweb(WHATWEB_JSONL)

    def test_metadata_plugins_are_not_findings(self):
        titles = " ".join(f["title"] for f in self.findings)
        for noise in ("Title", "Country", "IP"):
            self.assertNotIn(f"{noise} discloses", titles)
        self.assertNotIn("INDONESIA", titles)

    def test_version_disclosure_maps_to_server_version(self):
        disclosures = [f for f in self.findings if f["category"] == "version-disclosure"]
        self.assertTrue(disclosures)
        for f in disclosures:
            self.assertEqual(f["check"], "server_version")

    def test_version_parsed_from_string_when_absent(self):
        http_server = next(f for f in self.findings if f["tool"]["plugin"] == "HTTPServer")
        self.assertIn("1.18.0", http_server["tool"]["versions"])

    def test_explicit_version_field_used(self):
        apache = next(f for f in self.findings if f["tool"]["plugin"] == "Apache")
        self.assertEqual(apache["tool"]["versions"], ["2.4.41"])
        self.assertEqual(apache["target"]["path"], "/admin")

    def test_technology_without_version_is_recorded_not_verified(self):
        bootstrap = next(f for f in self.findings if f["tool"]["plugin"] == "Bootstrap")
        self.assertNotIn("check", bootstrap)

    def test_skipped_metadata_is_visible_in_provenance(self):
        skipped = [f["tool"].get("skipped_metadata_plugins") for f in self.findings]
        flat = {name for entry in skipped if entry for name in entry}
        self.assertIn("Title", flat)
        self.assertIn("Country", flat)

    def test_accepts_json_array_form(self):
        array = json.dumps([json.loads(WHATWEB_JSONL.splitlines()[1])])
        self.assertEqual(len(parse_whatweb(array)), 1)

    def test_empty_input(self):
        self.assertEqual(parse_whatweb(""), [])


class RegistryTests(unittest.TestCase):
    def test_all_four_instruments_have_parsers(self):
        self.assertEqual(set(PARSERS), {"nuclei", "zap", "nmap", "whatweb"})

    def test_every_inferred_check_is_real(self):
        for findings in (parse_nmap(NMAP_XML), parse_whatweb(WHATWEB_JSONL)):
            for finding in findings:
                if "check" in finding:
                    self.assertIn(finding["check"], KNOWN_CHECKS)


class ThroughPipelineTests(unittest.TestCase):
    def _assessment(self):
        return Assessment(
            assessment_id="ASM-NW",
            target=Target("http://target.example/"),
            authorization=Authorization(status=AuthorizationStatus.AUTHORIZED),
            scope=Scope(allowed_hosts=["target.example"]),
            profile=AssessmentProfile.SAFE_VERIFICATION,
        )

    def test_nmap_version_claim_refuted_when_no_banner(self):
        # Nmap claims nginx/1.18.0; the live server discloses nothing.
        transport = FakeTransport(default=HttpResponse(status=200, headers={}))
        adapter = ToolFindingAdapter.from_nmap(NMAP_XML)
        results = AssessmentController(transport=transport).run(self._assessment(), adapter)
        version = [r for r in results if r.finding.check == "server_version"]
        self.assertTrue(version)
        for result in version:
            self.assertEqual(result.verdict, Verdict.NOT_CONFIRMED)

    def test_open_ports_are_reported_not_dropped(self):
        transport = FakeTransport(default=HttpResponse(status=200))
        adapter = ToolFindingAdapter.from_nmap(NMAP_XML)
        results = AssessmentController(transport=transport).run(self._assessment(), adapter)
        ports = [r for r in results if r.finding.category == "open-port"]
        self.assertEqual(len(ports), 3)
        for result in ports:
            self.assertEqual(result.status, "reported")

    def test_whatweb_version_confirmed_when_server_discloses(self):
        transport = FakeTransport(default=HttpResponse(
            status=200, headers={"Server": "nginx/1.18.0"}))
        adapter = ToolFindingAdapter.from_whatweb(WHATWEB_JSONL)
        results = AssessmentController(transport=transport).run(self._assessment(), adapter)
        version = [r for r in results if r.finding.check == "server_version"]
        self.assertTrue(version)
        for result in version:
            self.assertEqual(result.verdict, Verdict.CONFIRMED)


class CliTests(unittest.TestCase):
    def _write(self, text, suffix):
        with tempfile.NamedTemporaryFile("w", suffix=suffix, delete=False) as handle:
            handle.write(text)
            return handle.name

    def test_verify_accepts_nmap_and_whatweb_flags(self):
        assessment = self._write(json.dumps({
            "assessment_id": "ASM-CLI-NW",
            "target": {"url": "http://target.example/"},
            "authorization": {"status": "authorized"},
            "scope": {"allowed_hosts": ["target.example"]},
        }), ".json")
        nmap = self._write(NMAP_XML, ".xml")
        whatweb = self._write(WHATWEB_JSONL, ".json")

        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main([
                "verify", "--assessment", assessment,
                "--nmap", nmap, "--whatweb", whatweb,
                "--format", "json", "--offline",
            ])
        self.assertEqual(code, 0)
        payload = json.loads(buf.getvalue())
        sources = {r["finding"]["source"] for r in payload["results"]}
        self.assertEqual(sources, {"nmap", "whatweb"})


if __name__ == "__main__":
    unittest.main()
