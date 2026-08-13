"""Tests for the Nuclei and OWASP ZAP output parsers."""

import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout

from enigma.agent.tools import ToolFindingAdapter, parse_nuclei, parse_zap
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

# --------------------------------------------------------------------------- #
# Realistic fixtures
# --------------------------------------------------------------------------- #
NUCLEI_JSONL = "\n".join(
    [
        json.dumps({
            "template-id": "http-missing-security-headers",
            "info": {"name": "HTTP Missing Security Headers", "severity": "info",
                     "tags": ["misconfig", "headers"]},
            "type": "http", "host": "http://target.example",
            "matched-at": "http://target.example/",
            "matcher-name": "content-security-policy",
        }),
        json.dumps({
            "template-id": "dir-listing",
            "info": {"name": "Directory Listing Enabled", "severity": "low", "tags": ["misconfig"]},
            "matched-at": "http://target.example/assets/",
        }),
        json.dumps({
            "template-id": "CVE-2021-41773",
            "info": {"name": "Apache Path Traversal", "severity": "critical", "tags": ["cve"]},
            "matched-at": "http://target.example/cgi-bin/",
        }),
        "",                       # blank line
        "not json at all",        # malformed line must be skipped
    ]
)

ZAP_REPORT = json.dumps({
    "@programName": "ZAP", "@version": "2.14.0",
    "site": [{
        "@name": "http://target.example", "@host": "target.example", "@port": "80",
        "alerts": [
            {
                "pluginid": "10038", "alert": "Content Security Policy (CSP) Header Not Set",
                "riskcode": "2", "confidence": "3", "desc": "<p>CSP is not set.</p>",
                "cweid": "693",
                "instances": [
                    {"uri": "http://target.example/", "method": "GET"},
                    {"uri": "http://target.example/login", "method": "GET"},
                ],
            },
            {
                "pluginid": "10010", "alert": "Cookie No HttpOnly Flag",
                "riskcode": "1", "confidence": "2", "desc": "",
                "instances": [{"uri": "http://target.example/", "evidence": "sid=abc"}],
            },
            {
                "pluginid": "40012", "alert": "Cross Site Scripting (Reflected)",
                "riskcode": "3", "confidence": "2", "desc": "",
                "instances": [{"uri": "http://target.example/search?q=xyz", "param": "q"}],
            },
            {
                "pluginid": "90022", "alert": "Application Error Disclosure",
                "riskcode": "2", "confidence": "2", "desc": "",
                "instances": [{"uri": "http://target.example/err"}],
            },
        ],
    }],
})


class NucleiParserTests(unittest.TestCase):
    def setUp(self):
        self.findings = parse_nuclei(NUCLEI_JSONL)

    def test_skips_blank_and_malformed_lines(self):
        self.assertEqual(len(self.findings), 3)

    def test_maps_missing_header_to_security_header_check(self):
        f = self.findings[0]
        self.assertEqual(f["check"], "security_header")
        self.assertEqual(f["parameters"]["header"], "Content-Security-Policy")
        self.assertEqual(f["target"]["path"], "/")
        self.assertEqual(f["target"]["host"], "target.example")

    def test_maps_directory_listing(self):
        f = self.findings[1]
        self.assertEqual(f["check"], "directory_listing")
        self.assertEqual(f["target"]["path"], "/assets/")

    def test_unmappable_template_has_no_check(self):
        f = self.findings[2]           # a CVE template — no safe automatic check
        self.assertNotIn("check", f)

    def test_severity_becomes_confidence_hypothesis(self):
        self.assertEqual(self.findings[2]["confidence"], 0.9)   # critical
        self.assertEqual(self.findings[0]["confidence"], 0.3)   # info

    def test_provenance_recorded(self):
        tool = self.findings[0]["tool"]
        self.assertEqual(tool["name"], "nuclei")
        self.assertEqual(tool["template_id"], "http-missing-security-headers")
        self.assertEqual(self.findings[0]["source"], "nuclei")

    def test_accepts_json_array_form(self):
        array = json.dumps([json.loads(NUCLEI_JSONL.splitlines()[0])])
        self.assertEqual(len(parse_nuclei(array)), 1)

    def test_accepts_file_path_and_file_object(self):
        with tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False) as handle:
            handle.write(NUCLEI_JSONL)
            path = handle.name
        self.assertEqual(len(parse_nuclei(path)), 3)
        with open(path, encoding="utf-8") as handle:
            self.assertEqual(len(parse_nuclei(handle)), 3)

    def test_empty_input(self):
        self.assertEqual(parse_nuclei(""), [])


class ZapParserTests(unittest.TestCase):
    def setUp(self):
        self.findings = parse_zap(ZAP_REPORT)

    def test_one_finding_per_instance(self):
        # 2 CSP instances + 1 cookie + 1 xss + 1 error disclosure
        self.assertEqual(len(self.findings), 5)

    def test_plugin_id_drives_check(self):
        csp = [f for f in self.findings if f["category"] == "zap-10038"]
        self.assertEqual(len(csp), 2)
        for f in csp:
            self.assertEqual(f["check"], "security_header")
            self.assertEqual(f["parameters"]["header"], "Content-Security-Policy")
        self.assertEqual({f["target"]["path"] for f in csp}, {"/", "/login"})

    def test_cookie_flag_mapping(self):
        cookie = next(f for f in self.findings if f["category"] == "zap-10010")
        self.assertEqual(cookie["check"], "cookie_flags")
        self.assertEqual(cookie["parameters"]["flag"], "HttpOnly")

    def test_reflected_xss_maps_to_reflection_with_param(self):
        xss = next(f for f in self.findings if f["category"] == "zap-40012")
        self.assertEqual(xss["check"], "reflection")
        self.assertEqual(xss["parameters"]["param"], "q")
        self.assertEqual(xss["target"]["path"], "/search")  # query stripped from path

    def test_unmappable_alert_has_no_check(self):
        err = next(f for f in self.findings if f["category"] == "zap-90022")
        self.assertNotIn("check", err)

    def test_zap_confidence_becomes_hypothesis_confidence(self):
        csp = next(f for f in self.findings if f["category"] == "zap-10038")
        self.assertEqual(csp["confidence"], 0.85)   # ZAP confidence 3 = High

    def test_provenance_recorded(self):
        csp = next(f for f in self.findings if f["category"] == "zap-10038")
        self.assertEqual(csp["source"], "zap")
        self.assertEqual(csp["tool"]["plugin_id"], "10038")
        self.assertEqual(csp["tool"]["risk"], "medium")

    def test_site_as_object_and_missing_instances(self):
        report = json.dumps({"site": {"@host": "h.example", "alerts": [
            {"pluginid": "10020", "alert": "Missing Anti-clickjacking Header", "confidence": "2"}
        ]}})
        findings = parse_zap(report)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["check"], "clickjacking")

    def test_invalid_json_raises(self):
        with self.assertRaises(ValueError):
            parse_zap("{not json")


class MappingIntegrityTests(unittest.TestCase):
    def test_every_inferred_check_is_a_real_enigma_check(self):
        for findings in (parse_nuclei(NUCLEI_JSONL), parse_zap(ZAP_REPORT)):
            for finding in findings:
                if "check" in finding:
                    self.assertIn(finding["check"], KNOWN_CHECKS)


class ToolFindingsThroughPipelineTests(unittest.TestCase):
    """Tool findings must be VERIFIED, not trusted."""

    def _assessment(self):
        return Assessment(
            assessment_id="ASM-TOOL",
            target=Target("http://target.example/"),
            authorization=Authorization(status=AuthorizationStatus.AUTHORIZED),
            scope=Scope(allowed_hosts=["target.example"]),
            profile=AssessmentProfile.SAFE_VERIFICATION,
        )

    def test_high_confidence_tool_finding_can_still_be_refuted(self):
        # ZAP is 'High' confidence that CSP is missing; the server disagrees.
        transport = FakeTransport(default=HttpResponse(
            status=200, headers={"Content-Security-Policy": "default-src 'self'"}))
        adapter = ToolFindingAdapter.from_zap(ZAP_REPORT)
        results = AssessmentController(transport=transport).run(self._assessment(), adapter)
        csp = [r for r in results if r.finding.check == "security_header"]
        self.assertTrue(csp)
        for result in csp:
            self.assertEqual(result.verdict, Verdict.NOT_CONFIRMED)

    def test_unmappable_tool_finding_is_reported_not_dropped(self):
        transport = FakeTransport(default=HttpResponse(status=200))
        adapter = ToolFindingAdapter.from_nuclei(NUCLEI_JSONL)
        results = AssessmentController(transport=transport).run(self._assessment(), adapter)
        self.assertEqual(len(results), 3)  # nothing dropped
        cve = next(r for r in results if r.finding.category == "CVE-2021-41773")
        self.assertEqual(cve.status, "reported")
        self.assertEqual(cve.verdict, Verdict.INCONCLUSIVE)

    def test_source_is_visible_in_the_report(self):
        transport = FakeTransport(default=HttpResponse(status=200))
        adapter = ToolFindingAdapter.from_nuclei(NUCLEI_JSONL)
        results = AssessmentController(transport=transport).run(self._assessment(), adapter)
        self.assertEqual(results[0].to_dict()["finding"]["source"], "nuclei")


class ToolCliTests(unittest.TestCase):
    def _write(self, text, suffix):
        with tempfile.NamedTemporaryFile("w", suffix=suffix, delete=False) as handle:
            handle.write(text)
            return handle.name

    def test_verify_accepts_nuclei_and_zap_flags(self):
        assessment = self._write(json.dumps({
            "assessment_id": "ASM-CLI-TOOL",
            "target": {"url": "http://target.example/"},
            "authorization": {"status": "authorized"},
            "scope": {"allowed_hosts": ["target.example"]},
        }), ".json")
        nuclei = self._write(NUCLEI_JSONL, ".jsonl")
        zap = self._write(ZAP_REPORT, ".json")

        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main([
                "verify", "--assessment", assessment,
                "--nuclei", nuclei, "--zap", zap,
                "--format", "json", "--offline",
            ])
        self.assertEqual(code, 0)
        payload = json.loads(buf.getvalue())
        self.assertEqual(payload["summary"]["total"], 8)  # 3 nuclei + 5 zap
        sources = {r["finding"]["source"] for r in payload["results"]}
        self.assertEqual(sources, {"nuclei", "zap"})

    def test_verify_without_any_findings_source_errors(self):
        assessment = self._write(json.dumps({
            "assessment_id": "ASM-CLI-NONE",
            "target": {"url": "http://target.example/"},
            "authorization": {"status": "authorized"},
            "scope": {"allowed_hosts": ["target.example"]},
        }), ".json")
        code = main(["verify", "--assessment", assessment, "--offline"])
        self.assertEqual(code, 1)


if __name__ == "__main__":
    unittest.main()
