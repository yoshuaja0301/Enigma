"""Parse Nmap XML output into Enigma findings.

Nmap works at the port/service layer while Enigma verifies at the HTTP layer, so
the mapping is deliberately narrow — only what Enigma can actually prove:

* a service banner carrying product/version → ``server_version``
* NSE ``http-methods`` advertising a risky method → ``http_method``
* NSE ``http-server-header`` → ``server_version``
* NSE ``http-security-headers`` naming a missing header → ``security_header``
* NSE ``http-cors`` → ``cors``

An **open port** itself is not something Enigma can verify over HTTP, so it is
recorded as a ``reported`` finding: it is the visibility-audit evidence Nmap
contributes, kept rather than dropped, but never presented as proven.

Security note: ``xml.etree.ElementTree`` is not hardened against entity-expansion
("billion laughs") attacks. Nmap never emits ``<!ENTITY``, so input containing an
entity declaration is rejected outright rather than parsed.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional
from xml.etree import ElementTree

from .common import clamp01, find_header, read_text

# Methods worth flagging when a server advertises them.
RISKY_METHODS = ("TRACE", "TRACK", "PUT", "DELETE", "CONNECT", "PATCH")

# Nmap service names that indicate HTTP, so an HTTP-layer check makes sense.
_HTTP_SERVICES = {"http", "https", "http-alt", "https-alt", "http-proxy", "www", "webcache"}

_ENTITY_RE = re.compile(r"<!ENTITY", re.IGNORECASE)


class NmapParseError(ValueError):
    """Raised when the input is not usable Nmap XML."""


def _is_http(service: Optional[ElementTree.Element], port_id: str) -> bool:
    if service is not None:
        name = (service.get("name") or "").lower()
        if name in _HTTP_SERVICES or name.startswith("http"):
            return True
        if (service.get("tunnel") or "").lower() == "ssl" and port_id in ("443", "8443"):
            return True
    return port_id in ("80", "443", "8080", "8443")


def _hostname(host: ElementTree.Element) -> Optional[str]:
    for hostname in host.findall("./hostnames/hostname"):
        name = hostname.get("name")
        if name:
            return name.lower()
    for address in host.findall("./address"):
        if (address.get("addrtype") or "").startswith("ipv"):
            addr = address.get("addr")
            if addr:
                return addr.lower()
    return None


def _banner(service: ElementTree.Element) -> str:
    parts = [service.get("product"), service.get("version"), service.get("extrainfo")]
    return " ".join(p for p in parts if p).strip()


def parse_nmap(source: Any) -> List[Dict[str, Any]]:
    """Parse Nmap XML (``nmap -oX``) into raw Enigma findings."""

    text = read_text(source)
    if not text.strip():
        return []
    if _ENTITY_RE.search(text):
        raise NmapParseError("refusing to parse Nmap XML containing an ENTITY declaration")

    try:
        root = ElementTree.fromstring(text)
    except ElementTree.ParseError as exc:
        raise NmapParseError(f"could not parse Nmap XML: {exc}") from exc
    if root.tag != "nmaprun":
        raise NmapParseError(f"not an Nmap XML report (root element is {root.tag!r})")

    findings: List[Dict[str, Any]] = []
    index = 0

    def add(
        title: str,
        category: str,
        confidence: float,
        host: Optional[str],
        port: str,
        check: Optional[str] = None,
        parameters: Optional[Dict[str, Any]] = None,
        description: str = "",
        extra: Optional[Dict[str, Any]] = None,
    ) -> None:
        nonlocal index
        index += 1
        finding: Dict[str, Any] = {
            "finding_id": f"NMAP-{index:04d}",
            "title": title,
            "description": description,
            "category": category,
            "confidence": clamp01(confidence),
            "target": {"path": "/"},
            "source": "nmap",
            "tool": {"name": "nmap", "port": port, **(extra or {})},
        }
        if host:
            finding["target"]["host"] = host
        if check:
            finding["check"] = check
            if parameters:
                finding["parameters"] = parameters
        findings.append(finding)

    for host in root.findall("./host"):
        hostname = _hostname(host)
        for port in host.findall("./ports/port"):
            state = port.find("./state")
            if state is None or (state.get("state") or "").lower() != "open":
                continue

            port_id = port.get("portid") or "0"
            protocol = port.get("protocol") or "tcp"
            service = port.find("./service")
            service_name = (service.get("name") if service is not None else None) or "unknown"
            http_like = _is_http(service, port_id)

            # 1. The open port itself — visibility evidence, not HTTP-verifiable.
            add(
                title=f"Open port {port_id}/{protocol} ({service_name})",
                category="open-port",
                confidence=0.5,
                host=hostname,
                port=port_id,
                description=f"Nmap reported {port_id}/{protocol} open running {service_name}.",
                extra={"service": service_name, "protocol": protocol},
            )

            # 2. A service banner disclosing product/version.
            if service is not None and http_like:
                banner = _banner(service)
                if banner:
                    add(
                        title=f"Service banner discloses version: {banner}",
                        category="version-disclosure",
                        confidence=0.7,
                        host=hostname,
                        port=port_id,
                        check="server_version",
                        description=f"Nmap read the banner {banner!r} on {port_id}/{protocol}.",
                        extra={"service": service_name, "banner": banner},
                    )

            # 3. NSE script results.
            for script in port.findall("./script"):
                script_id = (script.get("id") or "").lower()
                output = script.get("output") or ""
                if not http_like:
                    continue

                if script_id == "http-methods":
                    advertised = output.upper()
                    for method in RISKY_METHODS:
                        if re.search(rf"\b{method}\b", advertised):
                            add(
                                title=f"{method} method advertised",
                                category="http-methods",
                                confidence=0.7,
                                host=hostname,
                                port=port_id,
                                check="http_method",
                                parameters={"method": method},
                                description=output.strip(),
                                extra={"script": script_id},
                            )
                elif script_id in ("http-server-header", "http-generator"):
                    add(
                        title=f"Server header discloses: {output.strip()}",
                        category="version-disclosure",
                        confidence=0.7,
                        host=hostname,
                        port=port_id,
                        check="server_version",
                        description=output.strip(),
                        extra={"script": script_id},
                    )
                elif script_id == "http-security-headers":
                    header = find_header(output)
                    add(
                        title="Security header reported missing"
                        + (f": {header}" if header else ""),
                        category="security-headers",
                        confidence=0.6,
                        host=hostname,
                        port=port_id,
                        check="security_header" if header else None,
                        parameters={"header": header} if header else None,
                        description=output.strip(),
                        extra={"script": script_id},
                    )
                elif script_id in ("http-cors", "http-cross-domain-policy"):
                    add(
                        title="CORS configuration reported by Nmap",
                        category="cors",
                        confidence=0.6,
                        host=hostname,
                        port=port_id,
                        check="cors",
                        description=output.strip(),
                        extra={"script": script_id},
                    )

    return findings
