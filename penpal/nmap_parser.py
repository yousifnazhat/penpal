from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path
from xml.parsers import expat

from .models import Service


MAX_NMAP_XML_BYTES = 64 * 1024 * 1024


class NmapParseError(RuntimeError):
    pass


class _ForbiddenXmlDeclaration(Exception):
    pass


def parse_nmap_xml(path: str | Path, include_states: set[str] | None = None) -> list[Service]:
    xml_path = Path(path)
    if not xml_path.exists():
        raise NmapParseError(f"Nmap XML not found: {xml_path}")

    try:
        if xml_path.stat().st_size > MAX_NMAP_XML_BYTES:
            raise NmapParseError(f"Nmap XML exceeds {MAX_NMAP_XML_BYTES} bytes: {xml_path}")
        data = xml_path.read_bytes()
    except OSError as exc:
        raise NmapParseError(f"Unable to read Nmap XML: {xml_path}") from exc
    return _parse_xml(data, str(xml_path), include_states)


def parse_nmap_xml_text(text: str, include_states: set[str] | None = None) -> list[Service]:
    return _parse_xml(text.encode("utf-8"), "inline input", include_states)


def _parse_xml(data: bytes, label: str, include_states: set[str] | None) -> list[Service]:
    if len(data) > MAX_NMAP_XML_BYTES:
        raise NmapParseError(f"Nmap XML exceeds {MAX_NMAP_XML_BYTES} bytes: {label}")

    validator = expat.ParserCreate()
    validator.StartDoctypeDeclHandler = _reject_declaration
    validator.EntityDeclHandler = _reject_declaration
    try:
        validator.Parse(data, True)
    except _ForbiddenXmlDeclaration:
        raise NmapParseError(f"Nmap XML declarations are not allowed: {label}")
    except expat.ExpatError as exc:
        raise NmapParseError(f"Invalid Nmap XML: {label}") from exc
    try:
        root = ET.fromstring(data)
    except ET.ParseError as exc:
        raise NmapParseError(f"Invalid Nmap XML: {label}") from exc

    return _parse_root(root, include_states)


def _reject_declaration(*_args: object) -> None:
    raise _ForbiddenXmlDeclaration


def _parse_root(root: ET.Element, include_states: set[str] | None) -> list[Service]:
    include_states = include_states or {"open"}

    services: list[Service] = []
    for host in root.findall("host"):
        ports = host.find("ports")
        if ports is None:
            continue

        for port_node in ports.findall("port"):
            state_node = port_node.find("state")
            state = state_node.get("state", "") if state_node is not None else ""
            if state not in include_states:
                continue

            service_node = port_node.find("service")
            scripts = {script.get("id", "script"): script.get("output", "") for script in port_node.findall("script")}
            services.append(
                Service(
                    port=int(port_node.get("portid", "0")),
                    protocol=port_node.get("protocol", "tcp"),
                    state=state,
                    name=_attr(service_node, "name"),
                    product=_attr(service_node, "product"),
                    version=_attr(service_node, "version"),
                    extrainfo=_attr(service_node, "extrainfo"),
                    tunnel=_attr(service_node, "tunnel"),
                    scripts=scripts,
                )
            )

    return sorted(services, key=lambda svc: (svc.protocol, svc.port))


def _attr(node: ET.Element | None, name: str) -> str:
    if node is None:
        return ""
    return node.get(name, "")
