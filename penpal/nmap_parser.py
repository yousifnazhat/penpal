from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path

from .models import Service


class NmapParseError(RuntimeError):
    pass


def parse_nmap_xml(path: str | Path, include_states: set[str] | None = None) -> list[Service]:
    xml_path = Path(path)
    if not xml_path.exists():
        raise NmapParseError(f"Nmap XML not found: {xml_path}")

    include_states = include_states or {"open"}
    try:
        root = ET.parse(xml_path).getroot()
    except ET.ParseError as exc:
        raise NmapParseError(f"Invalid Nmap XML: {xml_path}") from exc

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
            scripts = {
                script.get("id", "script"): script.get("output", "")
                for script in port_node.findall("script")
            }
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

