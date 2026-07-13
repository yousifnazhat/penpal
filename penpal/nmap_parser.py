from __future__ import annotations

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

    include_states = include_states or {"open"}
    services: list[Service] = []
    path: list[str] = []
    current: Service | None = None

    def start_element(name: str, attrs: dict[str, str]) -> None:
        nonlocal current
        path.append(name)
        if path[-3:] == ["host", "ports", "port"]:
            current = Service(
                port=int(attrs.get("portid", "0")),
                protocol=attrs.get("protocol", "tcp"),
                state="",
            )
        elif current is not None and path[-2:] == ["port", "state"]:
            current.state = attrs.get("state", "")
        elif current is not None and path[-2:] == ["port", "service"]:
            for field in ("name", "product", "version", "extrainfo", "tunnel"):
                setattr(current, field, attrs.get(field, ""))
        elif current is not None and path[-2:] == ["port", "script"]:
            current.scripts[attrs.get("id", "script")] = attrs.get("output", "")

    def end_element(_name: str) -> None:
        nonlocal current
        if current is not None and path[-3:] == ["host", "ports", "port"]:
            if current.state in include_states:
                services.append(current)
            current = None
        path.pop()

    parser = expat.ParserCreate()
    parser.StartElementHandler = start_element
    parser.EndElementHandler = end_element
    parser.StartDoctypeDeclHandler = _reject_declaration
    parser.EntityDeclHandler = _reject_declaration
    try:
        parser.Parse(data, True)
    except _ForbiddenXmlDeclaration:
        raise NmapParseError(f"Nmap XML declarations are not allowed: {label}")
    except expat.ExpatError as exc:
        raise NmapParseError(f"Invalid Nmap XML: {label}") from exc
    return sorted(services, key=lambda service: (service.protocol, service.port))


def _reject_declaration(*_args: object) -> None:
    raise _ForbiddenXmlDeclaration
