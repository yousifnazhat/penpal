from __future__ import annotations

from .models import Service


HTTP_NAMES = {"http", "https", "http-proxy", "ssl/http"}

PORT_GUIDANCE: dict[int, list[str]] = {
    21: [
        "Check banner and anonymous login.",
        "List readable files and capture anything downloaded in loot/.",
    ],
    22: [
        "Record SSH version and host key details.",
        "Save credentialed checks for when valid creds are found.",
    ],
    25: [
        "Check SMTP banner, supported commands, and relay posture.",
        "Try safe user enumeration only when the lab rules allow it.",
    ],
    53: [
        "Try zone transfer against discovered nameservers.",
        "Brute-force subdomains when a domain name is known.",
    ],
    80: [
        "Run web fingerprinting, directory discovery, and screenshot capture.",
        "Check headers, robots.txt, sitemap.xml, source comments, and default files.",
    ],
    88: [
        "Identify the Kerberos realm and domain naming.",
        "Save AS-REP or Kerberoasting checks for authorized AD labs.",
    ],
    111: [
        "Enumerate RPC services and look for NFS exports.",
    ],
    135: [
        "Correlate with SMB, RPC, WinRM, and domain services.",
    ],
    139: [
        "Enumerate SMB shares, signing, null session posture, and domain/workgroup.",
    ],
    161: [
        "Check SNMP version and community exposure in authorized labs.",
        "Parse walks for users, processes, interfaces, and software hints.",
    ],
    389: [
        "Check LDAP naming contexts and anonymous bind posture.",
        "Record domain, users, groups, and password policy if readable.",
    ],
    443: [
        "Run web fingerprinting, TLS checks, directory discovery, and screenshot capture.",
        "Inspect certificates for hostnames and internal naming hints.",
    ],
    445: [
        "Enumerate SMB shares, signing, null session posture, and domain/workgroup.",
        "Check readable shares before trying credentialed actions.",
    ],
    2049: [
        "List NFS exports and check mount permissions.",
    ],
    3306: [
        "Record MySQL version and authentication posture.",
        "Save credentialed checks for when valid creds are found.",
    ],
    3389: [
        "Record RDP certificate details and hostname hints.",
        "Use credentialed login checks only with known valid creds.",
    ],
    5985: [
        "Mark WinRM as a credentialed follow-up path.",
    ],
    5986: [
        "Mark WinRM over TLS as a credentialed follow-up path.",
    ],
}


def recommendations_for(service: Service) -> list[str]:
    guidance: list[str] = []
    name = service.name.lower()
    if service.port in PORT_GUIDANCE:
        guidance.extend(PORT_GUIDANCE[service.port])
    if name in HTTP_NAMES and service.port not in {80, 443}:
        guidance.extend(PORT_GUIDANCE[80])
    if "ssl" in service.tunnel and service.port not in {443, 5986}:
        guidance.append("Inspect TLS certificate names and protocol support.")
    return dedupe(guidance)


def all_recommendations(services: list[Service]) -> dict[str, list[str]]:
    return {
        service.key: recommendations_for(service)
        for service in services
        if recommendations_for(service)
    }


def dedupe(values: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if value not in seen:
            seen.add(value)
            result.append(value)
    return result

