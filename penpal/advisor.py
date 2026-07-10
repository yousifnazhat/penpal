from __future__ import annotations

from dataclasses import dataclass, field
import re
from typing import Any

from .models import Evidence, Parameter, Service


MAIL_PORTS = {110, 143, 993, 995}
REMOTE_ACCESS_PORTS = {22, 3389, 5985, 5986, 445}
WEB_PORTS = {80, 443, 8080, 8000, 8008, 8443}


@dataclass
class Suggestion:
    id: str
    title: str
    reason: str
    confidence: str
    value: str
    risk: str
    supporting_facts: list[str]
    next_actions: list[str]
    command_examples: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "reason": self.reason,
            "confidence": self.confidence,
            "value": self.value,
            "risk": self.risk,
            "supporting_facts": list(self.supporting_facts),
            "next_actions": list(self.next_actions),
            "command_examples": list(self.command_examples),
            "metadata": dict(self.metadata),
        }


def build_suggestions(
    services: list[Service],
    evidence: list[Evidence],
    target_host: str = "<target>",
    target_name: str = "<target_name>",
    parameters: dict[str, Parameter] | None = None,
    reveal_secrets: bool = False,
    playbooks: list[dict[str, Any]] | None = None,
) -> list[Suggestion]:
    parameters = parameters or {}
    target_host = _parameter_value(parameters, "target_host", target_host, reveal_secrets)
    target_name = _parameter_value(parameters, "target_name", target_name, reveal_secrets)
    suggestions: list[Suggestion] = []
    service_ports = {service.port for service in services if service.state == "open"}
    service_names = {service.name.lower() for service in services if service.state == "open"}
    evidence_by_type: dict[str, list[Evidence]] = {}
    for item in evidence:
        evidence_by_type.setdefault(item.type, []).append(item)

    has_snmp = 161 in service_ports or "snmp" in service_names
    has_mail = bool(service_ports & MAIL_PORTS) or bool(service_names & {"imap", "pop3", "imaps", "pop3s"})
    has_remote = bool(service_ports & REMOTE_ACCESS_PORTS) or bool(
        service_names & {"ssh", "rdp", "ms-wbt-server", "winrm", "microsoft-ds"}
    )
    usernames = evidence_by_type.get("username", [])
    credential_candidates = evidence_by_type.get("credential_candidate", [])
    hostnames = evidence_by_type.get("hostname", []) + evidence_by_type.get("domain", [])
    web_paths = evidence_by_type.get("web_path", [])
    interesting_files = evidence_by_type.get("interesting_file", [])

    if has_snmp and has_mail and has_remote:
        suggestions.append(
            Suggestion(
                id="path_snmp_mail_remote",
                title="Investigate SNMP to mail to remote access path",
                reason="SNMP, mail, and remote access services are present, which can form a useful enumeration chain if SNMP reveals identities or configuration.",
                confidence="medium",
                value="high",
                risk="normal",
                supporting_facts=_facts_for_ports(services, {161} | MAIL_PORTS | REMOTE_ACCESS_PORTS),
                next_actions=[
                    "Run SNMP community checks if not already done.",
                    "If a community is valid, run snmpwalk and ingest the output.",
                    "Extract usernames, hostnames, processes, and credential-looking strings.",
                    "Use only known valid credentials for mail or remote access checks.",
                ],
                command_examples=[
                    f"snmpwalk -v2c -c <community> {target_host}",
                    f"snmpwalk -v2c -c <community> {target_host} 1.3.6.1.2.1.25.4.2.1.2",
                    f"snmpwalk -v2c -c <community> {target_host} 1.3.6.1.2.1.25.6.3.1.2",
                    f"python -m penpal ingest {target_name} --file .\\snmpwalk.txt --source snmpwalk --service udp/161",
                ],
            )
        )

    if usernames and has_mail:
        suggestions.append(
            Suggestion(
                id="usernames_to_mail",
                title="Use discovered usernames to guide mail enumeration",
                reason="Usernames were found and mail services are exposed. They can help build a focused username list for authorized mail checks.",
                confidence="medium",
                value="medium",
                risk="normal",
                supporting_facts=[_evidence_fact(item, reveal_secrets) for item in usernames[:6]]
                + _facts_for_ports(services, MAIL_PORTS),
                next_actions=[
                    "Review username source context before using them.",
                    "Build a usernames list in loot/ or evidence exports.",
                    "Test only credentials you already know or are authorized to validate.",
                ],
                command_examples=_mail_command_examples(services, target_host)
                + [
                    f"python -m penpal evidence {target_name}",
                    f"python -m penpal ingest {target_name} --file .\\mail-check.txt --source mail --service <tcp/port>",
                ],
            )
        )

    if credential_candidates and has_remote:
        suggestions.append(
            Suggestion(
                id="credentials_to_remote",
                title="Review credential candidates for remote access follow-up",
                reason="Credential-looking strings were found and remote access services are exposed.",
                confidence="medium",
                value="high",
                risk="normal",
                supporting_facts=[_evidence_fact(item, reveal_secrets) for item in credential_candidates[:5]]
                + _facts_for_ports(services, REMOTE_ACCESS_PORTS),
                next_actions=[
                    "Manually validate whether the candidate is a real credential.",
                    "Record confirmed credentials as evidence with their source.",
                    "Use known valid credentials against RDP, WinRM, SMB, or SSH when allowed.",
                ],
                command_examples=_remote_access_command_examples(services, target_host),
            )
        )

    if hostnames and _has_web(services):
        domain = _parameter_value(
            parameters, "domain", _first_value(evidence_by_type.get("domain", []), "<domain>"), reveal_secrets
        )
        suggestions.append(
            Suggestion(
                id="hostnames_to_vhosts",
                title="Feed discovered hostnames into web virtual host checks",
                reason="Hostnames or domains were found while HTTP services are exposed.",
                confidence="medium",
                value="medium",
                risk="normal",
                supporting_facts=[_evidence_fact(item, reveal_secrets) for item in hostnames[:6]]
                + _facts_for_ports(services, WEB_PORTS),
                next_actions=[
                    "Add discovered names to your local hosts mapping when appropriate.",
                    "Run vhost discovery using the known domain.",
                    "Ingest web discovery output so hidden apps become evidence.",
                ],
                command_examples=[
                    f'ffuf -u http://{target_host}/ -H "Host: FUZZ.{domain}" -w <wordlist> -mc all -fs <baseline_size>',
                    f"feroxbuster -u http://{domain}/ -w <wordlist> -o .\\penpal-workspace\\targets\\{target_name}\\web\\ferox-{domain}.txt",
                    f"python -m penpal ingest {target_name} --file .\\vhosts.txt --source ffuf --service tcp/80",
                ],
            )
        )

    if web_paths:
        suggestions.append(
            Suggestion(
                id="review_web_paths",
                title="Review discovered web paths",
                reason="Web paths were extracted from pasted output and may include hidden panels, backups, or application routes.",
                confidence="medium",
                value="medium",
                risk="passive",
                supporting_facts=[_evidence_fact(item, reveal_secrets) for item in web_paths[:8]],
                next_actions=[
                    "Open interesting paths manually and capture notes or screenshots.",
                    "Prioritize admin, backup, upload, config, and version-revealing paths.",
                    "Ingest any page titles, errors, or exposed files you find.",
                ],
                command_examples=_web_path_command_examples(services, web_paths, target_host)
                + [
                    f"python -m penpal ingest {target_name} --file .\\web-notes.txt --source manual-web --service <tcp/port>",
                ],
            )
        )

    if interesting_files:
        suggestions.append(
            Suggestion(
                id="review_interesting_files",
                title="Review interesting files for new facts",
                reason="File names or paths suggest configs, backups, keys, or other high-signal artifacts.",
                confidence="medium",
                value="high",
                risk="passive",
                supporting_facts=[_evidence_fact(item, reveal_secrets) for item in interesting_files[:8]],
                next_actions=[
                    "Move relevant downloaded files into loot/.",
                    "Extract usernames, hostnames, service names, and credential-looking strings.",
                    "Feed any confirmed facts back into the evidence store.",
                ],
                command_examples=[
                    'grep -RniE "pass|user|cred|key|token|secret" loot/',
                    "Get-ChildItem .\\loot -Recurse -File | Select-String -Pattern 'pass|user|cred|key|token|secret'",
                    f"python -m penpal ingest {target_name} --file .\\loot-review.txt --source loot-review",
                ],
            )
        )

    suggestions.extend(_playbook_suggestions(playbooks or [], services, evidence, reveal_secrets))
    defaults = {"target_host": target_host, "target_name": target_name}
    return _render_suggestion_parameters(dedupe_suggestions(suggestions), parameters, reveal_secrets, defaults)


def _playbook_suggestions(
    playbooks: list[dict[str, Any]],
    services: list[Service],
    evidence: list[Evidence],
    reveal_secrets: bool,
) -> list[Suggestion]:
    suggestions: list[Suggestion] = []
    for playbook in playbooks:
        matched_signals = _matched_playbook_signals(playbook, services, evidence, reveal_secrets)
        if matched_signals is None:
            continue
        supporting_facts = [fact for match in matched_signals for fact in match["facts"]]
        actions = playbook.get("actions", [])
        suggestions.append(
            Suggestion(
                id=f"playbook_{_suggestion_id(str(playbook['id']))}",
                title=str(playbook["title"]),
                reason=str(playbook["description"]),
                confidence="medium",
                value="high",
                risk=_highest_action_risk(actions),
                supporting_facts=supporting_facts,
                next_actions=[str(action["description"]) for action in actions],
                command_examples=[str(command) for action in actions for command in action.get("commands", [])],
                metadata={
                    "source": "playbook",
                    "playbook_id": playbook["id"],
                    "playbook_schema": playbook["schema"],
                    "playbook_tags": list(playbook.get("tags", [])),
                    "matched_signals": matched_signals,
                },
            )
        )
    return suggestions


def _matched_playbook_signals(
    playbook: dict[str, Any],
    services: list[Service],
    evidence: list[Evidence],
    reveal_secrets: bool,
) -> list[dict[str, Any]] | None:
    matches: list[dict[str, Any]] = []
    for index, signal in enumerate(playbook.get("signals", [])):
        matched = _match_playbook_signal(signal, services, evidence, reveal_secrets)
        if not matched:
            return None
        matches.append(
            {
                "index": index,
                "type": signal.get("type", ""),
                "criteria": dict(signal),
                "facts": matched,
            }
        )
    return matches


def _match_playbook_signal(
    signal: dict[str, Any],
    services: list[Service],
    evidence: list[Evidence],
    reveal_secrets: bool,
) -> list[str]:
    signal_type = signal.get("type")
    if signal_type in {"service", "service_any"}:
        return _match_service_signal(signal, services)
    if signal_type == "evidence":
        evidence_type = signal.get("evidence_type")
        return [_evidence_fact(item, reveal_secrets) for item in evidence if item.type == evidence_type][:8]
    return []


def _match_service_signal(signal: dict[str, Any], services: list[Service]) -> list[str]:
    ports = {signal["port"]} if "port" in signal else set(signal.get("ports", []))
    names = (
        {str(signal["name"]).lower()} if "name" in signal else {str(name).lower() for name in signal.get("names", [])}
    )
    protocol = str(signal.get("protocol", "")).lower()
    facts: list[str] = []
    for service in services:
        if service.state != "open":
            continue
        if protocol and service.protocol.lower() != protocol:
            continue
        if ports and service.port not in ports:
            continue
        if names and service.name.lower() not in names:
            continue
        facts.append(f"{service.protocol}/{service.port} {service.name or 'unknown'}")
    return facts[:8]


RISK_RANK = {"passive": 0, "normal": 1, "aggressive": 2, "approval_required": 3}


def _highest_action_risk(actions: list[dict[str, Any]]) -> str:
    return max((str(action["risk"]) for action in actions), key=lambda risk: RISK_RANK.get(risk, 0), default="normal")


def _suggestion_id(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", value).strip("._-") or "playbook"


def _has_web(services: list[Service]) -> bool:
    return any(service.port in WEB_PORTS or "http" in service.name.lower() for service in services)


def _mail_command_examples(services: list[Service], target_host: str) -> list[str]:
    commands: list[str] = []
    ports = {service.port for service in services if service.state == "open"}
    if 143 in ports:
        commands.extend(
            [
                f"nc -nv {target_host} 143",
                f'curl --url "imap://{target_host}:143/INBOX" --user "<known_user>:<known_password>" --verbose',
            ]
        )
    if 993 in ports:
        commands.extend(
            [
                f"openssl s_client -connect {target_host}:993 -crlf",
                f'curl --url "imaps://{target_host}:993/INBOX" --user "<known_user>:<known_password>" --verbose --insecure',
            ]
        )
    if 110 in ports:
        commands.extend(
            [
                f"nc -nv {target_host} 110",
                f'curl --url "pop3://{target_host}:110" --user "<known_user>:<known_password>" --verbose',
            ]
        )
    if 995 in ports:
        commands.extend(
            [
                f"openssl s_client -connect {target_host}:995 -crlf",
                f'curl --url "pop3s://{target_host}:995" --user "<known_user>:<known_password>" --verbose --insecure',
            ]
        )
    return commands or [f'curl --url "imap://{target_host}:143/INBOX" --user "<known_user>:<known_password>" --verbose']


def _remote_access_command_examples(services: list[Service], target_host: str) -> list[str]:
    commands: list[str] = []
    ports = {service.port for service in services if service.state == "open"}
    if 22 in ports:
        commands.append(f"ssh <known_user>@{target_host}")
    if 445 in ports:
        commands.extend(
            [
                f"smbclient -L //{target_host} -U <known_user>",
                f"smbclient //{target_host}/<share> -U <known_user>",
            ]
        )
    if 3389 in ports:
        commands.append(f"xfreerdp /v:{target_host} /u:<known_user> /p:<known_password> /cert:ignore")
    if 5985 in ports:
        commands.append(f"evil-winrm -i {target_host} -u <known_user> -p '<known_password>'")
    if 5986 in ports:
        commands.append(f"evil-winrm -S -i {target_host} -u <known_user> -p '<known_password>'")
    return commands or [f"ssh <known_user>@{target_host}"]


def _web_path_command_examples(services: list[Service], paths: list[Evidence], target_host: str) -> list[str]:
    web_service = next(
        (service for service in services if service.port in WEB_PORTS or "http" in service.name.lower()), None
    )
    port = web_service.port if web_service else 80
    scheme = "https" if port in {443, 8443} or (web_service and web_service.tunnel == "ssl") else "http"
    path = _first_value(paths, "/<path>")
    port_part = "" if (scheme == "http" and port == 80) or (scheme == "https" and port == 443) else f":{port}"
    return [
        f"curl -i {scheme}://{target_host}{port_part}{path}",
        f"feroxbuster -u {scheme}://{target_host}{port_part}/ -w <wordlist> -o .\\ferox-{port}.txt",
    ]


def _first_value(items: list[Evidence], fallback: str) -> str:
    return items[0].value if items else fallback


def _facts_for_ports(services: list[Service], ports: set[int]) -> list[str]:
    facts: list[str] = []
    for service in services:
        if service.state == "open" and service.port in ports:
            facts.append(f"{service.protocol}/{service.port} {service.name or 'unknown'}")
    return facts


def _evidence_fact(item: Evidence, reveal_secrets: bool = False) -> str:
    value = item.value if reveal_secrets or not item.sensitive else "<sensitive>"
    if item.service_key:
        return f"{item.type}: {value} ({item.service_key})"
    return f"{item.type}: {value}"


def dedupe_suggestions(suggestions: list[Suggestion]) -> list[Suggestion]:
    seen: set[str] = set()
    result: list[Suggestion] = []
    for suggestion in suggestions:
        if suggestion.id not in seen:
            seen.add(suggestion.id)
            result.append(suggestion)
    return result


PLACEHOLDER_RE = re.compile(r"<([A-Za-z0-9_.-]+)>")
PARAMETER_ALIASES: dict[str, tuple[str, ...]] = {
    "community": ("snmp_community",),
    "known_user": ("username", "user"),
    "known_password": ("password", "pass"),
    "domain": ("dns_domain",),
    "wordlist": ("web_wordlist", "dir_wordlist"),
}


def _render_suggestion_parameters(
    suggestions: list[Suggestion],
    parameters: dict[str, Parameter],
    reveal_secrets: bool,
    defaults: dict[str, str] | None = None,
) -> list[Suggestion]:
    defaults = defaults or {}
    for suggestion in suggestions:
        suggestion.command_examples = [
            _render_command(command, parameters, reveal_secrets, defaults) for command in suggestion.command_examples
        ]
    return suggestions


def _render_command(
    command: str,
    parameters: dict[str, Parameter],
    reveal_secrets: bool,
    defaults: dict[str, str] | None = None,
) -> str:
    defaults = defaults or {}

    def replace(match: re.Match[str]) -> str:
        name = match.group(1)
        value = _parameter_value(parameters, name, defaults.get(name, match.group(0)), reveal_secrets)
        return value

    return PLACEHOLDER_RE.sub(replace, command)


def _parameter_value(
    parameters: dict[str, Parameter],
    name: str,
    fallback: str,
    reveal_secrets: bool,
) -> str:
    parameter = parameters.get(name)
    if parameter is None:
        for alias in PARAMETER_ALIASES.get(name, ()):
            parameter = parameters.get(alias)
            if parameter is not None:
                break
    if parameter is None:
        return fallback
    if parameter.sensitive and not reveal_secrets:
        return f"<{name}>"
    return parameter.require_value()
