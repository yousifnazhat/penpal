from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .models import Parameter, Service, Target


@dataclass(frozen=True)
class ModuleSource:
    title: str
    url: str
    source_tier: str

    def to_dict(self) -> dict[str, str]:
        return {
            "title": self.title,
            "url": self.url,
            "source_tier": self.source_tier,
        }


@dataclass(frozen=True)
class PlannedModuleCommand:
    id: str
    module: str
    label: str
    args: list[str]
    cwd: str
    service_key: str
    source_label: str
    source_tier: str
    sources: list[dict[str, str]]
    risk: str = "normal"
    tags: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, object]:
        return {
            "id": self.id,
            "module": self.module,
            "label": self.label,
            "args": list(self.args),
            "cwd": self.cwd,
            "service_key": self.service_key,
            "source_label": self.source_label,
            "source_tier": self.source_tier,
            "sources": list(self.sources),
            "risk": self.risk,
            "tags": list(self.tags),
        }


@dataclass(frozen=True)
class ModuleCommandTemplate:
    id: str
    label: str
    args: tuple[str, ...]
    service_key: str
    source_label: str
    risk: str = "normal"
    tags: tuple[str, ...] = ()
    sources: tuple[ModuleSource, ...] = ()


@dataclass(frozen=True)
class ServiceModule:
    name: str
    description: str
    ports: tuple[int, ...]
    service_names: tuple[str, ...]
    templates: tuple[ModuleCommandTemplate, ...]


OFFICIAL_NMAP = ModuleSource(
    title="Nmap Reference Guide",
    url="https://nmap.org/book/man.html",
    source_tier="official",
)
OFFICIAL_FFUF = ModuleSource(
    title="ffuf GitHub",
    url="https://github.com/ffuf/ffuf",
    source_tier="official",
)
OFFICIAL_FEROXBUSTER = ModuleSource(
    title="feroxbuster Docs",
    url="https://epi052.github.io/feroxbuster-docs/",
    source_tier="official",
)
OWASP_WSTG = ModuleSource(
    title="OWASP Web Security Testing Guide",
    url="https://owasp.org/www-project-web-security-testing-guide/",
    source_tier="official",
)
USER_HTB_NOTES = ModuleSource(
    title="User HTB Academy Notes",
    url="local notes workspace",
    source_tier="internal",
)


MODULES: dict[str, ServiceModule] = {
    "snmp": ServiceModule(
        name="snmp",
        description="SNMP discovery, community validation, and high-signal walks.",
        ports=(161,),
        service_names=("snmp",),
        templates=(
            ModuleCommandTemplate(
                id="snmp-nmap-info",
                label="SNMP Nmap info scripts",
                args=(
                    "nmap",
                    "-sU",
                    "-sV",
                    "-p161",
                    "--script",
                    "snmp-info",
                    "{target_host}",
                    "-oA",
                    "{output_prefix}",
                ),
                service_key="udp/161",
                source_label="nmap-snmp",
                sources=(OFFICIAL_NMAP, USER_HTB_NOTES),
            ),
            ModuleCommandTemplate(
                id="snmp-community-check",
                label="SNMP community check",
                args=("onesixtyone", "-c", "{snmp_wordlist}", "{target_host}"),
                service_key="udp/161",
                source_label="onesixtyone",
                tags=("community",),
                sources=(USER_HTB_NOTES,),
            ),
            ModuleCommandTemplate(
                id="snmp-walk",
                label="SNMP walk with known community",
                args=("snmpwalk", "-v2c", "-c", "{community}", "{target_host}"),
                service_key="udp/161",
                source_label="snmpwalk",
                tags=("requires_parameter:community",),
                sources=(USER_HTB_NOTES,),
            ),
        ),
    ),
    "web": ServiceModule(
        name="web",
        description="HTTP(S) fingerprinting, content discovery, and virtual-host discovery.",
        ports=(80, 443, 8000, 8008, 8080, 8443),
        service_names=("http", "https", "http-proxy", "ssl/http"),
        templates=(
            ModuleCommandTemplate(
                id="web-nmap-http",
                label="HTTP Nmap scripts",
                args=(
                    "nmap",
                    "-sV",
                    "-sC",
                    "-p{web_ports}",
                    "--script",
                    "http-title,http-server-header",
                    "{target_host}",
                    "-oA",
                    "{output_prefix}",
                ),
                service_key="tcp/{first_web_port}",
                source_label="nmap-http",
                sources=(OFFICIAL_NMAP, OWASP_WSTG),
            ),
            ModuleCommandTemplate(
                id="web-feroxbuster",
                label="Web content discovery",
                args=("feroxbuster", "-u", "{web_url}", "-w", "{wordlist}", "-o", "{output_text}"),
                service_key="tcp/{first_web_port}",
                source_label="feroxbuster",
                sources=(OFFICIAL_FEROXBUSTER, OWASP_WSTG),
            ),
            ModuleCommandTemplate(
                id="web-vhost-ffuf",
                label="Virtual host discovery",
                args=(
                    "ffuf",
                    "-u",
                    "{web_url}",
                    "-H",
                    "Host: FUZZ.{domain}",
                    "-w",
                    "{wordlist}",
                    "-mc",
                    "all",
                    "-fs",
                    "{baseline_size}",
                ),
                service_key="tcp/{first_web_port}",
                source_label="ffuf-vhost",
                tags=("requires_parameter:domain",),
                sources=(OFFICIAL_FFUF, OWASP_WSTG),
            ),
        ),
    ),
    "smb": ServiceModule(
        name="smb",
        description="SMB share, host, and null-session enumeration.",
        ports=(139, 445),
        service_names=("microsoft-ds", "netbios-ssn", "smb"),
        templates=(
            ModuleCommandTemplate(
                id="smb-nmap-enum",
                label="SMB Nmap enumeration scripts",
                args=(
                    "nmap",
                    "-sV",
                    "-sC",
                    "-p139,445",
                    "--script",
                    "smb-enum-shares,smb-enum-users,smb-os-discovery",
                    "{target_host}",
                    "-oA",
                    "{output_prefix}",
                ),
                service_key="tcp/445",
                source_label="nmap-smb",
                sources=(OFFICIAL_NMAP, USER_HTB_NOTES),
            ),
            ModuleCommandTemplate(
                id="smb-null-shares",
                label="SMB null share listing",
                args=("smbclient", "-L", "//{target_host}", "-N"),
                service_key="tcp/445",
                source_label="smbclient",
                sources=(USER_HTB_NOTES,),
            ),
            ModuleCommandTemplate(
                id="smb-auth-shares",
                label="SMB authenticated share listing",
                args=("smbmap", "-H", "{target_host}", "-u", "{known_user}", "-p", "{known_password}"),
                service_key="tcp/445",
                source_label="smbmap",
                tags=("requires_parameter:known_user", "requires_parameter:known_password"),
                sources=(USER_HTB_NOTES,),
            ),
        ),
    ),
    "dns": ServiceModule(
        name="dns",
        description="DNS record queries, zone transfer checks, and name discovery.",
        ports=(53,),
        service_names=("domain", "dns"),
        templates=(
            ModuleCommandTemplate(
                id="dns-nmap",
                label="DNS Nmap service scan",
                args=("nmap", "-sV", "-sC", "-p53", "{target_host}", "-oA", "{output_prefix}"),
                service_key="tcp/53",
                source_label="nmap-dns",
                sources=(OFFICIAL_NMAP, USER_HTB_NOTES),
            ),
            ModuleCommandTemplate(
                id="dns-zone-transfer",
                label="DNS zone transfer attempt",
                args=("dig", "axfr", "@{target_host}", "{domain}"),
                service_key="tcp/53",
                source_label="dig-axfr",
                tags=("requires_parameter:domain",),
                sources=(USER_HTB_NOTES,),
            ),
            ModuleCommandTemplate(
                id="dns-records",
                label="DNS common record queries",
                args=("dig", "@{target_host}", "{domain}", "ANY"),
                service_key="tcp/53",
                source_label="dig-records",
                tags=("requires_parameter:domain",),
                sources=(USER_HTB_NOTES,),
            ),
        ),
    ),
}


def module_names() -> tuple[str, ...]:
    return tuple(sorted(MODULES))


def get_module(name: str) -> ServiceModule:
    try:
        return MODULES[name]
    except KeyError as exc:
        raise ValueError(f"Unknown module: {name}") from exc


def build_module_plan(
    module_name: str,
    target: Target,
    target_dir: Path,
    services: list[Service],
    parameters: dict[str, Parameter],
    reveal_secrets: bool = False,
) -> list[PlannedModuleCommand]:
    module = get_module(module_name)
    module_dir = target_dir / "modules" / module.name
    module_dir.mkdir(parents=True, exist_ok=True)
    context = _render_context(target, module, module_dir, services, parameters, reveal_secrets)

    plan: list[PlannedModuleCommand] = []
    for template in module.templates:
        rendered_args = [_render_value(value, context) for value in template.args]
        plan.append(
            PlannedModuleCommand(
                id=template.id,
                module=module.name,
                label=template.label,
                args=rendered_args,
                cwd=str(module_dir),
                service_key=_render_value(template.service_key, context),
                source_label=template.source_label,
                source_tier=_highest_source_tier(template.sources),
                sources=[source.to_dict() for source in template.sources],
                risk=template.risk,
                tags=template.tags,
            )
        )
    return plan


def module_matches_services(module_name: str, services: list[Service]) -> bool:
    module = get_module(module_name)
    ports = {service.port for service in services if service.state == "open"}
    names = {service.name.lower() for service in services if service.state == "open"}
    return bool(ports & set(module.ports)) or bool(names & set(module.service_names))


def _render_context(
    target: Target,
    module: ServiceModule,
    module_dir: Path,
    services: list[Service],
    parameters: dict[str, Parameter],
    reveal_secrets: bool,
) -> dict[str, str]:
    module_ports = _ports_for_module(module, services)
    first_web_port = module_ports[0] if module_ports else (module.ports[0] if module.ports else 0)
    scheme = "https" if first_web_port in {443, 8443} else "http"
    context = {
        "target_host": target.host,
        "target_name": target.name,
        "output_prefix": str(module_dir / module.name),
        "output_text": str(module_dir / f"{module.name}.txt"),
        "first_web_port": str(first_web_port),
        "web_ports": ",".join(str(port) for port in module_ports) or ",".join(str(port) for port in module.ports),
        "web_url": _web_url(scheme, target.host, first_web_port),
        "wordlist": "/usr/share/seclists/Discovery/Web-Content/raft-small-words.txt",
        "snmp_wordlist": "/usr/share/seclists/Discovery/SNMP/snmp.txt",
        "domain": "<domain>",
        "community": "<community>",
        "known_user": "<known_user>",
        "known_password": "<known_password>",
        "baseline_size": "<baseline_size>",
    }
    for name, parameter in parameters.items():
        if parameter.sensitive and not reveal_secrets:
            context[name] = f"<{name}>"
        else:
            context[name] = parameter.require_value()
    return context


def _render_value(value: str, context: dict[str, str]) -> str:
    rendered = value
    for key, replacement in context.items():
        rendered = rendered.replace("{" + key + "}", replacement)
    return rendered


def _ports_for_module(module: ServiceModule, services: list[Service]) -> list[int]:
    return sorted(
        {
            service.port
            for service in services
            if service.state == "open"
            and (service.port in module.ports or service.name.lower() in module.service_names)
        }
    )


def _web_url(scheme: str, host: str, port: int) -> str:
    if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
        return f"{scheme}://{host}/"
    return f"{scheme}://{host}:{port}/"


def _highest_source_tier(sources: tuple[ModuleSource, ...]) -> str:
    tiers = [source.source_tier for source in sources]
    if "official" in tiers:
        return "official"
    if "methodology" in tiers:
        return "methodology"
    if "internal" in tiers:
        return "internal"
    if "community" in tiers:
        return "community"
    return "unspecified"
