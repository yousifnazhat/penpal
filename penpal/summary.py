from __future__ import annotations

from .models import Service, Target
from .recommendations import recommendations_for


def render_summary(target: Target, services: list[Service]) -> str:
    lines = [
        f"# {target.name}",
        "",
        f"Host: `{target.host}`",
        f"Updated: `{target.updated_at}`",
        "",
        "## Services",
        "",
    ]

    if not services:
        lines.extend(["No services recorded yet.", ""])
    else:
        lines.extend(
            [
                "| Proto | Port | State | Service | Version |",
                "| --- | ---: | --- | --- | --- |",
            ]
        )
        for service in sorted(services, key=lambda svc: (svc.protocol, svc.port)):
            version = " ".join(bit for bit in [service.product, service.version, service.extrainfo] if bit)
            lines.append(
                f"| {service.protocol} | {service.port} | {service.state} | "
                f"{service.name or 'unknown'} | {version or '-'} |"
            )
        lines.append("")

    lines.extend(["## Next Checks", ""])
    any_guidance = False
    for service in sorted(services, key=lambda svc: (svc.protocol, svc.port)):
        guidance = recommendations_for(service)
        if not guidance:
            continue
        any_guidance = True
        lines.append(f"### {service.protocol}/{service.port} {service.name or 'unknown'}")
        lines.append("")
        for item in guidance:
            lines.append(f"- [ ] {item}")
        lines.append("")

    if not any_guidance:
        lines.extend(["No service-specific checks yet.", ""])

    return "\n".join(lines).rstrip() + "\n"

