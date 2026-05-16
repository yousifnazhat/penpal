from __future__ import annotations

import os
import subprocess
from pathlib import Path

from .models import CommandSpec, Service, Target


PROFILE_CHOICES = ("quick", "full-tcp", "version", "udp-top", "all")


def build_scan_plan(
    target: Target,
    target_dir: Path,
    profile: str,
    services: list[Service] | None = None,
    ports: str | None = None,
) -> list[CommandSpec]:
    scans_dir = target_dir / "scans" / "nmap"
    scans_dir.mkdir(parents=True, exist_ok=True)
    selected = expand_profiles(profile)
    plan: list[CommandSpec] = []

    for selected_profile in selected:
        plan.append(_build_nmap_command(target, scans_dir, selected_profile, services or [], ports))

    return plan


def expand_profiles(profile: str) -> list[str]:
    if profile == "all":
        return ["quick", "full-tcp", "version", "udp-top"]
    if profile not in PROFILE_CHOICES:
        raise ValueError(f"Unknown scan profile: {profile}")
    return [profile]


def format_command(args: list[str]) -> str:
    if os.name == "nt":
        return subprocess.list2cmdline(args)
    import shlex

    return shlex.join(args)


def _build_nmap_command(
    target: Target,
    scans_dir: Path,
    profile: str,
    services: list[Service],
    ports: str | None,
) -> CommandSpec:
    output_prefix = scans_dir / profile
    args = ["nmap", "-Pn"]

    if profile == "quick":
        args.extend(["-T4", "--open", "-oA", str(output_prefix), target.host])
        label = "Quick TCP discovery"
    elif profile == "full-tcp":
        args.extend(["-p-", "--min-rate", "5000", "--open", "-oA", str(output_prefix), target.host])
        label = "Full TCP discovery"
    elif profile == "version":
        discovered_ports = ports or _ports_arg(services, "tcp")
        if discovered_ports:
            args.extend(["-p", discovered_ports])
        args.extend(["-sV", "-sC", "-oA", str(output_prefix), target.host])
        label = "Service and default-script scan"
    elif profile == "udp-top":
        args.extend(["-sU", "--top-ports", "50", "--open", "-oA", str(output_prefix), target.host])
        label = "Top UDP scan"
    else:
        raise ValueError(f"Unknown profile: {profile}")

    return CommandSpec(
        id=profile,
        label=label,
        args=args,
        cwd=str(scans_dir.parent.parent),
        output_prefix=str(output_prefix),
        parser="nmap_xml",
    )


def _ports_arg(services: list[Service], protocol: str) -> str:
    ports = sorted({service.port for service in services if service.protocol == protocol})
    return ",".join(str(port) for port in ports)

