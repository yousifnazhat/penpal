from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from . import __version__
from .advisor import build_suggestions
from .api import serve
from .context import build_context
from .doctor import build_doctor_report, format_doctor_report
from .ingest import extract_evidence
from .nmap_parser import NmapParseError, parse_nmap_xml
from .playbooks import find_playbook, format_playbook, load_playbooks, scan_notes_vault, scan_playbooks
from .runner import RunnerError, run_plan
from .scan_profiles import PROFILE_CHOICES, build_scan_plan, format_command
from .scope import normalize_host
from .service_modules import build_module_plan, get_module, module_matches_services, module_names
from .sources import (
    DEFAULT_CACHE_DIR,
    DEFAULT_FACTS_PATH,
    DEFAULT_SEEDS_PATH,
    fetch_source_seed,
    load_reviewed_source_facts,
    load_source_seeds,
)
from .summary import render_summary
from .workspace import DEFAULT_WORKSPACE, Workspace, WorkspaceError


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    workspace = Workspace(args.workspace)

    try:
        return args.func(args, workspace)
    except (WorkspaceError, NmapParseError, RunnerError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return 130


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="penpal", description="PenPal enumeration assistant.")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument(
        "--workspace",
        default=DEFAULT_WORKSPACE,
        help=f"Workspace root. Default: {DEFAULT_WORKSPACE}",
    )
    subcommands = parser.add_subparsers(dest="command", required=True)

    doctor_cmd = subcommands.add_parser("doctor", help="Check the local PenPal and PI environment.")
    doctor_cmd.add_argument("--json", action="store_true", help="Emit machine-readable diagnostics.")
    doctor_cmd.set_defaults(func=cmd_doctor)

    init_cmd = subcommands.add_parser("init", help="Create a target workspace.")
    init_cmd.add_argument("host", help="Target IP, hostname, or lab name.")
    init_cmd.add_argument("--name", help="Friendly target name.")
    init_cmd.add_argument("--force", action="store_true", help="Reinitialize an existing target.")
    init_cmd.set_defaults(func=cmd_init)

    list_cmd = subcommands.add_parser("list", help="List targets.")
    list_cmd.set_defaults(func=cmd_list)

    scan_cmd = subcommands.add_parser("scan", help="Plan or execute scan commands.")
    scan_cmd.add_argument("name", help="Target name.")
    scan_cmd.add_argument("--profile", choices=PROFILE_CHOICES, default="quick")
    scan_cmd.add_argument("--ports", help="Comma-separated TCP ports for version scans.")
    scan_cmd.add_argument("--execute", action="store_true", help="Run the planned commands.")
    scan_cmd.add_argument("--timeout", type=int, help="Timeout per command in seconds.")
    scan_cmd.set_defaults(func=cmd_scan)

    parse_cmd = subcommands.add_parser("parse-nmap", help="Parse Nmap XML into the target services database.")
    parse_cmd.add_argument("name", help="Target name.")
    parse_cmd.add_argument("xml_path", help="Path to Nmap XML output.")
    parse_cmd.set_defaults(func=cmd_parse_nmap)

    services_cmd = subcommands.add_parser("services", help="Show recorded services.")
    services_cmd.add_argument("name", help="Target name.")
    services_cmd.add_argument("--json", action="store_true", help="Emit raw JSON.")
    services_cmd.set_defaults(func=cmd_services)

    evidence_cmd = subcommands.add_parser("evidence", help="Show extracted evidence.")
    evidence_cmd.add_argument("name", help="Target name.")
    evidence_cmd.add_argument("--reveal-secrets", action="store_true", help="Show sensitive evidence values.")
    evidence_cmd.add_argument("--json", action="store_true", help="Emit raw JSON.")
    evidence_cmd.set_defaults(func=cmd_evidence)

    ingest_cmd = subcommands.add_parser("ingest", help="Ingest pasted or saved tool output as evidence.")
    ingest_cmd.add_argument("name", help="Target name.")
    ingest_cmd.add_argument("--file", help="Text file to ingest. If omitted, reads piped stdin.")
    ingest_cmd.add_argument("--source", default="paste", help="Source label, such as snmpwalk or feroxbuster.")
    ingest_cmd.add_argument("--service", default="", help="Related service key, such as tcp/80 or udp/161.")
    ingest_cmd.add_argument("--playbooks", default="playbooks", help="Community playbook file or directory.")
    ingest_cmd.add_argument(
        "--reveal-secrets", action="store_true", help="Render sensitive parameters inside syntax examples."
    )
    ingest_cmd.add_argument("--json", action="store_true", help="Emit raw JSON.")
    ingest_cmd.set_defaults(func=cmd_ingest)

    suggest_cmd = subcommands.add_parser("suggest", help="Show deterministic next-step suggestions.")
    suggest_cmd.add_argument("name", help="Target name.")
    suggest_cmd.add_argument("--playbooks", default="playbooks", help="Community playbook file or directory.")
    suggest_cmd.add_argument(
        "--reveal-secrets", action="store_true", help="Render sensitive parameters inside syntax examples."
    )
    suggest_cmd.add_argument("--json", action="store_true", help="Emit raw JSON.")
    suggest_cmd.set_defaults(func=cmd_suggest)

    context_cmd = subcommands.add_parser("context", help="Emit PI-friendly target context JSON.")
    context_cmd.add_argument("name", help="Target name.")
    context_cmd.add_argument("--playbooks", default="playbooks", help="Community playbook file or directory.")
    context_cmd.add_argument("--reveal-secrets", action="store_true", help="Include sensitive parameters and evidence.")
    context_cmd.add_argument("--json", action="store_true", help="Emit raw JSON. Context output is always JSON.")
    context_cmd.set_defaults(func=cmd_context)

    modules_cmd = subcommands.add_parser("modules", help="Plan source-backed service enumeration modules.")
    modules_subcommands = modules_cmd.add_subparsers(dest="modules_action", required=True)

    modules_list_cmd = modules_subcommands.add_parser("list", help="List available service modules.")
    modules_list_cmd.add_argument("--json", action="store_true", help="Emit raw JSON.")
    modules_list_cmd.set_defaults(func=cmd_modules_list)

    modules_plan_cmd = modules_subcommands.add_parser("plan", help="Plan exact syntax for one target and module.")
    modules_plan_cmd.add_argument("name", help="Target name.")
    modules_plan_cmd.add_argument("module", choices=module_names(), help="Module name, such as snmp, web, smb, or dns.")
    modules_plan_cmd.add_argument(
        "--reveal-secrets", action="store_true", help="Render sensitive parameter values in planned syntax."
    )
    modules_plan_cmd.add_argument("--json", action="store_true", help="Emit raw JSON.")
    modules_plan_cmd.set_defaults(func=cmd_modules_plan)

    scope_cmd = subcommands.add_parser("scope", help="Configure and inspect engagement scope.")
    scope_subcommands = scope_cmd.add_subparsers(dest="scope_action", required=True)

    scope_set_cmd = scope_subcommands.add_parser("set", help="Set the enforced engagement scope.")
    scope_set_cmd.add_argument("--include", dest="includes", action="append", required=True)
    scope_set_cmd.add_argument("--exclude", dest="excludes", action="append", default=[])
    scope_set_cmd.add_argument("--json", action="store_true", help="Emit raw JSON.")
    scope_set_cmd.set_defaults(func=cmd_scope_set)

    scope_show_cmd = scope_subcommands.add_parser("show", help="Show the configured engagement scope.")
    scope_show_cmd.add_argument("--json", action="store_true", help="Emit raw JSON.")
    scope_show_cmd.set_defaults(func=cmd_scope_show)

    scope_check_cmd = scope_subcommands.add_parser("check", help="Check a host against engagement scope.")
    scope_check_cmd.add_argument("host", help="IP address or hostname to evaluate.")
    scope_check_cmd.add_argument("--json", action="store_true", help="Emit raw JSON.")
    scope_check_cmd.set_defaults(func=cmd_scope_check)

    scope_clear_cmd = scope_subcommands.add_parser("clear", help="Remove engagement scope enforcement.")
    scope_clear_cmd.add_argument(
        "--confirm",
        action="store_true",
        required=True,
        help="Confirm removal of the scope safety boundary.",
    )
    scope_clear_cmd.set_defaults(func=cmd_scope_clear)

    params_cmd = subcommands.add_parser("params", help="Manage target parameters used to fill command placeholders.")
    params_cmd.add_argument("name", help="Target name.")
    params_subcommands = params_cmd.add_subparsers(dest="params_action", required=True)

    params_list_cmd = params_subcommands.add_parser("list", help="List parameters.")
    params_list_cmd.add_argument("--reveal-secrets", action="store_true", help="Show sensitive values.")
    params_list_cmd.add_argument("--json", action="store_true", help="Emit raw JSON.")
    params_list_cmd.set_defaults(func=cmd_params_list)

    params_set_cmd = params_subcommands.add_parser("set", help="Set a parameter.")
    params_set_cmd.add_argument(
        "key", help="Parameter name, such as community, known_user, known_password, domain, or wordlist."
    )
    params_set_cmd.add_argument("value", help="Parameter value.")
    params_set_cmd.add_argument("--sensitive", action="store_true", help="Store as sensitive and mask by default.")
    params_set_cmd.add_argument("--source", default="manual", help="Source label for the value.")
    params_set_cmd.set_defaults(func=cmd_params_set)

    params_set_env_cmd = params_subcommands.add_parser(
        "set-env",
        help="Reference a sensitive parameter from the process environment.",
    )
    params_set_env_cmd.add_argument("key", help="Parameter name, such as known_password or token.")
    params_set_env_cmd.add_argument("env_var", help="Environment variable name. The value is never persisted.")
    params_set_env_cmd.set_defaults(func=cmd_params_set_env)

    params_unset_cmd = params_subcommands.add_parser("unset", help="Remove a parameter.")
    params_unset_cmd.add_argument("key", help="Parameter name.")
    params_unset_cmd.set_defaults(func=cmd_params_unset)

    summary_cmd = subcommands.add_parser("summary", help="Render target notes summary.")
    summary_cmd.add_argument("name", help="Target name.")
    summary_cmd.add_argument("--write", action="store_true", help="Write summary to notes.md.")
    summary_cmd.set_defaults(func=cmd_summary)

    notes_cmd = subcommands.add_parser("notes", help="Validate PenPal parse blocks in an HTB notes vault.")
    notes_cmd.add_argument("vault", help="Path to the Obsidian or HTB notes vault.")
    notes_cmd.add_argument("--json", action="store_true", help="Emit raw JSON.")
    notes_cmd.set_defaults(func=cmd_notes)

    playbooks_cmd = subcommands.add_parser("playbooks", help="Validate community playbook JSON files.")
    playbooks_cmd.add_argument("path", help="Path to a playbook JSON file or directory.")
    playbooks_cmd.add_argument("--show", help="Print one validated playbook by id.")
    playbooks_cmd.add_argument("--json", action="store_true", help="Emit raw JSON.")
    playbooks_cmd.set_defaults(func=cmd_playbooks)

    sources_cmd = subcommands.add_parser("sources", help="Inspect or fetch source dataset seeds.")
    sources_subcommands = sources_cmd.add_subparsers(dest="sources_action", required=True)

    sources_list_cmd = sources_subcommands.add_parser("list", help="List configured source seeds.")
    sources_list_cmd.add_argument("--seeds", default=str(DEFAULT_SEEDS_PATH), help="Path to SOURCE_SEEDS.json.")
    sources_list_cmd.add_argument("--json", action="store_true", help="Emit raw JSON.")
    sources_list_cmd.set_defaults(func=cmd_sources_list)

    sources_fetch_cmd = sources_subcommands.add_parser("fetch", help="Fetch one allowed source seed URL.")
    sources_fetch_cmd.add_argument("source_id", help="Source seed id, such as nmap or ffuf.")
    sources_fetch_cmd.add_argument("--url", help="Specific seed URL to fetch. Defaults to the first seed URL.")
    sources_fetch_cmd.add_argument("--seeds", default=str(DEFAULT_SEEDS_PATH), help="Path to SOURCE_SEEDS.json.")
    sources_fetch_cmd.add_argument(
        "--cache-dir", default=str(DEFAULT_CACHE_DIR), help="Ignored raw source cache directory."
    )
    sources_fetch_cmd.add_argument("--timeout", type=int, default=15, help="Fetch timeout in seconds.")
    sources_fetch_cmd.add_argument("--json", action="store_true", help="Emit raw JSON.")
    sources_fetch_cmd.set_defaults(func=cmd_sources_fetch)

    sources_reviewed_cmd = sources_subcommands.add_parser("reviewed", help="List reviewed source facts.")
    sources_reviewed_cmd.add_argument("--facts", default=str(DEFAULT_FACTS_PATH), help="Path to SOURCE_FACTS.json.")
    sources_reviewed_cmd.add_argument("--source-id", help="Filter by source seed id.")
    sources_reviewed_cmd.add_argument("--json", action="store_true", help="Emit raw JSON.")
    sources_reviewed_cmd.set_defaults(func=cmd_sources_reviewed)

    serve_cmd = subcommands.add_parser("serve", help="Start the JSON API for local integrations.")
    serve_cmd.add_argument("--host", default="127.0.0.1")
    serve_cmd.add_argument("--port", type=int, default=8765)
    serve_cmd.add_argument(
        "--allow-remote",
        action="store_true",
        help="Allow an unauthenticated non-loopback bind on a trusted, isolated network.",
    )
    serve_cmd.set_defaults(func=cmd_serve)

    mcp_cmd = subcommands.add_parser("mcp", help="Run the read-only local MCP server over stdio.")
    mcp_cmd.set_defaults(func=cmd_mcp)

    return parser


def cmd_doctor(args: argparse.Namespace, workspace: Workspace) -> int:
    report = build_doctor_report(workspace)
    print(json.dumps(report, indent=2) if args.json else format_doctor_report(report))
    return 1 if report["status"] == "error" else 0


def cmd_init(args: argparse.Namespace, workspace: Workspace) -> int:
    target = workspace.create_target(args.host, name=args.name, force=args.force)
    print(f"created target {target.name} -> {target.host}")
    print(f"workspace: {workspace.target_path(target.name)}")
    return 0


def cmd_list(args: argparse.Namespace, workspace: Workspace) -> int:
    targets = workspace.list_targets()
    if not targets:
        print("no targets yet")
        return 0
    for target in targets:
        print(f"{target.name:24} {target.host}")
    return 0


def cmd_scope_set(args: argparse.Namespace, workspace: Workspace) -> int:
    scope = workspace.set_scope(args.includes, args.excludes)
    if args.json:
        print(json.dumps({"enforced": True, "scope": scope.to_dict()}, indent=2))
        return 0
    print(f"engagement scope enforced with {len(scope.includes)} include and {len(scope.excludes)} exclude rules")
    print(f"scope: {workspace.scope_path()}")
    return 0


def cmd_scope_show(args: argparse.Namespace, workspace: Workspace) -> int:
    scope = workspace.load_scope()
    if args.json:
        print(json.dumps({"enforced": scope is not None, "scope": scope.to_dict() if scope else None}, indent=2))
        return 0
    if not scope:
        print("no engagement scope configured")
        return 0
    print("engagement scope enforced")
    for rule in scope.includes:
        print(f"include: {rule}")
    for rule in scope.excludes:
        print(f"exclude: {rule}")
    return 0


def cmd_scope_check(args: argparse.Namespace, workspace: Workspace) -> int:
    decision = workspace.evaluate_scope(args.host)
    if decision:
        payload = {"enforced": True, **decision.to_dict()}
    else:
        payload = {
            "enforced": False,
            "host": normalize_host(args.host),
            "allowed": True,
            "matched_include": None,
            "matched_exclude": None,
            "reason": "no engagement scope configured",
        }
    if args.json:
        print(json.dumps(payload, indent=2))
    else:
        status = "allowed" if payload["allowed"] else "blocked"
        print(f"{payload['host']}: {status} ({payload['reason']})")
    return 0 if payload["allowed"] else 2


def cmd_scope_clear(args: argparse.Namespace, workspace: Workspace) -> int:
    if workspace.clear_scope():
        print("engagement scope enforcement removed")
    else:
        print("no engagement scope configured")
    return 0


def cmd_scan(args: argparse.Namespace, workspace: Workspace) -> int:
    target = workspace.require_target(args.name)
    services = workspace.load_services(target.name)
    plan = build_scan_plan(
        target=target,
        target_dir=workspace.target_path(target.name),
        profile=args.profile,
        services=services,
        ports=args.ports,
    )

    for command in plan:
        print(f"[{command.id}] {command.label}")
        print(format_command(command.args))

    if not args.execute:
        print("\ndry-run only; add --execute to run")
        return 0

    results = run_plan(workspace, target.name, plan, timeout=args.timeout)
    for result in results:
        print(f"{result['command']['id']}: exit {result['returncode']}")
    return 0


def cmd_parse_nmap(args: argparse.Namespace, workspace: Workspace) -> int:
    workspace.require_target(args.name)
    parsed = parse_nmap_xml(args.xml_path)
    services = workspace.merge_services(args.name, parsed)
    print(f"parsed {len(parsed)} services; target now has {len(services)} services")
    return 0


def cmd_services(args: argparse.Namespace, workspace: Workspace) -> int:
    workspace.require_target(args.name)
    services = workspace.load_services(args.name)
    if args.json:
        print(json.dumps({"services": [service.to_dict() for service in services]}, indent=2))
        return 0

    if not services:
        print("no services recorded yet")
        return 0

    for service in services:
        version = " ".join(bit for bit in [service.product, service.version, service.extrainfo] if bit)
        print(f"{service.protocol}/{service.port:<5} {service.state:<10} {service.name or 'unknown':<16} {version}")
    return 0


def cmd_evidence(args: argparse.Namespace, workspace: Workspace) -> int:
    workspace.require_target(args.name)
    evidence = workspace.load_evidence(args.name)
    if args.json:
        print(json.dumps({"evidence": [item.to_dict(reveal=args.reveal_secrets) for item in evidence]}, indent=2))
        return 0

    if not evidence:
        print("no evidence recorded yet")
        return 0

    for item in evidence:
        service = f" {item.service_key}" if item.service_key else ""
        value = item.to_dict(reveal=args.reveal_secrets)["value"]
        print(f"{item.type:<22} {item.confidence:<7}{service:<10} {value}")
    return 0


def cmd_ingest(args: argparse.Namespace, workspace: Workspace) -> int:
    target = workspace.require_target(args.name)
    text = _read_ingest_text(args.file)
    existing_ids = {item.id for item in workspace.load_evidence(args.name)}
    result = extract_evidence(
        text,
        source=args.source,
        service_key=args.service,
        existing_ids=existing_ids,
    )
    saved = workspace.append_evidence(args.name, result.evidence)
    suggestions = build_suggestions(
        workspace.load_services(args.name),
        saved,
        target_host=target.host,
        target_name=target.name,
        parameters=workspace.load_parameters(target.name),
        reveal_secrets=args.reveal_secrets,
        playbooks=load_playbooks(args.playbooks),
    )

    if args.json:
        print(
            json.dumps(
                {
                    "added": [item.to_dict(reveal=args.reveal_secrets) for item in result.evidence],
                    "ignored_duplicates": result.ignored_duplicates,
                    "suggestions": [suggestion.to_dict() for suggestion in suggestions],
                },
                indent=2,
            )
        )
        return 0

    print(f"added {len(result.evidence)} evidence items")
    if result.ignored_duplicates:
        print(f"ignored {result.ignored_duplicates} duplicates")
    if result.evidence:
        for item in result.evidence[:12]:
            service = f" ({item.service_key})" if item.service_key else ""
            value = item.to_dict(reveal=args.reveal_secrets)["value"]
            print(f"- {item.type}: {value}{service}")
        if len(result.evidence) > 12:
            print(f"- ... {len(result.evidence) - 12} more")

    if suggestions:
        print("\nSuggestions:")
        for suggestion in suggestions[:5]:
            print(f"- {suggestion.title} [{suggestion.confidence}/{suggestion.value}/{suggestion.risk}]")
            print(f"  {suggestion.reason}")
            _print_suggestion_match(suggestion, indent="  ")
            if suggestion.command_examples:
                print("  Syntax:")
                for command in suggestion.command_examples[:3]:
                    print(f"    {command}")
    return 0


def cmd_suggest(args: argparse.Namespace, workspace: Workspace) -> int:
    target = workspace.require_target(args.name)
    suggestions = build_suggestions(
        workspace.load_services(args.name),
        workspace.load_evidence(args.name),
        target_host=target.host,
        target_name=target.name,
        parameters=workspace.load_parameters(target.name),
        reveal_secrets=args.reveal_secrets,
        playbooks=load_playbooks(args.playbooks),
    )
    if args.json:
        print(json.dumps({"suggestions": [suggestion.to_dict() for suggestion in suggestions]}, indent=2))
        return 0

    if not suggestions:
        print("no suggestions yet; add services and evidence first")
        return 0

    for suggestion in suggestions:
        print(f"{suggestion.title} [{suggestion.confidence}/{suggestion.value}/{suggestion.risk}]")
        print(f"Reason: {suggestion.reason}")
        _print_suggestion_match(suggestion)
        if suggestion.supporting_facts:
            print("Supporting facts:")
            for fact in suggestion.supporting_facts[:8]:
                print(f"- {fact}")
        print("Next actions:")
        for action in suggestion.next_actions:
            print(f"- {action}")
        if suggestion.command_examples:
            print("Syntax:")
            for command in suggestion.command_examples:
                print(f"- {command}")
        print()
    return 0


def cmd_context(args: argparse.Namespace, workspace: Workspace) -> int:
    print(
        json.dumps(
            build_context(
                workspace,
                args.name,
                playbooks_path=args.playbooks,
                reveal_secrets=args.reveal_secrets,
            ),
            indent=2,
        )
    )
    return 0


def cmd_modules_list(args: argparse.Namespace, workspace: Workspace) -> int:
    modules = [get_module(name) for name in module_names()]
    payload = {"modules": [_module_to_dict(module) for module in modules]}
    if args.json:
        print(json.dumps(payload, indent=2))
        return 0

    for module in modules:
        ports = ",".join(str(port) for port in module.ports)
        print(f"{module.name:<8} ports {ports:<24} {module.description}")
    return 0


def cmd_modules_plan(args: argparse.Namespace, workspace: Workspace) -> int:
    target = workspace.require_target(args.name)
    services = workspace.load_services(target.name)
    module = get_module(args.module)
    commands = build_module_plan(
        args.module,
        target,
        workspace.target_path(target.name),
        services,
        workspace.load_parameters(target.name),
        reveal_secrets=args.reveal_secrets,
    )
    payload = {
        "target": target.to_dict(),
        "module": _module_to_dict(module),
        "matched_services": module_matches_services(args.module, services),
        "commands": [command.to_dict() for command in commands],
    }
    if args.json:
        print(json.dumps(payload, indent=2))
        return 0

    print(f"{module.name} module for {target.name} ({target.host})")
    print(f"matched services: {payload['matched_services']}")
    for command in commands:
        print(f"\n[{command.id}] {command.label}")
        print(format_command(command.args))
        print(f"service: {command.service_key or 'unmatched'}")
        print(f"source tier: {command.source_tier}")
        for source in command.sources:
            print(f"- {source['title']} ({source['source_tier']})")
    return 0


def cmd_params_list(args: argparse.Namespace, workspace: Workspace) -> int:
    workspace.require_target(args.name)
    parameters = workspace.load_parameters(args.name)
    if args.json:
        print(
            json.dumps(
                {"parameters": [item.to_dict(reveal=args.reveal_secrets) for item in parameters.values()]},
                indent=2,
            )
        )
        return 0

    if not parameters:
        print("no parameters recorded yet")
        return 0

    for item in sorted(parameters.values(), key=lambda parameter: parameter.name):
        value = item.to_dict(reveal=args.reveal_secrets)["value"]
        markers = ["sensitive"] if item.sensitive else []
        if item.env_var:
            markers.append(f"env:{item.env_var}")
            markers.append("available" if item.resolved else "missing")
        suffix = f" [{' '.join(markers)}]" if markers else ""
        print(f"{item.name:<20} {value}{suffix}")
    return 0


def cmd_params_set(args: argparse.Namespace, workspace: Workspace) -> int:
    workspace.require_target(args.name)
    sensitive = args.sensitive or _looks_sensitive(args.key)
    parameter = workspace.set_parameter(
        args.name,
        args.key,
        args.value,
        sensitive=sensitive,
        source=args.source,
    )
    if parameter.sensitive:
        print("warning: sensitive plaintext is stored in the workspace; prefer params set-env", file=sys.stderr)
    value = "<sensitive>" if parameter.sensitive else parameter.value
    print(f"set {parameter.name} = {value}")
    return 0


def cmd_params_set_env(args: argparse.Namespace, workspace: Workspace) -> int:
    workspace.require_target(args.name)
    parameter = workspace.set_environment_parameter(args.name, args.key, args.env_var)
    status = "available" if parameter.resolved else "missing"
    print(f"set {parameter.name} from environment {parameter.env_var} ({status})")
    return 0


def cmd_params_unset(args: argparse.Namespace, workspace: Workspace) -> int:
    workspace.require_target(args.name)
    if workspace.unset_parameter(args.name, args.key):
        print(f"removed {args.key}")
    else:
        print(f"parameter not found: {args.key}")
    return 0


def cmd_summary(args: argparse.Namespace, workspace: Workspace) -> int:
    target = workspace.require_target(args.name)
    services = workspace.load_services(target.name)
    rendered = render_summary(target, services)
    if args.write:
        notes_path = workspace.target_path(target.name) / "notes.md"
        notes_path.write_text(rendered, encoding="utf-8")
        print(f"wrote {notes_path}")
    else:
        print(rendered)
    return 0


def cmd_notes(args: argparse.Namespace, workspace: Workspace) -> int:
    report = scan_notes_vault(args.vault)
    if args.json:
        print(json.dumps(report.to_dict(), indent=2))
        return 1 if report.errors else 0

    print(f"vault: {report.vault}")
    print(f"markdown files: {report.markdown_files}")
    print(f"penpal-ready notes: {report.penpal_notes}")
    print(f"methodology blocks: {report.methodology_blocks}")
    print(f"evidence rule blocks: {report.evidence_rule_blocks}")
    print(f"invalid blocks: {len(report.errors)}")
    if report.errors:
        print("\nInvalid blocks:")
        for block in report.errors:
            print(f"- {block.path}:{block.line} [{block.kind}] {block.error}")
        return 1
    return 0


def cmd_playbooks(args: argparse.Namespace, workspace: Workspace) -> int:
    if args.show:
        playbook = find_playbook(load_playbooks(args.path), args.show)
        if args.json:
            print(json.dumps(playbook, indent=2))
        else:
            print(format_playbook(playbook))
        return 0

    report = scan_playbooks(args.path)
    if args.json:
        print(json.dumps(report.to_dict(), indent=2))
        return 1 if report.errors else 0

    print(f"path: {report.root}")
    print(f"json files: {report.json_files}")
    print(f"valid playbooks: {report.valid_playbooks}")
    print(f"invalid playbooks: {len(report.errors)}")
    if report.errors:
        print("\nInvalid playbooks:")
        for playbook in report.errors:
            print(f"- {playbook.path}: {playbook.error}")
        return 1
    return 0


def cmd_sources_list(args: argparse.Namespace, workspace: Workspace) -> int:
    seeds = load_source_seeds(args.seeds)
    if args.json:
        print(json.dumps({"sources": seeds}, indent=2))
        return 0

    for seed in seeds:
        areas = ", ".join(seed.get("areas", []))
        print(f"{seed['id']:<24} {seed['tier']:<12} {seed['status']:<12} {areas}")
    return 0


def cmd_sources_fetch(args: argparse.Namespace, workspace: Workspace) -> int:
    result = fetch_source_seed(
        args.source_id,
        url=args.url,
        seeds_path=args.seeds,
        cache_dir=args.cache_dir,
        timeout=args.timeout,
    )
    data = result.to_dict()
    if args.json:
        print(json.dumps(data, indent=2))
        return 0

    print(f"source: {data['source']['id']} ({data['source']['tier']})")
    print(f"url: {data['final_url']}")
    print(f"status: {data['status']}")
    print(f"bytes: {data['bytes']}")
    print(f"cache: {data['cache_path']}")
    for fact in data["facts"]:
        print(f"- {fact['type']}: {fact['value']}")
    return 0


def cmd_sources_reviewed(args: argparse.Namespace, workspace: Workspace) -> int:
    facts = load_reviewed_source_facts(args.facts, source_id=args.source_id)
    if args.json:
        print(json.dumps({"schema": "penpal-reviewed-source-facts-v1", "facts": facts}, indent=2))
        return 0

    for fact in facts:
        print(f"{fact['id']:<36} {fact['source_id']:<16} {fact['fact_type']:<16} {fact['safety']}")
    return 0


def cmd_serve(args: argparse.Namespace, workspace: Workspace) -> int:
    workspace.ensure()
    serve(workspace, host=args.host, port=args.port, allow_remote=args.allow_remote)
    return 0


def cmd_mcp(args: argparse.Namespace, workspace: Workspace) -> int:
    try:
        from .mcp_server import run_mcp
    except ModuleNotFoundError as exc:
        if exc.name in {"mcp", "pydantic"}:
            raise ValueError('MCP support is not installed; run: python -m pip install "penpal-enum[mcp]"') from exc
        raise
    run_mcp(workspace)
    return 0


def _read_ingest_text(file_path: str | None) -> str:
    if file_path:
        return Path(file_path).read_text(encoding="utf-8")
    if sys.stdin.isatty():
        raise ValueError("pass --file or pipe text into stdin")
    return sys.stdin.read()


def _looks_sensitive(name: str) -> bool:
    lowered = name.lower()
    return any(token in lowered for token in ["pass", "password", "secret", "token", "key", "hash"])


def _print_suggestion_match(suggestion: Any, indent: str = "") -> None:
    lines = _matched_signal_lines(suggestion.metadata)
    if not lines:
        return
    print(f"{indent}Why this fired:")
    for line in lines:
        print(f"{indent}- {line}")


def _matched_signal_lines(metadata: dict[str, Any]) -> list[str]:
    if metadata.get("source") != "playbook":
        return []
    matches = metadata.get("matched_signals")
    if not isinstance(matches, list):
        return []

    lines: list[str] = []
    for match in matches:
        if not isinstance(match, dict):
            continue
        signal_type = str(match.get("type") or "signal")
        facts = match.get("facts")
        if not isinstance(facts, list):
            continue
        for fact in facts:
            if isinstance(fact, str) and fact.strip():
                lines.append(f"{signal_type}: {fact}")
    return lines[:8]


def _module_to_dict(module: Any) -> dict[str, Any]:
    return {
        "name": module.name,
        "description": module.description,
        "ports": list(module.ports),
        "service_names": list(module.service_names),
        "commands": [
            {
                "id": template.id,
                "label": template.label,
                "source_label": template.source_label,
                "risk": template.risk,
                "tags": list(template.tags),
                "sources": [source.to_dict() for source in template.sources],
            }
            for template in module.templates
        ],
    }


if __name__ == "__main__":
    raise SystemExit(main())
