from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .advisor import build_suggestions
from .api import serve
from .ingest import extract_evidence
from .nmap_parser import NmapParseError, parse_nmap_xml
from .runner import RunnerError, run_plan
from .scan_profiles import PROFILE_CHOICES, build_scan_plan, format_command
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
    parser.add_argument(
        "--workspace",
        default=DEFAULT_WORKSPACE,
        help=f"Workspace root. Default: {DEFAULT_WORKSPACE}",
    )
    subcommands = parser.add_subparsers(dest="command", required=True)

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
    evidence_cmd.add_argument("--json", action="store_true", help="Emit raw JSON.")
    evidence_cmd.set_defaults(func=cmd_evidence)

    ingest_cmd = subcommands.add_parser("ingest", help="Ingest pasted or saved tool output as evidence.")
    ingest_cmd.add_argument("name", help="Target name.")
    ingest_cmd.add_argument("--file", help="Text file to ingest. If omitted, reads piped stdin.")
    ingest_cmd.add_argument("--source", default="paste", help="Source label, such as snmpwalk or feroxbuster.")
    ingest_cmd.add_argument("--service", default="", help="Related service key, such as tcp/80 or udp/161.")
    ingest_cmd.add_argument("--reveal-secrets", action="store_true", help="Render sensitive parameters inside syntax examples.")
    ingest_cmd.add_argument("--json", action="store_true", help="Emit raw JSON.")
    ingest_cmd.set_defaults(func=cmd_ingest)

    suggest_cmd = subcommands.add_parser("suggest", help="Show deterministic next-step suggestions.")
    suggest_cmd.add_argument("name", help="Target name.")
    suggest_cmd.add_argument("--reveal-secrets", action="store_true", help="Render sensitive parameters inside syntax examples.")
    suggest_cmd.add_argument("--json", action="store_true", help="Emit raw JSON.")
    suggest_cmd.set_defaults(func=cmd_suggest)

    params_cmd = subcommands.add_parser("params", help="Manage target parameters used to fill command placeholders.")
    params_cmd.add_argument("name", help="Target name.")
    params_subcommands = params_cmd.add_subparsers(dest="params_action", required=True)

    params_list_cmd = params_subcommands.add_parser("list", help="List parameters.")
    params_list_cmd.add_argument("--reveal-secrets", action="store_true", help="Show sensitive values.")
    params_list_cmd.add_argument("--json", action="store_true", help="Emit raw JSON.")
    params_list_cmd.set_defaults(func=cmd_params_list)

    params_set_cmd = params_subcommands.add_parser("set", help="Set a parameter.")
    params_set_cmd.add_argument("key", help="Parameter name, such as community, known_user, known_password, domain, or wordlist.")
    params_set_cmd.add_argument("value", help="Parameter value.")
    params_set_cmd.add_argument("--sensitive", action="store_true", help="Store as sensitive and mask by default.")
    params_set_cmd.add_argument("--source", default="manual", help="Source label for the value.")
    params_set_cmd.set_defaults(func=cmd_params_set)

    params_unset_cmd = params_subcommands.add_parser("unset", help="Remove a parameter.")
    params_unset_cmd.add_argument("key", help="Parameter name.")
    params_unset_cmd.set_defaults(func=cmd_params_unset)

    summary_cmd = subcommands.add_parser("summary", help="Render target notes summary.")
    summary_cmd.add_argument("name", help="Target name.")
    summary_cmd.add_argument("--write", action="store_true", help="Write summary to notes.md.")
    summary_cmd.set_defaults(func=cmd_summary)

    serve_cmd = subcommands.add_parser("serve", help="Start the JSON API for a future frontend.")
    serve_cmd.add_argument("--host", default="127.0.0.1")
    serve_cmd.add_argument("--port", type=int, default=8765)
    serve_cmd.set_defaults(func=cmd_serve)

    return parser


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
        print(json.dumps({"evidence": [item.to_dict() for item in evidence]}, indent=2))
        return 0

    if not evidence:
        print("no evidence recorded yet")
        return 0

    for item in evidence:
        service = f" {item.service_key}" if item.service_key else ""
        print(f"{item.type:<22} {item.confidence:<7}{service:<10} {item.value}")
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
    )

    if args.json:
        print(
            json.dumps(
                {
                    "added": [item.to_dict() for item in result.evidence],
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
            print(f"- {item.type}: {item.value}{service}")
        if len(result.evidence) > 12:
            print(f"- ... {len(result.evidence) - 12} more")

    if suggestions:
        print("\nSuggestions:")
        for suggestion in suggestions[:5]:
            print(f"- {suggestion.title} [{suggestion.confidence}/{suggestion.value}/{suggestion.risk}]")
            print(f"  {suggestion.reason}")
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
        value = item.value if args.reveal_secrets or not item.sensitive else "<sensitive>"
        marker = " sensitive" if item.sensitive else ""
        print(f"{item.name:<20} {value}{marker}")
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
    value = "<sensitive>" if parameter.sensitive else parameter.value
    print(f"set {parameter.name} = {value}")
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


def cmd_serve(args: argparse.Namespace, workspace: Workspace) -> int:
    workspace.ensure()
    serve(workspace, host=args.host, port=args.port)
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


if __name__ == "__main__":
    raise SystemExit(main())
