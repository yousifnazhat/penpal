from __future__ import annotations

import argparse
import json

from .service_modules import build_module_plan, module_matches_services, module_names
from .workspace import DEFAULT_WORKSPACE, Workspace


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m penpal.module_cli", description="Plan source-backed PenPal service modules."
    )
    parser.add_argument("--workspace", default=DEFAULT_WORKSPACE)
    parser.add_argument("name", help="Target name.")
    parser.add_argument("module", choices=module_names())
    parser.add_argument(
        "--reveal-secrets", action="store_true", help="Render sensitive parameter values in planned syntax."
    )
    parser.add_argument("--json", action="store_true", help="Emit raw JSON.")
    args = parser.parse_args(argv)

    workspace = Workspace(args.workspace)
    target = workspace.require_target(args.name)
    services = workspace.load_services(target.name)
    plan = build_module_plan(
        args.module,
        target,
        workspace.target_path(target.name),
        services,
        workspace.load_parameters(target.name),
        reveal_secrets=args.reveal_secrets,
    )

    payload = {
        "target": target.to_dict(),
        "module": args.module,
        "matched_services": module_matches_services(args.module, services),
        "commands": [command.to_dict() for command in plan],
    }
    if args.json:
        print(json.dumps(payload, indent=2))
        return 0

    print(f"{args.module} module for {target.name} ({target.host})")
    print(f"matched services: {payload['matched_services']}")
    for command in plan:
        print(f"\n[{command.id}] {command.label}")
        print(" ".join(command.args))
        print(f"source tier: {command.source_tier}")
        for source in command.sources:
            print(f"- {source['title']} ({source['source_tier']})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
