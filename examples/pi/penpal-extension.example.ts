import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { execFile } from "node:child_process";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { Type } from "typebox";
import { registerPenpalIngestTool } from "./penpal-ingest-tool.example";

const execFileAsync = promisify(execFile);
const packageRoot = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const cwd = process.env.PENPAL_CWD ?? packageRoot;
const python = process.env.PENPAL_PYTHON ?? "python3";
const workspace = process.env.PENPAL_WORKSPACE;

export default function (pi: ExtensionAPI) {
  registerPenpalIngestTool(pi);

  pi.registerTool({
    name: "penpal_context",
    label: "PenPal context",
    description: "Read PenPal's masked deterministic context snapshot for a target.",
    parameters: Type.Object({
      target: Type.String({ description: "PenPal target name" }),
    }),
    async execute(_toolCallId, params, signal) {
      return textResult(await penpal(["context", params.target, "--json"], signal));
    },
  });

  pi.registerTool({
    name: "penpal_suggest",
    label: "PenPal suggestions",
    description: "Read PenPal's deterministic suggestions for a target.",
    parameters: Type.Object({
      target: Type.String({ description: "PenPal target name" }),
    }),
    async execute(_toolCallId, params, signal) {
      return textResult(await penpal(["suggest", params.target, "--json"], signal));
    },
  });

  pi.registerTool({
    name: "penpal_evidence",
    label: "PenPal evidence",
    description: "Read PenPal's extracted evidence for a target.",
    parameters: Type.Object({
      target: Type.String({ description: "PenPal target name" }),
    }),
    async execute(_toolCallId, params, signal) {
      return textResult(await penpal(["evidence", params.target, "--json"], signal));
    },
  });

  pi.registerTool({
    name: "penpal_playbooks_validate",
    label: "Validate PenPal playbooks",
    description: "Validate the repository playbooks directory.",
    parameters: Type.Object({}),
    async execute(_toolCallId, _params, signal) {
      return textResult(await penpal(["playbooks", "playbooks", "--json"], signal));
    },
  });

  pi.registerTool({
    name: "penpal_playbook_show",
    label: "Show PenPal playbook",
    description: "Read one validated playbook by id.",
    parameters: Type.Object({
      id: Type.String({ description: "Playbook id, such as snmp-mail-remote" }),
    }),
    async execute(_toolCallId, params, signal) {
      return textResult(await penpal(["playbooks", "playbooks", "--show", params.id], signal));
    },
  });

  pi.registerTool({
    name: "penpal_modules_list",
    label: "List PenPal service modules",
    description: "Read PenPal's source-backed service module registry.",
    parameters: Type.Object({}),
    async execute(_toolCallId, _params, signal) {
      return textResult(await penpal(["modules", "list", "--json"], signal));
    },
  });

  pi.registerTool({
    name: "penpal_module_plan",
    label: "Plan PenPal service module",
    description: "Read a source-backed service module plan for one target without executing commands.",
    parameters: Type.Object({
      target: Type.String({ description: "PenPal target name" }),
      module: Type.String({ description: "Module name, such as snmp, web, smb, or dns" }),
    }),
    async execute(_toolCallId, params, signal) {
      return textResult(await penpal(["modules", "plan", params.target, params.module, "--json"], signal));
    },
  });
}

async function penpal(args: string[], signal?: AbortSignal): Promise<string> {
  const fullArgs = ["-m", "penpal"];
  if (workspace) fullArgs.push("--workspace", workspace);
  fullArgs.push(...args);
  const { stdout } = await execFileAsync(python, fullArgs, {
    cwd,
    signal,
    timeout: 30_000,
    maxBuffer: 2_000_000,
  });
  return stdout.trim();
}

function textResult(text: string) {
  return {
    content: [{ type: "text" as const, text }],
    details: {},
  };
}
