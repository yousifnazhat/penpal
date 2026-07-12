import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { Type } from "typebox";

const execFileAsync = promisify(execFile);
const cwd = process.env.PENPAL_CWD ?? process.cwd();
const python = process.env.PENPAL_PYTHON ?? (process.platform === "win32" ? "python" : "python3");
const workspace = process.env.PENPAL_WORKSPACE;
const readOnlyTools = [
  "penpal_context",
  "penpal_suggest",
  "penpal_evidence",
  "penpal_playbooks_validate",
  "penpal_playbook_show",
  "penpal_modules_list",
  "penpal_module_plan",
];

export default function (pi: ExtensionAPI) {
  pi.registerTool({
    name: "penpal_context",
    label: "PenPal context",
    description: "Read PenPal's masked deterministic context snapshot for a target.",
    parameters: Type.Object({ target: Type.String({ description: "PenPal target name" }) }),
    async execute(_toolCallId, params, signal) {
      return readOnly(["context", params.target, "--json"], signal);
    },
  });

  pi.registerTool({
    name: "penpal_suggest",
    label: "PenPal suggestions",
    description: "Read PenPal's deterministic suggestions for a target.",
    parameters: Type.Object({ target: Type.String({ description: "PenPal target name" }) }),
    async execute(_toolCallId, params, signal) {
      return readOnly(["suggest", params.target, "--json"], signal);
    },
  });

  pi.registerTool({
    name: "penpal_evidence",
    label: "PenPal evidence",
    description: "Read PenPal's masked extracted evidence for a target.",
    parameters: Type.Object({ target: Type.String({ description: "PenPal target name" }) }),
    async execute(_toolCallId, params, signal) {
      return readOnly(["evidence", params.target, "--json"], signal);
    },
  });

  pi.registerTool({
    name: "penpal_playbooks_validate",
    label: "Validate PenPal playbooks",
    description: "Validate PenPal's bundled playbooks.",
    parameters: Type.Object({}),
    async execute(_toolCallId, _params, signal) {
      return readOnly(["playbooks", "playbooks", "--json"], signal);
    },
  });

  pi.registerTool({
    name: "penpal_playbook_show",
    label: "Show PenPal playbook",
    description: "Read one validated PenPal playbook by id.",
    parameters: Type.Object({ id: Type.String({ description: "Playbook id" }) }),
    async execute(_toolCallId, params, signal) {
      return readOnly(["playbooks", "playbooks", "--show", params.id], signal);
    },
  });

  pi.registerTool({
    name: "penpal_modules_list",
    label: "List PenPal service modules",
    description: "Read PenPal's source-backed service module registry.",
    parameters: Type.Object({}),
    async execute(_toolCallId, _params, signal) {
      return readOnly(["modules", "list", "--json"], signal);
    },
  });

  pi.registerTool({
    name: "penpal_module_plan",
    label: "Plan PenPal service module",
    description: "Read a source-backed module plan without executing commands.",
    parameters: Type.Object({
      target: Type.String({ description: "PenPal target name" }),
      module: Type.String({ description: "Module name, such as snmp, web, smb, or dns" }),
    }),
    async execute(_toolCallId, params, signal) {
      return readOnly(["modules", "plan", params.target, params.module, "--json"], signal);
    },
  });

  pi.registerCommand("penpal-status", {
    description: "Verify PenPal's read-only PI tools and deterministic core.",
    handler: async (_args, ctx) => {
      const registered = new Set(pi.getAllTools().map((tool) => tool.name));
      const missing = readOnlyTools.filter((tool) => !registered.has(tool));
      if (missing.length > 0) {
        ctx.ui.notify(`PenPal extension incomplete; missing tools: ${missing.join(", ")}`, "error");
        return;
      }
      try {
        const report = JSON.parse(await penpal(["playbooks", "playbooks", "--json"]));
        if (report.invalid_playbooks !== 0) {
          ctx.ui.notify(`PenPal core reported ${report.invalid_playbooks} invalid playbooks`, "error");
          return;
        }
        ctx.ui.notify(
          `PenPal ready: ${readOnlyTools.length} read-only tools registered; ${report.valid_playbooks} playbooks valid.`,
          "info",
        );
      } catch (error) {
        ctx.ui.notify(errorMessage(error), "error");
      }
    },
  });
}

async function readOnly(args: string[], signal?: AbortSignal) {
  try {
    return textResult(await penpal(args, signal));
  } catch (error) {
    return textResult(`error: ${errorMessage(error)}`);
  }
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

function errorMessage(error: unknown): string {
  if (error instanceof Error) {
    const stderr = (error as Error & { stderr?: string }).stderr?.trim();
    return stderr || error.message;
  }
  return String(error);
}

function textResult(text: string) {
  return { content: [{ type: "text" as const, text }], details: {} };
}
