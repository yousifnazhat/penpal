import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { Type } from "typebox";
import { registerPenpalIngestTool } from "./penpal-ingest-tool.example";

const execFileAsync = promisify(execFile);
const cwd = process.env.PENPAL_CWD ?? process.cwd();
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
