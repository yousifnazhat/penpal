import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { Type } from "typebox";

const execFileAsync = promisify(execFile);
const cwd = process.env.PENPAL_CWD ?? process.cwd();
const python = process.env.PENPAL_PYTHON ?? "python3";
const workspace = process.env.PENPAL_WORKSPACE;

export function registerPenpalIngestTool(pi: ExtensionAPI) {
  if (process.env.PENPAL_ENABLE_MUTATING_TOOLS !== "true") return;

  pi.registerTool({
    name: "penpal_ingest",
    label: "PenPal ingest",
    description: "Add operator-provided text to PenPal evidence after explicit approval.",
    parameters: Type.Object({
      target: Type.String({ description: "PenPal target name" }),
      text: Type.String({ description: "Operator-provided command output or notes to ingest" }),
      source: Type.String({ description: "Evidence source label, such as snmpwalk or operator-note" }),
      service: Type.Optional(Type.String({ description: "Related service key, such as tcp/80 or udp/161" })),
    }),
    async execute(_toolCallId, params, signal, _onUpdate, ctx) {
      const service = params.service ?? "";
      const command = [
        python,
        "-m",
        "penpal",
        ...(workspace ? ["--workspace", workspace] : []),
        "ingest",
        params.target,
        "--source",
        params.source,
        ...(service ? ["--service", service] : []),
        "--json",
      ].join(" ");
      const approved = await ctx.ui.confirm(
        [
          `PenPal will ingest operator-provided text into target ${params.target}.`,
          `Workspace: ${workspace ?? "default"}`,
          `Command: ${command}`,
          `Source: ${params.source}`,
          `Service: ${service || "none"}`,
          "This may add evidence and trigger new deterministic suggestions.",
          "Approve?",
        ].join("\n"),
      );
      if (!approved) {
        return textResult("Operator rejected PenPal ingest.");
      }
      return textResult(await penpalIngest(params, signal));
    },
  });
}

async function penpalIngest(
  params: { target: string; text: string; source: string; service?: string },
  signal?: AbortSignal,
): Promise<string> {
  const fullArgs = ["-m", "penpal"];
  if (workspace) fullArgs.push("--workspace", workspace);
  fullArgs.push("ingest", params.target, "--source", params.source);
  if (params.service) fullArgs.push("--service", params.service);
  fullArgs.push("--json");

  const child = execFileAsync(python, fullArgs, {
    cwd,
    signal,
    timeout: 30_000,
    maxBuffer: 2_000_000,
  });
  child.child.stdin?.end(params.text);
  const { stdout } = await child;
  return stdout.trim();
}

function textResult(text: string) {
  return {
    content: [{ type: "text" as const, text }],
    details: {},
  };
}
