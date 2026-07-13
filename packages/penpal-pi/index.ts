import type { ExtensionAPI, Theme, ThemeColor } from "@earendil-works/pi-coding-agent";
import { execFile } from "node:child_process";
import { resolve } from "node:path";
import { Type } from "typebox";

const cwd = process.env.PENPAL_CWD ?? process.cwd();
const python = process.env.PENPAL_PYTHON ?? (process.platform === "win32" ? "python" : "python3");
const workspace = process.env.PENPAL_WORKSPACE;
const activeWorkspace = resolve(cwd, workspace ?? "penpal-workspace");
const readOnlyTools = [
  "penpal_targets",
  "penpal_context",
  "penpal_suggest",
  "penpal_evidence",
  "penpal_playbooks_validate",
  "penpal_playbook_show",
  "penpal_modules_list",
  "penpal_module_plan",
];
const writeTools = ["penpal_target_create", "penpal_ingest", "penpal_focus_update"];
const allTools = [...readOnlyTools, ...writeTools];
const fullLogo = [
  "██████╗ ███████╗███╗   ██╗██████╗  █████╗ ██╗",
  "██╔══██╗██╔════╝████╗  ██║██╔══██╗██╔══██╗██║",
  "██████╔╝█████╗  ██╔██╗ ██║██████╔╝███████║██║",
  "██╔═══╝ ██╔══╝  ██║╚██╗██║██╔═══╝ ██╔══██║██║",
  "██║     ███████╗██║ ╚████║██║     ██║  ██║███████╗",
  "╚═╝     ╚══════╝╚═╝  ╚═══╝╚═╝     ╚═╝  ╚═╝╚══════╝",
  "       ···╼  ░▒▓ evidence > context > next step ▓▒░  ╾···",
];
const compactLogo = [
  " ____             ____       _",
  "|  _ \\ ___ _ __ |  _ \\ __ _| |",
  "| |_) / _ \\ '_ \\| |_) / _` | |",
  "|  __/  __/ | | |  __/ (_| | |",
  "|_|   \\___|_| |_|_|   \\__,_|_|",
  "     evidence > context > next step",
];
const logoColors: ThemeColor[] = [
  "accent",
  "mdLink",
  "syntaxFunction",
  "syntaxType",
  "thinkingHigh",
  "syntaxNumber",
  "warning",
  "success",
];
const PENPAL_GUIDANCE = `PenPal is the source of truth for enumeration evidence.
When the operator pastes enumeration output or asks you to save or analyze it, call penpal_ingest with the exact pasted text unchanged, then explain only its masked evidence and suggestions.
Present the first PenPal suggestion as the primary next step and no more than two alternatives. Use this stopping rule: after one complete pass of the listed actions without new supporting evidence, ask whether to mark that suggestion exhausted.
Call penpal_focus_update only when the operator's current message explicitly asks to mark a suggestion exhausted or reopened. Never infer exhaustion from tool output alone.
If no target is named, call penpal_targets; use the sole target or ask which target to use.
Call penpal_target_create only after the operator explicitly confirms the target is authorized, and wait for it to succeed before ingesting evidence.
Never invent evidence, authorization, source labels, service keys, or target details.`;

export default function (pi: ExtensionAPI) {
  let latestPrompt = "";
  pi.on("session_start", (_event, ctx) => {
    if (ctx.mode !== "tui") return;
    ctx.ui.setHeader((_tui, theme) => ({
      render: (width) => renderHeader(theme, width),
      invalidate() {},
    }));
  });

  pi.on("before_agent_start", async (event) => {
    latestPrompt = event.prompt;
    return { systemPrompt: `${event.systemPrompt}\n\n${PENPAL_GUIDANCE}` };
  });

  pi.on("tool_call", (event) => {
    if (event.toolName === "penpal_ingest") {
      const text = (event.input as { text?: unknown }).text;
      if (typeof text !== "string" || !latestPrompt.includes(text)) {
        return { block: true, reason: "PenPal can ingest only verbatim evidence from the operator's current message." };
      }
    }
    if (event.toolName === "penpal_focus_update") {
      const statement = (event.input as { operator_statement?: unknown }).operator_statement;
      if (typeof statement !== "string" || !latestPrompt.includes(statement)) {
        return { block: true, reason: "PenPal focus changes require an exact statement from the operator's current message." };
      }
    }
  });

  pi.registerTool({
    name: "penpal_targets",
    label: "PenPal targets",
    description: "List the targets currently stored in PenPal.",
    parameters: Type.Object({}),
    async execute(_toolCallId, _params, signal) {
      return run(["list"], signal);
    },
  });

  pi.registerTool({
    name: "penpal_target_create",
    label: "Create PenPal target",
    description: "Create a target only after the operator explicitly confirms they are authorized to assess it.",
    parameters: Type.Object({
      host: Type.String({ minLength: 1, description: "Authorized target IP address or hostname" }),
      name: Type.String({ minLength: 1, description: "Short target name" }),
      authorized: Type.Boolean({ description: "True only when the operator explicitly confirmed authorization" }),
    }),
    async execute(_toolCallId, params, signal) {
      if (!params.authorized) {
        return textResult("error: explicit operator authorization is required before creating a target");
      }
      return run(["init", params.host, "--name", params.name], signal);
    },
  });

  pi.registerTool({
    name: "penpal_ingest",
    label: "Ingest pasted evidence",
    description:
      "Store the operator's exact pasted enumeration output, extract masked evidence, detect Nmap services, and return deterministic suggestions.",
    parameters: Type.Object({
      target: Type.String({ minLength: 1, description: "Existing PenPal target name" }),
      text: Type.String({ minLength: 1, maxLength: 1_000_000, description: "Exact operator-pasted output" }),
      source: Type.Optional(Type.String({ minLength: 1, maxLength: 64, description: "Tool name when known" })),
      service: Type.Optional(
        Type.String({ minLength: 1, maxLength: 32, description: "Related service such as tcp/80 or udp/161" }),
      ),
    }),
    async execute(_toolCallId, params, signal) {
      const args = ["ingest", params.target, "--source", params.source ?? "paste", "--json"];
      if (params.service) args.push("--service", params.service);
      return run(args, signal, params.text);
    },
  });

  pi.registerTool({
    name: "penpal_focus_update",
    label: "Update PenPal focus",
    description:
      "Mark an existing suggestion exhausted or reopened only when the operator explicitly requests that change.",
    parameters: Type.Object({
      target: Type.String({ minLength: 1, description: "Existing PenPal target name" }),
      suggestion: Type.String({ minLength: 1, description: "Suggestion id returned by PenPal" }),
      status: Type.Union([Type.Literal("exhausted"), Type.Literal("reopened")]),
      operator_statement: Type.String({
        minLength: 1,
        maxLength: 1_000,
        description: "Exact operator text explicitly requesting this focus change",
      }),
    }),
    async execute(_toolCallId, params, signal) {
      return run(["focus", params.target, params.suggestion, params.status, "--json"], signal);
    },
  });

  pi.registerTool({
    name: "penpal_context",
    label: "PenPal context",
    description: "Read PenPal's masked deterministic context snapshot for a target.",
    parameters: Type.Object({ target: Type.String({ description: "PenPal target name" }) }),
    async execute(_toolCallId, params, signal) {
      return run(["context", params.target, "--json"], signal);
    },
  });

  pi.registerTool({
    name: "penpal_suggest",
    label: "PenPal suggestions",
    description: "Read PenPal's deterministic suggestions for a target.",
    parameters: Type.Object({ target: Type.String({ description: "PenPal target name" }) }),
    async execute(_toolCallId, params, signal) {
      return run(["suggest", params.target, "--json"], signal);
    },
  });

  pi.registerTool({
    name: "penpal_evidence",
    label: "PenPal evidence",
    description: "Read PenPal's masked extracted evidence for a target.",
    parameters: Type.Object({ target: Type.String({ description: "PenPal target name" }) }),
    async execute(_toolCallId, params, signal) {
      return run(["evidence", params.target, "--json"], signal);
    },
  });

  pi.registerTool({
    name: "penpal_playbooks_validate",
    label: "Validate PenPal playbooks",
    description: "Validate PenPal's bundled playbooks.",
    parameters: Type.Object({}),
    async execute(_toolCallId, _params, signal) {
      return run(["playbooks", "playbooks", "--json"], signal);
    },
  });

  pi.registerTool({
    name: "penpal_playbook_show",
    label: "Show PenPal playbook",
    description: "Read one validated PenPal playbook by id.",
    parameters: Type.Object({ id: Type.String({ description: "Playbook id" }) }),
    async execute(_toolCallId, params, signal) {
      return run(["playbooks", "playbooks", "--show", params.id], signal);
    },
  });

  pi.registerTool({
    name: "penpal_modules_list",
    label: "List PenPal service modules",
    description: "Read PenPal's source-backed service module registry.",
    parameters: Type.Object({}),
    async execute(_toolCallId, _params, signal) {
      return run(["modules", "list", "--json"], signal);
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
      return run(["modules", "plan", params.target, params.module, "--json"], signal);
    },
  });

  pi.registerCommand("penpal-status", {
    description: "Verify PenPal's PI tools and deterministic core.",
    handler: async (_args, ctx) => {
      const registered = new Set(pi.getAllTools().map((tool) => tool.name));
      const missing = allTools.filter((tool) => !registered.has(tool));
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
          `PenPal ready: ${allTools.length} tools registered (${readOnlyTools.length} read-only, ${writeTools.length} operator-controlled writes); ${report.valid_playbooks} playbooks valid; workspace: ${activeWorkspace}.`,
          "info",
        );
      } catch (error) {
        ctx.ui.notify(errorMessage(error), "error");
      }
    },
  });
}

function renderHeader(theme: Theme, width: number): string[] {
  const logo = width >= Math.max(...fullLogo.map((line) => line.length)) ? fullLogo : compactLogo;
  const details: Array<[string, string]> = [
    ["PenPal", "PI conversational cockpit"],
    ["Core", "deterministic Python"],
    ["Tools", `${allTools.length} registered`],
    ["Workspace", activeWorkspace],
    ["Safety", "masked + operator controlled"],
  ];
  const plainDetails = details.map(([label, value]) => `${label === "PenPal" ? `${label} //` : `${label}:`} ${value}`);
  const paintedLogo = logo.map((line, row) => paintLogo(line, row, theme));
  const paintedDetails = details.map(([label, value]) =>
    label === "PenPal"
      ? theme.bold(theme.fg("accent", `${label} // ${value}`))
      : `${theme.fg("success", `${label}:`)} ${theme.fg("text", value)}`,
  );
  paintedDetails.push("", logoColors.map((color) => theme.fg(color, "███")).join(""));
  plainDetails.push("", " ".repeat(logoColors.length * 3));

  const leftWidth = Math.max(...logo.map((line) => line.length));
  const lines = [""];
  if (width >= leftWidth + 4 + Math.max(...plainDetails.map((line) => line.length))) {
    const rows = Math.max(paintedLogo.length, paintedDetails.length);
    for (let row = 0; row < rows; row += 1) {
      const plainLeft = logo[row] ?? "";
      lines.push(`${paintedLogo[row] ?? ""}${" ".repeat(leftWidth - plainLeft.length + 4)}${paintedDetails[row] ?? ""}`.trimEnd());
    }
  } else {
    lines.push(...paintedLogo, "", ...paintedDetails);
  }
  lines.push("", theme.fg("muted", "Paste authorized enumeration to begin  ·  /penpal-status  ·  /help"), "");
  return lines;
}

function paintLogo(line: string, row: number, theme: Theme): string {
  const band = Math.max(1, Math.ceil(line.length / logoColors.length));
  const pieces: string[] = [];
  for (let start = 0; start < line.length; start += band) {
    const color = logoColors[(Math.floor(start / band) + row) % logoColors.length];
    pieces.push(theme.fg(color, line.slice(start, start + band)));
  }
  return pieces.join("");
}

async function run(args: string[], signal?: AbortSignal, input?: string) {
  try {
    return textResult(await penpal(args, signal, input));
  } catch (error) {
    return textResult(`error: ${errorMessage(error)}`);
  }
}

function penpal(args: string[], signal?: AbortSignal, input?: string): Promise<string> {
  const fullArgs = ["-m", "penpal"];
  if (workspace) fullArgs.push("--workspace", workspace);
  fullArgs.push(...args);
  return new Promise((resolvePromise, rejectPromise) => {
    const child = execFile(
      python,
      fullArgs,
      { cwd, signal, timeout: 30_000, maxBuffer: 2_000_000, encoding: "utf8" },
      (error, stdout, stderr) => {
        if (error) {
          (error as Error & { stderr?: string }).stderr = stderr;
          rejectPromise(error);
          return;
        }
        resolvePromise(stdout.trim());
      },
    );
    child.stdin?.end(input);
  });
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
