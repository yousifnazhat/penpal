import { execFileSync, spawn } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const adapterRoot = join(root, "packages", "penpal-pi");
const expectedVersion = readFileSync(join(root, ".pi-version"), "utf8").trim();
const piBin = process.env.PI_BIN ?? (process.platform === "win32" ? "pi.cmd" : "pi");
const allowVersionMismatch = /^(1|true|yes)$/i.test(process.env.PI_ALLOW_VERSION_MISMATCH ?? "");
const configDir = mkdtempSync(join(tmpdir(), "penpal-pi-check-"));
const adapterProject = mkdtempSync(join(tmpdir(), "penpal-pi-adapter-"));
const env = {
  ...process.env,
  PENPAL_CWD: root,
  PENPAL_PYTHON: process.env.PENPAL_PYTHON ?? (process.platform === "win32" ? "python" : "python3"),
  PI_CODING_AGENT_DIR: configDir,
  PI_OFFLINE: "1",
  PI_TELEMETRY: "0",
};
delete env.PENPAL_WORKSPACE;
const adapterEnv = {
  ...env,
  PENPAL_CWD: process.env.CI ? adapterProject : root,
  PI_CODING_AGENT_DIR: mkdtempSync(join(tmpdir(), "penpal-pi-adapter-check-")),
  ...(process.env.CI ? {} : { PYTHONPATH: [root, process.env.PYTHONPATH].filter(Boolean).join(delimiter) }),
};

try {
  const installedVersion = runPi(["--version"], root, env).trim();
  if (installedVersion !== expectedVersion && !allowVersionMismatch) {
    throw new Error(`expected PI ${expectedVersion}, found ${installedVersion}`);
  }
  console.log(`PI version: ${installedVersion}${installedVersion === expectedVersion ? "" : " (compatibility mode)"}`);

  await checkProjectPackage("checkout package", root, env, "../");

  mkdirSync(join(adapterProject, ".pi"));
  writeFileSync(join(adapterProject, ".pi", "settings.json"), JSON.stringify({ packages: [adapterRoot] }) + "\n");
  await checkProjectPackage("adapter package", adapterProject, adapterEnv, adapterRoot);
} finally {
  rmSync(configDir, { recursive: true, force: true });
  rmSync(adapterEnv.PI_CODING_AGENT_DIR, { recursive: true, force: true });
  rmSync(adapterProject, { recursive: true, force: true });
}

async function checkProjectPackage(label, projectRoot, projectEnv, packageMarker) {
  const listed = runPi(["list", "--approve"], projectRoot, projectEnv);
  if (!listed.includes("Project packages:") || !listed.includes(packageMarker)) {
    throw new Error(`${label} was not discovered:\n${listed}`);
  }
  console.log(`PI ${label}: discovered`);
  await checkRpc(projectRoot, projectEnv);
  console.log(`PI ${label} RPC harness: passed`);
}

function runPi(args, cwd, processEnv) {
  return execFileSync(piBin, args, {
    cwd,
    encoding: "utf8",
    env: processEnv,
    shell: process.platform === "win32",
    timeout: 20_000,
  });
}

function checkRpc(cwd, processEnv) {
  return new Promise((resolvePromise, rejectPromise) => {
    const child = spawn(piBin, ["--mode", "rpc", "--no-session", "--approve", "--offline"], {
      cwd,
      env: processEnv,
      shell: process.platform === "win32",
      stdio: ["pipe", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    let commandFound = false;
    let statusReceived = false;
    let promptAccepted = false;
    let ending = false;

    const timeout = setTimeout(() => {
      fail(new Error(`PI RPC smoke timed out. stderr:\n${stderr}`));
    }, 20_000);

    child.stderr.setEncoding("utf8");
    child.stderr.on("data", (chunk) => {
      stderr += chunk;
    });

    child.stdout.setEncoding("utf8");
    child.stdout.on("data", (chunk) => {
      stdout += chunk;
      const lines = stdout.split("\n");
      stdout = lines.pop() ?? "";
      for (const line of lines) {
        if (!line.trim()) continue;
        let message;
        try {
          message = JSON.parse(line);
        } catch (error) {
          fail(new Error(`PI RPC emitted non-JSON output: ${line}\n${error}`));
          return;
        }

        if (message.type === "extension_error") {
          fail(new Error(`PI extension error: ${JSON.stringify(message)}`));
          return;
        }
        if (message.type === "response" && message.command === "get_commands") {
          const commands = message.data?.commands ?? [];
          commandFound = commands.some((command) => command.name === "penpal-status");
          if (!commandFound) {
            fail(new Error(`penpal-status was not registered: ${JSON.stringify(commands)}`));
            return;
          }
          child.stdin.write(`${JSON.stringify({ id: "penpal-status", type: "prompt", message: "/penpal-status" })}\n`);
        }
        if (message.type === "extension_ui_request" && message.method === "notify") {
          if (message.notifyType === "error") {
            fail(new Error(message.message));
            return;
          }
          if (/^PenPal ready: 7 read-only tools registered; [1-9]\d* playbooks valid\.$/.test(message.message)) {
            statusReceived = true;
          }
        }
        if (message.type === "response" && message.command === "prompt" && message.id === "penpal-status") {
          if (!message.success) {
            fail(new Error(`penpal-status command failed: ${JSON.stringify(message)}`));
            return;
          }
          promptAccepted = true;
        }
        maybeEnd();
      }
    });

    child.on("error", fail);
    child.on("close", (code) => {
      clearTimeout(timeout);
      if (code === 0 && commandFound && statusReceived && promptAccepted) {
        resolvePromise();
      } else if (!ending) {
        rejectPromise(new Error(`PI RPC exited ${code}. stderr:\n${stderr}`));
      } else if (code !== 0) {
        rejectPromise(new Error(`PI RPC exited ${code}. stderr:\n${stderr}`));
      }
    });

    child.stdin.write(`${JSON.stringify({ type: "get_commands" })}\n`);

    function maybeEnd() {
      if (commandFound && statusReceived && promptAccepted && !ending) {
        ending = true;
        child.stdin.end();
      }
    }

    function fail(error) {
      if (ending) return;
      ending = true;
      clearTimeout(timeout);
      child.kill();
      rejectPromise(error);
    }
  });
}
