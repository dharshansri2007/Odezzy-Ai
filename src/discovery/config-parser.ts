import { readFile } from "node:fs/promises";
import { homedir, platform } from "node:os";
import { join } from "node:path";
import { McpServerConfig, McpServerConfigSchema } from "../types/index.js";

/**
 * Known MCP config file locations across common hosts.
 * Cross-platform: Claude Desktop's config path differs on macOS vs Windows vs Linux.
 */
function knownConfigPaths(): { host: string; path: string }[] {
  const home = homedir();
  const os = platform();

  const claudeDesktopPath =
    os === "darwin"
      ? join(home, "Library/Application Support/Claude/claude_desktop_config.json")
      : os === "win32"
        ? join(process.env.APPDATA ?? "", "Claude/claude_desktop_config.json")
        : join(home, ".config/Claude/claude_desktop_config.json");

  return [
    { host: "claude-desktop", path: claudeDesktopPath },
    { host: "cursor", path: join(home, ".cursor/mcp.json") },
    { host: "cursor-project", path: join(process.cwd(), ".cursor/mcp.json") },
    { host: "vscode", path: join(process.cwd(), ".vscode/mcp.json") },
  ];
}

/**
 * The shape MCP config files actually use on disk — different from our
 * internal McpServerConfig, so we normalize on the way in.
 */
interface RawMcpConfigFile {
  mcpServers?: Record<
    string,
    {
      command?: string;
      args?: string[];
      env?: Record<string, string>;
      url?: string;
      headers?: Record<string, string>;
    }
  >;
}

async function readOneConfig(host: string, path: string): Promise<McpServerConfig[]> {
  let raw: string;
  try {
    raw = await readFile(path, "utf-8");
  } catch {
    // File doesn't exist or isn't readable on this machine — expected for most hosts, not an error
    return [];
  }

  let parsed: RawMcpConfigFile;
  try {
    parsed = JSON.parse(raw);
  } catch (err) {
    console.warn(`[config-parser] ${path} is not valid JSON, skipping: ${(err as Error).message}`);
    return [];
  }

  const servers = parsed.mcpServers ?? {};
  const results: McpServerConfig[] = [];

  for (const [name, entry] of Object.entries(servers)) {
    const candidate = entry.url
      ? {
          name,
          sourceFile: path,
          transport: "http" as const,
          url: entry.url,
          headers: entry.headers,
        }
      : {
          name,
          sourceFile: path,
          transport: "stdio" as const,
          command: entry.command,
          args: entry.args,
          env: entry.env,
        };

    const validation = McpServerConfigSchema.safeParse(candidate);
    if (validation.success) {
      results.push(validation.data);
    } else {
      console.warn(`[config-parser] Skipping malformed server "${name}" in ${path}: ${validation.error.message}`);
    }
  }

  return results;
}

/**
 * Scans every known MCP config location on this machine and returns a
 * flat, deduplicated list of server configs. Never throws — a missing
 * or malformed config file is logged and skipped, not fatal.
 */
export async function discoverMcpConfigs(): Promise<McpServerConfig[]> {
  const paths = knownConfigPaths();
  const all = await Promise.all(paths.map(({ host, path }) => readOneConfig(host, path)));
  const flat = all.flat();

  // Dedupe by name — same server referenced from two config files keeps the first occurrence
  const seen = new Set<string>();
  return flat.filter((s) => {
    if (seen.has(s.name)) return false;
    seen.add(s.name);
    return true;
  });
}