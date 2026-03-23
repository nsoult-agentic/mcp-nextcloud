/**
 * MCP server for NextCloud — WebDAV file management tools.
 * Deployed via GitHub Actions → ghcr.io → Portainer CE GitOps polling.
 *
 * Tools:
 *   nextcloud-upload  — Upload a file to NextCloud via WebDAV PUT
 *   nextcloud-list    — List files/folders in a path via WebDAV PROPFIND
 *   nextcloud-mkdir   — Create a directory via WebDAV MKCOL
 *   nextcloud-search  — Search files by name via WebDAV REPORT
 *
 * SECURITY: Credentials read from /secrets/credentials.json (mounted from /srv/).
 * Credentials never appear in tool output. Generic error messages only.
 *
 * Usage: PORT=8902 SECRETS_DIR=/secrets bun run src/http.ts
 */
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { WebStandardStreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/webStandardStreamableHttp.js";
import { z } from "zod";

// ── Configuration ──────────────────────────────────────────

const PORT = Number(process.env["PORT"]) || 8902;
const SECRETS_DIR = process.env["SECRETS_DIR"] || "/secrets";

// ── Credential Loading ─────────────────────────────────────

interface Credentials {
  server: string;
  username: string;
  password: string;
}

function loadCredentials(): Credentials {
  const raw = readFileSync(resolve(SECRETS_DIR, "credentials.json"), "utf-8");
  const parsed = JSON.parse(raw);
  if (!parsed.server || !parsed.username || !parsed.password) {
    throw new Error("credentials.json must contain server, username, password");
  }
  return parsed as Credentials;
}

let creds: Credentials;
try {
  creds = loadCredentials();
} catch (e) {
  console.error("Failed to load credentials:", (e as Error).message);
  process.exit(1);
}

const WEBDAV_BASE = `${creds.server.replace(/\/+$/, "")}/remote.php/dav/files/${encodeURIComponent(creds.username)}`;
const AUTH_HEADER = `Basic ${btoa(`${creds.username}:${creds.password}`)}`;

// ── Path Validation ────────────────────────────────────────

function validatePath(p: string): string | null {
  if (p.includes("..")) return "Path traversal (..) not allowed";
  if (p.includes("\\")) return "Backslashes not allowed";
  if (p.length > 500) return "Path too long (max 500 chars)";
  return null;
}

function normalizePath(p: string): string {
  return "/" + p.replace(/^\/+/, "").replace(/\/+/g, "/");
}

// ── WebDAV Helper ──────────────────────────────────────────

async function webdav(
  method: string,
  path: string,
  headers: Record<string, string> = {},
  body?: BodyInit,
): Promise<Response> {
  const url = `${WEBDAV_BASE}${normalizePath(path)}`;
  return fetch(url, {
    method,
    headers: { Authorization: AUTH_HEADER, ...headers },
    body,
    signal: AbortSignal.timeout(30_000),
  });
}

// ── XML Parsing Helpers ────────────────────────────────────

function extractTag(xml: string, tag: string): string {
  const re = new RegExp(
    `<(?:[a-z]+:)?${tag}[^>]*>([\\s\\S]*?)<\\/(?:[a-z]+:)?${tag}>`,
    "i",
  );
  const m = xml.match(re);
  return m ? m[1].trim() : "";
}

function isCollection(xml: string): boolean {
  return /<(?:[a-z]+:)?collection\s*\/?>/.test(xml);
}

interface DavEntry {
  href: string;
  name: string;
  isDir: boolean;
  size: number;
  modified: string;
  contentType: string;
}

function parseMultistatus(xml: string, basePath: string): DavEntry[] {
  const entries: DavEntry[] = [];
  const responses = xml.split(/<(?:[a-z]+:)?response[^>]*>/i).slice(1);

  for (const block of responses) {
    const href = decodeURIComponent(extractTag(block, "href"));
    const modified = extractTag(block, "getlastmodified");
    const sizeStr = extractTag(block, "getcontentlength");
    const contentType = extractTag(block, "getcontenttype");
    const dir = isCollection(block);

    const parts = href.replace(/\/+$/, "").split("/");
    const name = parts[parts.length - 1] || "";

    // Skip entries with empty names
    if (name === "") continue;

    // Skip the directory itself (first entry in PROPFIND Depth:1)
    if (basePath) {
      const normalBase = basePath.replace(/\/+$/, "");
      const normalHref = href.replace(/\/+$/, "");
      if (normalHref === normalBase) continue;
    }

    entries.push({
      href,
      name,
      isDir: dir,
      size: sizeStr ? parseInt(sizeStr, 10) : 0,
      modified,
      contentType: dir ? "directory" : contentType,
    });
  }

  return entries;
}

// ── Formatting ─────────────────────────────────────────────

function fmtSize(bytes: number): string {
  if (bytes === 0) return "-";
  if (bytes >= 1e9) return `${(bytes / 1e9).toFixed(1)} GB`;
  if (bytes >= 1e6) return `${(bytes / 1e6).toFixed(1)} MB`;
  if (bytes >= 1e3) return `${(bytes / 1e3).toFixed(1)} KB`;
  return `${bytes} B`;
}

function fmtDate(dateStr: string): string {
  if (!dateStr) return "-";
  try {
    return new Date(dateStr).toISOString().slice(0, 16).replace("T", " ");
  } catch {
    return dateStr;
  }
}

// ── Tool: nextcloud-upload ─────────────────────────────────

const UploadInput = {
  path: z
    .string()
    .min(1)
    .max(500)
    .describe("Destination path including filename (e.g., 'Documents/report.pdf')"),
  content: z
    .string()
    .min(1)
    .max(10_000_000)
    .describe("File content — plain text or base64-encoded binary (max ~7.5MB decoded)"),
  encoding: z
    .enum(["text", "base64"])
    .default("text")
    .describe("Content encoding: 'text' (default) or 'base64' for binary files"),
};

async function upload(params: {
  path: string;
  content: string;
  encoding: string;
}): Promise<string> {
  const err = validatePath(params.path);
  if (err) return `Error: ${err}`;

  let contentType = "application/octet-stream";
  let reqBody: BodyInit;

  if (params.encoding === "base64") {
    try {
      const binary = atob(params.content);
      reqBody = new Blob([Uint8Array.from(binary, (c) => c.charCodeAt(0))]);
    } catch {
      return "Error: Invalid base64 content.";
    }
  } else {
    reqBody = params.content;
    contentType = "text/plain; charset=utf-8";
  }

  try {
    const res = await webdav("PUT", params.path, { "Content-Type": contentType }, reqBody);

    if (res.status === 201) return `Uploaded: ${params.path} (created)`;
    if (res.status === 204) return `Uploaded: ${params.path} (overwritten)`;
    if (res.status === 409)
      return "Error: Parent directory does not exist. Create it first with nextcloud-mkdir.";
    return `Upload failed (${res.status})`;
  } catch {
    return "Upload failed — NextCloud request error.";
  }
}

// ── Tool: nextcloud-list ───────────────────────────────────

const ListInput = {
  path: z
    .string()
    .max(500)
    .default("/")
    .describe("Directory path to list (default: root '/')"),
};

async function list(params: { path: string }): Promise<string> {
  const err = validatePath(params.path);
  if (err) return `Error: ${err}`;

  try {
    const res = await webdav("PROPFIND", params.path, { Depth: "1" });

    if (res.status === 404) return `Path not found: ${params.path}`;
    if (!res.ok && res.status !== 207) return `List failed (${res.status})`;

    const xml = await res.text();
    const userPath = `/remote.php/dav/files/${encodeURIComponent(creds.username)}${normalizePath(params.path)}`;
    const entries = parseMultistatus(xml, userPath);

    if (entries.length === 0) return `${params.path} — empty directory`;

    entries.sort((a, b) => {
      if (a.isDir !== b.isDir) return a.isDir ? -1 : 1;
      return a.name.localeCompare(b.name);
    });

    const lines = [`## ${params.path || "/"}`, ""];
    lines.push("| Name | Size | Modified | Type |");
    lines.push("|------|------|----------|------|");

    for (const e of entries) {
      const icon = e.isDir ? "dir" : "file";
      lines.push(
        `| [${icon}] ${e.name} | ${fmtSize(e.size)} | ${fmtDate(e.modified)} | ${e.contentType} |`,
      );
    }

    lines.push("", `${entries.length} items`);
    return lines.join("\n");
  } catch {
    return "List failed — NextCloud request error.";
  }
}

// ── Tool: nextcloud-mkdir ──────────────────────────────────

const MkdirInput = {
  path: z
    .string()
    .min(1)
    .max(500)
    .describe("Directory path to create (e.g., 'Documents/2026/Q1')"),
};

async function mkdir(params: { path: string }): Promise<string> {
  const err = validatePath(params.path);
  if (err) return `Error: ${err}`;

  try {
    const res = await webdav("MKCOL", params.path);

    if (res.status === 201) return `Created directory: ${params.path}`;
    if (res.status === 405) return `Directory already exists: ${params.path}`;
    if (res.status === 409)
      return "Error: Parent directory does not exist. Create parent directories first.";
    if (res.status === 507) return "Error: Insufficient storage on NextCloud.";
    return `Mkdir failed (${res.status})`;
  } catch {
    return "Mkdir failed — NextCloud request error.";
  }
}

// ── Tool: nextcloud-search ─────────────────────────────────

const SearchInput = {
  query: z
    .string()
    .min(1)
    .max(200)
    .describe("Search term — matches against file names"),
  path: z
    .string()
    .max(500)
    .default("/")
    .describe("Directory scope to search within (default: root)"),
  limit: z
    .number()
    .int()
    .min(1)
    .max(50)
    .default(20)
    .describe("Maximum results (default: 20)"),
};

async function search(params: {
  query: string;
  path: string;
  limit: number;
}): Promise<string> {
  const pathErr = validatePath(params.path);
  if (pathErr) return `Error: ${pathErr}`;

  // Sanitize search query for XML inclusion
  const safeQuery = params.query
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");

  const body = `<?xml version="1.0" encoding="UTF-8"?>
<oc:filter-files xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns" xmlns:nc="http://nextcloud.org/ns">
  <d:prop>
    <d:getlastmodified/>
    <d:getcontentlength/>
    <d:getcontenttype/>
    <d:resourcetype/>
  </d:prop>
  <oc:filter-rules>
    <oc:name>%${safeQuery}%</oc:name>
  </oc:filter-rules>
</oc:filter-files>`;

  try {
    const url = `${WEBDAV_BASE}${normalizePath(params.path)}`;
    const res = await fetch(url, {
      method: "REPORT",
      headers: {
        Authorization: AUTH_HEADER,
        "Content-Type": "application/xml; charset=utf-8",
      },
      body,
      signal: AbortSignal.timeout(30_000),
    });

    if (res.status === 501) return "Search not supported by this NextCloud version.";
    if (!res.ok && res.status !== 207) return `Search failed (${res.status})`;

    const xml = await res.text();
    // Empty basePath for search — no self-entry to skip
    const entries = parseMultistatus(xml, "");

    if (entries.length === 0) return `No files matching "${params.query}" found.`;

    const limited = entries.slice(0, params.limit);
    const davPrefix = `/remote.php/dav/files/${encodeURIComponent(creds.username)}/`;

    const lines = [`## Search: "${params.query}"`, ""];
    lines.push("| Path | Size | Modified | Type |");
    lines.push("|------|------|----------|------|");

    for (const e of limited) {
      const icon = e.isDir ? "dir" : "file";
      const relPath = e.href.includes(davPrefix)
        ? e.href.split(davPrefix)[1] || e.name
        : e.name;
      lines.push(
        `| [${icon}] ${relPath} | ${fmtSize(e.size)} | ${fmtDate(e.modified)} | ${e.contentType} |`,
      );
    }

    const suffix =
      entries.length > params.limit
        ? ` (showing ${params.limit} of ${entries.length})`
        : "";
    lines.push("", `${limited.length} results${suffix}`);
    return lines.join("\n");
  } catch {
    return "Search failed — NextCloud request error.";
  }
}

// ── MCP Server ─────────────────────────────────────────────

function createServer(): McpServer {
  const server = new McpServer({
    name: "mcp-nextcloud",
    version: "0.1.0",
  });

  server.tool(
    "nextcloud-upload",
    "Upload a file to NextCloud via WebDAV. Supports text and base64-encoded binary content.",
    UploadInput,
    async (params) => ({
      content: [{ type: "text" as const, text: await upload(params) }],
    }),
  );

  server.tool(
    "nextcloud-list",
    "List files and folders in a NextCloud directory. Returns name, size, modified date, and type.",
    ListInput,
    async (params) => ({
      content: [{ type: "text" as const, text: await list(params) }],
    }),
  );

  server.tool(
    "nextcloud-mkdir",
    "Create a directory (folder) on NextCloud. Parent directories must exist.",
    MkdirInput,
    async (params) => ({
      content: [{ type: "text" as const, text: await mkdir(params) }],
    }),
  );

  server.tool(
    "nextcloud-search",
    "Search for files by name on NextCloud. Supports partial matching within a directory scope.",
    SearchInput,
    async (params) => ({
      content: [{ type: "text" as const, text: await search(params) }],
    }),
  );

  return server;
}

// ── HTTP Server (stateless mode) ───────────────────────────

// Single server instance — reused across all requests
const mcpServer = createServer();

const httpServer = Bun.serve({
  port: PORT,
  hostname: "0.0.0.0",
  async fetch(req: Request): Promise<Response> {
    const url = new URL(req.url);

    if (url.pathname === "/health") {
      return new Response(
        JSON.stringify({ status: "ok", service: "mcp-nextcloud" }),
        { headers: { "Content-Type": "application/json" } },
      );
    }

    if (url.pathname === "/mcp") {
      const transport = new WebStandardStreamableHTTPServerTransport({
        sessionIdGenerator: undefined,
      });
      await mcpServer.connect(transport);
      return transport.handleRequest(req);
    }

    return new Response("Not Found", { status: 404 });
  },
});

console.log(`mcp-nextcloud listening on http://0.0.0.0:${PORT}/mcp`);
console.log("Tools: 4 | NextCloud: connected");

process.on("SIGTERM", () => {
  httpServer.stop();
  process.exit(0);
});

process.on("SIGINT", () => {
  httpServer.stop();
  process.exit(0);
});
