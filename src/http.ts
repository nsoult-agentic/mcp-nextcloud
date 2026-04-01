/**
 * MCP server for NextCloud — WebDAV file management tools.
 * Deployed via GitHub Actions → ghcr.io → Portainer CE GitOps polling.
 *
 * Tools:
 *   nextcloud-upload  — Upload a file to NextCloud via WebDAV PUT
 *   nextcloud-list    — List files/folders in a path via WebDAV PROPFIND
 *   nextcloud-mkdir   — Create a directory via WebDAV MKCOL
 *   nextcloud-search  — Search files by name via WebDAV REPORT
 *   nextcloud-share   — Share a file/folder with a user via OCS Share API
 *   nextcloud-move    — Move/rename a file or folder via WebDAV MOVE
 *   nextcloud-delete    — Delete a file or folder via WebDAV DELETE
 *   nextcloud-download  — Download file content via WebDAV GET (text or base64)
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
} catch {
  console.error("Failed to load credentials — check /secrets/credentials.json exists and is valid JSON");
  process.exit(1);
}

const WEBDAV_BASE = `${creds.server.replace(/\/+$/, "")}/remote.php/dav/files/${encodeURIComponent(creds.username)}`;
const AUTH_HEADER = `Basic ${btoa(`${creds.username}:${creds.password}`)}`;

// ── Path Validation ────────────────────────────────────────

function validatePath(p: string): string | null {
  if (p.length > 500) return "Path too long (max 500 chars)";
  // Decode URL-encoded characters before validation to catch %2e%2e bypasses
  let decoded: string;
  try {
    decoded = decodeURIComponent(p);
  } catch {
    return "Invalid path encoding";
  }
  if (decoded.includes("..")) return "Path traversal (..) not allowed";
  if (decoded.includes("\\")) return "Backslashes not allowed";
  if (/[\x00-\x1f]/.test(decoded)) return "Control characters not allowed";
  if (p.includes("%00") || p.includes("\x00")) return "Null bytes not allowed";
  if (/[?#@]/.test(p)) return "Path contains invalid characters";
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

// ── Output Sanitization ───────────────────────────────────

/** Strip markdown-active and control characters from untrusted strings in tool output */
function sanitizeOutput(s: string): string {
  return s.replace(/[|[\](){}#*_~`<>!\x00-\x1f]/g, "_").slice(0, 255);
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
    if (xml.length > 2_000_000)
      return "Response too large — directory has too many items. Use a more specific path.";
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
        `| [${icon}] ${sanitizeOutput(e.name)} | ${fmtSize(e.size)} | ${fmtDate(e.modified)} | ${sanitizeOutput(e.contentType)} |`,
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

    if (res.status === 201) {
      // PROPFIND forces NextCloud to register the folder in oc_filecache.
      // Without this, the OCS Share API returns 403 on newly created paths.
      try { await webdav("PROPFIND", params.path, { Depth: "0" }); } catch {}
      return `Created directory: ${params.path}`;
    }
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
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&apos;");

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
    if (xml.length > 2_000_000)
      return "Response too large — too many search results. Use a more specific query.";
    // Empty basePath for search — no self-entry to skip
    const entries = parseMultistatus(xml, "");

    if (entries.length === 0) return `No files matching "${params.query}" found.`;

    const limited = entries.slice(0, params.limit);

    const lines = [`## Search: "${params.query}"`, ""];
    lines.push("| Path | Size | Modified | Type |");
    lines.push("|------|------|----------|------|");

    for (const e of limited) {
      const icon = e.isDir ? "dir" : "file";
      // Strip WebDAV prefix without using credentials — use regex for safety
      const relPath = e.href.replace(/^.*\/remote\.php\/dav\/files\/[^/]+\//, "") || e.name;
      lines.push(
        `| [${icon}] ${sanitizeOutput(relPath)} | ${fmtSize(e.size)} | ${fmtDate(e.modified)} | ${sanitizeOutput(e.contentType)} |`,
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

// ── OCS API Helper (for Share API) ────────────────────────

const OCS_BASE = `${creds.server.replace(/\/+$/, "")}/ocs/v2.php/apps/files_sharing/api/v1`;

async function ocsPost(
  endpoint: string,
  body: Record<string, string | number>,
): Promise<{ status: number; data: any }> {
  const res = await fetch(`${OCS_BASE}${endpoint}`, {
    method: "POST",
    headers: {
      Authorization: AUTH_HEADER,
      "OCS-APIRequest": "true",
      "Content-Type": "application/x-www-form-urlencoded",
      Accept: "application/json",
    },
    body: new URLSearchParams(
      Object.entries(body).map(([k, v]) => [k, String(v)]),
    ),
    signal: AbortSignal.timeout(15_000),
  });
  const json = await res.json();
  return { status: res.status, data: json?.ocs?.data ?? json };
}

// ── Tool: nextcloud-share ─────────────────────────────────

const ShareInput = {
  path: z
    .string()
    .min(1)
    .max(500)
    .describe("Path to the file or folder to share (e.g., 'Shared/Accounting')"),
  shareWith: z
    .string()
    .min(1)
    .max(100)
    .describe("NextCloud username to share with (e.g., 'admin')"),
  permissions: z
    .enum(["read", "read-write", "all"])
    .default("read-write")
    .describe("Permission level: 'read' (view only), 'read-write' (edit), 'all' (edit + reshare + delete)"),
};

async function share(params: {
  path: string;
  shareWith: string;
  permissions: string;
}): Promise<string> {
  const err = validatePath(params.path);
  if (err) return `Error: ${err}`;

  // Map permission strings to NextCloud OCS permission integers
  // 1=read, 2=update, 4=create, 8=delete, 16=reshare
  const permMap: Record<string, number> = {
    "read": 1,
    "read-write": 1 + 2 + 4,     // read + update + create
    "all": 1 + 2 + 4 + 8 + 16,   // read + update + create + delete + reshare
  };

  const permInt = permMap[params.permissions] ?? 7;

  try {
    const { status, data } = await ocsPost("/shares", {
      path: normalizePath(params.path),
      shareType: 0, // 0 = user share
      shareWith: params.shareWith,
      permissions: permInt,
    });

    if (status === 200) {
      const shareId = data?.id ?? "unknown";
      return `Shared "${params.path}" with ${params.shareWith} (${params.permissions}). Share ID: ${shareId}`;
    }
    if (status === 404) return `Error: Path not found — "${params.path}"`;
    if (status === 403) return `Error: Insufficient permissions to share this path.`;

    const msg = data?.message || data?.meta?.message || "";
    if (msg) return `Share failed (${status}): ${sanitizeOutput(msg)}`;
    return `Share failed (${status})`;
  } catch {
    return "Share failed — NextCloud request error.";
  }
}

// ── Tool: nextcloud-move ──────────────────────────────────

const MoveInput = {
  from: z
    .string()
    .min(1)
    .max(500)
    .describe("Source path (e.g., 'Shared/old-name.pdf')"),
  to: z
    .string()
    .min(1)
    .max(500)
    .describe("Destination path (e.g., 'Shared/Accounting/Invoices/invoice.pdf')"),
};

async function move(params: { from: string; to: string }): Promise<string> {
  const fromErr = validatePath(params.from);
  if (fromErr) return `Error (from): ${fromErr}`;
  const toErr = validatePath(params.to);
  if (toErr) return `Error (to): ${toErr}`;

  const destUrl = `${WEBDAV_BASE}${normalizePath(params.to)}`;

  try {
    const res = await webdav("MOVE", params.from, {
      Destination: destUrl,
      Overwrite: "F", // Don't overwrite existing files
    });

    if (res.status === 201) return `Moved: "${params.from}" → "${params.to}"`;
    if (res.status === 204) return `Moved: "${params.from}" → "${params.to}" (replaced existing)`;
    if (res.status === 404) return `Error: Source not found — "${params.from}"`;
    if (res.status === 409) return `Error: Destination parent directory does not exist.`;
    if (res.status === 412) return `Error: Destination already exists. Use a different name or delete it first.`;
    return `Move failed (${res.status})`;
  } catch {
    return "Move failed — NextCloud request error.";
  }
}

// ── Tool: nextcloud-delete ────────────────────────────────

const DeleteInput = {
  path: z
    .string()
    .min(1)
    .max(500)
    .describe("Path to the file or folder to delete (e.g., 'Shared/test-folder')"),
};

async function del(params: { path: string }): Promise<string> {
  const err = validatePath(params.path);
  if (err) return `Error: ${err}`;

  try {
    const res = await webdav("DELETE", params.path);

    if (res.status === 204) return `Deleted: "${params.path}"`;
    if (res.status === 404) return `Error: Not found — "${params.path}"`;
    if (res.status === 403) return `Error: Insufficient permissions to delete this path.`;
    return `Delete failed (${res.status})`;
  } catch {
    return "Delete failed — NextCloud request error.";
  }
}

// ── Tool: nextcloud-download ─────────────────────────────

const DownloadInput = {
  path: z
    .string()
    .min(1)
    .max(500)
    .describe("Path to the file to download (e.g., 'Shared/Accounting/Invoices/2026/invoice.pdf')"),
};

const MAX_DOWNLOAD_SIZE = 10 * 1024 * 1024; // 10MB

const TEXT_EXTENSIONS = new Set([
  "txt", "md", "csv", "json", "xml", "html", "htm", "yaml", "yml",
  "toml", "ini", "cfg", "conf", "log", "sh", "bash", "ts", "js",
  "py", "rb", "go", "rs", "java", "c", "h", "cpp", "css", "sql",
]);

async function download(params: { path: string }): Promise<{
  type: "text" | "base64";
  content: string;
  mimeType: string;
  size: number;
}> {
  const err = validatePath(params.path);
  if (err) throw new Error(err);

  const res = await webdav("GET", params.path);

  if (res.status === 404) throw new Error(`File not found: "${params.path}"`);
  if (res.status === 403) throw new Error("Insufficient permissions to read this file.");
  if (!res.ok) throw new Error(`Download failed (${res.status})`);

  const contentLength = Number(res.headers.get("content-length") || 0);
  if (contentLength > MAX_DOWNLOAD_SIZE) {
    throw new Error(`File too large (${(contentLength / 1024 / 1024).toFixed(1)}MB). Max: 10MB.`);
  }

  const mimeType = res.headers.get("content-type") || "application/octet-stream";
  const ext = params.path.split(".").pop()?.toLowerCase() || "";
  const isText = TEXT_EXTENSIONS.has(ext) || mimeType.startsWith("text/");

  const buffer = await res.arrayBuffer();

  if (buffer.byteLength > MAX_DOWNLOAD_SIZE) {
    throw new Error(`File too large (${(buffer.byteLength / 1024 / 1024).toFixed(1)}MB). Max: 10MB.`);
  }

  if (isText) {
    return {
      type: "text",
      content: new TextDecoder().decode(buffer),
      mimeType,
      size: buffer.byteLength,
    };
  }

  // Binary files (PDF, images, docx, etc.) — return base64
  const bytes = new Uint8Array(buffer);
  let binary = "";
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return {
    type: "base64",
    content: btoa(binary),
    mimeType,
    size: buffer.byteLength,
  };
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

  server.tool(
    "nextcloud-share",
    "Share a file or folder with a NextCloud user. Sets permissions (read, read-write, or all).",
    ShareInput,
    async (params) => ({
      content: [{ type: "text" as const, text: await share(params) }],
    }),
  );

  server.tool(
    "nextcloud-move",
    "Move or rename a file/folder on NextCloud. Destination parent must exist.",
    MoveInput,
    async (params) => ({
      content: [{ type: "text" as const, text: await move(params) }],
    }),
  );

  server.tool(
    "nextcloud-delete",
    "Delete a file or folder on NextCloud. Use with caution — deletion is permanent.",
    DeleteInput,
    async (params) => ({
      content: [{ type: "text" as const, text: await del(params) }],
    }),
  );

  server.tool(
    "nextcloud-download",
    "Download a file from NextCloud. Returns text content for text files, base64 for binary files (PDF, images, etc.). Max 10MB.",
    DownloadInput,
    async (params) => {
      try {
        const result = await download(params);
        if (result.type === "text") {
          return {
            content: [{ type: "text" as const, text: result.content }],
          };
        }
        // Binary — return as embedded resource with base64
        return {
          content: [{
            type: "resource" as const,
            resource: {
              uri: `nextcloud://${normalizePath(params.path)}`,
              mimeType: result.mimeType,
              blob: result.content,
            },
          }],
        };
      } catch (e) {
        return {
          content: [{ type: "text" as const, text: `Error: ${(e as Error).message}` }],
        };
      }
    },
  );

  return server;
}

// ── Rate Limiter ──────────────────────────────────────────

const RATE_LIMIT = 30;
const RATE_WINDOW_MS = 60_000;
const requestTimestamps: number[] = [];

function isRateLimited(): boolean {
  const now = Date.now();
  while (requestTimestamps.length > 0 && requestTimestamps[0] < now - RATE_WINDOW_MS) {
    requestTimestamps.shift();
  }
  if (requestTimestamps.length >= RATE_LIMIT) return true;
  requestTimestamps.push(now);
  return false;
}

// ── HTTP Server (stateless mode) ───────────────────────────

// Per the MCP SDK stateless pattern, a new server instance is created per
// request so that .connect() is only called once per McpServer lifetime.
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
      if (isRateLimited()) {
        return new Response("Rate limit exceeded", { status: 429 });
      }
      const server = createServer();
      const transport = new WebStandardStreamableHTTPServerTransport({
        sessionIdGenerator: undefined,
      });
      await server.connect(transport);
      return transport.handleRequest(req);
    }

    return new Response("Not Found", { status: 404 });
  },
});

console.log(`mcp-nextcloud listening on http://0.0.0.0:${PORT}/mcp`);
console.log("Tools: 8 | NextCloud: connected");

process.on("SIGTERM", () => {
  httpServer.stop();
  process.exit(0);
});

process.on("SIGINT", () => {
  httpServer.stop();
  process.exit(0);
});
