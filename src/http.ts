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
 *   nextcloud-copy    — Copy a file or folder via WebDAV COPY (server-side, no data transfer)
 *   nextcloud-delete    — Delete a file or folder via WebDAV DELETE
 *   nextcloud-download  — Download file content via WebDAV GET (text or base64)
 *   nextcloud-list-users — List users available for sharing via OCS Sharees API (no admin required)
 *
 * SECURITY: Credentials read from /secrets/credentials.json (mounted from /srv/).
 * Credentials never appear in tool output. Generic error messages only.
 *
 * Usage: PORT=8902 SECRETS_DIR=/secrets bun run src/http.ts
 */
import { readFileSync, statSync, realpathSync, writeFileSync, mkdirSync } from "node:fs";
import { resolve, basename, dirname } from "node:path";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { WebStandardStreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/webStandardStreamableHttp.js";
import { z } from "zod";
import {
  escapeXml,
  fmtDate,
  fmtSize,
  isRateLimited as isRateLimitedPure,
  isTextFile,
  normalizePath,
  parseMultistatus,
  RATE_LIMIT,
  RATE_WINDOW_MS,
  resolvePermissions,
  sanitizeOutput,
  sanitizeReceivedFilename,
  validatePath,
} from "./webdav-util.js";

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
  console.error(
    "Failed to load credentials — check /secrets/credentials.json exists and is valid JSON",
  );
  process.exit(1);
}

const WEBDAV_BASE = `${creds.server.replace(/\/+$/, "")}/remote.php/dav/files/${encodeURIComponent(creds.username)}`;
const AUTH_HEADER = `Basic ${btoa(`${creds.username}:${creds.password}`)}`;

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
    ...(body === undefined ? {} : { body }),
    signal: AbortSignal.timeout(30_000),
  });
}

// ── Tool: nextcloud-upload ─────────────────────────────────

const UploadInput = {
  path: z
    .string()
    .min(1)
    .max(500)
    .describe(
      "Destination path on NextCloud including filename (e.g., 'Documents/report.pdf'). Existing files are overwritten.",
    ),
  content: z
    .string()
    .min(1)
    .max(10_000_000)
    .optional()
    .describe(
      "Inline file content — plain text or base64-encoded binary (max ~7.5MB decoded). Mutually exclusive with local_path — provide one or the other.",
    ),
  encoding: z
    .enum(["text", "base64"])
    .default("text")
    .describe(
      "Encoding of the content parameter: 'text' (default) or 'base64'. Only applies when using content, not local_path.",
    ),
  local_path: z
    .string()
    .min(1)
    .max(1000)
    .optional()
    .describe(
      "Absolute path to a file on disk to upload directly (e.g., '/tmp/recording.wav'). Preferred for binary files — no base64 needed. Max 100MB. Mutually exclusive with content.",
    ),
};

const MAX_LOCAL_UPLOAD_SIZE = 100 * 1024 * 1024; // 100MB

// Allowed source directories for local_path uploads.
// Resolved paths must start with one of these prefixes.
// Prevents reading /proc, /secrets, or other sensitive paths.
const ALLOWED_SOURCE_DIRS = (process.env["UPLOAD_ALLOWED_DIRS"] || "/tmp,/data")
  .split(",")
  .map((d) => d.trim())
  .filter((d) => d.length > 0);

if (ALLOWED_SOURCE_DIRS.length === 0) {
  console.error(
    "UPLOAD_ALLOWED_DIRS produced no valid directories — refusing to start. Fix the env var (no empty entries, no trailing commas).",
  );
  process.exit(1);
}

/** Validate a local_path and return the real (symlink-resolved) path, or an error string. */
function validateLocalPath(
  localPath: string,
): { resolved: string; size: number } | { error: string } {
  // Resolve symlinks to their true target — prevents symlink escape from allowed dirs
  let realPath: string;
  try {
    realPath = realpathSync(localPath);
  } catch (e) {
    const msg = e instanceof Error ? e.message : "unknown error";
    return { error: `Cannot resolve path: ${msg}` };
  }

  // Must land in an allowed directory (checked against the REAL path, not the symlink)
  if (
    !ALLOWED_SOURCE_DIRS.some((prefix) => realPath === prefix || realPath.startsWith(`${prefix}/`))
  ) {
    return { error: "local_path is not in an allowed directory." };
  }

  // Must be a regular file (not directory, device, pipe)
  try {
    const stat = statSync(realPath);
    if (!stat.isFile()) return { error: "local_path is not a regular file." };
    if (stat.size > MAX_LOCAL_UPLOAD_SIZE) {
      return {
        error: `File too large (${(stat.size / 1024 / 1024).toFixed(1)}MB). Max: ${MAX_LOCAL_UPLOAD_SIZE / 1024 / 1024}MB.`,
      };
    }
    return { resolved: realPath, size: stat.size };
  } catch (e) {
    const msg = e instanceof Error ? e.message : "unknown error";
    return { error: `Cannot access file: ${msg}` };
  }
}

/** Resolved upload payload, or an error message to return to the caller. */
type UploadSource =
  | { reqBody: BodyInit; contentType: string; fileSizeBytes: number; timeoutMs: number }
  | { error: string };

/** Resolve the request body, content type, size, and timeout from an upload's input source. */
function resolveUploadSource(params: {
  content?: string | undefined;
  encoding: string;
  local_path?: string | undefined;
}): UploadSource {
  if (params.local_path) {
    const result = validateLocalPath(params.local_path);
    if ("error" in result) return { error: result.error };

    const file = Bun.file(result.resolved);
    return {
      reqBody: file,
      fileSizeBytes: result.size,
      contentType: file.type || "application/octet-stream",
      // Scale timeout: base 30s + 1s per MB, capped at 300s
      timeoutMs: Math.min(30_000 + Math.ceil(result.size / (1024 * 1024)) * 1_000, 300_000),
    };
  }

  if (params.content) {
    if (params.encoding === "base64") {
      try {
        const binary = atob(params.content);
        return {
          reqBody: new Blob([Uint8Array.from(binary, (c) => c.charCodeAt(0))]),
          fileSizeBytes: binary.length,
          contentType: "application/octet-stream",
          timeoutMs: 30_000,
        };
      } catch {
        return { error: "Invalid base64 content." };
      }
    }
    return {
      reqBody: params.content,
      fileSizeBytes: new TextEncoder().encode(params.content).length,
      contentType: "text/plain; charset=utf-8",
      timeoutMs: 30_000,
    };
  }

  return { error: "Provide either content (inline data) or local_path (file on disk)." };
}

async function upload(params: {
  path: string;
  content?: string | undefined;
  encoding: string;
  local_path?: string | undefined;
}): Promise<string> {
  const err = validatePath(params.path);
  if (err) return `Error: ${err}`;

  // Reject ambiguous input — exactly one source required
  if (params.local_path && params.content) {
    return "Error: Provide either local_path or content, not both. Use local_path for files on disk, content for inline data.";
  }

  const source = resolveUploadSource(params);
  if ("error" in source) return `Error: ${source.error}`;
  const { reqBody, contentType, fileSizeBytes, timeoutMs } = source;

  const sizeStr =
    fileSizeBytes >= 1e6
      ? `${(fileSizeBytes / 1e6).toFixed(1)}MB`
      : `${(fileSizeBytes / 1e3).toFixed(1)}KB`;

  try {
    const url = `${WEBDAV_BASE}${normalizePath(params.path)}`;
    const res = await fetch(url, {
      method: "PUT",
      headers: { Authorization: AUTH_HEADER, "Content-Type": contentType },
      body: reqBody,
      signal: AbortSignal.timeout(timeoutMs),
    });

    if (res.status === 201) return `Uploaded: ${params.path} (created, ${sizeStr})`;
    if (res.status === 204) return `Uploaded: ${params.path} (overwritten, ${sizeStr})`;
    if (res.status === 409)
      return "Error: Parent directory does not exist. Create it first with nextcloud-mkdir.";
    return `Upload failed (${res.status})`;
  } catch (e) {
    const msg = e instanceof Error ? e.message : "";
    return `Upload failed — NextCloud request error.${msg ? ` (${msg})` : ""}`;
  }
}

// ── Tool: nextcloud-list ───────────────────────────────────

const ListInput = {
  path: z.string().max(500).default("/").describe("Directory path to list (default: root '/')"),
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
  path: z.string().min(1).max(500).describe("Directory path to create (e.g., 'Documents/2026/Q1')"),
};

async function mkdir(params: { path: string }): Promise<string> {
  const err = validatePath(params.path);
  if (err) return `Error: ${err}`;

  try {
    const res = await webdav("MKCOL", params.path);

    if (res.status === 201) {
      // PROPFIND forces NextCloud to register the folder in oc_filecache.
      // Without this, the OCS Share API returns 403 on newly created paths.
      try {
        await webdav("PROPFIND", params.path, { Depth: "0" });
      } catch {}
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
  query: z.string().min(1).max(200).describe("Search term — matches against file names"),
  path: z
    .string()
    .max(500)
    .default("/")
    .describe("Directory scope to search within (default: root)"),
  limit: z.number().int().min(1).max(50).default(20).describe("Maximum results (default: 20)"),
};

async function search(params: { query: string; path: string; limit: number }): Promise<string> {
  const pathErr = validatePath(params.path);
  if (pathErr) return `Error: ${pathErr}`;

  // Sanitize search query for XML inclusion
  const safeQuery = escapeXml(params.query);

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
      entries.length > params.limit ? ` (showing ${params.limit} of ${entries.length})` : "";
    lines.push("", `${limited.length} results${suffix}`);
    return lines.join("\n");
  } catch {
    return "Search failed — NextCloud request error.";
  }
}

// ── OCS API Helpers ───────────────────────────────────────

const OCS_SHARE_BASE = `${creds.server.replace(/\/+$/, "")}/ocs/v2.php/apps/files_sharing/api/v1`;

// OCS responses are untyped JSON from NextCloud. Model them as a recursive
// JSON value so callers can navigate without `any`.
type OcsJson =
  | string
  | number
  | boolean
  | null
  | undefined
  | OcsJson[]
  | { [key: string]: OcsJson };

/** Read a property from an OCS JSON value, returning undefined for non-objects. */
function ocsProp(value: OcsJson, key: string): OcsJson {
  if (value !== null && typeof value === "object" && !Array.isArray(value)) {
    return value[key];
  }
  return undefined;
}

type Sharee = { label: string; value: { shareWith: string } };

/** Coerce an OCS JSON value into the sharee list shape, skipping malformed entries. */
function toSharees(value: OcsJson): Sharee[] {
  if (!Array.isArray(value)) return [];
  const result: Sharee[] = [];
  for (const entry of value) {
    const shareWith = ocsProp(ocsProp(entry, "value"), "shareWith");
    const label = ocsProp(entry, "label");
    if (typeof shareWith === "string") {
      result.push({
        label: typeof label === "string" ? label : "",
        value: { shareWith },
      });
    }
  }
  return result;
}

async function ocsGet(
  baseUrl: string,
  endpoint: string,
  params: Record<string, string> = {},
): Promise<{ status: number; data: OcsJson; meta: OcsJson }> {
  const qs = new URLSearchParams(params);
  const sep = endpoint.includes("?") ? "&" : "?";
  const url = `${baseUrl}${endpoint}${qs.toString() ? sep + qs.toString() : ""}`;
  const res = await fetch(url, {
    method: "GET",
    headers: {
      Authorization: AUTH_HEADER,
      "OCS-APIRequest": "true",
      Accept: "application/json",
    },
    signal: AbortSignal.timeout(15_000),
  });
  const json = (await res.json()) as OcsJson;
  const ocs = ocsProp(json, "ocs");
  return {
    status: res.status,
    data: ocsProp(ocs, "data") ?? json,
    meta: ocsProp(ocs, "meta") ?? {},
  };
}

const OCS_BASE = OCS_SHARE_BASE;

async function ocsPost(
  endpoint: string,
  body: Record<string, string | number>,
): Promise<{ status: number; data: OcsJson }> {
  const res = await fetch(`${OCS_BASE}${endpoint}`, {
    method: "POST",
    headers: {
      Authorization: AUTH_HEADER,
      "OCS-APIRequest": "true",
      "Content-Type": "application/x-www-form-urlencoded",
      Accept: "application/json",
    },
    body: new URLSearchParams(Object.entries(body).map(([k, v]) => [k, String(v)])),
    signal: AbortSignal.timeout(15_000),
  });
  const json = (await res.json()) as OcsJson;
  return { status: res.status, data: ocsProp(ocsProp(json, "ocs"), "data") ?? json };
}

// ── Tool: nextcloud-list-users (via Sharees API — no admin required) ──

const ListUsersInput = {
  search: z
    .string()
    .max(100)
    .default("")
    .describe("Search term to filter users by username or display name (empty = all)"),
  limit: z
    .number()
    .int()
    .min(1)
    .max(100)
    .default(50)
    .describe("Maximum users to return (default: 50)"),
};

async function listUsers(params: { search: string; limit: number }): Promise<string> {
  try {
    const qp: Record<string, string> = {
      search: params.search,
      itemType: "file",
      perPage: String(params.limit),
    };

    const { status, data } = await ocsGet(OCS_SHARE_BASE, "/sharees", qp);

    if (status !== 200) {
      return `List users failed (HTTP ${status})`;
    }

    const exactUsers = ocsProp(ocsProp(data, "exact"), "users");
    const directUsers = ocsProp(data, "users");
    const users = toSharees(directUsers ?? exactUsers);
    const exact = toSharees(exactUsers);
    const all = [...exact, ...users];

    // Deduplicate by shareWith
    const seen = new Set<string>();
    const unique = all.filter((u) => {
      const id = u.value.shareWith;
      if (!id || seen.has(id)) return false;
      seen.add(id);
      return true;
    });

    if (unique.length === 0) return "No users found.";

    const lines = unique.map((u) => {
      const id = sanitizeOutput(u.value.shareWith);
      const name = sanitizeOutput(u.label);
      return id === name ? `- ${id}` : `- ${id} (${name})`;
    });

    return `## Users (${unique.length})\n${lines.join("\n")}`;
  } catch {
    return "List users failed — NextCloud request error.";
  }
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
    .describe(
      "Permission level: 'read' (view only), 'read-write' (edit), 'all' (edit + reshare + delete)",
    ),
};

async function share(params: {
  path: string;
  shareWith: string;
  permissions: string;
}): Promise<string> {
  const err = validatePath(params.path);
  if (err) return `Error: ${err}`;

  const permInt = resolvePermissions(params.permissions);

  try {
    const { status, data } = await ocsPost("/shares", {
      path: normalizePath(params.path),
      shareType: 0, // 0 = user share
      shareWith: params.shareWith,
      permissions: permInt,
    });

    if (status === 200) {
      const id = ocsProp(data, "id");
      const shareId = id === undefined || id === null ? "unknown" : id;
      return `Shared "${params.path}" with ${params.shareWith} (${params.permissions}). Share ID: ${shareId}`;
    }
    if (status === 404) return `Error: Path not found — "${params.path}"`;
    if (status === 403) return `Error: Insufficient permissions to share this path.`;

    const directMsg = ocsProp(data, "message");
    const metaMsg = ocsProp(ocsProp(data, "meta"), "message");
    const msg = typeof directMsg === "string" && directMsg ? directMsg : metaMsg;
    if (typeof msg === "string" && msg) return `Share failed (${status}): ${sanitizeOutput(msg)}`;
    return `Share failed (${status})`;
  } catch {
    return "Share failed — NextCloud request error.";
  }
}

// ── Tool: nextcloud-move ──────────────────────────────────

const MoveInput = {
  from: z.string().min(1).max(500).describe("Source path (e.g., 'Shared/old-name.pdf')"),
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
    if (res.status === 204) return `Moved: "${params.from}" → "${params.to}"`;
    if (res.status === 404) return `Error: Source not found — "${params.from}"`;
    if (res.status === 409) return `Error: Destination parent directory does not exist.`;
    if (res.status === 412)
      return `Error: Destination already exists. Use a different name or delete it first.`;
    return `Move failed (${res.status})`;
  } catch {
    return "Move failed — NextCloud request error.";
  }
}

// ── Tool: nextcloud-copy ──────────────────────────────────

const CopyInput = {
  from: z.string().min(1).max(500).describe("Source path (e.g., 'Shared/document.pdf')"),
  to: z.string().min(1).max(500).describe("Destination path (e.g., 'Shared/Archive/document.pdf')"),
};

async function copy(params: { from: string; to: string }): Promise<string> {
  const fromErr = validatePath(params.from);
  if (fromErr) return `Error (from): ${fromErr}`;
  const toErr = validatePath(params.to);
  if (toErr) return `Error (to): ${toErr}`;

  const destUrl = `${WEBDAV_BASE}${normalizePath(params.to)}`;

  try {
    const res = await webdav("COPY", params.from, {
      Destination: destUrl,
      Overwrite: "F", // Don't overwrite existing files
    });

    if (res.status === 201) return `Copied: "${params.from}" → "${params.to}"`;
    if (res.status === 204) return `Copied: "${params.from}" → "${params.to}" (overwrote existing)`;
    if (res.status === 404) return `Error: Source not found — "${params.from}"`;
    if (res.status === 409) return `Error: Destination parent directory does not exist.`;
    if (res.status === 412)
      return `Error: Destination already exists. Use a different name or delete it first.`;
    return `Copy failed (${res.status})`;
  } catch {
    return "Copy failed — NextCloud request error.";
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

const DOWNLOAD_ALLOWED_DIRS = (process.env["DOWNLOAD_ALLOWED_DIRS"] || "/tmp,/data")
  .split(",")
  .map((d) => d.trim())
  .filter((d) => d.length > 0);

/** Validate a save_path for downloads — parent dir must exist and be in allowed dirs. */
function validateSavePath(savePath: string): { resolved: string } | { error: string } {
  const absPath = resolve(savePath);
  const dir = dirname(absPath);
  let realDir: string;
  try {
    realDir = realpathSync(dir);
  } catch {
    return { error: `Parent directory does not exist: ${dir}` };
  }

  const filename = basename(absPath);
  if (!filename || filename === "." || filename === "..") {
    return { error: "save_path must include a filename" };
  }

  const resolvedPath = resolve(realDir, filename);

  if (
    !DOWNLOAD_ALLOWED_DIRS.some(
      (prefix) => resolvedPath === prefix || resolvedPath.startsWith(`${prefix}/`),
    )
  ) {
    return { error: "save_path is not in an allowed directory." };
  }

  return { resolved: resolvedPath };
}

const DownloadInput = {
  path: z
    .string()
    .min(1)
    .max(500)
    .describe("Path to the file to download (e.g., 'Shared/Accounting/Invoices/2026/invoice.pdf')"),
  save_path: z
    .string()
    .min(1)
    .max(1000)
    .optional()
    .describe(
      "Save downloaded file to this local path instead of returning content. Must be in an allowed directory (/tmp or /data). Example: '/data/upload/icon.png'",
    ),
};

const MAX_DOWNLOAD_SIZE = 25 * 1024 * 1024; // 25MB

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
    throw new Error(
      `File too large (${(contentLength / 1024 / 1024).toFixed(1)}MB). Max: ${MAX_DOWNLOAD_SIZE / 1024 / 1024}MB.`,
    );
  }

  const mimeType = res.headers.get("content-type") || "application/octet-stream";
  const isText = isTextFile(params.path, mimeType);

  const buffer = await res.arrayBuffer();

  if (buffer.byteLength > MAX_DOWNLOAD_SIZE) {
    throw new Error(
      `File too large (${(buffer.byteLength / 1024 / 1024).toFixed(1)}MB). Max: ${MAX_DOWNLOAD_SIZE / 1024 / 1024}MB.`,
    );
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
  return {
    type: "base64",
    content: Buffer.from(buffer).toString("base64"),
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
    "Upload a file to NextCloud. Two modes: (1) pass content for inline text or base64 data, (2) pass local_path for files already on disk (preferred for binary files — no encoding needed, up to 100MB). Provide exactly one of content or local_path.",
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
    "nextcloud-list-users",
    "List NextCloud users available for file sharing. Returns usernames and display names. Uses the Sharees API (no admin required).",
    ListUsersInput,
    async (params) => ({
      content: [{ type: "text" as const, text: await listUsers(params) }],
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
    "nextcloud-copy",
    "Copy a file or folder on NextCloud server-side via WebDAV COPY. No data transfer through the MCP — works for any file size.",
    CopyInput,
    async (params) => ({
      content: [{ type: "text" as const, text: await copy(params) }],
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
    "Download a file from NextCloud. Returns text content for text files, base64 for binary files (PDF, images, etc.). Max 25MB. Use save_path to save directly to disk instead of returning content.",
    DownloadInput,
    async (params) => {
      try {
        // Save to disk mode
        if (params.save_path) {
          const validation = validateSavePath(params.save_path);
          if ("error" in validation) {
            return { content: [{ type: "text" as const, text: `Error: ${validation.error}` }] };
          }

          const result = await download(params);
          const buffer =
            result.type === "text"
              ? Buffer.from(result.content)
              : Buffer.from(result.content, "base64");

          writeFileSync(validation.resolved, buffer);
          return {
            content: [
              {
                type: "text" as const,
                text: `Downloaded: ${params.path} → ${validation.resolved} (${fmtSize(buffer.byteLength)})`,
              },
            ],
          };
        }

        // Return content mode (default)
        const result = await download(params);
        if (result.type === "text") {
          return {
            content: [{ type: "text" as const, text: result.content }],
          };
        }
        // Binary — return as embedded resource with base64
        return {
          content: [
            {
              type: "resource" as const,
              resource: {
                uri: `nextcloud://${encodeURI(normalizePath(params.path))}`,
                mimeType: result.mimeType,
                blob: result.content,
              },
            },
          ],
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

const requestTimestamps: number[] = [];

function isRateLimited(): boolean {
  return isRateLimitedPure(requestTimestamps, Date.now(), RATE_LIMIT, RATE_WINDOW_MS);
}

// ── HTTP Server (stateless mode) ───────────────────────────

const JSON_HEADERS = { "Content-Type": "application/json" } as const;

/** Build a JSON Response with the standard content-type header. */
function jsonResponse(payload: unknown, status: number): Response {
  return new Response(JSON.stringify(payload), { status, headers: JSON_HEADERS });
}

async function handleHealth(): Promise<Response> {
  try {
    const check = await webdav("PROPFIND", "/", { Depth: "0" });
    const ok = check.status === 207 || check.ok;
    return jsonResponse(
      { status: ok ? "ok" : "degraded", service: "mcp-nextcloud", nextcloud: ok },
      ok ? 200 : 503,
    );
  } catch {
    return jsonResponse({ status: "degraded", service: "mcp-nextcloud", nextcloud: false }, 503);
  }
}

async function handleReceive(req: Request, url: URL): Promise<Response> {
  try {
    const filename = url.searchParams.get("filename");
    if (!filename) return jsonResponse({ error: "Missing ?filename= parameter" }, 400);

    // Sanitize filename — strip path components, allow only safe characters
    const clean = sanitizeReceivedFilename(filename);
    if (!clean) return jsonResponse({ error: "Invalid filename" }, 400);

    const body = await req.arrayBuffer();
    if (body.byteLength === 0) return jsonResponse({ error: "Empty body" }, 400);
    if (body.byteLength > 50 * 1024 * 1024) {
      return jsonResponse({ error: "File too large (max 50MB)" }, 413);
    }

    const uploadDir = "/data/upload";
    mkdirSync(uploadDir, { recursive: true });
    const dest = resolve(uploadDir, clean);

    // Final path traversal check
    if (!dest.startsWith(`${uploadDir}/`)) {
      return jsonResponse({ error: "Path traversal rejected" }, 400);
    }

    writeFileSync(dest, Buffer.from(body));
    const sizeMB = (body.byteLength / 1_048_576).toFixed(2);
    console.log(`[receive] Staged file: ${clean} (${sizeMB} MB)`);

    return jsonResponse(
      { staged: clean, size_bytes: body.byteLength, local_path: `/data/upload/${clean}` },
      200,
    );
  } catch (e) {
    const msg = e instanceof Error ? e.message : "unknown error";
    console.error(`[receive] Error: ${msg}`);
    return jsonResponse({ error: "Internal error" }, 500);
  }
}

async function handleMcp(req: Request): Promise<Response> {
  if (isRateLimited()) {
    return new Response("Rate limit exceeded", { status: 429 });
  }
  const server = createServer();
  // Stateless mode: omitting sessionIdGenerator disables session management
  // (a fresh transport is created per request).
  const transport = new WebStandardStreamableHTTPServerTransport({});
  await server.connect(transport);
  return transport.handleRequest(req);
}

// Per the MCP SDK stateless pattern, a new server instance is created per
// request so that .connect() is only called once per McpServer lifetime.
const httpServer = Bun.serve({
  port: PORT,
  hostname: "0.0.0.0",
  async fetch(req: Request): Promise<Response> {
    const url = new URL(req.url);

    if (url.pathname === "/health") return handleHealth();
    if (url.pathname === "/receive" && req.method === "POST") return handleReceive(req, url);
    if (url.pathname === "/mcp") return handleMcp(req);

    return new Response("Not Found", { status: 404 });
  },
});

console.log(`mcp-nextcloud listening on http://0.0.0.0:${PORT}/mcp`);
console.log("Tools: 11 | NextCloud: connected");

process.on("SIGTERM", () => {
  httpServer.stop();
  process.exit(0);
});

process.on("SIGINT", () => {
  httpServer.stop();
  process.exit(0);
});
