/**
 * Pure, deterministic helpers for the NextCloud MCP server.
 *
 * Extracted from http.ts so the path validation, WebDAV XML parsing,
 * output sanitization, formatting, permission mapping, rate-limiting and
 * download-type logic can be unit tested without booting the HTTP server
 * or loading credentials. No I/O, no side effects, no top-level execution.
 */

// ── Path Validation ────────────────────────────────────────

/** Returns an error message string if the path is unsafe, or null if it is OK. */
export function validatePath(p: string): string | null {
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
  // biome-ignore lint/suspicious/noControlCharactersInRegex: matching control chars IS the security intent here
  if (/[\x00-\x1f]/.test(decoded)) return "Control characters not allowed";
  if (p.includes("%00") || p.includes("\x00")) return "Null bytes not allowed";
  if (/[?]/.test(p)) return "Path contains invalid characters";
  return null;
}

/** Collapse slashes and percent-encode each path segment, always leading with "/". */
export function normalizePath(p: string): string {
  return `/${p
    .replace(/^\/+/, "")
    .replace(/\/+/g, "/")
    .split("/")
    .map((s) => encodeURIComponent(s))
    .join("/")}`;
}

// ── XML Parsing Helpers ────────────────────────────────────

/** Extract the inner text of the first matching (namespace-agnostic) XML tag. */
function extractTag(xml: string, tag: string): string {
  const re = new RegExp(`<(?:[a-z]+:)?${tag}[^>]*>([\\s\\S]*?)<\\/(?:[a-z]+:)?${tag}>`, "i");
  const m = xml.match(re);
  return m?.[1] ? m[1].trim() : "";
}

/** Detect a WebDAV <collection/> marker (directory) in a response block. */
function isCollection(xml: string): boolean {
  return /<(?:[a-z]+:)?collection\s*\/?>/.test(xml);
}

export interface DavEntry {
  href: string;
  name: string;
  isDir: boolean;
  size: number;
  modified: string;
  contentType: string;
}

/** Parse a WebDAV multistatus XML body into DavEntry records, skipping the self-entry. */
export function parseMultistatus(xml: string, basePath: string): DavEntry[] {
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
      size: sizeStr ? Number.parseInt(sizeStr, 10) : 0,
      modified,
      contentType: dir ? "directory" : contentType,
    });
  }

  return entries;
}

// ── Output Sanitization ───────────────────────────────────

/** Escape characters that break markdown tables while preserving filenames intact.
 *  Only pipe (|) and newlines break table structure — escape pipes, strip control chars.
 *  All other characters (underscores, brackets, etc.) are preserved so clients can
 *  use displayed names for subsequent operations (download, move, delete). */
export function sanitizeOutput(s: string): string {
  return (
    s
      // biome-ignore lint/suspicious/noControlCharactersInRegex: stripping control chars IS the sanitization intent
      .replace(/[\x00-\x1f\r\n]/g, "")
      .replace(/\|/g, "\\|")
      .slice(0, 255)
  );
}

/** Escape a user-supplied search term for safe inclusion in a WebDAV REPORT XML body. */
export function escapeXml(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&apos;");
}

/** Sanitize an uploaded filename for the /receive endpoint — strip path components,
 *  keep only [A-Za-z0-9._-]. Returns "" for names that resolve to nothing safe. */
export function sanitizeReceivedFilename(filename: string): string {
  const base = filename.split(/[/\\]/).pop() ?? "";
  const clean = base.replace(/[^a-zA-Z0-9._-]/g, "_");
  if (!clean || clean === "." || clean === "..") return "";
  return clean;
}

// ── Formatting ─────────────────────────────────────────────

/** Human-readable byte size. 0 → "-"; otherwise B / KB / MB / GB at SI (1e3) steps. */
export function fmtSize(bytes: number): string {
  if (bytes === 0) return "-";
  if (bytes >= 1e9) return `${(bytes / 1e9).toFixed(1)} GB`;
  if (bytes >= 1e6) return `${(bytes / 1e6).toFixed(1)} MB`;
  if (bytes >= 1e3) return `${(bytes / 1e3).toFixed(1)} KB`;
  return `${bytes} B`;
}

/** Format an HTTP/WebDAV date string as "YYYY-MM-DD HH:MM"; "-" for empty; echo on parse error. */
export function fmtDate(dateStr: string): string {
  if (!dateStr) return "-";
  try {
    return new Date(dateStr).toISOString().slice(0, 16).replace("T", " ");
  } catch {
    return dateStr;
  }
}

// ── Sharing permissions ────────────────────────────────────

// Map permission strings to NextCloud OCS permission integers.
// 1=read, 2=update, 4=create, 8=delete, 16=reshare
export const PERMISSION_MAP: Record<string, number> = {
  read: 1,
  "read-write": 1 + 2 + 4, // read + update + create
  all: 1 + 2 + 4 + 8 + 16, // read + update + create + delete + reshare
};

/** Resolve a permission keyword to its OCS integer; defaults to 7 (read-write) for unknown. */
export function resolvePermissions(permission: string): number {
  return PERMISSION_MAP[permission] ?? 7;
}

// ── Download type detection ────────────────────────────────

const TEXT_EXTENSIONS = new Set([
  "txt",
  "md",
  "csv",
  "json",
  "xml",
  "html",
  "htm",
  "yaml",
  "yml",
  "toml",
  "ini",
  "cfg",
  "conf",
  "log",
  "sh",
  "bash",
  "ts",
  "js",
  "py",
  "rb",
  "go",
  "rs",
  "java",
  "c",
  "h",
  "cpp",
  "css",
  "sql",
]);

/** Decide whether a downloaded file should be treated as text (vs base64 binary). */
export function isTextFile(path: string, mimeType: string): boolean {
  const ext = path.split(".").pop()?.toLowerCase() || "";
  return TEXT_EXTENSIONS.has(ext) || mimeType.startsWith("text/");
}

// ── Rate Limiter ──────────────────────────────────────────

export const RATE_LIMIT = 30;
export const RATE_WINDOW_MS = 60_000;

/** Sliding-window rate-limit check.
 *
 * Mutates `timestamps` in place: prunes entries older than the window, and on
 * an allowed request appends `now`. Returns true when the request should be
 * rejected (limit reached). `now`/`limit`/`windowMs` are injectable for tests. */
export function isRateLimited(
  timestamps: number[],
  now: number,
  limit: number = RATE_LIMIT,
  windowMs: number = RATE_WINDOW_MS,
): boolean {
  while (timestamps.length > 0 && (timestamps[0] as number) < now - windowMs) {
    timestamps.shift();
  }
  if (timestamps.length >= limit) return true;
  timestamps.push(now);
  return false;
}
