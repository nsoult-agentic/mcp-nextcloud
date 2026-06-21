import { describe, expect, test } from "bun:test";

import {
  escapeXml,
  fmtDate,
  fmtSize,
  isRateLimited,
  isTextFile,
  normalizePath,
  parseMultistatus,
  PERMISSION_MAP,
  RATE_LIMIT,
  RATE_WINDOW_MS,
  resolvePermissions,
  sanitizeOutput,
  sanitizeReceivedFilename,
  validatePath,
} from "../src/webdav-util.js";

// Expected values below are derived by hand from the code's own rules and
// constants — not by mirroring whatever the implementation returns — so a
// logic regression is actually caught.

// ── validatePath ───────────────────────────────────────────

describe("validatePath", () => {
  test("accepts a normal path (null = OK)", () => {
    expect(validatePath("Documents/report.pdf")).toBeNull();
    expect(validatePath("/")).toBeNull();
  });

  test("rejects paths longer than 500 chars (boundary)", () => {
    expect(validatePath("a".repeat(500))).toBeNull(); // exactly 500 OK
    expect(validatePath("a".repeat(501))).toBe("Path too long (max 500 chars)");
  });

  test("rejects literal traversal", () => {
    expect(validatePath("../etc/passwd")).toBe("Path traversal (..) not allowed");
  });

  test("rejects URL-encoded traversal (%2e%2e decodes to ..)", () => {
    expect(validatePath("%2e%2e/secrets")).toBe("Path traversal (..) not allowed");
  });

  test("rejects malformed percent-encoding", () => {
    // A lone % is not valid encoding → decodeURIComponent throws.
    expect(validatePath("%zz")).toBe("Invalid path encoding");
  });

  test("rejects backslashes", () => {
    expect(validatePath("foo\\bar")).toBe("Backslashes not allowed");
  });

  test("rejects control characters", () => {
    expect(validatePath("foo\x01bar")).toBe("Control characters not allowed");
  });

  test("rejects encoded null byte before decode", () => {
    // %00 decodes to \x00 which is also a control char; the %00 raw check
    // catches it. Either way it must be rejected.
    expect(validatePath("foo%00bar")).not.toBeNull();
  });

  test("rejects question marks", () => {
    expect(validatePath("foo?bar")).toBe("Path contains invalid characters");
  });
});

// ── normalizePath ──────────────────────────────────────────

describe("normalizePath", () => {
  test("always leads with a single slash", () => {
    expect(normalizePath("foo")).toBe("/foo");
    expect(normalizePath("/foo")).toBe("/foo");
    expect(normalizePath("///foo")).toBe("/foo");
  });

  test("collapses duplicate inner slashes", () => {
    expect(normalizePath("a//b///c")).toBe("/a/b/c");
  });

  test("percent-encodes each segment but not the separators", () => {
    expect(normalizePath("My Docs/a b.txt")).toBe("/My%20Docs/a%20b.txt");
  });

  test("encodes special chars within a segment", () => {
    expect(normalizePath("a&b")).toBe("/a%26b");
  });
});

// ── escapeXml ──────────────────────────────────────────────

describe("escapeXml", () => {
  test("escapes the five XML entities", () => {
    expect(escapeXml(`<a href="x" foo='y'>&`)).toBe(
      "&lt;a href=&quot;x&quot; foo=&apos;y&apos;&gt;&amp;",
    );
  });

  test("escapes ampersand first so entities are not double-escaped", () => {
    // "&lt;" as input must become "&amp;lt;", not "&lt;".
    expect(escapeXml("&lt;")).toBe("&amp;lt;");
  });

  test("leaves plain text untouched", () => {
    expect(escapeXml("invoice 2026")).toBe("invoice 2026");
  });
});

// ── sanitizeOutput ─────────────────────────────────────────

describe("sanitizeOutput", () => {
  test("escapes pipes so markdown tables do not break", () => {
    expect(sanitizeOutput("a|b")).toBe("a\\|b");
  });

  test("strips control chars and newlines", () => {
    expect(sanitizeOutput("a\nb\r\tc\x00d")).toBe("abcd");
  });

  test("preserves underscores, brackets and unicode", () => {
    expect(sanitizeOutput("my_file [v2] café")).toBe("my_file [v2] café");
  });

  test("truncates to 255 chars", () => {
    expect(sanitizeOutput("x".repeat(300))).toHaveLength(255);
  });
});

// ── sanitizeReceivedFilename ───────────────────────────────

describe("sanitizeReceivedFilename", () => {
  test("strips directory components", () => {
    expect(sanitizeReceivedFilename("/etc/passwd")).toBe("passwd");
    expect(sanitizeReceivedFilename("a/b/c.txt")).toBe("c.txt");
    expect(sanitizeReceivedFilename("a\\b\\c.txt")).toBe("c.txt");
  });

  test("replaces unsafe characters with underscore", () => {
    expect(sanitizeReceivedFilename("my file!.txt")).toBe("my_file_.txt");
  });

  test("keeps dots, dashes and underscores", () => {
    expect(sanitizeReceivedFilename("a.b-c_d.txt")).toBe("a.b-c_d.txt");
  });

  test("rejects names that resolve to nothing safe", () => {
    expect(sanitizeReceivedFilename("..")).toBe("");
    expect(sanitizeReceivedFilename(".")).toBe("");
    expect(sanitizeReceivedFilename("/")).toBe("");
  });
});

// ── fmtSize ────────────────────────────────────────────────

describe("fmtSize", () => {
  test("zero renders as a dash", () => {
    expect(fmtSize(0)).toBe("-");
  });

  test("bytes below 1e3", () => {
    expect(fmtSize(1)).toBe("1 B");
    expect(fmtSize(999)).toBe("999 B");
  });

  test("KB / MB / GB boundaries use SI 1e3 steps", () => {
    expect(fmtSize(1_000)).toBe("1.0 KB");
    expect(fmtSize(1_500)).toBe("1.5 KB");
    expect(fmtSize(1_000_000)).toBe("1.0 MB");
    expect(fmtSize(2_500_000)).toBe("2.5 MB");
    expect(fmtSize(1_000_000_000)).toBe("1.0 GB");
  });
});

// ── fmtDate ────────────────────────────────────────────────

describe("fmtDate", () => {
  test("empty string renders as a dash", () => {
    expect(fmtDate("")).toBe("-");
  });

  test("formats an HTTP date as 'YYYY-MM-DD HH:MM' in UTC", () => {
    // Wed, 21 Oct 2015 07:28:00 GMT → 2015-10-21 07:28
    expect(fmtDate("Wed, 21 Oct 2015 07:28:00 GMT")).toBe("2015-10-21 07:28");
  });

  test("formats an ISO date", () => {
    expect(fmtDate("2026-06-21T15:04:05.000Z")).toBe("2026-06-21 15:04");
  });

  test("an unparseable date echoes the input (no throw)", () => {
    expect(fmtDate("not-a-date")).toBe("not-a-date");
  });
});

// ── resolvePermissions / PERMISSION_MAP ────────────────────

describe("resolvePermissions", () => {
  test("read = 1", () => {
    expect(resolvePermissions("read")).toBe(1);
  });

  test("read-write = read+update+create = 7", () => {
    expect(resolvePermissions("read-write")).toBe(7);
  });

  test("all = read+update+create+delete+reshare = 31", () => {
    expect(resolvePermissions("all")).toBe(31);
  });

  test("unknown keyword defaults to 7", () => {
    expect(resolvePermissions("bogus")).toBe(7);
  });

  test("PERMISSION_MAP integers match the OCS bit semantics", () => {
    expect(PERMISSION_MAP.read).toBe(1);
    expect(PERMISSION_MAP["read-write"]).toBe(1 + 2 + 4);
    expect(PERMISSION_MAP.all).toBe(1 + 2 + 4 + 8 + 16);
  });
});

// ── isTextFile ─────────────────────────────────────────────

describe("isTextFile", () => {
  test("known text extension → text regardless of mime", () => {
    expect(isTextFile("notes.md", "application/octet-stream")).toBe(true);
    expect(isTextFile("data.csv", "application/octet-stream")).toBe(true);
  });

  test("text/* mime → text even for unknown extension", () => {
    expect(isTextFile("file.bin", "text/plain")).toBe(true);
  });

  test("binary extension + binary mime → not text", () => {
    expect(isTextFile("photo.png", "image/png")).toBe(false);
    expect(isTextFile("doc.pdf", "application/pdf")).toBe(false);
  });

  test("extension matching is case-insensitive", () => {
    expect(isTextFile("README.MD", "application/octet-stream")).toBe(true);
  });

  test("no extension + binary mime → not text", () => {
    expect(isTextFile("LICENSE", "application/octet-stream")).toBe(false);
  });
});

// ── parseMultistatus ───────────────────────────────────────

const SAMPLE_XML = `<?xml version="1.0"?>
<d:multistatus xmlns:d="DAV:">
  <d:response>
    <d:href>/remote.php/dav/files/alice/Docs/</d:href>
    <d:propstat><d:prop>
      <d:getlastmodified>Wed, 21 Oct 2015 07:28:00 GMT</d:getlastmodified>
      <d:resourcetype><d:collection/></d:resourcetype>
    </d:prop></d:propstat>
  </d:response>
  <d:response>
    <d:href>/remote.php/dav/files/alice/Docs/sub/</d:href>
    <d:propstat><d:prop>
      <d:resourcetype><d:collection/></d:resourcetype>
    </d:prop></d:propstat>
  </d:response>
  <d:response>
    <d:href>/remote.php/dav/files/alice/Docs/report.pdf</d:href>
    <d:propstat><d:prop>
      <d:getcontentlength>2048</d:getcontentlength>
      <d:getcontenttype>application/pdf</d:getcontenttype>
      <d:resourcetype/>
    </d:prop></d:propstat>
  </d:response>
</d:multistatus>`;

describe("parseMultistatus", () => {
  test("skips the self-entry matching basePath", () => {
    const entries = parseMultistatus(SAMPLE_XML, "/remote.php/dav/files/alice/Docs");
    // Docs/ itself is dropped, leaving sub/ and report.pdf.
    expect(entries.map((e) => e.name)).toEqual(["sub", "report.pdf"]);
  });

  test("with empty basePath nothing is skipped as self", () => {
    const entries = parseMultistatus(SAMPLE_XML, "");
    expect(entries).toHaveLength(3);
  });

  test("classifies collections vs files and parses size", () => {
    const entries = parseMultistatus(SAMPLE_XML, "");
    const sub = entries.find((e) => e.name === "sub");
    const report = entries.find((e) => e.name === "report.pdf");
    expect(sub?.isDir).toBe(true);
    expect(sub?.contentType).toBe("directory"); // overridden for dirs
    expect(report?.isDir).toBe(false);
    expect(report?.size).toBe(2048);
    expect(report?.contentType).toBe("application/pdf");
  });

  test("missing content length defaults size to 0", () => {
    const entries = parseMultistatus(SAMPLE_XML, "");
    const sub = entries.find((e) => e.name === "sub");
    expect(sub?.size).toBe(0);
  });

  test("decodes percent-encoded hrefs to readable names", () => {
    const xml = `<d:multistatus xmlns:d="DAV:"><d:response>
      <d:href>/remote.php/dav/files/alice/My%20File.txt</d:href>
      <d:propstat><d:prop><d:getcontentlength>5</d:getcontentlength></d:prop></d:propstat>
    </d:response></d:multistatus>`;
    const entries = parseMultistatus(xml, "");
    expect(entries[0]?.name).toBe("My File.txt");
  });

  test("empty multistatus yields no entries", () => {
    expect(parseMultistatus("<d:multistatus></d:multistatus>", "")).toEqual([]);
  });
});

// ── isRateLimited (sliding window) ─────────────────────────

describe("isRateLimited", () => {
  test("allows up to the limit then blocks", () => {
    const ts: number[] = [];
    // limit=3, window=1000ms, fixed clock at t=1000.
    expect(isRateLimited(ts, 1000, 3, 1000)).toBe(false); // 1st
    expect(isRateLimited(ts, 1000, 3, 1000)).toBe(false); // 2nd
    expect(isRateLimited(ts, 1000, 3, 1000)).toBe(false); // 3rd
    expect(isRateLimited(ts, 1000, 3, 1000)).toBe(true); // 4th blocked
    expect(ts).toHaveLength(3); // blocked request not recorded
  });

  test("entries older than the window are pruned, freeing capacity", () => {
    const ts = [0, 0, 0]; // three hits at t=0
    // At t=1001 with window=1000, all three are older than now-window (1) → pruned.
    expect(isRateLimited(ts, 1001, 3, 1000)).toBe(false);
    expect(ts).toEqual([1001]);
  });

  test("the prune boundary is strict (< now - window)", () => {
    // entry at exactly now-window is NOT pruned (uses < not <=).
    const ts = [1]; // now-window = 1001-1000 = 1; 1 < 1 is false → kept
    expect(isRateLimited(ts, 1001, 1, 1000)).toBe(true); // at capacity, blocked
    expect(ts).toEqual([1]);
  });

  test("default constants are the documented values", () => {
    expect(RATE_LIMIT).toBe(30);
    expect(RATE_WINDOW_MS).toBe(60_000);
  });
});
