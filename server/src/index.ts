import express, { Request, Response, NextFunction } from "express";
import helmet from "helmet";
import cors from "cors";
import rateLimit from "express-rate-limit";
import { createClient } from "@supabase/supabase-js";
import { lookup } from "dns/promises";
import { createHash, timingSafeEqual } from "crypto";

/* ---------------------------------------------------------------- config */

const PORT = Number(process.env.PORT || 3001);
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;
const CRON_SECRET = process.env.CRON_SECRET;
const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN;
const STORAGE_BUCKET = "e2ee-files";
const LINK_FETCH_TIMEOUT_MS = 3000;

if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY || !CRON_SECRET) {
  console.error(
    "Missing required env vars: SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, CRON_SECRET",
  );
  process.exit(1);
}

const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, {
  auth: { persistSession: false },
});

/* ---------------------------------------------------------------- app */

const app = express();

app.set("trust proxy", 1);
app.use(helmet());
app.use(
  cors({
    origin: ALLOWED_ORIGIN ? ALLOWED_ORIGIN.split(",").map((o) => o.trim()) : true,
    credentials: true,
  }),
);
app.use(express.json({ limit: "1mb" }));

const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 200,
  standardHeaders: true,
  legacyHeaders: false,
});
const strictLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
});
app.use(globalLimiter);

/* ---------------------------------------------------------------- utils */

function validateCronSecret(authHeader: string | undefined): boolean {
  const expected = `Bearer ${CRON_SECRET}`;
  const a = Buffer.from(authHeader ?? "", "utf8");
  const b = Buffer.from(expected, "utf8");
  if (a.length !== b.length) return false;
  return timingSafeEqual(a, b);
}

/* ---------------- SSRF protection: block private/internal IP ranges ---------------- */

interface DnsAddress {
  address: string;
  family: number;
}

// IPv4 private / reserved ranges that must never be fetched.
const IPV4_PRIVATE_RANGES: Array<{ net: number; maskBits: number }> = [
  { net: ipv4ToNumber("0.0.0.0")!, maskBits: mask(8) },
  { net: ipv4ToNumber("10.0.0.0")!, maskBits: mask(8) },
  { net: ipv4ToNumber("100.64.0.0")!, maskBits: mask(10) }, // carrier-grade NAT
  { net: ipv4ToNumber("127.0.0.0")!, maskBits: mask(8) }, // loopback
  { net: ipv4ToNumber("169.254.0.0")!, maskBits: mask(16) }, // link-local
  { net: ipv4ToNumber("172.16.0.0")!, maskBits: mask(12) },
  { net: ipv4ToNumber("192.0.0.0")!, maskBits: mask(24) }, // IETF protocol assignments
  { net: ipv4ToNumber("192.0.2.0")!, maskBits: mask(24) }, // documentation / TEST-NET-1
  { net: ipv4ToNumber("192.168.0.0")!, maskBits: mask(16) },
  { net: ipv4ToNumber("198.18.0.0")!, maskBits: mask(15) }, // benchmarking
  { net: ipv4ToNumber("224.0.0.0")!, maskBits: mask(4) }, // multicast
  { net: ipv4ToNumber("240.0.0.0")!, maskBits: mask(4) }, // reserved
];

function mask(bits: number): number {
  return (0xFFFFFFFF << (32 - bits)) >>> 0;
}

function ipv4ToNumber(ip: string): number | null {
  const parts = ip.split(".");
  if (parts.length !== 4) return null;
  let num = 0;
  for (const p of parts) {
    const n = Number(p);
    if (!Number.isInteger(n) || n < 0 || n > 255) return null;
    num = (num << 8) | n;
  }
  return num >>> 0;
}

function ipv4InRange(ipNum: number, netNum: number, maskBits: number): boolean {
  return (ipNum & maskBits) === (netNum & maskBits);
}

function isBlockedIp(ip: string): boolean {
  // IPv4-mapped IPv6: ::ffff:a.b.c.d -> check the IPv4 part.
  if (ip.startsWith("::ffff:")) {
    const ipv4 = ip.slice("::ffff:".length);
    const num = ipv4ToNumber(ipv4);
    if (num === null) return true; // unparseable -> treat as blocked
    return IPV4_PRIVATE_RANGES.some((r) => ipv4InRange(num, r.net, r.maskBits));
  }

  if (ip.includes(":")) {
    const lower = ip.toLowerCase();
    // IPv6 loopback
    if (lower === "::1") return true;
    // IPv6 link-local fe80::/10
    if (lower.startsWith("fe80:")) return true;
    // IPv6 unique local fc00::/7 (fc00::/8 and fd00::/8)
    if (lower.startsWith("fc") || lower.startsWith("fd")) return true;
    // IPv6 documentation 2001:db8::/32
    if (lower.startsWith("2001:0db8") || lower.startsWith("2001:db8")) return true;
    return false;
  }

  const num = ipv4ToNumber(ip);
  if (num === null) return true; // unparseable -> treat as blocked
  return IPV4_PRIVATE_RANGES.some((r) => ipv4InRange(num, r.net, r.maskBits));
}

async function resolveAll(hostname: string): Promise<DnsAddress[]> {
  // dns/promises.lookup with { all: true } returns all A/AAAA records.
  return (await lookup(hostname, { all: true })) as DnsAddress[];
}

/* ---------------------------------------------------------------- routes */

app.get("/health", (_req: Request, res: Response) => {
  res.json({ status: "ok", timestamp: new Date().toISOString() });
});

app.post(
  "/api/cleanup",
  strictLimiter,
  async (req: Request, res: Response) => {
    if (!validateCronSecret(req.headers.authorization)) {
      return res.status(401).json({ error: "unauthorized" });
    }

    const now = new Date();

    // 1. Expire disappearing messages via the database function.
    const { error: rpcError } = await supabase.rpc("cleanup_expired_messages");
    if (rpcError) {
      console.error("cleanup_expired_messages rpc failed:", rpcError);
      return res
        .status(500)
        .json({ error: "failed to expire messages", detail: rpcError.message });
    }

    // 2. Remove expired / viewed view-once media blobs from Supabase Storage.
    const { data: fileMessages, error: fetchError } = await supabase
      .from("messages")
      .select("id, ciphertext, message_type, is_view_once, viewed_at, expires_at")
      .eq("message_type", "file");

    if (fetchError) {
      console.error("fetch file messages failed:", fetchError);
      return res.status(500).json({ error: "failed to list file messages" });
    }

    const pathsToRemove: string[] = [];
    const idsToDelete: string[] = [];

    for (const m of fileMessages ?? []) {
      let shouldRemove = false;
      if (m.is_view_once === true && m.viewed_at) shouldRemove = true; // viewed view-once
      if (m.expires_at && new Date(m.expires_at) < now) shouldRemove = true; // expired

      if (!shouldRemove) continue;

      try {
        const card = JSON.parse(m.ciphertext) as { path?: string };
        if (card.path) pathsToRemove.push(card.path);
      } catch {
        // malformed ciphertext; still remove the row
      }
      idsToDelete.push(m.id);
    }

    if (pathsToRemove.length > 0) {
      const { error: storageError } = await supabase
        .storage.from(STORAGE_BUCKET)
        .remove(pathsToRemove);
      if (storageError) {
        console.error("storage remove failed:", storageError);
        // Continue to delete rows even if blob removal partially fails.
      }
    }

    if (idsToDelete.length > 0) {
      const { error: deleteError } = await supabase
        .from("messages")
        .delete()
        .in("id", idsToDelete);
      if (deleteError) {
        console.error("delete messages failed:", deleteError);
        return res.status(500).json({ error: "failed to delete messages" });
      }
    }

    res.json({
      status: "ok",
      cleanedMessages: idsToDelete.length,
      removedBlobs: pathsToRemove.length,
      timestamp: new Date().toISOString(),
    });
  },
);

app.post(
  "/api/link-preview",
  strictLimiter,
  async (req: Request, res: Response) => {
    const { url } = req.body as { url?: unknown };
    if (typeof url !== "string" || !url.trim()) {
      return res.status(400).json({ error: "url is required" });
    }

    let parsed: URL;
    try {
      parsed = new URL(url.trim());
    } catch {
      return res.status(400).json({ error: "invalid url" });
    }

    // Only public HTTPS URLs are allowed.
    if (parsed.protocol !== "https:") {
      return res.status(400).json({ error: "only https urls are allowed" });
    }

    const hostname = parsed.hostname;
    if (!hostname) {
      return res.status(400).json({ error: "url has no host" });
    }

    // SSRF: resolve all addresses and block private/internal ranges.
    let addresses: DnsAddress[];
    try {
      addresses = await resolveAll(hostname);
    } catch {
      return res.status(400).json({ error: "could not resolve host" });
    }
    if (addresses.length === 0) {
      return res.status(400).json({ error: "host resolved to no addresses" });
    }
    for (const a of addresses) {
      if (isBlockedIp(a.address)) {
        return res.status(400).json({ error: "url resolves to a blocked address" });
      }
    }

    // Fetch server-side so the client IP is never exposed to the external domain.
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), LINK_FETCH_TIMEOUT_MS);
    let html: string;
    try {
      const response = await fetch(parsed.toString(), {
        signal: controller.signal,
        headers: {
          "User-Agent": "MessengerApp-LinkPreview/1.0 (+https://messengerapp.local)",
          Accept: "text/html",
        },
        redirect: "follow",
      });
      if (!response.ok) {
        return res.status(502).json({ error: "failed to fetch url" });
      }
      const contentType = response.headers.get("content-type") ?? "";
      if (!contentType.includes("text/html")) {
        return res.status(400).json({ error: "url does not serve html" });
      }
      html = await response.text();
    } catch {
      return res.status(504).json({ error: "request timed out or failed" });
    } finally {
      clearTimeout(timer);
    }

    const title = extractTitle(html);
    const description =
      extractMeta(html, "description") ?? extractMeta(html, "og:description");
    const image = extractOgImage(html, parsed);

    res.json({
      url: parsed.toString(),
      title: title ?? null,
      description: description ?? null,
      image: image ?? null,
      fetchedAt: new Date().toISOString(),
    });
  },
);

/* ---------------------------------------------------------------- html extraction */

function extractTitle(html: string): string | null {
  const m = html.match(/<title[^>]*>([\s\S]*?)<\/title>/i);
  if (!m) return null;
  return escapeHtml(m[1].trim()).slice(0, 500) || null;
}

function extractMeta(html: string, name: string): string | null {
  const escaped = escapeRegExp(name);
  const m = html.match(
    new RegExp(
      `<meta[^>]*?name=["']${escaped}["'][^>]*?content=["']([^"']*)["']`,
      "i",
    ),
  );
  return m ? (escapeHtml(m[1].trim()).slice(0, 1000) || null) : null;
}

function extractOgImage(html: string, base: URL): string | null {
  const m = html.match(
    /<meta[^>]*?property=["']og:image["'][^>]*?content=["']([^"']*)["']/i,
  );
  if (!m) return null;
  try {
    return new URL(m[1].trim(), base).toString();
  } catch {
    return null;
  }
}

function escapeHtml(s: string): string {
  return s.replace(/[&<>"']/g, (c) => {
    const map: Record<string, string> = {
      "&": "&amp;",
      "<": "&lt;",
      ">": "&gt;",
      '"': "&quot;",
      "'": "&#39;",
    };
    return map[c] ?? c;
  });
}

function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/* ---------------------------------------------------------------- start */

app.listen(PORT, "0.0.0.0", () => {
  console.log(`messengerapp-server listening on :${PORT}`);
});

export default app;
