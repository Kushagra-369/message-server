import { Request, Response, NextFunction } from "express";

/* ================= MEMORY STORES ================= */

// IP ban store with expiry
const bannedIPs = new Map<string, number>();

// request counter with reset window
const requestMap = new Map<string, { count: number; time: number }>();

// config
const REQUEST_WINDOW = 60 * 1000; // 1 min window
const MAX_REQUESTS = 100;

export const firewall = (req: Request, res: Response, next: NextFunction) => {

  /* ================= SAFE IP DETECTION ================= */
  /* ================= AUTH ROUTE BYPASS ================= */
  // login / oauth routes should never be blocked
  const authBypassRoutes = [
    "/user_login",
    "/auth/google",
    "/auth/github",
    "/auth/google/callback",
    "/auth/github/callback",
  ];

  if (authBypassRoutes.some(route => req.path.startsWith(route))) {
    return next();
  }

  const ip =
    (req.headers["x-forwarded-for"] as string)?.split(",")[0]?.trim() ||
    req.socket.remoteAddress ||
    "unknown";

  const userAgent = (req.headers["user-agent"] || "").toLowerCase();

  /* ================= TEMP IP BAN CHECK ================= */

  const banExpiry = bannedIPs.get(ip);

  if (banExpiry) {
    if (Date.now() < banExpiry) {
      return res.status(403).json({ msg: "IP temporarily blocked" });
    }
    bannedIPs.delete(ip);
  }

  /* ================= BASIC BOT DETECTION ================= */
  // NOTE: user-agent blocking is weak, only soft filter
  const badAgents = ["sqlmap", "nikto", "acunetix"];

  if (badAgents.some(agent => userAgent.includes(agent))) {
    bannedIPs.set(ip, Date.now() + 10 * 60 * 1000);
    return res.status(403).json({ msg: "Blocked by firewall" });
  }

  /* ================= REQUEST FLOOD CHECK ================= */

  const now = Date.now();
  const record = requestMap.get(ip);

  if (!record) {
    requestMap.set(ip, { count: 1, time: now });
  } else {
    if (now - record.time > REQUEST_WINDOW) {
      // reset window
      requestMap.set(ip, { count: 1, time: now });
    } else {
      record.count += 1;

      if (record.count > MAX_REQUESTS) {
        bannedIPs.set(ip, now + 5 * 60 * 1000);
        return res.status(429).json({ msg: "Too many requests" });
      }
    }
  }

  /* ================= SIMPLE PAYLOAD SCAN ================= */

  const bodyString = JSON.stringify(req.body || {}).toLowerCase();

  if (
    bodyString.includes("$where") ||
    bodyString.includes("<script") ||
    bodyString.includes("javascript:")
  ) {
    bannedIPs.set(ip, now + 15 * 60 * 1000);
    return res.status(400).json({ msg: "Malicious payload detected" });
  }

  next();
};

/* ================= CLEANUP MEMORY ================= */

// prevent memory leak
setInterval(() => {
  const now = Date.now();

  for (const [ip, expiry] of bannedIPs.entries()) {
    if (now > expiry) bannedIPs.delete(ip);
  }

  for (const [ip, data] of requestMap.entries()) {
    if (now - data.time > REQUEST_WINDOW) {
      requestMap.delete(ip);
    }
  }
}, 60 * 1000);