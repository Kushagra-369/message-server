import { Request, Response, NextFunction } from "express";

/* ================= MEMORY STORES ================= */

// simple temp IP ban store
const bannedIPs = new Map<string, number>();

// request counter (basic anti-bot)
const requestMap = new Map<string, number>();

export const firewall = (req: Request, res: Response, next: NextFunction) => {

  const ip = req.ip ?? "";
  const userAgent = (req.headers["user-agent"] || "").toLowerCase();

  /* ================= TEMP IP BAN CHECK ================= */

  const banExpiry = bannedIPs.get(ip);
  if (banExpiry && Date.now() < banExpiry) {
    return res.status(403).json({ msg: "IP temporarily blocked" });
  } else if (banExpiry) {
    bannedIPs.delete(ip);
  }

  /* ================= BAD USER AGENTS ================= */

  const badAgents = ["sqlmap", "nikto", "curl", "postman", "wget"];

  if (badAgents.some(agent => userAgent.includes(agent))) {
    bannedIPs.set(ip, Date.now() + 10 * 60 * 1000); // 10 min ban
    return res.status(403).json({ msg: "Blocked by firewall (agent)" });
  }

  /* ================= LARGE PAYLOAD BLOCK ================= */

  const contentLength = req.headers["content-length"];
  if (contentLength && Number(contentLength) > 1_000_000) {
    return res.status(413).json({ msg: "Payload too large" });
  }

  /* ================= SIMPLE SPAM DETECTOR ================= */

  const count = requestMap.get(ip) || 0;
  requestMap.set(ip, count + 1);

  if (count > 100) {
    bannedIPs.set(ip, Date.now() + 5 * 60 * 1000); // auto ban 5 min
    return res.status(429).json({ msg: "Too many suspicious requests" });
  }

  /* ================= BASIC INJECTION CHECK ================= */

  const bodyString = JSON.stringify(req.body || {});
  if (bodyString.includes("$where") || bodyString.includes("<script")) {
    bannedIPs.set(ip, Date.now() + 15 * 60 * 1000);
    return res.status(400).json({ msg: "Malicious payload detected" });
  }

  next();
};