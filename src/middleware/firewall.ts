import { Request, Response, NextFunction } from "express";

export const firewall = (req: Request, res: Response, next: NextFunction) => {

    // 🚫 blocked IP example
    const blockedIPs = ["123.45.67.89"];

    const ip = req.ip ?? "";

    if (blockedIPs.includes(ip)) {
        return res.status(403).json({ msg: "Blocked by firewall" });
    }

    // 🚫 large payload attack
    if (req.headers["content-length"] && Number(req.headers["content-length"]) > 1_000_000) {
        return res.status(413).json({ msg: "Payload too large" });
    }

    next();
};