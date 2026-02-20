import { Request, Response, NextFunction, RequestHandler } from "express";
import jwt, { JwtPayload } from "jsonwebtoken";
import User from "../model/user_model";
import mongoose from "mongoose";

export const authenticateUser: RequestHandler = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  try {
    /* ================= TOKEN EXTRACTION ================= */

    const token = req.cookies?.access_token;

    if (!token) {
      return res.status(401).json({ message: "Authorization token missing" });
    }

    if (!token) {
      return res.status(401).json({ message: "Token missing" });
    }

    /* ================= JWT VERIFY ================= */

    const decoded = jwt.verify(
      token,
      process.env.JWT_User_SECRET_KEY as string,
      { algorithms: ["HS256"] }
    ) as JwtPayload;

    if (!decoded || !decoded.userId) {
      return res.status(401).json({ message: "Invalid token payload" });
    }

    /* ================= DEVICE CHECK ================= */

    const currentUA = (req.headers["user-agent"] || "")
      .toString()
      .toLowerCase();

    const tokenUA = (decoded.ua || "").toString().toLowerCase();

    if (tokenUA && currentUA) {
      const tokenBrowser = tokenUA.split(" ")[0];
      const currentBrowser = currentUA.split(" ")[0];

      if (tokenBrowser !== currentBrowser) {
        return res.status(401).json({ message: "Device mismatch" });
      }
    }

    /* ================= OBJECT ID VALIDATION ================= */

    const userId = decoded.userId;

    if (!mongoose.Types.ObjectId.isValid(userId)) {
      return res.status(401).json({ message: "Invalid token" });
    }

    /* ================= USER FETCH ================= */

    const user = await User.findById(userId)
      .select("_id role verification")
      .lean();

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    if (user.verification?.isDelete) {
      return res.status(403).json({ message: "User deleted" });
    }

    if (!user.verification?.isVerify) {
      return res.status(403).json({ message: "User not verified" });
    }

    if (
      !user.verification?.isEmailVerified &&
      !user.verification?.isMobileVerified
    ) {
      return res.status(403).json({ message: "Verification required" });
    }

    /* ================= SAFE ATTACH ================= */

    req.user = {
      _id: user._id.toString(),
      role: user.role,
    };

    next();
  } catch (error: any) {
    console.error("JWT Auth Error:", error.message);

    if (error.name === "TokenExpiredError") {
      return res.status(401).json({ message: "Token expired" });
    }

    return res.status(401).json({ message: "Unauthorized" });
  }
};