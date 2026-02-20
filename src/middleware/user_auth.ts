import { Request, Response, NextFunction } from "express";
import jwt, { JwtPayload } from "jsonwebtoken";
import User from "../model/user_model";
import mongoose from "mongoose";

interface AuthRequest extends Request {
  user?: any;
}

export const authenticateUser = async (
  req: AuthRequest,
  res: Response,
  next: NextFunction
) => {
  try {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({ message: "Authorization token missing!" });
    }

    const token = authHeader.split(" ")[1];
    if (!token) {
      return res.status(401).json({ message: "Token missing!" });
    }

    const decoded = jwt.verify(
      token,
      process.env.JWT_User_SECRET_KEY as string
    ) as JwtPayload;

    if (decoded.ua !== req.headers["user-agent"]) {
      return res.status(401).json({ message: "Device mismatch" });
    }

    const userId = decoded.userId;

    if (!mongoose.Types.ObjectId.isValid(userId)) {
      return res.status(401).json({ message: "Invalid token!" });
    }

    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ message: "User not found!" });
    }

    if (user.verification.isDelete) {
      return res.status(403).json({ message: "User is deleted!" });
    }

    if (!user.verification.isVerify) {
      return res.status(403).json({ message: "User is not verified!" });
    }

    if (
      !user.verification.isEmailVerified &&
      !user.verification.isMobileVerified
    ) {
      return res.status(403).json({ message: "Email or mobile not verified!" });
    }

    req.user = user;

    next();
  } catch (error) {
    console.error("JWT Auth Error:", error);
    return res.status(401).json({ message: "Unauthorized" });
  }
};
