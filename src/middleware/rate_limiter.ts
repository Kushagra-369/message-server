import rateLimit from "express-rate-limit";

/* ================= LOGIN LIMITER ================= */

export const loginLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { msg: "Too many login attempts, try later" }
});

/* ================= OTP LIMITER ================= */

export const otpLimiter = rateLimit({
  windowMs: 5 * 60 * 1000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  message: { msg: "OTP spam detected" }
});

/* ================= GLOBAL API LIMITER (OPTIONAL BUT STRONG) ================= */

export const apiLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 120,
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => {
    return res.status(429).json({
      type: "ROBOT_CHECK",   // 👈 frontend ke liye signal
      message: "Too many requests",
    });
  }
});