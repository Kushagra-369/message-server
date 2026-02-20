import rateLimit from "express-rate-limit";

// 🔐 login firewall
export const loginLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  max: 10,
  message: "Too many login attempts"
});

// 🔐 otp firewall (strict)
export const otpLimiter = rateLimit({
  windowMs: 5 * 60 * 1000,
  max: 5,
  message: "OTP spam detected"
});