import { body, param } from "express-validator";

/* ================= LOGIN VALIDATION ================= */

export const validateLogin = [
  body("email")
    .isEmail()
    .withMessage("Invalid email"),

  body("password")
    .isLength({ min: 6, max: 50 })
    .withMessage("Password must be 6-50 characters"),
];

/* ================= SIGNUP VALIDATION ================= */

export const validateSignup = [
  body("username")
    .trim()
    .isLength({ min: 3, max: 20 })
    .withMessage("Username must be 3-20 chars"),

  body("first_name")
    .trim()
    .notEmpty()
    .withMessage("First name required"),

  body("last_name")
    .trim()
    .notEmpty()
    .withMessage("Last name required"),

  body("email")
    .isEmail()
    .withMessage("Invalid email"),

  body("password")
    .isLength({ min: 6, max: 50 })
    .withMessage("Password must be 6-50 characters"),

  body("country_code")
    .notEmpty()
    .withMessage("Country code required"),

  body("mobile_No")
    .isLength({ min: 10, max: 15 })
    .withMessage("Invalid mobile number"),
];

/* ================= OTP VALIDATION ================= */

export const validateOTP = [
  param("userId")
    .isMongoId()
    .withMessage("Invalid userId"),

  body("otp")
    .isLength({ min: 4, max: 8 })
    .withMessage("Invalid OTP"),
];

/* ================= PASSWORD UPDATE ================= */

export const validatePasswordUpdate = [
  body("password")
    .isLength({ min: 6, max: 50 })
    .withMessage("Password must be 6-50 characters"),
];

/* ================= FORGOT PASSWORD EMAIL ================= */

export const validateForgotEmail = [
  body("email")
    .isEmail()
    .withMessage("Invalid email"),
];

/* ================= TOKEN PARAM VALIDATION ================= */

export const validateTokenParam = [
  param("token")
    .notEmpty()
    .withMessage("Token missing"),
];