import express from "express";
import passport from "../config/passport";

import { authenticateUser } from "../middleware/user_auth";
import { loginLimiter, otpLimiter } from "../middleware/rate_limiter";
import { validate } from "../middleware/validate";
import {validateLogin,validateSignup,validateOTP,validatePasswordUpdate,validateForgotEmail,validateTokenParam} from "../validation/auth.validation";

import {create_user,user_otp_verification,user_login,auth_me,get_user_by_id,user_google_auth,user_github_auth,user_resend_otp,user_update_password,user_forgot_password_gmail,forgotten_update_password} from "../controller/user_controller";

const router = express.Router();

/* ================= PUBLIC ROUTES ================= */
/* firewall already server.ts me hai — yaha repeat nahi */

router.post("/create_user", loginLimiter, validateSignup, validate, create_user);
router.post("/verify_otp/:userId", otpLimiter, validateOTP, validate, user_otp_verification);
router.post("/resend_otp/:userId", otpLimiter, validateOTP, validate, user_resend_otp);
router.post("/user_login", loginLimiter, validateLogin, validate, user_login);
router.post("/forgot_password_gmail", loginLimiter, validateForgotEmail, validate, user_forgot_password_gmail);
router.post("/forgotten_update_password/:token", loginLimiter, validateTokenParam, validatePasswordUpdate, validate, forgotten_update_password);

/* ================= PROTECTED ROUTES ================= */

router.post("/update_password", authenticateUser, validatePasswordUpdate, validate, user_update_password);
router.get("/get_user_by_id/:userId", authenticateUser, get_user_by_id);
router.get("/auth_me", authenticateUser, auth_me);

/* ================= OAUTH ROUTES ================= */

router.get("/auth/google", passport.authenticate("google", { scope: ["profile", "email"] }));
router.get("/auth/google/callback", passport.authenticate("google", { session: false }), user_google_auth);
router.get("/auth/github", passport.authenticate("github", { scope: ["user:email"] }));
router.get("/auth/github/callback", passport.authenticate("github", { session: false }), user_github_auth);

/* ================= TEST ROUTE (PROTECTED NOW) ================= */

router.get("/test_user/:userId", authenticateUser, get_user_by_id);

export default router;