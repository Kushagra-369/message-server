import express from "express";
import multer from "multer";
import { authenticateUser } from "../middleware/user_auth";
import passport from "../config/passport";

const router = express.Router();

import { create_user, user_otp_verification, user_login, auth_me,get_user_by_id, user_google_auth, user_github_auth,user_resend_otp,user_update_password,user_forgot_password_gmail , forgotten_update_password } from "../controller/user_controller";

const upload = multer();

router.post("/create_user", upload.none(), create_user);
router.post("/verify_otp/:userId", user_otp_verification);
router.post("/resend_otp/:userId", user_resend_otp);
router.post("/user_login", upload.none(), user_login);
router.post("/update_password", upload.none(), authenticateUser, user_update_password);
router.get("/get_user_by_id/:userId", authenticateUser, get_user_by_id);
router.get("/test_user/:userId", get_user_by_id);
router.get("/auth_me", authenticateUser, auth_me);

// 🔵 GOOGLE AUTH START
router.get("/auth/google",passport.authenticate("google", {scope: ["profile", "email"],}));
router.get("/auth/google/callback",passport.authenticate("google", { session: false }),user_google_auth);
router.get("/auth/github",passport.authenticate("github", {  scope: ["user:email"],}));
router.get("/auth/github/callback",passport.authenticate("github", { session: false }),user_github_auth);



router.post("/forgot_password_gmail", upload.none(), user_forgot_password_gmail);
router.post("/forgotten_update_password/:token", upload.none(), forgotten_update_password);

export default router;
