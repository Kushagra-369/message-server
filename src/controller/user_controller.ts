import { Request, Response } from "express";
import User from "../model/user_model";
import { errorHandler } from '../middleware/error_handling';
import { NewUserOtp } from '../mobile/otp';
import crypto from 'crypto';
import { otpVerificationUserMessage, forgotPasswordUserMessage, forgotPasswordthroughgmail } from "../mail/user_mail";
import { upload_project_img, deleteImg } from "../image/upload";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import { Profile } from "passport-google-oauth20";

export const create_user = async (req: Request, res: Response) => {
    try {
        const { website } = req.body;

        if (website) {
            return res.status(400).json({ message: "Bot detected" });
        }
        const {
            username,
            first_name,
            last_name,
            email,
            country_code,
            password,
            mobile_No,
            gender,
        } = req.body;

        const file = req.file;

        // 🔥 generate OTP
        const otp = crypto.randomInt(1000, 10000);
        const otpExpires = Date.now() + 5 * 60 * 1000;

        // 🔍 check user exists
        const userExists = await User.findOne({ email });


        /* ===================================================
            CASE 1️⃣  USER EXISTS
        =================================================== */
        if (userExists) {
            // 👉 already verified → go login
            if (userExists.verification?.isVerify) {
                return res.status(409).json({
                    message: "User already verified",
                    next: "LOGIN",
                });
            }

            // 👉 NOT VERIFIED → resend OTP
            userExists.verification.emailotp = otp;
            userExists.verification.mobileotp = otp;
            userExists.verification.otpExpires = otpExpires;

            await userExists.save();

            await otpVerificationUserMessage(
                userExists.first_name,
                userExists.email,
                otp
            );

            if (userExists.mobile_No) {
                await NewUserOtp(
                    userExists.first_name,
                    userExists.last_name,
                    userExists.mobile_No,
                    otp
                );
            }

            return res.status(201).json({
                message: "OTP resent",
                user: { _id: userExists._id }, // 👈 IMPORTANT
            });
        }

        /* ===================================================
            CASE 2️⃣  NEW USER CREATE
        =================================================== */

        let profileImg: any = null;

        if (file) {
            profileImg = await upload_project_img(file.path);
        }

        const bcryptPassword = await bcrypt.hash(password, 10);

        const verification = {
            emailotp: otp,
            mobileotp: otp,
            otpExpires,
        };

        const user = await User.create({
            username,
            first_name,
            last_name,
            email,
            country_code,
            password: bcryptPassword,
            mobile_No,
            gender,
            profileImg,
            verification,
        });

        // 🔥 SEND OTP
        await otpVerificationUserMessage(first_name, email, otp);

        if (mobile_No) {
            await NewUserOtp(first_name, last_name, mobile_No, otp);
        }

        return res.status(201).json({
            status: true,
            message: "User created & OTP sent",
            user: { _id: user._id }, // 👈 IMPORTANT FOR FRONTEND
        });
    } catch (err: unknown) {
        return errorHandler(err, res);
    }
};
// above create_user if user send password and exiting mail or mobile number updated password

export const user_otp_verification = async (req: Request, res: Response) => {
    try {
        const { userId } = req.params;
        const { otp } = req.body;

        console.log("OTP from body:", otp);


        const user = await User.findById(userId);

        if (!user) { return res.status(404).json({ message: 'User not found!' }); }

        const lockDurations = [5 * 60 * 1000, 15 * 60 * 1000, 60 * 60 * 1000, 3 * 60 * 60 * 1000, 24 * 60 * 60 * 1000, 7 * 24 * 60 * 60 * 1000, 30 * 24 * 60 * 60 * 1000, 365 * 24 * 60 * 60 * 1000] // 5 min, 15 min,  1 hr, 3 hr

        if (user.verification.lockUntil && user.verification.lockUntil > new Date()) {
            const remainingTime = Math.ceil((user.verification.lockUntil.getTime() - Date.now()) / 1000);
            return res.status(403).json({ message: `Account is locked. Try again in ${remainingTime} seconds.` });
        }
        if (otp !== user.verification.emailotp && otp !== user.verification.mobileotp) {
            user.verification.wrongAttempts += 1;

            if (user.verification.wrongAttempts % 3 === 0) {
                const lockTime = lockDurations[Math.min(Math.floor(user.verification.wrongAttempts / 3) - 1, lockDurations.length - 1)] ?? lockDurations[lockDurations.length - 1];

                user.verification.lockUntil = new Date(Date.now() + (lockTime ?? 0));
            }

            await user.save();
            let attemptsLeft = 3 - (user.verification.wrongAttempts % 3);
            if (attemptsLeft === 3) attemptsLeft = 0;

            let message = "Invalid OTP!";
            if (attemptsLeft > 0) {
                message += ` ${attemptsLeft} attempts left`;
            }

            return res.status(400).json({ message });
        }

        user.verification.isVerify = true;
        user.verification.isEmailVerified = true;
        user.verification.isMobileVerified = true;
        user.verification.wrongAttempts = 0;
        user.verification.lockUntil = null;

        await user.save();

        res.status(200).json({ message: 'OTP verified successfully!' });

    }

    catch (err) { return errorHandler(err, res); }
}

export const user_login = async (req: Request, res: Response) => {
    try {
        const { website } = req.body;

        if (website) {
            return res.status(400).json({ message: "Bot detected" });
        }
        const { email, password, username, mobile_No } = req.body;

        if (!password) {
            return res.status(400).json({ message: "Password is required!" });
        }

        // 👤 atleast one identifier compulsory
        if (!email && !username && !mobile_No) {
            return res.status(400).json({
                message: "Email, username or mobile number is required!"
            });
        }

        const orConditions: any[] = [];

        if (email) orConditions.push({ email });
        if (username) orConditions.push({ username });
        if (mobile_No) orConditions.push({ mobile_No });

        const user = await User.findOne({
            $or: orConditions
        }).select("+password");

        if (!user) {
            return res.status(404).json({ message: 'User not found!' });
        }
        if (!user.verification.isVerify) {
            return res.status(400).json({ message: 'User is not verified!' });
        }
        if (!user.verification.isEmailVerified && !user.verification.isMobileVerified) {
            return res.status(400).json({ message: 'Email is not verified!' });
        }
        if (user.verification.isDelete) {
            return res.status(400).json({ message: 'User is deleted!' });
        }



        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) {
            return res.status(400).json({ message: 'Invalid password!' });
        }

        const token = jwt.sign(
            {
                userId: user._id,
                ua: req.headers["user-agent"],
                ip: req.ip
            },
            process.env.JWT_User_SECRET_KEY as string,
            { expiresIn: "7d" }
        );
        const safeUser = { _id: user._id, username: user.username, first_name: user.first_name, last_name: user.last_name, email: user.email, profileImg: user.profileImg, role: user.role, bio: user.bio, isOnline: user.isOnline, status: user.status, };

        res.status(200).json({ message: "Login successful!", user: safeUser, token, });
    }

    catch (err) { return errorHandler(err, res); }
}

export const auth_me = async (req: any, res: Response) => {
    try {
        const user = req.user;

        const safeUser = {
            _id: user._id,
            username: user.username,
            first_name: user.first_name,
            last_name: user.last_name,
            email: user.email,
            profileImg: user.profileImg,
            bio: user.bio,
            role: user.role,
            isOnline: user.isOnline,
            status: user.status,
            createdAt: user.createdAt,
            updatedAt: user.updatedAt,
        };

        return res.status(200).json({
            success: true,
            user: safeUser,
        });

    } catch (err) {
        return errorHandler(err, res);
    }
};


export const get_user_by_id = async (req: Request, res: Response) => {
    try {
        const { userId } = req.params;

        if (!userId) {
            return res.status(400).json({
                message: "User ID required!",
            });
        }

        const user = await User.findById(userId).select("-password");

        if (!user) {
            return res.status(404).json({
                message: "User not found!",
            });
        }

        return res.status(200).json({
            success: true,
            message: "User fetched successfully",
            user,
        });
    } catch (err) {
        return errorHandler(err, res);
    }
};


export const user_google_auth = async (req: Request, res: Response) => {
    try {
        const googleUser = req.user as Profile;

        const email = googleUser?.emails?.[0]?.value;
        const name = googleUser?.displayName || "Google User";

        if (!email) {
            return res.status(400).json({ message: "Email not found from Google" });
        }

        let user = await User.findOne({ email });

        if (!user) {
            const username = email.split("@")[0] + crypto.randomBytes(3).toString("hex");
            const nameParts = name.split(" ");
            const first_name = nameParts[0] || "Google";
            const last_name = nameParts.slice(1).join(" ") || "User";
            const randomPassword = await bcrypt.hash(crypto.randomBytes(20).toString("hex"), 10);

            user = await User.create({
                username,
                first_name,
                last_name,
                email,
                avatar: "https://via.placeholder.com/150",
                country_code: "+91",
                password: randomPassword,
                verification: {
                    isVerify: true,
                    isEmailVerified: true,
                    isMobileVerified: false,
                    isDelete: false,
                    wrongAttempts: 0,
                    lockUntil: null,
                },
            });
        }

        // ✅ SAME TOKEN LOGIC AS NORMAL LOGIN
        const token = jwt.sign(
            { userId: user._id },
            process.env.JWT_User_SECRET_KEY as string,
            { expiresIn: "7d" }
        );

        // ✅ FRONTEND KO TOKEN BHEJO
        return res.redirect(`http://localhost:5173/login?token=${token}`);

    } catch (err) {
        return errorHandler(err, res);
    }
};


export const user_github_auth = async (req: Request, res: Response) => {
    try {
        const githubUser: any = req.user;

        const email = githubUser?.emails?.[0]?.value || githubUser?._json?.email;

        const name = githubUser?.displayName || githubUser?.username || "Github User";

        if (!email) { return res.redirect("http://localhost:5173/login?error=no_email"); }

        let user = await User.findOne({ email });

        if (!user) {
            const username = email.split("@")[0] + crypto.randomBytes(3).toString("hex");

            const nameParts = name.split(" ");
            const first_name = nameParts[0] || "Github";
            const last_name = nameParts.slice(1).join(" ") || "User";

            const randomPassword = await bcrypt.hash(
                crypto.randomBytes(20).toString("hex"),
                10
            );

            user = await User.create({
                username, first_name, last_name, email, avatar: "https://via.placeholder.com/150", country_code: "+91", password: randomPassword,
                verification: {
                    isVerify: true,
                    isEmailVerified: true,
                    isMobileVerified: false,
                    isDelete: false,
                    wrongAttempts: 0,
                    lockUntil: null,
                },
            });
        }

        return res.redirect("http://localhost:5173/home");

    } catch (err) {
        return errorHandler(err, res);
    }
};

export const user_resend_otp = async (req: Request, res: Response) => {
    try {
        const { userId } = req.params;

        const user = await User.findById(userId);

        if (!user) {
            return res.status(404).json({ message: "User not found!" });
        }

        if (user.verification.isVerify) {
            return res.status(400).json({ message: "User already verified!" });
        }

        const emailOtp = Math.floor(1000 + Math.random() * 9000);
        const mobileOtp = Math.floor(1000 + Math.random() * 9000);

        await User.findByIdAndUpdate(userId, {
            $set: {
                "verification.emailotp": emailOtp,
                "verification.mobileotp": mobileOtp,
                "verification.userOtp": emailOtp,
                "verification.otpExpiry": new Date(Date.now() + 5 * 60 * 1000),
            },
        });

        console.log("New Email OTP:", emailOtp);
        console.log("New Mobile OTP:", mobileOtp);

        return res.status(200).json({
            message: "OTP resent successfully",
        });

    } catch (err) {
        return errorHandler(err, res);
    }
};

export const user_update_password = async (req: Request, res: Response) => {
    try {
        const { email, username, mobile_No, oldPassword, newPassword } = req.body;

        if (!email && !username && !mobile_No) {
            return res.status(400).json({
                message: "Provide email, username, or mobile number",
            });
        }

        if (!oldPassword || !newPassword) {
            return res.status(400).json({
                message: "Old password and new password required",
            });
        }

        // ✅ Build query safely
        const query: any = {};
        if (email) query.email = email;
        if (username) query.username = username;
        if (mobile_No) query.mobile_No = mobile_No;

        const user = await User.findOne(query).select("+password");

        if (!user) {
            return res.status(404).json({ message: "User not found" });
        }

        const isMatch = await bcrypt.compare(oldPassword, user.password);

        if (!isMatch) {
            return res.status(400).json({ message: "Old password is incorrect" });
        }

        user.password = await bcrypt.hash(newPassword, 10);

        await user.save();

        return res.status(200).json({
            message: "Password updated successfully",
        });

    } catch (err) {
        return errorHandler(err, res);
    }
};

export const update_user_text_info = async (req: Request, res: Response) => {
    try {
        const { userId } = req.params;
        const { first_name, last_name, country_code, gender, bio } = req.body;

        const user = await User.findById(userId);

        if (!user) {
            return res.status(404).json({ message: "User not found!" });
        }

        if (first_name !== undefined) user.first_name = first_name;
        if (last_name !== undefined) user.last_name = last_name;
        if (country_code !== undefined) user.country_code = country_code;
        if (gender !== undefined) user.gender = gender;
        if (bio !== undefined) user.bio = bio;

        await user.save();

        return res.status(200).json({
            message: "User text info updated successfully",
            user: user.toJSON(),
        });

    } catch (err) {
        return errorHandler(err, res);
    }
};

export const update_user_profile_image = async (req: Request, res: Response) => {
    try {
        const { userId } = req.params;
        const file = req.file;

        if (!file) {
            return res.status(400).json({ message: "Image file required!" });
        }

        const user = await User.findById(userId);

        if (!user) {
            return res.status(404).json({ message: "User not found!" });
        }

        // ✅ old image delete
        if (user.profileImg?.public_id) {
            await deleteImg(user.profileImg.public_id);
        }

        // ✅ upload new image
        const uploadedImg = await upload_project_img(file.path);

        user.profileImg = {
            public_id: uploadedImg.public_id,
            secure_url: uploadedImg.secure_url,
        };

        await user.save();

        return res.status(200).json({
            message: "Profile image updated successfully",
            user: user.toJSON(),
        });

    } catch (err) {
        return errorHandler(err, res);
    }
};

export const user_forgot_password_gmail = async (req: Request, res: Response) => {
    try {
        const { email, username } = req.body;

        const user = await User.findOne({
            $or: [{ email }, { username }]
        });

        if (!user) {
            return res.status(404).json({ message: "User not found!" });
        }

        if (user.verification.isDelete) {
            return res.status(400).json({ message: "User is deleted!" });
        }

        if (!user.verification.isVerify) {
            return res.status(400).json({ message: "User is not verified!" });
        }
        const resetToken = jwt.sign(
            { userId: user._id },
            process.env.RESET_PASSWORD_SECRET!,
            { expiresIn: "5m" }
        );

        user.verification.forgotPassswordToken = resetToken;

        await user.save();

        await forgotPasswordthroughgmail(
            user.first_name,
            user.email,
            resetToken
        );

        return res.status(200).json({
            message: "Reset link sent to email",
        });

    } catch (err) {
        return errorHandler(err, res);
    }
};

export const forgotten_update_password = async (req: Request, res: Response) => {
    try {
        const { newPassword } = req.body;
        const { token } = req.params;

        if (!newPassword) {
            return res.status(400).json({ message: "New password is required!" });
        }

        if (!token) {
            return res.status(400).json({ message: "Token missing!" });
        }

        // JWT verify karo
        const tokenStr = Array.isArray(token) ? token[0] : token;

        const decoded: any = jwt.verify(tokenStr as string, process.env.RESET_PASSWORD_SECRET!);

        const user = await User.findById(decoded.userId);

        if (!user) {
            return res.status(404).json({ message: "User not found!" });
        }

        user.password = await bcrypt.hash(newPassword, 10);
        await user.save();


        console.log("DECODED TOKEN =", decoded);


        return res.status(200).json({
            message: "Password updated successfully",
        });

    } catch (err) {
        console.log("JWT ERROR =", err); // 👈 ADD THIS
        return errorHandler(err, res);
    }

};

