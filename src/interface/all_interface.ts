import { Document, Types } from "mongoose";

export interface IUser extends Document {
   _id: Types.ObjectId;

   /* =======================
      BASIC PROFILE
   ======================= */
   username: string;
   first_name: string;
   last_name: string;
   email: string;
   password: string;
   country_code: string;
   mobile_No?: string;
   avatar?: string;
   profileImg?: {
      public_id?: string;
      secure_url?: string;
   };

   gender?: "male" | "female" | "other" | "";
   bio?: string;

   role: "admin" | "user";

   /* =======================
      ACCOUNT / OTP STATUS
   ======================= */
   verification: {
      isEmailVerified: boolean,
      isMobileVerified: boolean,
      isDelete: boolean,
      isVerify: boolean,
      emailotp: number,
      mobileotp: Number,
      userOtp: string,
      otpExpires: number ,
      wrongAttempts: number,
      lockUntil: Date | null,
      forgotPasswordOTP: number | null,
      forgotPasswordVerification: boolean,
      forgotPasswordOTPExpiry: number | null,
      forgotPassswordToken: string | null,
      forgotPasswordExpire: number | null,
      },

   /* =======================
      MESSAGING / SOCIAL
   ======================= */
   contacts: Types.ObjectId[];
   blockedUsers: Types.ObjectId[];

   isOnline: boolean;
   lastSeen: Date;
   isTyping: boolean;

   status: "online" | "offline" | "away" | "busy";

   /* =======================
      SOCKET / DEVICE
   ======================= */
   activeSession?: {
      socketId?: string | null;
      lastLogin: Date;
   };

   /* =======================
      TIMESTAMPS
   ======================= */
   createdAt: Date;
   updatedAt: Date;
}
