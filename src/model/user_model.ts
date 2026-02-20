import mongoose, { Schema, Model } from "mongoose";
import { IUser } from "../interface/all_interface";

const UserSchema: Schema<IUser> = new Schema(
  {

    username: { type: String, required: true, unique: true, trim: true, lowercase: true, },

    first_name: { type: String, required: true, trim: true, },

    last_name: { type: String, required: true, trim: true, },

    email: { type: String, required: true, unique: true, lowercase: true, trim: true, index: true, },
    country_code: { type: String, required: true, enum: ['+1', '+44', '+91', '+92', '+971'], match: /^\+\d{1,4}$/ },
    mobile_No: { type: String, required: false, unique: true, sparse: true, trim: true },
    avatar: { type: String, default: "https://via.placeholder.com/150" },

    password: { type: String, required: true, select: false, },

    profileImg: {
      public_id: {
        type: String,
      },
      secure_url: {
        type: String,
        default: "https://via.placeholder.com/150",
      },
    },

    gender: { type: String, enum: ["male", "female", "other", ""], },

    bio: { type: String, maxlength: 300, default: "I am using this app" },

    role: { type: String, enum: ["admin", "user"], default: "user", },
    verification: {
      isEmailVerified: { type: Boolean, default: false },
      isMobileVerified: { type: Boolean, default: false },
      isDelete: { type: Boolean, default: false },
      isVerify: { type: Boolean, default: false },
      emailotp: { type: Number },
      mobileotp: { type: Number },
      userOtp: { type: Number, default: null },
      otpExpiry: { type: Date, default: null },
      wrongAttempts: { type: Number, default: 0 },
      lockUntil: { type: Date, default: null },
      forgotPasswordOTP: { type: Number, default: null },
      forgotPasswordVerification: { type: Boolean, default: false },
      forgotPasswordOTPExpiry: { type: Number, default: null },
      forgotPassswordToken: { type: String, default: null },
      forgotPasswordExpire: { type: Number, default: null },

    },


    contacts: [{ type: Schema.Types.ObjectId, ref: "User", },],

    blockedUsers: [{ type: Schema.Types.ObjectId, ref: "User", },],

    isOnline: {
      type: Boolean,
      default: false,
    },

    lastSeen: {
      type: Date,
      default: Date.now,
    },

    isTyping: {
      type: Boolean,
      default: false,
    },

    status: {
      type: String,
      enum: ["online", "offline", "away", "busy"],
      default: "offline",
    },

    activeSession: {
      socketId: { type: String, default: null },
      lastLogin: { type: Date, default: Date.now }
    },

  },
  { timestamps: true }
);


const User: Model<IUser> =
  mongoose.models.User || mongoose.model<IUser>("User", UserSchema);

export default User;
