const nodemailer = require("nodemailer");
const dotenv = require("dotenv")
dotenv.config()

export const transporter = nodemailer.createTransport({
  host: "smtp.gmail.com",
  port: 465,
  secure: true, 
  service: "gmail",
  auth: { 
    user: process.env.NodeMailerUser, 
    pass: process.env.NodeMailerPassword,
  },
});

export const otpVerificationUserMessage = async (name: String, email: String, otp: Number) => {
    try {
        const info = await transporter.sendMail({
            from: `"Messaging App" <${process.env.NodeMailerUser}>`,
            to: email,
            subject: "Your OTP Verification Code",
            html: `
                <div style="font-family: Arial, sans-serif; padding: 20px;">
                    <h2>Hello ${name},</h2>
                    <p>Your OTP for verification is:</p>
                    <h1 style="color: #4CAF50;">${otp}</h1>
                    <p>This OTP is valid for 5 minutes.</p>
                    <br/>
                    <p>Thanks,<br/>Hartron Team</p>
                </div>
            `,
        });

        console.log("User confirmation email sent:", info.messageId);
        return true;

    }
    catch (error) { console.log("Mail error:", error); }
};

export const forgotPasswordUserMessage = async (name: String, email: String, otp: Number) => {
    try {
        const info = await transporter.sendMail({
            from: `"Messaging App" <${process.env.NodeMailerUser}>`,
            to: email,
            subject: "Your OTP for Password Reset",
            html: `
                <div style="font-family: Arial, sans-serif; padding: 20px;">
                    <h2>Hello ${name},</h2>
                    <p>Your OTP for password reset is:</p>
                    <h1 style="color: #4CAF50;">${otp}</h1>
                    <p>This OTP is valid for 5 minutes.</p> 
                    <br/>
                    <p>Thanks,<br/>AuraLink Team</p>
                </div>
            `,
        });
    }
    catch (error) { console.log("Mail error:", error); }
}

export const forgotPasswordthroughgmail = async (name: string,email: string,token: string) => {
    try {

        const resetLink = `http://localhost:5173/forgot_password?token=${token}`;

        await transporter.sendMail({
            from: `"Messaging App" <${process.env.NodeMailerUser}>`,
            to: email,
            subject: "Your Link for Password Reset",
            html: `
                <h2>Hello ${name}</h2>
                <a href="${resetLink}">Reset Password</a>
            `,
        });

    } catch (error) {
        console.log("Mail error:", error);
    }
};
