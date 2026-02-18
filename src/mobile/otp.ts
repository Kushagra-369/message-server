import fetch from "node-fetch"; 

export const NewUserOtp = async (firstName: string, lastName: string, mobile: string, otp: number) => {
    try {
        const message = `Hi ${firstName} ${lastName}, your OTP for account verification is ${otp}. Do not share this with anyone.`;

        const response = await fetch("https://www.fast2sms.com/dev/bulkV2", {
            method: "POST",
            headers: {
                authorization: process.env.FAST2SMS_API_KEY as string,
                "Content-Type": "application/json",
            },
            body: JSON.stringify({ route: "q", message: message, language: "english", numbers: mobile }),
        });

        return { success: true, message: "OTP sent successfully" };
    }
    catch (error: any) { console.error("OTP SMS Error:", error.message); }
};