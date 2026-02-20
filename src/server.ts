import dotenv from "dotenv";
dotenv.config();

import express from "express";
import cors from "cors";
import mongoose from "mongoose";
import router from "./routes/routes";

import helmet from "helmet";
import rateLimit from "express-rate-limit";
import hpp from "hpp";

import { firewall } from "./middleware/firewall";
import cookieParser from "cookie-parser";

const app = express();
app.use(cookieParser());

/* ================= EXPRESS HARDENING ================= */

// hide tech stack
app.disable("x-powered-by");

// trust proxy (needed for real IP detection)
app.set("trust proxy", 1);

/* ================= SECURITY MIDDLEWARE ================= */

// 🔐 secure headers
app.use(
  helmet({
    crossOriginResourcePolicy: { policy: "cross-origin" }
  })
);

// 🔐 secure CORS
app.use(
  cors({
    origin: process.env.CLIENT_URL || "http://localhost:5173",
    credentials: true,
    methods: ["GET", "POST", "PUT", "DELETE", "PATCH"],
  })
);

// 🔐 body parser (small limit = DOS protection)
app.use(express.json({ limit: "10kb" }));

// 🔐 NoSQL injection protection


// 🔐 query pollution protection
app.use(hpp());

// 🔐 custom firewall (runs before rate limit)
app.use(firewall);

// 🔐 global rate limiter
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
  message: { msg: "Too many requests — firewall active" },
});
app.use(limiter);

/* ================= DATABASE ================= */

const mongoURL = process.env.MONGO_URI;
const PORT = process.env.PORT || 1928;

if (!mongoURL) {
  throw new Error("❌ MONGO_URI missing");
}

mongoose
  .connect(mongoURL)
  .then(() => console.log("🌐 MongoDB connected"))
  .catch((err) => {
    console.error("MongoDB error:", err);
    process.exit(1);
  });

/* ================= ROUTES ================= */

app.get("/", (_req, res) => {
  res.send("Server is running");
});

app.use("/", router);

/* ================= GLOBAL ERROR HANDLER (VERY IMPORTANT) ================= */

app.use((err: any, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
  console.error("🔥 Server Error:", err.message);

  res.status(err.status || 500).json({
    msg: "Internal server error",
  });
});

/* ================= SERVER ================= */

app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});