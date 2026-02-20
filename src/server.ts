import dotenv from "dotenv";
dotenv.config();

import express from "express";
import cors from "cors";
import mongoose from "mongoose";
import router from "./routes/routes";

import helmet from "helmet";
import rateLimit from "express-rate-limit";
import hpp from "hpp";
import mongoSanitize from "express-mongo-sanitize";

import { firewall } from "./middleware/firewall"; // 👈 custom firewall add

const app = express();

/* ================= SECURITY FIREWALL ================= */

// trust proxy (important for rate limit + IP detection)
app.set("trust proxy", 1);

// 🔥 secure headers
app.use(helmet());

// 🔥 secure cors
app.use(
  cors({
    origin: process.env.CLIENT_URL || "http://localhost:5173",
    credentials: true,
  })
);

// 🔥 body parser (limit added)
app.use(express.json({ limit: "10kb" }));

// 🔥 Mongo injection protection
app.use(
  mongoSanitize({
    allowDots: true,
    replaceWith: "_",
  })
);

// 🔥 custom firewall (IP / bot / payload detection)
app.use(firewall);

// 🔥 brute force firewall (GLOBAL)
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
  message: { msg: "Too many requests — firewall active" },
});
app.use(limiter);

// 🔥 query pollution attack block
app.use(hpp());

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

/* ================= SERVER ================= */

app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});