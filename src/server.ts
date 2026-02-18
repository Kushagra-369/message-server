import dotenv from "dotenv";
dotenv.config();
import express from "express";
import cors from "cors";
import mongoose from "mongoose";
import router from "./routes/routes";

const app = express();

app.use(express.json());
app.use(cors());

const mongoURL = process.env.MONGO_URI;
const PORT = process.env.PORT || 1928;

if (!mongoURL) { 
  console.error("❌ MONGO_URI not found in environment variables");
  process.exit(1);
} 

mongoose
  .connect(mongoURL)
  .then(() => console.log("🌐 MongoDB connected"))
  .catch((err) => {
    console.error("MongoDB error:", err);
    process.exit(1);
  });

// health check
app.get("/", (_req, res) => {
  res.send("Server is running");
}); 

app.use("/", router);

app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});
