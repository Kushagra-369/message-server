import { v2 as cloudinary } from "cloudinary";
import sharp from "sharp";

/* ================= ENV VALIDATION ================= */

const cloudName = process.env.Cloud_name;
const apiKey = process.env.API_key;
const apiSecret = process.env.API_secret;

if (!cloudName || !apiKey || !apiSecret) {
  throw new Error("❌ Cloudinary environment variables missing");
}

/* ================= CLOUDINARY CONFIG ================= */

cloudinary.config({
  cloud_name: cloudName,
  api_key: apiKey,
  api_secret: apiSecret
});

/* ================= CONSTANTS ================= */

const MAX_SIZE = 2 * 1024 * 1024; // 2MB

/* ================= UPLOAD IMAGE ================= */

export const upload_project_img = async (img: Buffer) => {
  try {
    /* ---------- BASIC VALIDATION ---------- */

    if (!img || !Buffer.isBuffer(img)) {
      throw new Error("Invalid image buffer");
    }

    if (img.length > MAX_SIZE) {
      throw new Error("Image too large");
    }

    /* ---------- FILE TYPE CHECK ---------- */

    const metadata = await sharp(img).metadata();

    if (
      !metadata.format ||
      !["jpeg", "jpg", "png", "webp"].includes(metadata.format)
    ) {
      throw new Error("Unsupported image format");
    }

    /* ---------- IMAGE OPTIMIZATION ---------- */

    const optimizedBuffer = await sharp(img)
      .rotate()
      .resize(1080, 720, { fit: "inside", withoutEnlargement: true })
      .jpeg({ quality: 80, mozjpeg: true })
      .toBuffer();

    /* ---------- CLOUDINARY UPLOAD ---------- */

    const uploadResult = await cloudinary.uploader.upload(
      `data:image/jpeg;base64,${optimizedBuffer.toString("base64")}`,
      {
        resource_type: "image",
        quality: "auto",
        folder: "travelly/profile"
      }
    );

    return {
      public_id: uploadResult.public_id,
      secure_url: uploadResult.secure_url
    };
  } catch (error) {
    console.error("Upload Error:", error);
    throw new Error("Image upload failed");
  }
};

/* ================= DELETE IMAGE ================= */

export const deleteImg = async (publicId: string) => {
  try {
    if (!publicId) return;

    await cloudinary.uploader.destroy(publicId, {
      resource_type: "image"
    });
  } catch (error) {
    console.error("Delete Image Error:", error);
    throw new Error("Image delete failed");
  }
};