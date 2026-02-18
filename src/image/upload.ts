
const cloudinary = require('cloudinary').v2;
const sharp = require('sharp');
require('dotenv').config();


cloudinary.config({
    cloud_name: process.env.Cloud_name,
    api_key: process.env.API_key,
    api_secret: process.env.API_secret
});

export const upload_project_img = async (img: Buffer | string) => {
    try {
       
        const optimizedBuffer = await sharp(img)
            .resize(1080, 720, { fit: "inside", withoutEnlargement: true })
            .jpeg({ quality: 80, mozjpeg: true })
            .toBuffer();

        const uploadResult = await cloudinary.uploader.upload(
            `data:image/jpeg;base64,${optimizedBuffer.toString("base64")}`,
            { resource_type: "auto", quality: "auto", folder: "travelly/profile" }
        );
       

        return { public_id: uploadResult.public_id, secure_url: uploadResult.secure_url };
    } catch (error) {
        console.error("Error during image optimization or upload:", error);
        throw error;
    }
};

export const deleteImg = async (publicId: string) => {
    try {
        await cloudinary.uploader.destroy(publicId);
    } catch (error) {
        console.error("Error deleting image:", error);
        throw error;
    }
}; 
