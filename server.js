require("dotenv").config();
const express = require("express");
const jwt = require("jsonwebtoken");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const axios = require("axios");
const crypto = require("crypto");
const multer = require('multer');
const fs = require('fs');
const path = require('path');
const pdfParse = require('pdf-parse');
const mammoth = require('mammoth');

const app = express();
app.use(express.json());

const JWT_SECRET = process.env.JWT_SECRET;
const MONGO_URI = process.env.MONGO_URI;
const GEMINI_API_KEY = process.env.GEMINI_API_KEY;

mongoose.connect(MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
    .then(() => console.log("MongoDB connected"))
    .catch(err => console.error("MongoDB connection error:", err));

const applicantSchema = new mongoose.Schema({
    name: String,
    email: String,
    education: Object,
    experience: Object,
    skills: [String],
    summary: String
});
const Applicant = mongoose.model("Applicant", applicantSchema);

const ENCRYPTION_KEY = crypto.scryptSync(JWT_SECRET, 'salt', 32);

function encrypt(text) {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv("aes-256-cbc", ENCRYPTION_KEY, iv);
    let encrypted = cipher.update(text, "utf8", "hex");
    encrypted += cipher.final("hex");
    return iv.toString("hex") + encrypted;
}

function decrypt(text) {
    const iv = Buffer.from(text.slice(0, 32), "hex");
    const encryptedText = text.slice(32);
    const decipher = crypto.createDecipheriv("aes-256-cbc", ENCRYPTION_KEY, iv);
    let decrypted = decipher.update(encryptedText, "hex", "utf8");
    decrypted += decipher.final("utf8");
    return decrypted;
}

const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        const uploadPath = path.join(__dirname, 'uploads');
        if (!fs.existsSync(uploadPath)) {
            fs.mkdirSync(uploadPath);
        }
        cb(null, uploadPath);
    },
    filename: (req, file, cb) => {
        cb(null, `${Date.now()}-${file.originalname}`);
    }
});

const fileFilter = (req, file, cb) => {
    const allowedTypes = ['application/pdf', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'];
    if (allowedTypes.includes(file.mimetype)) {
        cb(null, true);
    } else {
        cb(new Error('Invalid file type. Only PDF and DOCX are allowed.'), false);
    }
};

const upload = multer({ 
    storage: storage,
    fileFilter: fileFilter,
    limits: { fileSize: 5 * 1024 * 1024 } 
});

app.post("/auth/login", (req, res) => {
    const { username, password } = req.body;
    if (username === "naval.ravikant" && password === "05111974") {
        const token = jwt.sign({ username }, JWT_SECRET, { expiresIn: "1h" });
        return res.json({ JWT: token });
    }
    res.status(401).json({ error: "Invalid credentials" });
});

function verifyToken(req, res, next) {
    const token = req.headers["authorization"];
    if (!token) return res.status(401).json({ error: "Access denied" });
    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) return res.status(401).json({ error: "Invalid token" });
        req.user = decoded;
        next();
    });
}
// LLM Prompt for Resume Parsing
const generateLLMPrompt = (rawText) => `
Extract structured data from the following raw text and format it into this JSON structure:
{
  "name": "",
  "email": "",
  "education": {
    "degree": "",
    "branch": "",
    "institution": "",
    "year": ""
  },
  "experience": {
    "job_title": "",
    "company": ""
  },
  "skills": [],
  "summary": ""
}

Raw Text: """${rawText}"""
`;

// Function: Call Google Gemini API
async function processWithLLM(rawText) {
    try {
        const response = await axios.post(
            "https://generativelanguage.googleapis.com/v1beta/models/gemini-pro:generateContent",
            {
                contents: [{ parts: [{ text: generateLLMPrompt(rawText) }] }],
            },
            {
                headers: { "Content-Type": "application/json" },
                params: { key: process.env.GEMINI_API_KEY },
            }
        );

        const llmResponse = response.data?.candidates?.[0]?.content?.parts?.[0]?.text;
        return JSON.parse(llmResponse); // Ensure valid JSON response
    } catch (error) {
        console.error("Error processing with LLM:", error.response?.data || error.message);
        return null;
    }
}

// Resume Data Enrichment API
app.post("/resume/enrich", verifyToken, async (req, res) => {
    try {
        const { raw_text } = req.body;
        if (!raw_text) return res.status(404).json({ error: "No raw text provided" });

        const structuredData = await processWithLLM(raw_text);
        if (!structuredData) return res.status(500).json({ error: "Failed to process text" });

        // Encrypt sensitive fields before storing in MongoDB
        structuredData.name = encrypt(structuredData.name);
        structuredData.email = encrypt(structuredData.email);

        // Store in MongoDB
        const result = await Applicant.create(structuredData);
        if (!result) return res.status(500).json({ error: "Database insertion failed" });

        res.status(200).json({ message: "Resume processed successfully", data: structuredData });
    } catch (error) {
        console.error("Error:", error);
        res.status(500).json({ error: "Internal Server Error" });
    }
});

app.post("/resume/search", verifyToken, async (req, res) => {
    const { name } = req.body;
    if (!name) return res.status(400).json({ error: "Name is required" });

    try {
        const applicants = await Applicant.find();
        const regex = new RegExp(name, "i");
        const results = applicants.filter(a => regex.test(decrypt(a.name)));

        if (!results.length) return res.status(404).json({ error: "No matching records found" });

        res.status(200).json(results.map(a => ({
            name: decrypt(a.name),
            email: decrypt(a.email),
            education: a.education,
            experience: a.experience,
            skills: a.skills,
            summary: a.summary
        })));
    } catch (error) {
        console.error("Error details:", error);  // Log error for debugging
        res.status(500).json({ error: "Error searching records", details: error.message });
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
