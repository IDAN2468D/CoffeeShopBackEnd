const express = require('express');
const bodyParser = require("body-parser");
const mongoose = require("mongoose");
const crypto = require("crypto");
const nodemailer = require("nodemailer");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const bcrypt = require("bcrypt");
const multer = require('multer');
const path = require('path');
const fs = require('fs');

const app = express();
const port = process.env.PORT || 4000;

app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(cors());

// Connect to MongoDB
mongoose.connect(process.env.MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
    .then(() => console.log("Connected to MongoDB"))
    .catch(err => console.error("Error connecting to MongoDB:", err));

// Define User model
const User = require("./models/user");

// Configure multer for file uploads
const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, './uploads/'),
    filename: (req, file, cb) => cb(null, `${file.fieldname}-${Date.now()}${path.extname(file.originalname)}`)
});
const upload = multer({ storage, limits: { fileSize: 1000000 }, fileFilter: checkFileType }).single('profilePic');

function checkFileType(file, cb) {
    const filetypes = /jpeg|jpg|png|gif/;
    const extname = filetypes.test(path.extname(file.originalname).toLowerCase());
    const mimetype = filetypes.test(file.mimetype);
    cb(mimetype && extname ? null : 'Error: Images Only!', mimetype && extname);
}

// Start server
app.listen(port, () => console.log(`Server is running on port ${port}`));

// Define routes
app.post("/register", async (req, res) => {
    try {
        const { name, email, password } = req.body;
        const hashedPassword = await bcrypt.hash(password, 10);
        if (await User.findOne({ email })) {
            return res.status(400).json({ message: "Email already registered" });
        }
        const newUser = new User({ name, email, password: hashedPassword, verificationToken: crypto.randomBytes(20).toString("hex") });
        await newUser.save();
        await sendVerificationEmail(newUser.email, newUser.verificationToken);
        res.status(201).json({ message: "Registration successful. Please check your email for verification." });
    } catch (error) {
        res.status(500).json({ message: "Registration failed" });
    }
});

const sendVerificationEmail = async (email, verificationToken) => {
    const transporter = nodemailer.createTransport({
        service: "Gmail",
        auth: { user: process.env.EMAIL, pass: process.env.EMAIL_PASS },
        tls: { rejectUnauthorized: false }
    });
    const mailOptions = {
        from: process.env.EMAIL,
        to: email,
        subject: "Email Verification",
        text: `Please click the following link to verify your email: https://yourdomain.com/verify/${verificationToken}`
    };
    try {
        await transporter.sendMail(mailOptions);
    } catch (error) {
        console.error("Error sending verification email:", error);
    }
};

app.get("/verify/:token", async (req, res) => {
    try {
        const user = await User.findOne({ verificationToken: req.params.token });
        if (!user) return res.status(404).json({ message: "Invalid verification token" });
        user.verified = true;
        user.verificationToken = undefined;
        await user.save();
        res.status(200).json({ message: "Email verified successfully" });
    } catch (error) {
        res.status(500).json({ message: "Email verification failed" });
    }
});

app.get('/user-exist', async (req, res) => {
    const response = await checkUserExist(req.query.email);
    res.json(response);
});

const checkUserExist = async (email) => {
    try {
        return !!await User.findOne({ email });
    } catch (error) {
        console.error("Error checking user existence:", error);
        return false;
    }
};

const generateSecretKey = () => crypto.randomBytes(32).toString("hex");
const secretKey = generateSecretKey();

app.post("/login", async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await User.findOne({ email });
        if (!user || !(await bcrypt.compare(password, user.password))) {
            return res.status(401).json({ message: "Invalid email or password" });
        }
        const token = jwt.sign({ userId: user._id }, secretKey);
        res.status(200).json({ token });
    } catch (error) {
        res.status(500).json({ message: "Login failed" });
    }
});

app.post("/forgot-password", async (req, res) => {
    try {
        const user = await User.findOne({ email: req.body.email });
        if (!user) return res.status(404).json({ message: "User not found" });
        user.resetToken = crypto.randomBytes(20).toString('hex');
        user.resetTokenExpires = Date.now() + 3600000;
        await user.save();
        await sendResetPasswordEmail(user.email, user.resetToken);
        res.status(200).json({ message: "Password reset instructions sent to your email" });
    } catch (error) {
        res.status(500).json({ message: "Forgot password failed" });
    }
});

const sendResetPasswordEmail = async (email, resetToken) => {
    const transporter = nodemailer.createTransport({
        service: "Gmail",
        auth: { user: process.env.EMAIL, pass: process.env.EMAIL_PASS },
        tls: { rejectUnauthorized: false }
    });
    const mailOptions = {
        from: process.env.EMAIL,
        to: email,
        subject: "Reset Password",
        text: `To reset your password, click the following link: https://yourdomain.com/reset-password/${resetToken}`
    };
    try {
        await transporter.sendMail(mailOptions);
    } catch (error) {
        console.error("Error sending reset password email:", error);
    }
};

app.post("/reset-password/:token", async (req, res) => {
    try {
        const user = await User.findOne({ resetToken: req.params.token, resetTokenExpires: { $gt: Date.now() } });
        if (!user) return res.status(400).json({ message: "Invalid or expired reset token" });
        user.password = await bcrypt.hash(req.body.newPassword, 10);
        user.resetToken = undefined;
        user.resetTokenExpires = undefined;
        await user.save();
        res.status(200).json({ message: "Password reset successful" });
    } catch (error) {
        res.status(500).json({ message: "Password reset failed" });
    }
});

// Route to upload profile picture
app.post('/upload-profile-pic', (req, res) => {
    upload(req, res, async (err) => {
        if (err) return res.status(400).json({ message: err.message });
        if (!req.file) return res.status(400).json({ message: 'No file selected' });
        try {
            const user = await User.findById(req.body.userId);
            if (!user) return res.status(404).json({ message: 'User not found' });
            user.profilePic = req.file.path;
            await user.save();
            res.status(200).json({ message: 'Profile picture uploaded successfully', path: req.file.path });
        } catch (error) {
            res.status(500).json({ message: 'Profile picture upload failed' });
        }
    });
});
