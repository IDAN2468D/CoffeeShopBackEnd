const express = require('express');
const bodyParser = require("body-parser");
const mongoose = require("mongoose");
const crypto = require("crypto");
const nodemailer = require("nodemailer");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const bcrypt = require("bcrypt");

const app = express()
const port = 4000;
const ip = "localhost"

app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(cors());

app.listen(port, ip, () => {
    console.log(`Server is running on ${ip} port :${port}`);
});

mongoose
    .connect("mongodb+srv://idankzm:idankzm2468@cluster0.purdk.mongodb.net/CoffeeShop?retryWrites=true&w=majority", {
        useNewUrlParser: true,
        useUnifiedTopology: true,
    })
    .then(() => {
        console.log("Connected to MongoDB");
    })
    .catch((err) => {
        console.log("Error connecting to MongoDb", err);
    });

const User = require("./models/user");

app.post("/register", async (req, res) => {
    try {
        const { name, email, password } = req.body;
        const hashedPassword = await bcrypt.hash(password, 10);
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            console.log("Email already registered:", email);
            return res.status(400).json({ message: "Email already registered" });
        }
        const newUser = new User({ name, email, password: hashedPassword });
        newUser.verificationToken = crypto.randomBytes(20).toString("hex");
        await newUser.save();
        console.log("New User Registered:", newUser);
        sendVerificationEmail(newUser.email, newUser.verificationToken);

        res.status(201).json({
            message:
                "Registration successful. Please check your email for verification.",
        });
    } catch (error) {
        console.log("Error during registration:", error);
        res.status(500).json({ message: "Registration failed" });
    }
});

const sendVerificationEmail = async (email, verificationToken) => {
    const transporter = nodemailer.createTransport({
        service: "Gmail",
        auth: {
            user: "idankzm@gmail.com",
            pass: "yddxnhwipxuecbne",
        },
        tls: {
            rejectUnauthorized: false,
        },
    });
    const mailOptions = {
        from: "idankzm@gmail.com",
        to: email,
        subject: "Email Verification",
        text: `Please click the following link to verify your email: http://192.168.1.190:4000/verify/${verificationToken}`,
    };
    try {
        await transporter.sendMail(mailOptions);
        console.log("Verification email sent successfully");
    } catch (error) {
        console.error("Error sending verification email:", error);
    }
};

app.get("/verify/:token", async (req, res) => {
    try {
        const token = req.params.token;
        const user = await User.findOne({ verificationToken: token });
        if (!user) {
            return res.status(404).json({ message: "Invalid verification token" });
        }
        user.verified = true;
        user.verificationToken = undefined;
        await user.save();
        res.status(200).json({ message: "Email verified successfully" });
    } catch (error) {
        res.status(500).json({ message: "Email verification Failed" });
    }
});

app.get('/user-exist', async (req, res, next) => {
    const { email } = req.query;
    const response = await checkUserExist(email);
    res.json(response);
});

const checkUserExist = async (email) => {
    try {
        const existingUser = await User.findOne({ email });
        return !!existingUser;
    } catch (error) {
        console.error("Error checking user existence:", error);
        return false;
    }
};

const generateSecretKey = () => {
    const secretKey = crypto.randomBytes(32).toString("hex");

    return secretKey
}

const secretKey = generateSecretKey();

app.post("/login", async (req, res) => {
    try {
        const { email, password } = req.body;

        const user = await User.findOne({ email });
        if (!user) {
            return res.status(401).json({ message: "Invalid email or password" });
        }

        const passwordMatch = await bcrypt.compare(password, user.password);
        if (!passwordMatch) {
            return res.status(401).json({ message: "Invalid password" });
        }

        const token = jwt.sign({ userId: user._id }, secretKey);
        res.status(200).json({ token });
    } catch (error) {
        console.error('Login Error:', error);
        res.status(500).json({ message: "Login Failed" });
    }
});

app.post("/forgot-password", async (req, res) => {
    try {
        const { email } = req.body;
        const user = await User.findOne({ email });

        if (!user) {
            return res.status(404).json({ message: "User not found" });
        }

        const resetToken = require('crypto').randomBytes(20).toString('hex');
        user.resetToken = resetToken;
        user.resetTokenExpires = Date.now() + 3600000;
        await user.save();

        sendResetPasswordEmail(user.email, resetToken);
        await sendVerificationEmail(user.email, resetToken);
        console.log('Email:', user.email);
        console.log('Reset Token:', resetToken);

        res.status(200).json({
            message: "Password reset instructions sent to your email",
        });
    } catch (error) {
        console.error("Error during forgot password:", error);
        res.status(500).json({ message: "Forgot password failed" });
    }
});

const sendResetPasswordEmail = async (email, resetToken) => {
    const transporter = nodemailer.createTransport({
        service: "Gmail",
        auth: {
            user: "idankzm@gmail.com",
            pass: "yddxnhwipxuecbne",
        },
        tls: {
            rejectUnauthorized: false,
        },
    });
    const mailOptions = {
        from: "idankzm@gmail.com",
        to: email,
        subject: "Reset Password",
        text: `To reset your password, click the following link: http://192.168.1.190:4000/reset-password/${resetToken}`,
    };
    try {
        await transporter.sendMail(mailOptions);
        console.log("Reset password email sent successfully");
    } catch (error) {
        console.error("Error sending reset password email:", error);
    }
};

app.post("/reset-password/:token", async (req, res) => {
    try {
        const { token } = req.params;
        const { newPassword } = req.body;

        const user = await User.findOne({
            resetToken: token,
            resetTokenExpires: { $gt: Date.now() },
        });
        if (!user || !user._id) {
            console.log('Token check failed. User not found or expired.');
            return res.status(400).json({ message: "Invalid or expired reset token" });
        }
        user.password = await bcrypt.hash(newPassword, 10);
        user.resetToken = undefined;
        user.resetTokenExpires = undefined;
        await user.save();
        res.status(200).json({ message: "Password reset successful" });
    } catch (error) {
        console.error("Error during password reset:", error);
        res.status(500).json({ message: "Password reset failed" });
    }
});
