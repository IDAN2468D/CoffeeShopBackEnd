const mongoose = require("mongoose");

const userSchema = new mongoose.Schema({
    name: {
        type: String,
        required: true,
    },
    email: {
        type: String,
        required: true,
        unique: true,
    },
    password: {
        type: String,
        required: true,
    },
    verified: {
        type: Boolean,
        default: false,
    },
    resetToken: {
        type: String,
        required: false,
    },
    resetTokenExpires: {
        type: Date,
        default: Date.now() + 3600000,
    },
    verificationToken: String,
    profilePic: {
        type: String,
        required: false,
    },
});

const User = mongoose.model("User", userSchema);

module.exports = User;
