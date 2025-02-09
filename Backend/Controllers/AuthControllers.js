const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const User = require("../Models/userModel");

const app = express();
app.use(express.json());
app.use(cookieParser());

// Signup Controller
const signup = async (req, res) => {
    const { username, email, password } = req.body;
    try {
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ message: "User already exists. Please log in." });
        }
        const hashedPassword = await bcrypt.hash(password, 10);

        // Include username in the JWT payload
        const token = jwt.sign(
            { userId: existingUser.username, username: existingUser.username, email: existingUser.email },
            { expiresIn: '24h' }
        );

        const user = new User({
            name: username,
            email: email,
            password: hashedPassword,
        });
        await user.save();
        console.log("Signup successful");

        res.cookie('token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict'
        });
        res.status(201).json({ message: "Signup successful", token });
    } catch (error) {
        console.error("Signup error:", error);
        res.status(500).json({ message: "Internal Server Error" });
    }
};

const login = async (req, res) => {
    const { username, password } = req.body;
    try {
        const existingUser = await User.findOne({ name: username });
        if (!existingUser) {
            return res.status(400).json({ message: "User not found. Please sign up." });
        }
        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) {
            return res.status(401).json({ message: "Invalid credentials" });
        }

        // Include username in the JWT payload
        const token = jwt.sign(
            { userId: existingUser.username, username: existingUser.username, email: existingUser.email }, // Ensure username is included here
            { expiresIn: '24h' }
        );

        res.cookie('token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict'
        });
        res.status(200).json({ message: "Logged in successfully", token });
    } catch (error) {
        console.error("Login error:", error);
        res.status(500).json({ message: "Internal Server Error" });
    }
};

// Validate Authentication Controller
const validateAuth = async (req, res) => {
    try {
        const cookieHeader = req.headers.cookie;
        if (!cookieHeader) {
            return res.status(401).json({ isAuthenticated: false, message: "No cookie provided" });
        }
        const token = cookieHeader
            .split('; ')
            .find(row => row.startsWith('token='))
            ?.split('=')[1];
        if (!token) {
            return res.status(401).json({ isAuthenticated: false, message: "Token not found in cookies" });
        }
        jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
            if (err) {
                return res.status(401).json({ isAuthenticated: false, message: "Invalid or expired token" });
            }
            return res.status(200).json({ 
                isAuthenticated: true, 
                userId: decoded.userId,
                email: decoded.email
            });
        });
    } catch (error) {
        console.error("Token validation error:", error);
        return res.status(500).json({ isAuthenticated: false, message: "Server error" });
    }
};

// Logout Controller
const logout = (req, res) => {
    res.cookie('token', '', { expires: new Date(0), httpOnly: true });
    res.status(200).json({ message: "Logged out successfully" });
};

// Export controllers
module.exports = {
    signup,
    login,
    validateAuth,
    logout
};
