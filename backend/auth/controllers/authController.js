const User = require("../models/User");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { logLoginSuccess, logLoginFailure, logRegistration, logAccess } = require("../utils/auditLogger");

const JWT_SECRET = process.env.JWT_SECRET || "secureshare_jwt_secret_dev_key_2026";

// REGISTER
const register = async (req, res) => {
    try {
        const { name, email, password, role } = req.body;

        if (!name || !email || !password) {
            logRegistration(req, email || "anonymous", false, "Missing required fields");
            return res.status(400).json({
                message: "Name, email, and password are required"
            });
        }

        const existingUser = await User.findOne({ email });

        if (existingUser) {
            logRegistration(req, email, false, "User already exists");
            return res.status(400).json({
                message: "User already exists"
            });
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        const user = await User.create({
            name,
            email,
            password: hashedPassword,
            role: role === "admin" ? "admin" : "user"
        });

        logRegistration(req, user, true);

        res.status(201).json({
            message: "Registration successful",
            user: {
                id: user._id,
                name: user.name,
                email: user.email,
                role: user.role
            }
        });

    } catch (error) {
        logRegistration(req, req.body?.email || "anonymous", false, error.message);
        res.status(500).json({
            message: "Registration failed",
            error: error.message
        });
    }
};


// LOGIN
const login = async (req, res) => {
    try {
        const { email, username, password } = req.body;
        const userIdentifier = email || username;

        if (!userIdentifier || !password) {
            logLoginFailure(req, userIdentifier || "anonymous", "Missing credentials");
            return res.status(400).json({
                message: "Email/username and password are required"
            });
        }

        let user = await User.findOne({ email: userIdentifier });
        if (!user && username) {
            user = await User.findOne({ username: userIdentifier });
        }
        if (!user && userIdentifier.includes("@")) {
            user = await User.findOne({ email: userIdentifier });
        }
        if (!user) {
            // Check standalone fallback
            user = User.getSeededUser && User.getSeededUser(userIdentifier);
        }

        if (!user) {
            logLoginFailure(req, userIdentifier, `User '${userIdentifier}' not found`);
            return res.status(401).json({
                message: "Invalid email or password"
            });
        }

        const isMatch = await bcrypt.compare(password, user.password);

        if (!isMatch) {
            logLoginFailure(req, email, `Incorrect password for user '${email}'`);
            return res.status(401).json({
                message: "Invalid email or password"
            });
        }

        const token = jwt.sign(
            {
                id: user._id,
                email: user.email,
                name: user.name,
                role: user.role
            },
            JWT_SECRET,
            {
                expiresIn: "1h"
            }
        );

        logLoginSuccess(req, user);

        res.json({
            message: "Login successful",
            token,
            user: {
                id: user._id,
                name: user.name,
                email: user.email,
                role: user.role
            }
        });

    } catch (error) {
        logLoginFailure(req, req.body?.email || "unknown", `Internal error: ${error.message}`);
        res.status(500).json({
            message: "Login failed",
            error: error.message
        });
    }
};


module.exports = {
    register,
    login
};