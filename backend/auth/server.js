const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const path = require("path");

require("dotenv").config({ path: path.resolve(__dirname, "../../.env") });
require("dotenv").config();

const authRoutes = require("./routes/auth");
const { LOG_FILE } = require("./utils/auditLogger");

const app = express();

app.use(cors());
app.use(express.json());

// Mount authentication routes
app.use("/api/auth", authRoutes);

// Health check endpoint
app.get(["/api/health", "/api/auth/health", "/health"], (req, res) => {
    res.json({
        status: "healthy",
        service: "SecureShare Authentication API",
        version: "1.0.0",
        timestamp: new Date().toISOString(),
        db_connected: mongoose.connection.readyState === 1,
        log_file: LOG_FILE
    });
});

app.get("/", (req, res) => {
    res.json({
        name: "SecureShare Authentication Backend",
        status: "online",
        endpoints: {
            "POST /api/auth/register": "Register a new user (name, email, password, role)",
            "POST /api/auth/login": "User login (email, password)",
            "GET /api/auth/profile": "Get current user profile (Bearer token required)",
            "GET /api/auth/admin": "Admin protected route (Bearer token required)",
            "GET /api/health": "Health check"
        }
    });
});

const PORT = process.env.PORT || process.env.AUTH_PORT || 5000;
const MONGO_URI = process.env.MONGO_URI;

let server = null;

if (MONGO_URI) {
    mongoose
        .connect(MONGO_URI)
        .then(() => {
            console.log("[SecureShare Auth] MongoDB connected successfully");
        })
        .catch((error) => {
            console.warn("[SecureShare Auth] MongoDB connection warning:", error.message);
        });
} else {
    console.log("[SecureShare Auth] No MONGO_URI provided; running in standalone mode");
}

if (require.main === module) {
    server = app.listen(PORT, () => {
        console.log(`[SecureShare Auth] Server running on port ${PORT}`);
        console.log(`[SecureShare Auth] Audit logs routed to: ${LOG_FILE}`);
    });
}

module.exports = app;