const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const path = require("path");

require("dotenv").config({ path: path.resolve(__dirname, "../../.env") });
require("dotenv").config();

const authRoutes = require("./routes/auth");
const simulationRoutes = require("./routes/simulationRoutes");
const fileRoutes = require("./routes/fileRoutes");
const alertRoutes = require("./routes/alertRoutes");
const { LOG_FILE } = require("./utils/auditLogger");
const { spawn } = require("child_process");
const fs = require("fs");

const app = express();

// Explicit and permissive CORS support for Vercel, Render, and local development
const allowedOrigins = [
  "https://secureshare-cybersecurity.vercel.app",
  "https://secureshare-api-suph.onrender.com",
  "http://localhost:5173",
  "http://localhost:5174",
  "http://localhost:3000",
  "http://127.0.0.1:5173",
  "http://127.0.0.1:5174"
];

app.use(
  cors({
    origin: (origin, callback) => {
      if (!origin || allowedOrigins.includes(origin) || origin.endsWith(".vercel.app") || origin.endsWith(".onrender.com")) {
        return callback(null, true);
      }
      return callback(null, true); // Allow other clients / tools
    },
    credentials: true,
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"],
    allowedHeaders: ["Content-Type", "Authorization", "X-User", "X-Filename", "X-Description", "X-User-Email"]
  })
);

app.use(express.json());

// 1. Mount Authentication Routes (/api/auth)
app.use("/api/auth", authRoutes);

// 2. Mount File Vault Routes (/api/files)
app.use("/api/files", fileRoutes);

// 3. Mount Simulation Routes (/api/simulate, /api/clear-logs)
app.use("/api", simulationRoutes);

// 4. Mount Alert and Log Routes (/api/alerts, /api/stats, /api/logs, /api/analyze)
app.use("/api", alertRoutes);

// Health check endpoints
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

// Root fallback health-check route
app.get("/", (req, res) => {
    res.status(200).json({ status: "OK", message: "SecureShare API is running" });
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

function autoSpawnMicroservices() {
    const analyzerPath = path.resolve(__dirname, "../analyzer/server.py");
    const filesPath = path.resolve(__dirname, "../files/server.py");

    if (fs.existsSync(analyzerPath)) {
        try {
            const analyzer = spawn("python3", [analyzerPath, "--port", "5001"], {
                detached: false,
                stdio: "ignore"
            });
            analyzer.unref();
            console.log("[SecureShare Gateway] Spawned Threat Analyzer daemon on port 5001");
        } catch (e) {
            console.warn("[SecureShare Gateway] Notice spawning analyzer:", e.message);
        }
    }

    if (fs.existsSync(filesPath)) {
        try {
            const files = spawn("python3", [filesPath, "--port", "8001"], {
                detached: false,
                stdio: "ignore"
            });
            files.unref();
            console.log("[SecureShare Gateway] Spawned Files Vault daemon on port 8001");
        } catch (e) {
            console.warn("[SecureShare Gateway] Notice spawning files vault:", e.message);
        }
    }
}

if (require.main === module) {
    autoSpawnMicroservices();
    server = app.listen(PORT, () => {
        console.log(`[SecureShare Gateway] Unified API running on port ${PORT}`);
        console.log(`[SecureShare Gateway] Audit logs routed to: ${LOG_FILE}`);
    });
}

module.exports = app;