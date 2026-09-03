/**
 * SecureShare Cybersecurity - Auth Audit Logger
 * Writes structured access and security logs to backend/logs/app_access.log
 * Compatible with backend/analyzer/parser.py
 */

const fs = require("fs");
const path = require("path");

const LOG_DIR = path.resolve(__dirname, "../../logs");
const LOG_FILE = process.env.AUDIT_LOG_FILE || path.join(LOG_DIR, "app_access.log");

// Ensure log directory exists
try {
    if (!fs.existsSync(LOG_DIR)) {
        fs.mkdirSync(LOG_DIR, { recursive: true });
    }
} catch (err) {
    console.error("[AuditLogger] Error creating log directory:", err.message);
}

/**
 * Clean and format IP address
 */
function getClientIp(req) {
    if (!req) return "127.0.0.1";
    let ip = req.headers?.["x-forwarded-for"] || req.socket?.remoteAddress || req.ip || "127.0.0.1";
    if (typeof ip === "string" && ip.includes(",")) {
        ip = ip.split(",")[0].trim();
    }
    if (typeof ip === "string" && ip.startsWith("::ffff:")) {
        ip = ip.substring(7);
    }
    if (ip === "::1") {
        ip = "127.0.0.1";
    }
    return ip || "127.0.0.1";
}

/**
 * Format timestamp as ISO UTC
 */
function getTimestamp() {
    return new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
}

/**
 * Core log writer
 */
function logAccess({
    req,
    statusCode = 200,
    user = "anonymous",
    message = "",
    ip = null,
    method = null,
    endpoint = null,
    userAgent = null
}) {
    try {
        const clientIp = ip || getClientIp(req);
        const httpMethod = (method || req?.method || "GET").toUpperCase();
        const requestEndpoint = endpoint || req?.originalUrl || req?.url || "/";
        const cleanUser = (user || "anonymous").replace(/"/g, '\\"');
        const cleanMsg = (message || "").replace(/"/g, '\\"');
        const rawUa = userAgent || req?.headers?.["user-agent"] || "-";
        const cleanUa = (rawUa || "-").replace(/"/g, '\\"');
        const timestamp = getTimestamp();

        // Format: [2026-08-31T10:30:15Z] IP="127.0.0.1" METHOD="POST" ENDPOINT="/api/auth/login" STATUS=200 USER="user" MSG="Message" USER_AGENT="UA"
        const logLine = `[${timestamp}] IP="${clientIp}" METHOD="${httpMethod}" ENDPOINT="${requestEndpoint}" STATUS=${statusCode} USER="${cleanUser}" MSG="${cleanMsg}" USER_AGENT="${cleanUa}"\n`;

        const targetFile = process.env.AUDIT_LOG_FILE || LOG_FILE;
        try {
            const dir = path.dirname(targetFile);
            if (!fs.existsSync(dir)) {
                fs.mkdirSync(dir, { recursive: true });
            }
            fs.appendFileSync(targetFile, logLine, "utf8");
        } catch (err) {
            console.error("[AuditLogger] Failed to write log:", err.message);
        }

        return logLine;
    } catch (err) {
        console.error("[AuditLogger] Unexpected error in logAccess:", err.message);
        return null;
    }
}

/**
 * Helper: Log successful login
 */
function logLoginSuccess(req, user) {
    return logAccess({
        req,
        statusCode: 200,
        user: typeof user === "string" ? user : user?.email || user?.name || "user",
        message: "Login successful: Session established"
    });
}

/**
 * Helper: Log failed login
 */
function logLoginFailure(req, user, reason = "Invalid credentials provided") {
    return logAccess({
        req,
        statusCode: 401,
        user: typeof user === "string" ? user : user?.email || user?.name || "unknown",
        message: `Login failed: ${reason}`
    });
}

/**
 * Helper: Log registration
 */
function logRegistration(req, user, success = true, reason = "") {
    return logAccess({
        req,
        statusCode: success ? 201 : 400,
        user: typeof user === "string" ? user : user?.email || user?.name || "anonymous",
        message: success ? "User registered successfully" : `Registration failed: ${reason}`
    });
}

/**
 * Helper: Log unauthorized or forbidden access
 */
function logSecurityViolation(req, user = "anonymous", message = "Unauthorized access attempt", statusCode = 401) {
    return logAccess({
        req,
        statusCode,
        user: typeof user === "string" ? user : user?.email || "anonymous",
        message
    });
}

module.exports = {
    LOG_FILE,
    LOG_DIR,
    logAccess,
    logLoginSuccess,
    logLoginFailure,
    logRegistration,
    logSecurityViolation,
    getClientIp
};
