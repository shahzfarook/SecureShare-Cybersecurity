const jwt = require("jsonwebtoken");
const { logSecurityViolation } = require("../utils/auditLogger");

const JWT_SECRET = process.env.JWT_SECRET || "secureshare_jwt_secret_dev_key_2026";

const protect = (req, res, next) => {
    try {
        const authHeader = req.headers.authorization;

        if (!authHeader || !authHeader.startsWith("Bearer ")) {
            logSecurityViolation(req, "anonymous", "Unauthorized: Missing or invalid Bearer token", 401);
            return res.status(401).json({
                message: "Not authorized"
            });
        }

        const token = authHeader.split(" ")[1];

        const decoded = jwt.verify(
            token,
            JWT_SECRET
        );

        req.user = decoded;

        next();

    } catch (error) {
        logSecurityViolation(req, "anonymous", `Invalid or expired token: ${error.message}`, 401);
        return res.status(401).json({
            message: "Invalid or expired token"
        });
    }
};


const adminOnly = (req, res, next) => {
    if (!req.user || req.user.role !== "admin") {
        const username = req.user?.email || req.user?.name || "non-admin";
        logSecurityViolation(req, username, `Forbidden: Admin access required (role: ${req.user?.role || "none"})`, 403);
        return res.status(403).json({
            message: "Admin access required"
        });
    }

    next();
};


module.exports = {
    protect,
    adminOnly
};