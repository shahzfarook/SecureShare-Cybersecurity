const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const http = require("node:http");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");

const app = require("../server");
const {
    LOG_FILE,
    logAccess,
    logLoginSuccess,
    logLoginFailure,
    logRegistration,
    logSecurityViolation,
    getClientIp
} = require("../utils/auditLogger");
const { protect, adminOnly } = require("../middleware/authMiddleware");

const JWT_SECRET = process.env.JWT_SECRET || "secureshare_jwt_secret_dev_key_2026";

test.describe("SecureShare Auth & Audit Logger Suite", () => {

    test("1. Audit Logger formats and writes log lines correctly to disk", async () => {
        const testUser = `test_audit_user_${Date.now()}`;
        const mockReq = {
            headers: { "user-agent": "SecureShare-Audit-Test/1.0", "x-forwarded-for": "198.51.100.77" },
            method: "POST",
            originalUrl: "/api/auth/login"
        };

        const logLine = logLoginFailure(mockReq, testUser, "Invalid password attempt");
        assert.ok(logLine, "logLine should not be null");
        assert.match(logLine, /^\[\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\]/);
        assert.match(logLine, /IP="198\.51\.100\.77"/);
        assert.match(logLine, /METHOD="POST"/);
        assert.match(logLine, /ENDPOINT="\/api\/auth\/login"/);
        assert.match(logLine, /STATUS=401/);
        assert.match(logLine, new RegExp(`USER="${testUser}"`));
        assert.match(logLine, /MSG="Login failed: Invalid password attempt"/);

        // Verify file was written
        await new Promise((resolve) => setTimeout(resolve, 50));
        assert.ok(fs.existsSync(LOG_FILE), "Log file should exist on disk");
        const content = fs.readFileSync(LOG_FILE, "utf8");
        assert.ok(content.includes(testUser), "Log file should contain logged user");
    });

    test("2. getClientIp handles various proxy and direct IP formats", () => {
        assert.equal(getClientIp({ headers: { "x-forwarded-for": "203.0.113.195, 10.0.0.1" } }), "203.0.113.195");
        assert.equal(getClientIp({ headers: {}, socket: { remoteAddress: "::ffff:192.168.1.50" } }), "192.168.1.50");
        assert.equal(getClientIp({ headers: {}, socket: { remoteAddress: "::1" } }), "127.0.0.1");
        assert.equal(getClientIp(null), "127.0.0.1");
    });

    test("3. JWT Token Generation and Verification", () => {
        const payload = { id: "user123", email: "sec@secureshare.local", role: "admin" };
        const token = jwt.sign(payload, JWT_SECRET, { expiresIn: "1h" });
        assert.ok(typeof token === "string" && token.length > 20);

        const decoded = jwt.verify(token, JWT_SECRET);
        assert.equal(decoded.id, "user123");
        assert.equal(decoded.email, "sec@secureshare.local");
        assert.equal(decoded.role, "admin");
    });

    test("4. Password hashing and bcrypt comparison", async () => {
        const plainPassword = "SuperSecretSecurePassword!2026";
        const hashedPassword = await bcrypt.hash(plainPassword, 10);
        assert.notEqual(hashedPassword, plainPassword);

        const matches = await bcrypt.compare(plainPassword, hashedPassword);
        assert.equal(matches, true);

        const wrongMatches = await bcrypt.compare("WrongPassword123", hashedPassword);
        assert.equal(wrongMatches, false);
    });

    test("5. Middleware: protect rejects requests without token (401)", () => {
        const req = { headers: {} };
        let statusSent = null;
        let jsonSent = null;
        const res = {
            status: (code) => { statusSent = code; return res; },
            json: (data) => { jsonSent = data; return res; }
        };
        let nextCalled = false;

        protect(req, res, () => { nextCalled = true; });
        assert.equal(statusSent, 401);
        assert.equal(jsonSent.message, "Not authorized");
        assert.equal(nextCalled, false);
    });

    test("6. Middleware: protect approves requests with valid Bearer token", () => {
        const token = jwt.sign({ id: "user456", role: "user" }, JWT_SECRET);
        const req = { headers: { authorization: `Bearer ${token}` } };
        let nextCalled = false;
        const res = {
            status: () => res,
            json: () => res
        };

        protect(req, res, () => { nextCalled = true; });
        assert.equal(nextCalled, true);
        assert.equal(req.user.id, "user456");
        assert.equal(req.user.role, "user");
    });

    test("7. Middleware: adminOnly allows admin and denies user (403)", () => {
        const adminReq = { user: { role: "admin" } };
        let adminNext = false;
        adminOnly(adminReq, {}, () => { adminNext = true; });
        assert.equal(adminNext, true);

        const userReq = { user: { role: "user" } };
        let statusSent = null;
        const res = {
            status: (code) => { statusSent = code; return res; },
            json: () => res
        };
        let userNext = false;
        adminOnly(userReq, res, () => { userNext = true; });
        assert.equal(statusSent, 403);
        assert.equal(userNext, false);
    });

    test("8. Express App HTTP Endpoints (Health, Auth, Profile)", async () => {
        const server = http.createServer(app);
        await new Promise((resolve) => server.listen(0, resolve));
        const port = server.address().port;

        try {
            // Test GET /api/health
            const healthRes = await fetch(`http://127.0.0.1:${port}/api/health`);
            assert.equal(healthRes.status, 200);
            const healthData = await healthRes.json();
            assert.equal(healthData.status, "healthy");
            assert.equal(healthData.service, "SecureShare Authentication API");

            // Test POST /api/auth/login missing body validation
            const loginRes = await fetch(`http://127.0.0.1:${port}/api/auth/login`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({})
            });
            assert.equal(loginRes.status, 400);

            // Test GET /api/auth/profile without token (401)
            const profileRes = await fetch(`http://127.0.0.1:${port}/api/auth/profile`);
            assert.equal(profileRes.status, 401);

            // Test GET /api/auth/profile with valid token
            const token = jwt.sign({ id: "test_id", email: "tester@secureshare.local", role: "user" }, JWT_SECRET);
            const authProfileRes = await fetch(`http://127.0.0.1:${port}/api/auth/profile`, {
                headers: { Authorization: `Bearer ${token}` }
            });
            assert.equal(authProfileRes.status, 200);
            const profileData = await authProfileRes.json();
            assert.equal(profileData.user.email, "tester@secureshare.local");

        } finally {
            await new Promise((resolve) => server.close(resolve));
        }
    });

});
