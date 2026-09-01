/**
 * SecureShare Cybersecurity Platform Launcher
 * Starts Auth API (5000), Analyzer API (5001), and Frontend (5173) concurrently
 */

const { spawn } = require("child_process");
const path = require("path");

const ROOT_DIR = __dirname;

const processes = [
    {
        name: "AUTH",
        cmd: "node",
        args: ["backend/auth/server.js"],
        color: "\x1b[36m", // Cyan
        env: { ...process.env, PORT: "5000" }
    },
    {
        name: "ANALYZER",
        cmd: "python3",
        args: ["backend/analyzer/server.py", "--port", "5001"],
        color: "\x1b[32m", // Green
        env: { ...process.env, ANALYZER_PORT: "5001" }
    },
    {
        name: "FRONTEND",
        cmd: "npx",
        args: ["vite", "--host", "0.0.0.0", "--port", "5173"],
        cwd: path.join(ROOT_DIR, "frontend"),
        color: "\x1b[35m", // Magenta
        env: { ...process.env }
    }
];

const children = [];
const RESET = "\x1b[0m";

console.log("\n=======================================================");
console.log(" 🔐 Starting SecureShare Cybersecurity Platform");
console.log("=======================================================");
console.log("  • Auth Server API:     http://localhost:5000");
console.log("  • Threat Analyzer API: http://localhost:5001");
console.log("  • Frontend Dashboard:  http://localhost:5173");
console.log("=======================================================\n");

processes.forEach((proc) => {
    const child = spawn(proc.cmd, proc.args, {
        cwd: proc.cwd || ROOT_DIR,
        env: proc.env,
        stdio: ["ignore", "pipe", "pipe"],
        shell: true
    });

    children.push({ name: proc.name, child });

    const prefix = `${proc.color}[${proc.name}]${RESET} `;

    child.stdout.on("data", (data) => {
        const lines = data.toString().trim().split("\n");
        lines.forEach((line) => {
            if (line.trim()) console.log(`${prefix}${line}`);
        });
    });

    child.stderr.on("data", (data) => {
        const lines = data.toString().trim().split("\n");
        lines.forEach((line) => {
            if (line.trim()) console.error(`${prefix}${line}`);
        });
    });

    child.on("exit", (code, signal) => {
        console.log(`${prefix}Exited with code ${code ?? signal}`);
    });
});

function shutdown() {
    console.log("\n[SecureShare] Gracefully stopping all services...");
    children.forEach(({ child }) => {
        try {
            child.kill("SIGTERM");
        } catch {}
    });
    setTimeout(() => process.exit(0), 1000);
}

process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);
