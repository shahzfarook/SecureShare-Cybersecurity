const express = require("express");
const router = express.Router();
const { forwardToService } = require("./proxyUtil");

// GET /api/alerts -> forwards to Python Analyzer on port 5001
router.get("/alerts", forwardToService(5001));

// GET /api/stats -> forwards to Python Analyzer on port 5001
router.get("/stats", forwardToService(5001));

// GET /api/logs -> forwards to Python Analyzer on port 5001
router.get("/logs", forwardToService(5001));

// POST /api/analyze -> forwards to Python Analyzer on port 5001
router.post("/analyze", forwardToService(5001));

module.exports = router;
