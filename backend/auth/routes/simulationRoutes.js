const express = require("express");
const router = express.Router();
const { forwardToService } = require("./proxyUtil");

// POST /api/simulate -> forwards to Python Analyzer on port 5001
router.post("/simulate", forwardToService(5001));

// POST /api/clear-logs -> forwards to Python Analyzer on port 5001
router.post("/clear-logs", forwardToService(5001));

module.exports = router;
