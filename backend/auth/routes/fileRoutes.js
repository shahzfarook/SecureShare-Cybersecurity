const express = require("express");
const router = express.Router();
const { forwardToService } = require("./proxyUtil");

// Forwards all /api/files requests to Python File Vault on port 8001
router.use(forwardToService(8001));

module.exports = router;
