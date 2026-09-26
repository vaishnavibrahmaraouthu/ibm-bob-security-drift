"use strict";

const express = require("express");
const fs      = require("fs");
const path    = require("path");

const { analyzeRepository } = require("../services/analyzeRepository");

const router = express.Router();

// POST /api/analysis
// Body: { "repositoryPath": "<local path>" }
// Returns the structured AnalysisResult JSON from the analysis engine.
router.post("/", async (req, res) => {
  try {
    const { repositoryPath } = req.body;

    // ── Input validation ───────────────────────────────────────────────────
    if (!repositoryPath) {
      return res.status(400).json({
        message: "repositoryPath is required"
      });
    }

    if (typeof repositoryPath !== "string") {
      return res.status(400).json({
        message: "repositoryPath must be a string"
      });
    }

    const resolved = path.resolve(repositoryPath);

    if (!fs.existsSync(resolved)) {
      return res.status(400).json({
        message: "Repository path does not exist"
      });
    }

    if (!fs.statSync(resolved).isDirectory()) {
      return res.status(400).json({
        message: "Repository path must be a directory"
      });
    }

    // ── Run analysis ───────────────────────────────────────────────────────
    const result = analyzeRepository(resolved);

    res.json(result);

  } catch (error) {
    console.error(error);

    res.status(500).json({
      message: "Analysis failed"
    });
  }
});

module.exports = router;
