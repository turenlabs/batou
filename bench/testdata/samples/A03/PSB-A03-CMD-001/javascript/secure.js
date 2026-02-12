// PSB-A03-CMD-001: Deployment script runner
// CWE: CWE-78
// Expected: (none - secure)
const express = require("express");
const { execFile } = require("child_process");
const app = express();
app.use(express.json());

const ALLOWED_SERVICES = new Set(["api", "web", "worker", "scheduler"]);

app.post("/api/deploy", (req, res) => {
  const { service, environment } = req.body;

  if (!["staging", "production"].includes(environment)) {
    return res.status(400).json({ error: "invalid environment" });
  }
  if (!ALLOWED_SERVICES.has(service)) {
    return res.status(400).json({ error: "unknown service" });
  }

  execFile("/opt/deploy/run.sh", [service, environment], (err, stdout, stderr) => {
    if (err) {
      return res.status(500).json({ error: "deployment failed" });
    }
    res.json({ status: "deployed", output: stdout });
  });
});

module.exports = app;
