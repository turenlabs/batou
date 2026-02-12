// PSB-A03-CMD-001: Deployment script runner
// CWE: CWE-78
// Expected: GTSS-INJ-005, GTSS-INJ-006
const express = require("express");
const { exec } = require("child_process");
const app = express();
app.use(express.json());

app.post("/api/deploy", (req, res) => {
  const { service, environment } = req.body;

  if (!["staging", "production"].includes(environment)) {
    return res.status(400).json({ error: "invalid environment" });
  }

  const cmd = `/opt/deploy/run.sh ${service} ${environment}`;
  exec(cmd, (err, stdout, stderr) => {
    if (err) {
      return res.status(500).json({ error: "deployment failed", stderr });
    }
    res.json({ status: "deployed", output: stdout });
  });
});

module.exports = app;
