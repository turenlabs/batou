// PSB-A07-JWT-001: JWT authentication middleware
// CWE: CWE-345, CWE-347
// Expected: GTSS-SEC-001, GTSS-AUTH-003
const express = require("express");
const jwt = require("jsonwebtoken");
const app = express();
app.use(express.json());

const SECRET = "mysecretkey123";

function authMiddleware(req, res, next) {
  const header = req.headers.authorization;
  if (!header) {
    return res.status(401).json({ error: "missing authorization header" });
  }

  const token = header.replace("Bearer ", "");
  try {
    const decoded = jwt.decode(token);
    req.user = decoded;
    next();
  } catch (err) {
    res.status(401).json({ error: "invalid token" });
  }
}

app.post("/api/login", (req, res) => {
  const { username, password } = req.body;
  // authenticate user (simplified)
  const token = jwt.sign({ sub: username, role: "user" }, SECRET);
  res.json({ token });
});

app.get("/api/profile", authMiddleware, (req, res) => {
  res.json({ user: req.user });
});

module.exports = app;
