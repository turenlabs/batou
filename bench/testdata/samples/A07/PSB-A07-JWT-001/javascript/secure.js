// PSB-A07-JWT-001: JWT authentication middleware
// CWE: CWE-345, CWE-347
// Expected: (none - secure)
const express = require("express");
const jwt = require("jsonwebtoken");
const app = express();
app.use(express.json());

const SECRET = process.env.JWT_SECRET;

function authMiddleware(req, res, next) {
  const header = req.headers.authorization;
  if (!header || !header.startsWith("Bearer ")) {
    return res.status(401).json({ error: "missing authorization header" });
  }

  const token = header.slice(7);
  try {
    const decoded = jwt.verify(token, SECRET, {
      algorithms: ["HS256"],
      complete: true,
    });
    req.user = decoded.payload;
    next();
  } catch (err) {
    res.status(401).json({ error: "invalid token" });
  }
}

app.post("/api/login", (req, res) => {
  const { username, password } = req.body;
  const token = jwt.sign({ sub: username, role: "user" }, SECRET, {
    algorithm: "HS256",
    expiresIn: "1h",
  });
  res.json({ token });
});

app.get("/api/profile", authMiddleware, (req, res) => {
  res.json({ user: req.user });
});

module.exports = app;
