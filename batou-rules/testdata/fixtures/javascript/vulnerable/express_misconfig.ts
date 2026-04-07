import express from 'express';
import session from 'express-session';

const app = express();

// VULNERABLE: No helmet middleware for security headers

// VULNERABLE: Insecure session configuration
app.use(session({
  secret: 'keyboard cat',
  cookie: {
    secure: false,
    httpOnly: false,
    sameSite: 'none',
  }
}));

// VULNERABLE: Trust proxy set to true (trusts all proxies)
app.set('trust proxy', true);

// VULNERABLE: Static serving project root
app.use(express.static('.'));

// VULNERABLE: Stack trace leak in error handler
app.use((err, req, res, next) => {
  res.status(500).send(err.stack);
});

// VULNERABLE: Dynamic require with user input
app.get('/plugin/:name', (req, res) => {
  const plugin = require(req.params.name);
  res.json(plugin.run());
});

// VULNERABLE: Process.env leaked to client
app.get('/debug', (req, res) => {
  res.json(process.env);
});

app.listen(3000);
