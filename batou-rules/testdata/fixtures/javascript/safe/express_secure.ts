import express from 'express';
import helmet from 'helmet';
import session from 'express-session';

const app = express();

// SAFE: Helmet middleware for security headers
app.use(helmet());

// SAFE: Secure session configuration
app.use(session({
  secret: process.env.SESSION_SECRET,
  cookie: {
    secure: true,
    httpOnly: true,
    sameSite: 'strict',
    maxAge: 24 * 60 * 60 * 1000,
  },
  resave: false,
  saveUninitialized: false,
}));

// SAFE: Trust proxy with specific hop count
app.set('trust proxy', 1);

// SAFE: Static serving from dedicated public directory
app.use(express.static('public'));

// SAFE: Error handler with generic message
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: 'Internal server error' });
});

// SAFE: Static module loading with allowlist
const plugins = {
  markdown: require('./plugins/markdown'),
  csv: require('./plugins/csv'),
};

app.get('/plugin/:name', (req, res) => {
  const plugin = plugins[req.params.name];
  if (!plugin) {
    return res.status(404).json({ error: 'Plugin not found' });
  }
  res.json(plugin.run());
});

// SAFE: Specific env vars only
app.get('/config', (req, res) => {
  res.json({
    apiUrl: process.env.PUBLIC_API_URL,
    appName: process.env.APP_NAME,
  });
});

app.listen(3000);
