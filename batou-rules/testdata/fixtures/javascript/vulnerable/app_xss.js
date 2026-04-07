// Reflected and DOM XSS
// Expected: GTSS-XSS-001, GTSS-XSS-003, GTSS-XSS-005
// CWE-79, OWASP A03
const express = require('express');
const app = express();

app.get('/search', (req, res) => {
  const query = req.query.q;

  // VULNERABLE: Reflected XSS via document.write
  res.send(`
    <html>
    <body>
      <script>document.write('Search results for: ' + '${query}')</script>
    </body>
    </html>
  `);
});

app.get('/profile', (req, res) => {
  const username = req.query.username;

  // VULNERABLE: DOM XSS via innerHTML
  res.send(`
    <html>
    <body>
      <div id="user"></div>
      <script>
        document.getElementById('user').innerHTML = '${username}';
      </script>
    </body>
    </html>
  `);
});
