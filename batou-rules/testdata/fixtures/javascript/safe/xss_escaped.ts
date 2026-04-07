import { Request, Response } from 'express';
import createDOMPurify from 'dompurify';
import { JSDOM } from 'jsdom';
import escapeHtml from 'escape-html';

const window = new JSDOM('').window;
const DOMPurify = createDOMPurify(window);

// SAFE: HTML escaping before rendering user input
export function searchHandler(req: Request, res: Response): void {
  const query = req.query.q as string;

  // SAFE: Escape HTML entities before inserting into response
  const safeQuery = escapeHtml(query);

  res.send(`
    <html>
      <body>
        <h1>Search Results</h1>
        <p>You searched for: ${safeQuery}</p>
        <div id="results">No results found.</div>
      </body>
    </html>
  `);
}

// SAFE: Using DOMPurify to sanitize HTML before rendering
export function renderUserContent(req: Request, res: Response): void {
  const userContent = req.body.content;

  // SAFE: Sanitize HTML with DOMPurify
  const cleanHtml = DOMPurify.sanitize(userContent);

  res.json({ html: cleanHtml });
}

// SAFE: Using res.json() for structured data (no HTML injection)
export function profileHandler(req: Request, res: Response): void {
  const username = req.query.name as string;

  // SAFE: Return JSON instead of rendering HTML
  res.json({ username, profile: {} });
}

// SAFE: Using textContent instead of innerHTML
export function renderSafeDOM(): string {
  return `
    <script>
      const query = new URLSearchParams(window.location.search).get('q');
      document.getElementById('search-term').textContent = query;
    </script>
  `;
}
