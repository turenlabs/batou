import { Request, Response } from 'express';

// VULNERABLE: Reflected XSS - user input directly echoed in response
export function searchHandler(req: Request, res: Response): void {
  const query = req.query.q as string;

  // VULNERABLE: Unsanitized user input reflected in HTML response via res.send
  res.send(`
    <html>
      <body>
        <h1>Search Results</h1>
        <p>You searched for: ${query}</p>
        <div id="results">No results found.</div>
      </body>
    </html>
  `);
}

// VULNERABLE: Setting response header from user input
export function profileHandler(req: Request, res: Response): void {
  const username = req.query.name as string;
  res.setHeader('X-User-Name', username);
  res.send(`<h1>Profile: ${username}</h1>`);
}
