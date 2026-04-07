import { Request, Response } from 'express';
import mongoose from 'mongoose';

const ReviewSchema = new mongoose.Schema({
  productId: String,
  author: String,
  message: String,
  createdAt: { type: Date, default: Date.now },
});
const Review = mongoose.model('Review', ReviewSchema);

// VULNERABLE: Stored XSS - user input stored in DB then rendered with dangerouslySetInnerHTML
export async function createReview(req: Request, res: Response): Promise<void> {
  const { productId, message } = req.body;
  const author = req.user?.name || 'Anonymous';

  // User input stored directly without sanitization
  const review = await Review.create({ productId, author, message });
  res.status(201).json(review);
}

export async function renderReviews(req: Request, res: Response): Promise<void> {
  const reviews = await Review.find({ productId: req.params.id });

  // VULNERABLE: rendering stored user content as raw HTML
  const html = reviews.map(r =>
    `<div class="review"><strong>${r.author}</strong><p>${r.message}</p></div>`
  ).join('');

  // VULNERABLE: dangerouslySetInnerHTML={{ __html: html }} pattern
  res.send(`
    <html><body>
      <div dangerouslySetInnerHTML={{ __html: "${html}" }}></div>
    </body></html>
  `);
}
