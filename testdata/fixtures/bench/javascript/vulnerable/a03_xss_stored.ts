// Source: OWASP Juice Shop - Stored XSS in product reviews
// Expected: BATOU-XSS-001 (innerHTML assignment) or BATOU-XSS-003 (document.write)
// OWASP: A03:2021 - Injection (Stored XSS)

import { Request, Response } from 'express';

interface Review {
  id: number;
  productId: number;
  message: string;
  author: string;
}

const reviews: Review[] = [];

export function addReview(req: Request, res: Response): void {
  const review: Review = {
    id: reviews.length + 1,
    productId: parseInt(req.params.productId),
    message: req.body.message,
    author: req.body.author,
  };
  reviews.push(review);
  res.json(review);
}

export function renderReviews(req: Request, res: Response): void {
  const productId = parseInt(req.params.productId);
  const productReviews = reviews.filter(r => r.productId === productId);
  let html = '<div class="reviews">';
  for (const review of productReviews) {
    html += `<div class="review"><p>${review.message}</p><span>${review.author}</span></div>`;
  }
  html += '</div>';
  res.send(html);
}
