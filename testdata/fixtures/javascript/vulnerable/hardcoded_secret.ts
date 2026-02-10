import jwt from 'jsonwebtoken';
import Stripe from 'stripe';

// VULNERABLE: Hardcoded JWT signing secret
const secret = "super_secret_jwt_key_do_not_share_2024!";

// VULNERABLE: Hardcoded API key (Stripe format)
const stripe = new Stripe('sk_live_4eC39HqLyjWDarjtT1zdp7dc', { apiVersion: '2023-10-16' });

// VULNERABLE: Hardcoded database connection string with credentials
const mongoUri = "mongodb://admin:Str0ngP@ssw0rd123@prod-db.example.com:27017/shopdb";

// VULNERABLE: Hardcoded password
const password = "R3allyStr0ng#Passw0rd!@2024";

// VULNERABLE: Hardcoded API key assigned to apikey variable
const api_key = "ak_prod_9f8e7d6c5b4a3210fedcba9876543210abcdef";

export function signToken(userId: string): string {
  // VULNERABLE: jwt.sign with hardcoded secret string
  return jwt.sign({ sub: userId, role: 'user' }, 'my-hardcoded-jwt-secret-key-very-unsafe');
}

export function getStripeClient(): Stripe {
  return stripe;
}

export function connectDB(): string {
  return mongoUri;
}
