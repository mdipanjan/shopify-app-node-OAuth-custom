import express from 'express';
import axios from 'axios';
import crypto from 'crypto';
import cookieParser from 'cookie-parser';
import session from 'express-session';
import { URLSearchParams } from 'url';
import mongoose from 'mongoose';
import dotenv from 'dotenv';

require('dotenv').config()

declare module 'express-session' {
  interface SessionData {
    state?: string;
  }
}

const app = express();
const PORT = 3434;
const shopUrl = 'email-test-v0-strore.myshopify.com'
const apiKey = process.env.SHOPIFY_API_KEY;
const apiSecret = process.env.SHOPIFY_API_SECRET;
if (!apiKey || !apiSecret) {
  throw new Error('SHOPIFY_API_KEY and SHOPIFY_API_SECRET must be set');
}

mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/shopify_app')
  .then(() => console.log('Connected to MongoDB'))
  .catch((err) => console.error('MongoDB connection error:', err));

  // MongoDB Schema and Model
const shopSchema = new mongoose.Schema({
  shop: { type: String, unique: true, required: true },
  accessToken: { type: String, required: true },
});
const Shop = mongoose.model('Shop', shopSchema);


const scopes = 'write_products,read_customers,write_orders';
const forwardingAddress = 'https://50b9-115-96-111-209.ngrok-free.app'; // our ngrok url

app.use(cookieParser());
app.use(session({
  secret: 'your_session_secret',
  resave: false,
  saveUninitialized: true,
}));

app.get('/shopify', (req, res) => {
  const shop = req.query.shop as string;
  if (shop) {
    const state = crypto.randomBytes(16).toString('hex');
    const redirectUri = `${forwardingAddress}/shopify/callback`;
    const installUrl = `https://${shop}/admin/oauth/authorize?client_id=${apiKey}&scope=${scopes}&state=${state}&redirect_uri=${redirectUri}`;
    
    req.session.state = state;
    res.redirect(installUrl);
  } else {
    res.status(400).send('Missing "shop" parameter');
  }
});

app.get('/shopify/callback', async (req, res) => {
  const { shop, hmac, code, state } = req.query;
  const stateCookie = req.session.state;

  if (state !== stateCookie) {
    return res.status(403).send('Request origin cannot be verified');
  }

  if (shop && hmac && code) {
    // HMAC Validation
    const message = new URLSearchParams(Object.entries(req.query as Record<string, string>).filter(([key]) => key !== 'hmac')).toString();
    const generatedHash = crypto
      .createHmac('sha256', apiSecret)
      .update(message)
      .digest('hex');

    if (generatedHash !== hmac) {
      return res.status(400).send('HMAC validation failed');
    }

    // Exchange temporary code for a permanent access token
    const accessTokenRequestUrl = `https://${shop}/admin/oauth/access_token`;
    const accessTokenPayload = {
      client_id: apiKey,
      client_secret: apiSecret,
      code,
    };

    try {
      const accessTokenResponse = await axios.post(accessTokenRequestUrl, accessTokenPayload);
      const accessToken = accessTokenResponse.data.access_token;

            // Store the access token in MongoDB
            await storeAccessToken(shop as string, accessToken);

      const shopRequestUrl = `https://${shop}/admin/shop.json`;
      const shopRequestHeaders = {
        'X-Shopify-Access-Token': accessToken,
      };

      const shopResponse = await axios.get(shopRequestUrl, { headers: shopRequestHeaders });
      res.status(200).json(shopResponse.data);
    } catch (error) {
      console.error('Error:', error);
      res.status(500).send('An error occurred during the OAuth process');
    }
  } else {
    res.status(400).send('Required parameters missing');
  }
});

async function storeAccessToken(shop: string, accessToken: string) {
  try {
    await Shop.findOneAndUpdate(
      { shop },
      { shop, accessToken },
      { upsert: true, new: true }
    );
    console.log(`Access token stored for shop: ${shop}`);
  } catch (error) {
    console.error('Error storing access token:', error);
    throw error;
  }
}


app.listen(PORT, () => {
  console.log(`App listening on port ${PORT}`);
  console.log(`The shopify OAuth URL is: ${forwardingAddress}/shopify?shop=${shopUrl}`);
});