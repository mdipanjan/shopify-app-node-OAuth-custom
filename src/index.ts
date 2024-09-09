import express from 'express';
import axios from 'axios';
import crypto from 'crypto';
import cookieParser from 'cookie-parser';
import session from 'express-session';
import { URLSearchParams } from 'url';
import mongoose from 'mongoose';
import path from 'path';
import dotenv from 'dotenv';

dotenv.config();

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
// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(session({
  secret: 'your_session_secret',
  resave: false,
  saveUninitialized: true,
}));
app.use(express.static(path.join(__dirname, 'public')));


mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/shopify_app')
  .then(() => console.log('Connected to MongoDB'))
  .catch((err) => console.error('MongoDB connection error:', err));

  // MongoDB Schema and Model
const shopSchema = new mongoose.Schema({
  shop: { type: String, unique: true, required: true },
  accessToken: { type: String, required: true },
});
const Shop = mongoose.model('Shop', shopSchema);


const scopes = 'read_products,write_products,unauthenticated_read_content,unauthenticated_read_customer_tags,unauthenticated_read_product_tags,unauthenticated_read_product_listings,unauthenticated_write_checkouts,unauthenticated_read_checkouts,unauthenticated_write_customers,unauthenticated_read_customers';
const forwardingAddress = 'https://77e5-115-96-153-0.ngrok-free.app'; // our ngrok url


// Add this route
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});
app.get('/dashboard', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

app.get('/catalog', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'catalog.html'));
});

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
          // Redirect to a page where the user can choose to generate a Storefront token
    res.redirect(`/generate-storefront-token?shop=${shop}`);


      // const shopResponse = await axios.get(shopRequestUrl, { headers: shopRequestHeaders });
      // res.status(200).json(shopResponse.data);

    } catch (error) {
      console.error('Error:', error);
      res.status(500).send('An error occurred during the OAuth process');
    }
  } else {
    res.status(400).send('Required parameters missing');
  }
});
app.get('/generate-storefront-token', async (req, res) => {
  const { shop } = req.query;
  
  // Render a page with a button to generate the token
  res.send(`
    <h1>Generate Storefront Access Token</h1>
    <p>Click the button below to generate a Storefront Access Token for ${shop}</p>
    <form method="POST" action="/create-storefront-token">
      <input type="hidden" name="shop" value="${shop}">
      <button type="submit">Generate Token</button>
    </form>
  `);
});

app.post('/create-storefront-token', async (req, res) => {
  const { shop } = req.body;
  
  try {
    const shopData = await Shop.findOne({ shop });
    if (!shopData) {
      return res.status(404).send('Shop not found');
    }

    const storefrontToken = await createStorefrontAccessToken(shop, shopData.accessToken);
    
    // Store the Storefront Access Token
    await storeStorefrontToken(shop, storefrontToken.access_token);

    res.send('Storefront Access Token generated successfully!');
  } catch (error) {
    console.error('Error generating Storefront Access Token:', error);
    res.status(500).send('Error generating Storefront Access Token');
  }
});
async function storeStorefrontToken(shop: string, storefrontToken: string) {
  await Shop.findOneAndUpdate(
    { shop },
    { storefrontAccessToken: storefrontToken },
    { new: true }
  );
}


async function createStorefrontAccessToken(shop: string, accessToken: string  ) {
  const url = `https://${shop}/admin/api/2024-07/storefront_access_tokens.json`;
  const headers = {
    'X-Shopify-Access-Token': accessToken,
    'Content-Type': 'application/json'
  };
  const data = {
    storefront_access_token: {
      title: "Your App Name Storefront Token"
    }
  };

  try {
    const response = await axios.post(url, data, { headers });
    return response.data.storefront_access_token;
  } catch (error) {
    console.error('Error creating Storefront Access Token:', error);
    throw error;
  }
}


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

app.get('/shop-info', async (req, res) => {
  const { shop } = req.query;
  if (!shop) {
    return res.status(400).send('Missing shop parameter');
  }

  try {
    const shopData = await Shop.findOne({ shop });
    if (!shopData) {
      return res.status(404).send('Shop not found');
    }

    const shopInfoUrl = `https://${shop}/admin/api/2023-07/shop.json`;
    const response = await axios.get(shopInfoUrl, {
      headers: {
        'X-Shopify-Access-Token': shopData.accessToken
      }
    });

    res.json(response.data.shop);
  } catch (error) {
    console.error('Error fetching shop info:', error);
    res.status(500).send('Error fetching shop info');
  }
});

app.post('/api/create-checkout', async (req, res) => {
  const { shop, items, address } = req.body;
  try {
    const shopData = await Shop.findOne({ shop });
    if (!shopData) {
      return res.status(404).send('Shop not found');
    }

    const storefrontAccessToken = shopData.accessToken; // You'll need to store this when setting up the app
    
    const createCartMutation = `
      mutation createCart($input: CartInput!) {
        cartCreate(input: $input) {
          cart {
            checkoutUrl
          }
        }
      }
    `;

    const variables = {
      input: {
        lines: items.map((item: { quantity: number; variant_id: string }) => ({
          quantity: item.quantity,
          merchandiseId: item.variant_id
        }))
      }
    };

    const response = await axios.post(`https://${shop}/api/2023-07/graphql.json`, {
      query: createCartMutation,
      variables
    }, {
      headers: {
        'X-Shopify-Storefront-Access-Token': storefrontAccessToken,
        'Content-Type': 'application/json'
      }
    });

    const checkoutUrl = response.data.data.cartCreate.cart.checkoutUrl;
    res.json({ checkoutUrl });
  } catch (error) {
    console.error('Error creating checkout:', error);
    res.status(500).send('Error creating checkout');
  }
});

app.get('/products', async (req, res) => {
  const { shop } = req.query;
  if (!shop) {
    return res.status(400).send('Missing shop parameter');
  }

  try {
    const shopData = await Shop.findOne({ shop });
    if (!shopData) {
      return res.status(404).send('Shop not found');
    }

    const productsUrl = `https://${shop}/admin/api/2023-07/products.json`;
    const response = await axios.get(productsUrl, {
      headers: {
        'X-Shopify-Access-Token': shopData.accessToken
      }
    });

    res.json(response.data.products);
  } catch (error) {
    console.error('Error fetching products:', error);
    res.status(500).send('Error fetching products');
  }
});

// New route to add a product
app.post('/products', async (req, res) => {
  const { shop } = req.query;
  const productData = req.body;

  if (!shop) {
    return res.status(400).send('Missing shop parameter');
  }

  if (!productData) {
    return res.status(400).send('Missing product data');
  }

  try {
    const shopData = await Shop.findOne({ shop });
    if (!shopData) {
      return res.status(404).send('Shop not found');
    }

    const productsUrl = `https://${shop}/admin/api/2023-07/products.json`;
    const response = await axios.post(productsUrl, 
      { product: productData },
      {
        headers: {
          'X-Shopify-Access-Token': shopData.accessToken,
          'Content-Type': 'application/json'
        }
      }
    );

    res.status(201).json(response.data.product);
  } catch (error) {
    console.error('Error adding product:', error);
    res.status(500).send('Error adding product');
  }
});


app.listen(PORT, () => {
  console.log(`App listening on port ${PORT}`);
  console.log(`The shopify OAuth URL is: ${forwardingAddress}/shopify?shop=${shopUrl}`);
});