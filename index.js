///////////// Initial Setup /////////////

// our env file needed to import our variables.
const dotenv = require('dotenv').config();
// our express server.
const express = require('express');
// nodes built in cryptography helper.
const crypto = require('crypto');
// simple cookie parser we installed earlier.
const cookie = require('cookie');
// help us to generate random strings.
const nonce = require('nonce')();
// nodes built in querystrng helps us build url query strings.
const querystring = require('querystring');
// our request library.
const axios = require('axios');

// our shopify keys
const shopifyApiPublicKey = process.env.SHOPIFY_API_PUBLIC_KEY;
const shopifyApiSecretKey = process.env.SHOPIFY_API_SECRET_KEY;

// the scope of the store we want (permissions)
const scopes = 'write_products';
// the ngrok forwarding address.
const appUrl = 'https://509cee43.ngrok.io';

const app = express();
const PORT = 3000

app.get('/', (req, res) => {
  res.send('Ello Govna')
});

///////////// Helper Functions /////////////

// returns our redirect uri.
const buildRedirectUri = () => `${appUrl}/shopify/callback`;

// returns the url we redirect the client to which will request permission from the user to access their store.
const buildInstallUrl = (shop, state, redirectUri) => `https://${shop}/admin/oauth/authorize?client_id=${shopifyApiPublicKey}&scope=${scopes}&state=${state}&redirect_uri=${redirectUri}`;

// returns the url where we need to post in order to get our access token.
const buildAccessTokenRequestUrl = (shop) => `https://${shop}/admin/oauth/access_token`;

// returns the url we get from to receive shop data, but this could be changed to products or orders etc.
const buildShopDataRequestUrl = (shop) => `https://${shop}/admin/shop.json`;

// returns our encrypted hash to compare to the one we receive from shopify.
const generateEncryptedHash = (params) => crypto.createHmac('sha256', shopifyApiSecretKey).update(params).digest('hex');

// request to get our access token.
const fetchAccessToken = async (shop, data) => await axios(buildAccessTokenRequestUrl(shop), {
  method: 'POST',
  data
});

// request to get the shot data.
const fetchShopData = async (shop, accessToken) => await axios(buildShopDataRequestUrl(shop), {
  method: 'GET',
  headers: {
    'X-Shopify-Access-Token': accessToken
  }
});

///////////// Route Handlers /////////////

app.get('/shopify', (req, res) => {

  // The shop will be in a query string attached to the url. it would look like this https://whatever.com/shopify?shop=<The Shop Url>.

  const shop = req.query.shop;

  // If the shop param isn't present return.
  if (!shop) { return res.status(400).send('no shop')}

  // We create a state variable equal to a random string.
  const state = nonce();

  // We use helper methods to create the url we are going to redirect the client to.
  const installShopUrl = buildInstallUrl(shop, state, buildRedirectUri())

  // We add a cookie to their browser with the random state string typically this would be encrypted in production.
  res.cookie('state', state) // should be encrypted in production
  // We redirect them to the install url where they will apprve our scope and give us permission to access their data.
  res.redirect(installShopUrl);
});

app.get('/shopify/callback', async (req, res) => {

  // once they approve our access (in the previous route) they are then sent to our callback route which provides the shop, code, state, hmac, and timestamp query params.. we chose to only destructure a few of them.
  const { shop, code, state } = req.query;

  // we parse the cooke their client sent back to us and pull out the state.
  const stateCookie = cookie.parse(req.headers.cookie).state;

  // We ensure the request is valid by comparing the two.
  if (state !== stateCookie) { return res.status(403).send('Cannot be verified')}

  // We now pull out the hmac from req.query and create a new object (params) that will contain everything (shop, code, state, timestamp) but the hmac key/value pair.
  const { hmac, ...params } = req.query

  //We then transform the params into a query string.
  const queryParams = querystring.stringify(params)

  // We then generate an encrypted hash with said queryParams.
  const hash = generateEncryptedHash(queryParams)

  // We compare the hmac shopify sent to us with the one we just generated, if they aren't the same we know it's an invalid request.
  if (hash !== hmac) { return res.status(400).send('HMAC validation failed')}

  // We setup a try/catch block for our requests.
  try {

    // we create our payload that will be included in our first request to get the access token.
    const data = {
      client_id: shopifyApiPublicKey,
      client_secret: shopifyApiSecretKey,
      code
    };

    // we await the response from our helper function.
    const tokenResponse = await fetchAccessToken(shop, data)

    // We destructure the response and pull out the access token.
    const { access_token } = tokenResponse.data

    // Once we have our access token we can send another request to get the information we desire (this coul be any number of different endpoints shopify has but we chose the shop data for this example).
    const shopData = await fetchShopData(shop, access_token)

    // if all went well you should see the shop data in the browser from here you would obviously do whatever you need to this is only for example purposes to show it worked.

    res.send(shopData.data.shop)

  } catch(err) {
    console.log(err)
    // If it errors out we log it and return an error.
    res.status(500).send('something went wrong')
  }
});

///////////// Start the Server /////////////

app.listen(PORT, () => console.log(`listening on port ${PORT}`));
