const express = require('express');
const session = require('express-session');
const bodyParser = require('body-parser');
const path = require('path');
require('dotenv').config();
const { request } = require('@awenk/http-helper-api');


const app = express();

// Middleware untuk parsing body
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());

// Session
app.use(session({
  secret: process.env.SESSION_SECRET || 'secret-123',
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,  // aman dari XSS
    secure: false,   // true kalau pakai HTTPS
    sameSite: 'lax', // default aman
    maxAge: 1000 * 60 * 60 * 24 // 1 hari
  }
}));

// View engine
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Halaman utama
app.get('/', (req, res) => {
    let ssoUrl = null
  if (!req.session.user) {
    ssoUrl = `${process.env.SSO_BASE_URL}/oauth/authorize` +
      `?client_id=${process.env.CLIENT_ID}` +
      `&redirect_uri=${encodeURIComponent(process.env.REDIRECT_URI)}` +
      `&state=xyz`;    
  }

  // Jika sudah login
  res.render('home', { user: req.session.user, ssoUrl });
});

// Callback setelah authorize
app.get('/callback', async (req, res) => {
  const { code, state } = req.query;

  if (!code) {
    return res.status(400).send('Authorization code missing');
  }

  try {
    const tokenResponse = await request(`${process.env.SSO_BASE_URL}/oauth/token`, {
		    method: 'POST',
		    headers: {
                'Accept': 'application/json',
                'Content-Type': 'application/json'
            },
		    body: JSON.stringify({
                client_id: process.env.CLIENT_ID,
                client_secret: process.env.CLIENT_SECRET,
                code,
                redirect_uri: process.env.REDIRECT_URI
            }),
            onlyBody: true
		});

    console.log('SSO Response:', tokenResponse);

    if (tokenResponse.statusCode && tokenResponse.statusCode !== 200) {
      return res.status(400).json({ error: tokenResponse });
    }

    // Simpan user dan token ke session
    req.session.user = tokenResponse.user;
    req.session.token = tokenResponse.access_token;

    res.redirect('/');
  } catch (error) {
    console.error('Token exchange error:', error);
    return res.status(500).send('Error during token exchange');
  }
});

// Logout
app.get('/logout', (req, res) => {
  req.session.destroy(err => {
    if (err) {
      console.error('Logout error:', err);
      return res.status(500).send('Logout failed');
    }
    res.clearCookie('connect.sid'); // nama default cookie express-session
    res.redirect('/');
  });
});

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => console.log(`Client app running on port ${PORT}`));
