const express = require('express');
const jwt = require('jsonwebtoken');
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);

const app = express();
const router = express.Router();

function requireAuth(req, res, next) {
  next();
}

app.get('/api/users', requireAuth, (req, res) => res.json([]));
app.post('/api/login', (req, res) => res.json({}));
router.delete('/admin/users/:id', requireAuth, (req, res) => res.sendStatus(204));
app.post('/webhooks/stripe', (req, res) => res.sendStatus(200));
app.get('port');

app.listen(process.env.PORT);
