// server.js — SolveMate Backend
// Auth: email + password accounts with JWT tokens
// Storage: simple JSON file (no database setup needed)
// AI: Anthropic Claude (your key, hidden from users)
// Payments: Stripe Checkout (subscriptions)

require('dotenv').config();
const express = require('express');
const cors    = require('cors');
const bcrypt  = require('bcryptjs');
const jwt     = require('jsonwebtoken');
const fs      = require('fs');
const path    = require('path');

const app  = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET  = process.env.JWT_SECRET || 'dev-secret-change-in-production';
const USERS_FILE  = path.join(__dirname, 'users.json');

// Free tier limit
const FREE_QUESTION_LIMIT = 10;

// ─────────────────────────────────────────────
// STRIPE SETUP (optional — only if key is set)
// ─────────────────────────────────────────────

let stripe = null;
if (process.env.STRIPE_SECRET_KEY) {
  try {
    stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
  } catch (e) {
    console.warn('⚠️  Stripe package not installed. Run: npm install stripe');
    console.warn('   Payments will be disabled until you install it.');
  }
}

// ─────────────────────────────────────────────
// USER STORAGE (simple JSON file)
// ─────────────────────────────────────────────

function loadUsers() {
  try { return JSON.parse(fs.readFileSync(USERS_FILE, 'utf8')); }
  catch { return {}; }
}

function saveUsers(users) {
  fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
}

// ─────────────────────────────────────────────
// MIDDLEWARE
// ─────────────────────────────────────────────

// Stripe webhook needs raw body — must come BEFORE express.json()
app.use('/api/webhook', express.raw({ type: 'application/json' }));

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ─────────────────────────────────────────────
// AUTH HELPER
// ─────────────────────────────────────────────

function requireAuth(req, res, next) {
  const token = req.body?.token || req.headers['authorization']?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: 'Not logged in.' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: 'Session expired. Please log in again.' });
  }
}

// ─────────────────────────────────────────────
// ROUTES
// ─────────────────────────────────────────────

// Health check
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', uptime: process.uptime() });
});

// ── SIGN UP ──────────────────────────────────
app.post('/api/signup', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password)    return res.status(400).json({ error: 'Email and password are required.' });
  if (password.length < 6)    return res.status(400).json({ error: 'Password must be at least 6 characters.' });

  const users = loadUsers();
  const key   = email.toLowerCase().trim();

  if (users[key]) return res.status(400).json({ error: 'That email is already registered. Try logging in.' });

  try {
    const hash = await bcrypt.hash(password, 10);
    users[key] = {
      email:              key,
      password:           hash,
      createdAt:          new Date().toISOString(),
      plan:               'free',          // 'free' or 'pro'
      freeQuestionsUsed:  0,               // counts against FREE_QUESTION_LIMIT
      totalQuestionsUsed: 0,               // lifetime total
      lastUsed:           null,
      stripeCustomerId:   null,
      stripeSubscriptionId: null,
    };
    saveUsers(users);

    const token = jwt.sign({ email: key }, JWT_SECRET, { expiresIn: '30d' });
    console.log(`✅ New user: ${key}`);
    res.json({ success: true, token, email: key });
  } catch (err) {
    console.error('Signup error:', err.message);
    res.status(500).json({ error: 'Server error. Please try again.' });
  }
});

// ── LOG IN ───────────────────────────────────
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password are required.' });

  const users = loadUsers();
  const key   = email.toLowerCase().trim();
  const user  = users[key];

  if (!user) return res.status(401).json({ error: 'No account found with that email.' });

  const valid = await bcrypt.compare(password, user.password);
  if (!valid) return res.status(401).json({ error: 'Incorrect password.' });

  const token = jwt.sign({ email: key }, JWT_SECRET, { expiresIn: '30d' });
  console.log(`🔑 Login: ${key}`);
  res.json({ success: true, token, email: key });
});

// ── ME (plan status + usage) ─────────────────
app.post('/api/me', requireAuth, (req, res) => {
  const users = loadUsers();
  const user  = users[req.user.email];
  if (!user) return res.status(404).json({ error: 'User not found.' });

  const freeUsed  = user.freeQuestionsUsed  || 0;
  const freeLimit = FREE_QUESTION_LIMIT;
  const plan      = user.plan || 'free';

  res.json({
    success: true,
    user: {
      email:             user.email,
      createdAt:         user.createdAt,
      plan,
      freeQuestionsUsed: freeUsed,
      freeQuestionLimit: freeLimit,
      freeRemaining:     plan === 'pro' ? null : Math.max(0, freeLimit - freeUsed),
      totalQuestionsUsed: user.totalQuestionsUsed || 0,
    }
  });
});

// ── ANSWER QUESTION ──────────────────────────
app.post('/api/answer', requireAuth, async (req, res) => {
  const { question, choices, multiSelect, fillInBlank } = req.body;

  if (!question) {
    return res.status(400).json({ error: 'Question is required.' });
  }
  if (!fillInBlank && (!Array.isArray(choices) || choices.length < 2)) {
    return res.status(400).json({ error: 'At least 2 choices are required for multiple choice.' });
  }

  // ── Paywall check ──────────────────────────
  const users = loadUsers();
  const user  = users[req.user.email];
  if (!user) return res.status(401).json({ error: 'User not found.' });

  const plan      = user.plan || 'free';
  const freeUsed  = user.freeQuestionsUsed || 0;

  if (plan !== 'pro' && freeUsed >= FREE_QUESTION_LIMIT) {
    return res.status(402).json({
      error: 'upgrade_required',
      message: `You've used all ${FREE_QUESTION_LIMIT} free questions. Upgrade to Pro for unlimited access!`,
      freeQuestionsUsed: freeUsed,
      freeQuestionLimit: FREE_QUESTION_LIMIT,
    });
  }

  if (!process.env.ANTHROPIC_API_KEY) {
    console.error('ANTHROPIC_API_KEY not set!');
    return res.status(500).json({ error: 'Server not configured. Contact support.' });
  }

  // Build prompt based on question type
  let prompt;
  let maxTokens = 10;

  if (fillInBlank) {
    prompt =
      `You are a knowledgeable student completing a fill-in-the-blank exam question.\n` +
      `Provide ONLY the exact word or short phrase that correctly completes the blank.\n` +
      `Do not include quotes, punctuation, or any explanation — just the answer itself.\n\n` +
      `Question: ${question}`;
    maxTokens = 60;
  } else {
    const choicesList = choices
      .map((c, i) => `${String.fromCharCode(65 + i)}) ${c}`)
      .join('\n');

    prompt = multiSelect
      ? `Select all correct answers for this exam question. Usually 2-3 options are correct, NOT all of them.\n` +
        `YOUR ENTIRE RESPONSE MUST BE ONLY the correct letters separated by commas. Nothing else. No words. No explanation.\n` +
        `Example response: "A, C" or "B, D, E"\n\n` +
        `Question: ${question}\n\nChoices:\n${choicesList}`
      : `Choose the single correct answer for this exam question.\n` +
        `YOUR ENTIRE RESPONSE MUST BE ONLY the one letter. Nothing else. No words. No explanation.\n` +
        `Example response: "B"\n\n` +
        `Question: ${question}\n\nChoices:\n${choicesList}`;
  }

  try {
    const response = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type':      'application/json',
        'x-api-key':         process.env.ANTHROPIC_API_KEY,
        'anthropic-version': '2023-06-01',
      },
      body: JSON.stringify({
        model:      'claude-sonnet-4-6',
        max_tokens: maxTokens,
        messages:   [{ role: 'user', content: prompt }],
      }),
    });

    const data = await response.json();
    if (!response.ok) throw new Error(data.error?.message || `API error ${response.status}`);

    const rawText = data.content[0].text.trim();

    // Track usage
    const freshUsers = loadUsers();
    if (freshUsers[req.user.email]) {
      if (freshUsers[req.user.email].plan !== 'pro') {
        freshUsers[req.user.email].freeQuestionsUsed = (freshUsers[req.user.email].freeQuestionsUsed || 0) + 1;
      }
      freshUsers[req.user.email].totalQuestionsUsed = (freshUsers[req.user.email].totalQuestionsUsed || 0) + 1;
      freshUsers[req.user.email].lastUsed = new Date().toISOString();
      saveUsers(freshUsers);
    }

    // Recalculate remaining for response
    const updatedUser   = freshUsers[req.user.email];
    const freeRemaining = updatedUser.plan === 'pro'
      ? null
      : Math.max(0, FREE_QUESTION_LIMIT - (updatedUser.freeQuestionsUsed || 0));

    // Fill-in-blank: return the text answer directly
    if (fillInBlank) {
      return res.json({ success: true, textAnswer: rawText, freeRemaining });
    }

    // Multiple choice: parse ONLY standalone answer letters
    const maxLetter = String.fromCharCode(65 + choices.length - 1);
    const pattern   = new RegExp(`\\b([A-${maxLetter}])\\b`, 'g');
    const matches   = [...rawText.toUpperCase().matchAll(pattern)];

    const seen    = new Set();
    const indices = [];
    for (const m of matches) {
      const idx = m[1].charCodeAt(0) - 65;
      if (!seen.has(idx) && idx >= 0 && idx < choices.length) {
        seen.add(idx);
        indices.push(idx);
      }
    }

    if (indices.length === 0) {
      throw new Error(`Unexpected AI response: "${rawText}"`);
    }

    console.log(`Answer for "${question.slice(0,60)}...": ${rawText} → indices [${indices}]`);
    res.json({ success: true, answerIndices: indices, freeRemaining });

  } catch (err) {
    console.error('AI error:', err.message);
    res.status(500).json({ success: false, error: err.message });
  }
});

// ── CREATE STRIPE CHECKOUT SESSION ───────────
app.post('/api/create-checkout-session', requireAuth, async (req, res) => {
  if (!stripe) {
    return res.status(500).json({ error: 'Payments not configured. Add STRIPE_SECRET_KEY to .env.' });
  }
  if (!process.env.STRIPE_PRICE_ID) {
    return res.status(500).json({ error: 'STRIPE_PRICE_ID not set in .env.' });
  }

  const users = loadUsers();
  const user  = users[req.user.email];
  if (!user) return res.status(401).json({ error: 'User not found.' });

  if (user.plan === 'pro') {
    return res.status(400).json({ error: 'You already have a Pro subscription.' });
  }

  try {
    // Create or reuse Stripe customer
    let customerId = user.stripeCustomerId;
    if (!customerId) {
      const customer = await stripe.customers.create({ email: user.email });
      customerId = customer.id;
      const freshUsers = loadUsers();
      freshUsers[req.user.email].stripeCustomerId = customerId;
      saveUsers(freshUsers);
    }

    const session = await stripe.checkout.sessions.create({
      customer:             customerId,
      payment_method_types: ['card'],
      line_items: [{
        price:    process.env.STRIPE_PRICE_ID,
        quantity: 1,
      }],
      mode:        'subscription',
      success_url: `${process.env.SITE_URL || 'http://localhost:3000'}/success.html`,
      cancel_url:  `${process.env.SITE_URL  || 'http://localhost:3000'}/?cancelled=1`,
      metadata:    { email: user.email },
    });

    res.json({ success: true, url: session.url });
  } catch (err) {
    console.error('Stripe error:', err.message);
    res.status(500).json({ error: 'Could not create checkout session.' });
  }
});

// ── STRIPE WEBHOOK ────────────────────────────
app.post('/api/webhook', (req, res) => {
  if (!stripe) return res.sendStatus(200);

  const sig     = req.headers['stripe-signature'];
  const secret  = process.env.STRIPE_WEBHOOK_SECRET;

  let event;
  try {
    event = secret
      ? stripe.webhooks.constructEvent(req.body, sig, secret)
      : JSON.parse(req.body.toString());
  } catch (err) {
    console.error('Webhook signature failed:', err.message);
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  if (event.type === 'checkout.session.completed') {
    const session = event.data.object;
    const email   = session.metadata?.email;
    if (email) {
      const users = loadUsers();
      if (users[email]) {
        users[email].plan                 = 'pro';
        users[email].stripeSubscriptionId = session.subscription;
        saveUsers(users);
        console.log(`⭐ Upgraded to Pro: ${email}`);
      }
    }
  }

  if (event.type === 'customer.subscription.deleted') {
    const sub     = event.data.object;
    const users   = loadUsers();
    const email   = Object.keys(users).find(e => users[e].stripeSubscriptionId === sub.id);
    if (email) {
      users[email].plan                 = 'free';
      users[email].freeQuestionsUsed    = 0; // reset counter on downgrade
      users[email].stripeSubscriptionId = null;
      saveUsers(users);
      console.log(`⬇️  Downgraded to Free: ${email}`);
    }
  }

  res.sendStatus(200);
});

// ─────────────────────────────────────────────
// ADMIN ROUTES (password protected)
// ─────────────────────────────────────────────

function requireAdmin(req, res, next) {
  const pw = req.headers['x-admin-password'] || req.body?.adminPassword;
  if (!pw || pw !== process.env.ADMIN_PASSWORD) {
    return res.status(401).json({ error: 'Unauthorized.' });
  }
  next();
}

// List all users
app.post('/api/admin/users', requireAdmin, (req, res) => {
  const users = loadUsers();
  const list  = Object.values(users).map(u => ({
    email:             u.email,
    plan:              u.plan || 'free',
    freeQuestionsUsed: u.freeQuestionsUsed || 0,
    totalQuestionsUsed: u.totalQuestionsUsed || 0,
    createdAt:         u.createdAt,
    lastUsed:          u.lastUsed,
  }));
  // Sort newest first
  list.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
  res.json({ success: true, users: list, total: list.length });
});

// Set a user's plan (free or pro)
app.post('/api/admin/set-plan', requireAdmin, (req, res) => {
  const { email, plan } = req.body;
  if (!email || !['free', 'pro'].includes(plan)) {
    return res.status(400).json({ error: 'Provide email and plan (free or pro).' });
  }
  const users = loadUsers();
  const key   = email.toLowerCase().trim();
  if (!users[key]) return res.status(404).json({ error: 'User not found.' });

  users[key].plan = plan;
  if (plan === 'pro') {
    // Granting pro manually — clear any Stripe fields if set manually
    users[key].freeQuestionsUsed = 0;
  } else {
    // Downgrading — reset free count so they get fresh start
    users[key].freeQuestionsUsed    = 0;
    users[key].stripeSubscriptionId = null;
  }
  saveUsers(users);
  console.log(`🔧 Admin set ${key} → ${plan}`);
  res.json({ success: true, message: `${key} is now on ${plan}.` });
});

// Reset a user's free question count
app.post('/api/admin/reset-usage', requireAdmin, (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: 'Email required.' });
  const users = loadUsers();
  const key   = email.toLowerCase().trim();
  if (!users[key]) return res.status(404).json({ error: 'User not found.' });

  users[key].freeQuestionsUsed = 0;
  saveUsers(users);
  console.log(`🔧 Admin reset usage for ${key}`);
  res.json({ success: true, message: `Usage reset for ${key}.` });
});

// Delete a user
app.post('/api/admin/delete-user', requireAdmin, (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: 'Email required.' });
  const users = loadUsers();
  const key   = email.toLowerCase().trim();
  if (!users[key]) return res.status(404).json({ error: 'User not found.' });

  delete users[key];
  saveUsers(users);
  console.log(`🗑️  Admin deleted ${key}`);
  res.json({ success: true, message: `${key} deleted.` });
});

// ── CANCEL SUBSCRIPTION ───────────────────────
app.post('/api/cancel-subscription', requireAuth, async (req, res) => {
  if (!stripe) return res.status(500).json({ error: 'Payments not configured.' });

  const users = loadUsers();
  const user  = users[req.user.email];
  if (!user || user.plan !== 'pro') return res.status(400).json({ error: 'No active subscription.' });

  try {
    await stripe.subscriptions.cancel(user.stripeSubscriptionId);
    // Webhook will handle setting plan back to free
    res.json({ success: true, message: 'Subscription cancelled.' });
  } catch (err) {
    console.error('Cancel error:', err.message);
    res.status(500).json({ error: 'Could not cancel subscription.' });
  }
});

// ─────────────────────────────────────────────
// START
// ─────────────────────────────────────────────

app.listen(PORT, () => {
  console.log(`\n🚀 Server running on port ${PORT}`);
  console.log(`   ANTHROPIC_API_KEY: ${process.env.ANTHROPIC_API_KEY ? '✅ set' : '❌ MISSING — add it to .env'}`);
  console.log(`   JWT_SECRET:        ${JWT_SECRET !== 'dev-secret-change-in-production' ? '✅ set' : '⚠️  using default (ok for local testing)'}`);
  console.log(`   STRIPE_SECRET_KEY: ${process.env.STRIPE_SECRET_KEY ? '✅ set' : '⚠️  not set — payments disabled'}`);
  console.log(`   STRIPE_PRICE_ID:   ${process.env.STRIPE_PRICE_ID   ? '✅ set' : '⚠️  not set — payments disabled'}`);
  console.log(`   Free tier limit:   ${FREE_QUESTION_LIMIT} questions`);
  console.log(`\n   Open http://localhost:${PORT} in your browser\n`);
});
