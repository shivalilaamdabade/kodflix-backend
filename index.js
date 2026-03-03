require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const mysql = require('mysql2/promise');
const path = require('path');

const app = express();

// allow list for CORS; add your frontend origin(s) or use env vars
// when the frontend runs on Vercel it will come from a public URL, not localhost.
const allowedOrigins = [
  'http://localhost:3000',
  'http://localhost:8081', // webpack dev server default port
  'http://localhost:3001',
  'https://kodflix-app-one.vercel.app',
  // production frontend URL(s): set these in Render (or hard‑code if you prefer)
  process.env.FRONTEND_URL,                 // e.g. https://kodfilx-frontend-git-master-...vercel.app
  process.env.FRONTEND_URL_SECONDARY,       // placeholder for any other domain
].filter(Boolean);
app.use(
  cors({
    origin: (origin, callback) => {
      // Accept requests with no origin (curl, native apps) or from our
      // explicit allow list, or any vercel.app subdomain to cover deployments.
      if (!origin
          || allowedOrigins.includes(origin)
          || origin.endsWith('.vercel.app')) {
        return callback(null, true);
      }
      return callback(new Error('Not allowed by CORS'));
    },
  })
);
app.use(express.json());

// Health check root: return 200 so GET / doesn't show 404 when
// frontend static files are not deployed alongside the backend (Render).
app.get('/', (req, res) => {
  return res.status(200).json({ status: 'ok' });
});

// Serve static files from frontend public folder
app.use(express.static(path.join(__dirname, '../frontend/public')));

// create a connection pool using DATABASE_URL
const dbUrl = process.env.DATABASE_URL;
let pool = null;
let useMemory = false;
// fallback in-memory user store for local development when DB is unreachable
const memoryUsers = [];

if (dbUrl) {
  try {
    pool = mysql.createPool(dbUrl);
    // try a simple query to ensure the host resolves/connects
    pool.execute('SELECT 1').catch(err => {
      console.error('Database connectivity test failed:', err.message);
      console.warn('Switching to in-memory user store');
      useMemory = true;
      pool = null;
    });
  } catch (err) {
    console.error('Error creating MySQL pool with DATABASE_URL:', err);
    console.warn('Falling back to in-memory user store');
    useMemory = true;
    pool = null;
  }
} else {
  console.warn('DATABASE_URL not set; using in-memory user store');
  useMemory = true;
}

app.post('/signup', async (req, res) => {
  const { username, email, password } = req.body;
  if (!username || !email || !password) {
    return res.status(400).json({ message: 'Missing fields' });
  }
  try {
    const hashed = await bcrypt.hash(password, 10);
    if (useMemory) {
      if (memoryUsers.find(u => u.username === username)) {
        return res.status(409).json({ message: 'Username already taken' });
      }
      memoryUsers.push({ username, email, password: hashed });
      return res.status(201).json({ message: 'User created (memory)' });
    }
    try {
      const [result] = await pool.execute(
        'INSERT INTO users (username, email, password) VALUES (?, ?, ?)',
        [username, email, hashed]
      );
      return res.status(201).json({ message: 'User created' });
    } catch (dbErr) {
      console.error('DB error during signup:', dbErr.message);
      // fallback to memory if connection issues
      if (dbErr.code === 'ENOTFOUND' || dbErr.code === 'ECONNREFUSED') {
        console.warn('Switching to in-memory store due to DB error');
        useMemory = true;
        memoryUsers.push({ username, email, password: hashed });
        return res.status(201).json({ message: 'User created (memory)' });
      }
      throw dbErr; // rethrow to outer catch
    }
  } catch (err) {
    console.error(err);
    return res.status(500).json({ message: 'Server error' });
  }
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ message: 'Missing fields' });
  }
  try {
    let user;
    if (useMemory) {
      user = memoryUsers.find(u => u.username === username);
    } else {
      try {
        const [rows] = await pool.execute(
          'SELECT * FROM users WHERE username = ?',
          [username]
        );
        user = rows.length ? rows[0] : null;
      } catch (dbErr) {
        console.error('DB error during login:', dbErr.message);
        if (dbErr.code === 'ENOTFOUND' || dbErr.code === 'ECONNREFUSED') {
          console.warn('Switching to in-memory store due to DB error');
          useMemory = true;
          user = memoryUsers.find(u => u.username === username);
        } else {
          throw dbErr;
        }
      }
    }
    if (!user) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }
    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }
    return res.status(200).json({ message: 'success' });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ message: 'Server error' });
  }
});

// Serve index.html for all unmatched routes (SPA routing)
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, '../frontend/public/index.html'));
});

const port = process.env.PORT || 3001;
app.listen(port, () => {
  console.log(`Backend listening on port ${port}`);
});
