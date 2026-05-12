require('dotenv').config();
const express = require('express');
const cors = require('cors');
const pool = require('./db');

const app = express();
app.use(cors());
app.use(express.json());

app.get('/', (req, res) => {
  res.json({ ok: true, service: 'Gevox API' });
});

app.get('/health', async (req, res) => {
  try {
    const result = await pool.query('SELECT NOW()');
    res.json({ ok: true, db: true, now: result.rows[0].now });
  } catch (error) {
    res.status(500).json({ ok: false, db: false, error: error.message });
  }
});

app.get('/tenants', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM tenants ORDER BY id ASC');
    res.json(result.rows);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/products', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM products ORDER BY id ASC');
    res.json(result.rows);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/customers', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM customers ORDER BY id ASC');
    res.json(result.rows);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

const port = process.env.PORT || process.env.APP_PORT || 3000;
app.listen(port, () => {
  console.log(`Gevox API running on port ${port}`);
});
