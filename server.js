require('dotenv').config();
const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const pool = require('./db');
const authMiddleware = require('./auth');

const app = express();
app.use(cors());
app.use(express.json());

// --- PUBLICAS ---

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

app.post('/auth/login', async (req, res) => {
  const { email, senha } = req.body;
  if (!email || !senha) return res.status(400).json({ error: 'Email e senha obrigatorios' });
  try {
    const result = await pool.query('SELECT * FROM users WHERE email = $1 AND ativo = true LIMIT 1', [email]);
    if (result.rows.length === 0) return res.status(401).json({ error: 'Credenciais invalidas' });
    const user = result.rows[0];
    const senhaValida = await bcrypt.compare(senha, user.senha_hash);
    if (!senhaValida) return res.status(401).json({ error: 'Credenciais invalidas' });
    const token = jwt.sign(
      { id: user.id, email: user.email, perfil: user.perfil, tenant_id: user.tenant_id },
      process.env.JWT_SECRET,
      { expiresIn: '8h' }
    );
    res.json({ token, perfil: user.perfil, nome: user.nome });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// --- PROTEGIDAS ---

app.get('/auth/me', authMiddleware, (req, res) => {
  res.json({ user: req.user });
});

// TENANTS
app.get('/tenants', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM tenants ORDER BY id ASC');
    res.json(result.rows);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/tenants/:id', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM tenants WHERE id = $1', [req.params.id]);
    if (result.rows.length === 0) return res.status(404).json({ error: 'Tenant nao encontrado' });
    res.json(result.rows[0]);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// PRODUCTS
app.get('/products', authMiddleware, async (req, res) => {
  try {
    const { tenant_id } = req.user;
    const result = await pool.query('SELECT * FROM products WHERE tenant_id = $1 ORDER BY id ASC', [tenant_id]);
    res.json(result.rows);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/products', authMiddleware, async (req, res) => {
  const { codigo, nome, descricao, categoria, unidade, preco_compra, preco_venda, estoque_atual, estoque_minimo } = req.body;
  const { tenant_id } = req.user;
  try {
    const result = await pool.query(
      'INSERT INTO products (tenant_id, tipo_item, codigo, nome, descricao, categoria, unidade, preco_compra, preco_venda, estoque_atual, estoque_minimo) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) RETURNING *',
      [tenant_id, 'produto', codigo, nome, descricao, categoria, unidade, preco_compra, preco_venda, estoque_atual || 0, estoque_minimo || 0]
    );
    res.status(201).json(result.rows[0]);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.put('/products/:id', authMiddleware, async (req, res) => {
  const { nome, descricao, categoria, preco_venda, estoque_atual, ativo } = req.body;
  const { tenant_id } = req.user;
  try {
    const result = await pool.query(
      'UPDATE products SET nome=$1, descricao=$2, categoria=$3, preco_venda=$4, estoque_atual=$5, ativo=$6 WHERE id=$7 AND tenant_id=$8 RETURNING *',
      [nome, descricao, categoria, preco_venda, estoque_atual, ativo, req.params.id, tenant_id]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Produto nao encontrado' });
    res.json(result.rows[0]);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// CUSTOMERS
app.get('/customers', authMiddleware, async (req, res) => {
  try {
    const { tenant_id } = req.user;
    const result = await pool.query('SELECT * FROM customers WHERE tenant_id = $1 ORDER BY id ASC', [tenant_id]);
    res.json(result.rows);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/customers', authMiddleware, async (req, res) => {
  const { nome, telefone, email, endereco, observacoes } = req.body;
  const { tenant_id } = req.user;
  try {
    const result = await pool.query(
      'INSERT INTO customers (tenant_id, nome, telefone, email, endereco, observacoes) VALUES ($1,$2,$3,$4,$5,$6) RETURNING *',
      [tenant_id, nome, telefone, email, endereco, observacoes]
    );
    res.status(201).json(result.rows[0]);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// USERS
app.get('/users', authMiddleware, async (req, res) => {
  try {
    const { tenant_id } = req.user;
    const result = await pool.query('SELECT id, nome, email, perfil, ativo, created_at FROM users WHERE tenant_id = $1 ORDER BY id ASC', [tenant_id]);
    res.json(result.rows);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// DASHBOARD
app.get('/dashboard/summary', authMiddleware, async (req, res) => {
  const { tenant_id } = req.user;
  try {
    const [products, customers, sales] = await Promise.all([
      pool.query('SELECT COUNT(*) FROM products WHERE tenant_id=$1 AND ativo=true', [tenant_id]),
      pool.query('SELECT COUNT(*) FROM customers WHERE tenant_id=$1 AND ativo=true', [tenant_id]),
      pool.query('SELECT COUNT(*) FROM sales_orders WHERE tenant_id=$1', [tenant_id]),
    ]);
    res.json({
      total_products: products.rows[0].count,
      total_customers: customers.rows[0].count,
      total_sales: sales.rows[0].count,
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

const port = process.env.PORT || process.env.APP_PORT || 3000;
app.listen(port, () => {
  console.log(`Gevox API running on port ${port}`);
});
