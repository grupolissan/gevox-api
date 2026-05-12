require('dotenv').config();
const express = require('express');
const cors = require('cors');
const pool = require('./db');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();

const allowedOrigins = [
  'https://app.gevox.com.br',
  'https://admin.gevox.com.br',
  'https://gevox.com.br',
  'http://localhost:3000',
  'http://localhost:5173'
];

app.use(cors({
  origin(origin, callback) {
    if (!origin) return callback(null, true);
    if (allowedOrigins.includes(origin)) return callback(null, true);
    return callback(new Error('Origem não permitida pelo CORS'));
  }
}));

app.use(express.json());

function generateToken(user) {
  return jwt.sign(
    {
      id: String(user.id),
      email: user.email,
      perfil: user.perfil,
      tenant_id: String(user.tenant_id)
    },
    process.env.JWT_SECRET,
    { expiresIn: '8h' }
  );
}

function authMiddleware(req, res, next) {
  const authHeader = req.headers.authorization;

  if (!authHeader) {
    return res.status(401).json({ error: 'Token nao fornecido' });
  }

  const parts = authHeader.split(' ');

  if (parts.length !== 2) {
    return res.status(401).json({ error: 'Token mal formatado' });
  }

  const [scheme, token] = parts;

  if (!/^Bearer$/i.test(scheme)) {
    return res.status(401).json({ error: 'Token mal formatado' });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) {
      return res.status(401).json({ error: 'Token invalido' });
    }

    req.user = decoded;
    next();
  });
}

function requirePerfil(...perfisPermitidos) {
  return (req, res, next) => {
    if (!req.user || !perfisPermitidos.includes(req.user.perfil)) {
      return res.status(403).json({ error: 'Acesso negado' });
    }
    next();
  };
}

function getTenantFilter(req, tableAlias = '') {
  const prefix = tableAlias ? `${tableAlias}.` : '';
  if (req.user.perfil === 'superadmin') {
    return { clause: '', params: [] };
  }
  return {
    clause: `WHERE ${prefix}tenant_id = $1`,
    params: [req.user.tenant_id]
  };
}

app.get('/', (req, res) => {
  res.json({ ok: true, service: 'Gevox API', version: 'v1' });
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
  try {
    const { email, senha } = req.body;

    if (!email || !senha) {
      return res.status(400).json({ error: 'Email e senha são obrigatórios' });
    }

    const result = await pool.query(
      `SELECT id, email, senha_hash, perfil, tenant_id, ativo, nome
       FROM users
       WHERE email = $1
       LIMIT 1`,
      [email]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'Credenciais invalidas' });
    }

    const user = result.rows[0];

    if (!user.ativo) {
      return res.status(403).json({ error: 'Usuario inativo' });
    }

    const senhaValida = await bcrypt.compare(senha, user.senha_hash);

    if (!senhaValida) {
      return res.status(401).json({ error: 'Credenciais invalidas' });
    }

    const token = generateToken(user);

    res.json({
      token,
      user: {
        id: user.id,
        nome: user.nome,
        email: user.email,
        perfil: user.perfil,
        tenant_id: user.tenant_id
      }
    });
  } catch (error) {
    res.status(500).json({ error: 'Erro interno no login', detail: error.message });
  }
});

app.get('/auth/me', authMiddleware, (req, res) => {
  res.json({ user: req.user });
});

app.get('/api/v1/tenants', authMiddleware, async (req, res) => {
  try {
    const filtro = getTenantFilter(req);
    const query = `
      SELECT *
      FROM tenants
      ${filtro.clause}
      ORDER BY id ASC
    `;
    const result = await pool.query(query, filtro.params);
    res.json(result.rows);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/v1/products', authMiddleware, async (req, res) => {
  try {
    const filtro = getTenantFilter(req);
    const query = `
      SELECT *
      FROM products
      ${filtro.clause}
      ORDER BY id ASC
    `;
    const result = await pool.query(query, filtro.params);
    res.json(result.rows);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/v1/customers', authMiddleware, async (req, res) => {
  try {
    const filtro = getTenantFilter(req);
    const query = `
      SELECT *
      FROM customers
      ${filtro.clause}
      ORDER BY id ASC
    `;
    const result = await pool.query(query, filtro.params);
    res.json(result.rows);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/v1/users', authMiddleware, requirePerfil('superadmin', 'admin'), async (req, res) => {
  try {
    const filtro = getTenantFilter(req);
    const query = `
      SELECT id, nome, email, perfil, tenant_id, ativo, created_at
      FROM users
      ${filtro.clause}
      ORDER BY id ASC
    `;
    const result = await pool.query(query, filtro.params);
    res.json(result.rows);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/v1/dashboard/summary', authMiddleware, async (req, res) => {
  try {
    const filtroProducts = getTenantFilter(req);
    const filtroCustomers = getTenantFilter(req);
    const filtroUsers = getTenantFilter(req);

    const [products, customers, users] = await Promise.all([
      pool.query(`SELECT COUNT(*)::int AS total FROM products ${filtroProducts.clause}`, filtroProducts.params),
      pool.query(`SELECT COUNT(*)::int AS total FROM customers ${filtroCustomers.clause}`, filtroCustomers.params),
      pool.query(`SELECT COUNT(*)::int AS total FROM users ${filtroUsers.clause}`, filtroUsers.params)
    ]);

    res.json({
      products: products.rows[0].total,
      customers: customers.rows[0].total,
      users: users.rows[0].total
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/tenants', authMiddleware, async (req, res) => {
  try {
    const filtro = getTenantFilter(req);
    const query = `
      SELECT *
      FROM tenants
      ${filtro.clause}
      ORDER BY id ASC
    `;
    const result = await pool.query(query, filtro.params);
    res.json(result.rows);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/products', authMiddleware, async (req, res) => {
  try {
    const filtro = getTenantFilter(req);
    const query = `
      SELECT *
      FROM products
      ${filtro.clause}
      ORDER BY id ASC
    `;
    const result = await pool.query(query, filtro.params);
    res.json(result.rows);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/customers', authMiddleware, async (req, res) => {
  try {
    const filtro = getTenantFilter(req);
    const query = `
      SELECT *
      FROM customers
      ${filtro.clause}
      ORDER BY id ASC
    `;
    const result = await pool.query(query, filtro.params);
    res.json(result.rows);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

const port = process.env.PORT || process.env.APP_PORT || 3000;
app.listen(port, () => {
  console.log(`Gevox API running on port ${port}`);
});
