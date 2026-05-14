require('dotenv').config();
const express = require('express');
const cors = require('cors');
const pool = require('./db');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
app.disable('x-powered-by');

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

app.use(express.json({ limit: '1mb' }));

const isProduction = process.env.NODE_ENV === 'production';

function logError(error) {
  console.error(error);
}

function internalError(res, error) {
  logError(error);
  return res.status(500).json({
    error: isProduction ? 'Erro interno do servidor' : error.message
  });
}

function normalizeEmail(email) {
  return String(email || '').trim().toLowerCase();
}

function normalizeSlug(slug) {
  return String(slug || '').trim().toLowerCase();
}

function onlyDigits(value) {
  return String(value || '').replace(/\D/g, '');
}

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(email || '').trim());
}

function isValidSlug(slug) {
  return /^[a-z0-9-]+$/.test(String(slug || '').trim());
}

function isValidPerfil(perfil) {
  return ['superadmin', 'admin', 'user'].includes(perfil);
}

function isPositiveOrZeroNumber(value) {
  return !Number.isNaN(Number(value)) && Number(value) >= 0;
}

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

function canManageTenantId(req, tenantId) {
  if (req.user.perfil === 'superadmin') return true;
  return String(req.user.tenant_id) === String(tenantId);
}

function getRequestIp(req) {
  const forwarded = req.headers['x-forwarded-for'];
  if (forwarded) {
    return String(forwarded).split(',')[0].trim();
  }
  return req.ip || req.connection?.remoteAddress || 'unknown';
}

// Rate limit simples para login
const loginAttempts = new Map();
const LOGIN_WINDOW_MS = 15 * 60 * 1000;
const LOGIN_MAX_ATTEMPTS = 5;

function checkLoginRateLimit(req, res, next) {
  const ip = getRequestIp(req);
  const now = Date.now();
  const current = loginAttempts.get(ip);

  if (!current || now > current.expiresAt) {
    loginAttempts.set(ip, {
      count: 1,
      expiresAt: now + LOGIN_WINDOW_MS
    });
    return next();
  }

  if (current.count >= LOGIN_MAX_ATTEMPTS) {
    return res.status(429).json({
      error: 'Muitas tentativas de login. Tente novamente em alguns minutos'
    });
  }

  current.count += 1;
  next();
}

function clearLoginRateLimit(req) {
  const ip = getRequestIp(req);
  loginAttempts.delete(ip);
}

function validateTenantInput(body) {
  const planosPermitidos = ['basico', 'pro', 'premium'];
  const statusPermitidos = ['ativado', 'desativado', 'pendente'];

  if (!body.nome_fantasia || !String(body.nome_fantasia).trim()) {
    return 'Nome da empresa é obrigatório';
  }

  if (!body.slug || !String(body.slug).trim()) {
    return 'Slug é obrigatório';
  }

  if (!isValidSlug(body.slug)) {
    return 'Slug inválido. Use apenas letras minúsculas, números e hífen';
  }

  if (body.plano && !planosPermitidos.includes(body.plano)) {
    return 'Plano inválido';
  }

  if (body.status_assinatura && !statusPermitidos.includes(body.status_assinatura)) {
    return 'Status da assinatura inválido';
  }

  if (body.email && !isValidEmail(body.email)) {
    return 'Email inválido';
  }

  if (body.total_credito !== undefined && !isPositiveOrZeroNumber(body.total_credito)) {
    return 'Crédito total inválido';
  }

  const cpfCnpj = onlyDigits(body.cpf_cnpj);
  if (body.cpf_cnpj && ![11, 14].includes(cpfCnpj.length)) {
    return 'CPF ou CNPJ inválido';
  }

  return null;
}

function validateProductInput(body) {
  if (!body.nome || !String(body.nome).trim()) {
    return 'Nome do produto é obrigatório';
  }

  if (body.preco !== undefined && Number.isNaN(Number(body.preco))) {
    return 'Preço inválido';
  }

  if (body.estoque !== undefined && Number.isNaN(Number(body.estoque))) {
    return 'Estoque inválido';
  }

  return null;
}

function validateCustomerInput(body) {
  if (!body.nome || !String(body.nome).trim()) {
    return 'Nome do cliente é obrigatório';
  }

  if (body.email && !isValidEmail(body.email)) {
    return 'Email inválido';
  }

  return null;
}

function validateUserInput(body, { isUpdate = false } = {}) {
  if (!body.nome || !String(body.nome).trim()) {
    return 'Nome do usuário é obrigatório';
  }

  if (!body.email || !isValidEmail(body.email)) {
    return 'Email inválido';
  }

  if (!isUpdate && (!body.senha || String(body.senha).length < 6)) {
    return 'Senha deve ter pelo menos 6 caracteres';
  }

  if (isUpdate && body.senha && String(body.senha).length < 6) {
    return 'Senha deve ter pelo menos 6 caracteres';
  }

  if (body.perfil && !isValidPerfil(body.perfil)) {
    return 'Perfil inválido';
  }

  return null;
}

app.get('/', (req, res) => {
  res.json({ ok: true, service: 'Gevox API', version: 'v1' });
});

app.get('/health', async (req, res) => {
  try {
    const result = await pool.query('SELECT NOW()');
    res.json({ ok: true, db: true, now: result.rows[0].now });
  } catch (error) {
    logError(error);
    res.status(500).json({ ok: false, db: false, error: 'Erro interno do servidor' });
  }
});

app.post('/auth/login', checkLoginRateLimit, async (req, res) => {
  try {
    const email = normalizeEmail(req.body.email);
    const senha = String(req.body.senha || '');

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

    clearLoginRateLimit(req);

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
    return internalError(res, error);
  }
});

app.get('/auth/me', authMiddleware, (req, res) => {
  res.json({ user: req.user });
});

app.get('/api/v1/tenants', authMiddleware, async (req, res) => {
  try {
    const filtro = getTenantFilter(req);
    const query = `
      SELECT
        id,
        nome_fantasia,
        razao_social,
        cpf_cnpj,
        whatsapp_principal,
        email,
        plano,
        status_assinatura,
        total_credito,
        ativo,
        slug,
        created_at,
        updated_at
      FROM tenants
      ${filtro.clause}
      ORDER BY id ASC
    `;
    const result = await pool.query(query, filtro.params);
    res.json(result.rows);
  } catch (error) {
    return internalError(res, error);
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
    return internalError(res, error);
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
    return internalError(res, error);
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
    return internalError(res, error);
  }
});

app.get('/api/v1/dashboard/summary', authMiddleware, async (req, res) => {
  try {
    const filtroProducts = getTenantFilter(req);
    const filtroCustomers = getTenantFilter(req);
    const filtroUsers = getTenantFilter(req);
    const filtroTenants = getTenantFilter(req);

    const [products, customers, users, credits] = await Promise.all([
      pool.query(
        `SELECT COUNT(*)::int AS total FROM products ${filtroProducts.clause}`,
        filtroProducts.params
      ),
      pool.query(
        `SELECT COUNT(*)::int AS total FROM customers ${filtroCustomers.clause}`,
        filtroCustomers.params
      ),
      pool.query(
        `SELECT COUNT(*)::int AS total FROM users ${filtroUsers.clause}`,
        filtroUsers.params
      ),
      pool.query(
        `SELECT COALESCE(SUM(total_credito), 0)::numeric AS total FROM tenants ${filtroTenants.clause}`,
        filtroTenants.params
      )
    ]);

    res.json({
      products: products.rows[0].total,
      customers: customers.rows[0].total,
      users: users.rows[0].total,
      total_credito: Number(credits.rows[0].total || 0)
    });
  } catch (error) {
    return internalError(res, error);
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
    return internalError(res, error);
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
    return internalError(res, error);
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
    return internalError(res, error);
  }
});

// ========== CRUD - TENANTS ==========
app.post('/api/v1/tenants', authMiddleware, requirePerfil('superadmin', 'admin'), async (req, res) => {
  try {
    const validationError = validateTenantInput(req.body);
    if (validationError) {
      return res.status(400).json({ error: validationError });
    }

    const nome_fantasia = String(req.body.nome_fantasia).trim();
    const razao_social = String(req.body.razao_social || nome_fantasia).trim();
    const cpf_cnpj = req.body.cpf_cnpj ? onlyDigits(req.body.cpf_cnpj) : null;
    const whatsapp_principal = req.body.whatsapp_principal ? String(req.body.whatsapp_principal).trim() : null;
    const email = req.body.email ? normalizeEmail(req.body.email) : null;
    const plano = req.body.plano || 'basico';
    const status_assinatura = req.body.status_assinatura || 'ativado';
    const total_credito = Number(req.body.total_credito || 0);
    const ativo = req.body.ativo !== false;
    const slug = normalizeSlug(req.body.slug);

    const slugCheck = await pool.query(
      'SELECT id FROM tenants WHERE slug = $1 LIMIT 1',
      [slug]
    );

    if (slugCheck.rows.length > 0) {
      return res.status(409).json({ error: 'Já existe uma empresa com este slug' });
    }

    const result = await pool.query(
      `INSERT INTO tenants (
        nome_fantasia,
        razao_social,
        cpf_cnpj,
        whatsapp_principal,
        email,
        plano,
        status_assinatura,
        total_credito,
        ativo,
        slug
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
      RETURNING *`,
      [
        nome_fantasia,
        razao_social,
        cpf_cnpj,
        whatsapp_principal,
        email,
        plano,
        status_assinatura,
        total_credito,
        ativo,
        slug
      ]
    );

    res.json(result.rows[0]);
  } catch (error) {
    return internalError(res, error);
  }
});

app.put('/api/v1/tenants/:id', authMiddleware, requirePerfil('superadmin', 'admin'), async (req, res) => {
  try {
    const { id } = req.params;
    const validationError = validateTenantInput(req.body);

    if (validationError) {
      return res.status(400).json({ error: validationError });
    }

    if (req.user.perfil !== 'superadmin') {
      const tenantCheck = await pool.query(
        'SELECT id, tenant_id FROM tenants WHERE id = $1 LIMIT 1',
        [id]
      );

      if (tenantCheck.rows.length === 0) {
        return res.status(404).json({ error: 'Tenant nao encontrado' });
      }

      if (!canManageTenantId(req, tenantCheck.rows[0].id)) {
        return res.status(403).json({ error: 'Acesso negado para este tenant' });
      }
    }

    const nome_fantasia = String(req.body.nome_fantasia).trim();
    const razao_social = String(req.body.razao_social || nome_fantasia).trim();
    const cpf_cnpj = req.body.cpf_cnpj ? onlyDigits(req.body.cpf_cnpj) : null;
    const whatsapp_principal = req.body.whatsapp_principal ? String(req.body.whatsapp_principal).trim() : null;
    const email = req.body.email ? normalizeEmail(req.body.email) : null;
    const plano = req.body.plano || 'basico';
    const status_assinatura = req.body.status_assinatura || 'ativado';
    const total_credito = Number(req.body.total_credito || 0);
    const ativo = req.body.ativo !== false;
    const slug = normalizeSlug(req.body.slug);

    const slugCheck = await pool.query(
      'SELECT id FROM tenants WHERE slug = $1 AND id <> $2 LIMIT 1',
      [slug, id]
    );

    if (slugCheck.rows.length > 0) {
      return res.status(409).json({ error: 'Já existe uma empresa com este slug' });
    }

    const result = await pool.query(
      `UPDATE tenants
       SET
         nome_fantasia = $1,
         razao_social = $2,
         cpf_cnpj = $3,
         whatsapp_principal = $4,
         email = $5,
         plano = $6,
         status_assinatura = $7,
         total_credito = $8,
         ativo = $9,
         slug = $10
       WHERE id = $11
       RETURNING *`,
      [
        nome_fantasia,
        razao_social,
        cpf_cnpj,
        whatsapp_principal,
        email,
        plano,
        status_assinatura,
        total_credito,
        ativo,
        slug,
        id
      ]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Tenant nao encontrado' });
    }

    res.json(result.rows[0]);
  } catch (error) {
    return internalError(res, error);
  }
});

app.delete('/api/v1/tenants/:id', authMiddleware, requirePerfil('superadmin', 'admin'), async (req, res) => {
  try {
    const { id } = req.params;

    if (req.user.perfil !== 'superadmin' && String(req.user.tenant_id) !== String(id)) {
      return res.status(403).json({ error: 'Acesso negado para este tenant' });
    }

    const result = await pool.query(
      'DELETE FROM tenants WHERE id = $1 RETURNING *',
      [id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Tenant nao encontrado' });
    }

    res.json({ ok: true, deleted: result.rows[0] });
  } catch (error) {
    return internalError(res, error);
  }
});

// ========== CRUD - PRODUCTS ==========
app.post('/api/v1/products', authMiddleware, async (req, res) => {
  try {
    const validationError = validateProductInput(req.body);
    if (validationError) {
      return res.status(400).json({ error: validationError });
    }

    const tenantId = req.user.perfil === 'superadmin'
      ? (req.body.tenant_id || null)
      : req.user.tenant_id;

    if (!tenantId) {
      return res.status(400).json({ error: 'tenant_id é obrigatório' });
    }

    const nome = String(req.body.nome).trim();
    const preco = Number(req.body.preco || 0);
    const estoque = Number(req.body.estoque || 0);

    const result = await pool.query(
      'INSERT INTO products (nome, preco, estoque, tenant_id) VALUES ($1, $2, $3, $4) RETURNING *',
      [nome, preco, estoque, tenantId]
    );

    res.json(result.rows[0]);
  } catch (error) {
    return internalError(res, error);
  }
});

app.put('/api/v1/products/:id', authMiddleware, async (req, res) => {
  try {
    const validationError = validateProductInput(req.body);
    if (validationError) {
      return res.status(400).json({ error: validationError });
    }

    const filtro = getTenantFilter(req);
    const { id } = req.params;
    const nome = String(req.body.nome).trim();
    const preco = Number(req.body.preco || 0);
    const estoque = Number(req.body.estoque || 0);

    let query = `
      UPDATE products
      SET nome = $1, preco = $2, estoque = $3
      WHERE id = $4
    `;
    let params = [nome, preco, estoque, id];

    if (filtro.clause) {
      query += ' AND tenant_id = $5';
      params.push(req.user.tenant_id);
    }

    query += ' RETURNING *';

    const result = await pool.query(query, params);

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Produto nao encontrado' });
    }

    res.json(result.rows[0]);
  } catch (error) {
    return internalError(res, error);
  }
});

app.delete('/api/v1/products/:id', authMiddleware, async (req, res) => {
  try {
    const filtro = getTenantFilter(req);
    const { id } = req.params;

    let query = 'DELETE FROM products WHERE id = $1';
    let params = [id];

    if (filtro.clause) {
      query += ' AND tenant_id = $2';
      params.push(req.user.tenant_id);
    }

    query += ' RETURNING *';

    const result = await pool.query(query, params);

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Produto nao encontrado' });
    }

    res.json({ ok: true, deleted: result.rows[0] });
  } catch (error) {
    return internalError(res, error);
  }
});

// ========== CRUD - CUSTOMERS ==========
app.post('/api/v1/customers', authMiddleware, async (req, res) => {
  try {
    const validationError = validateCustomerInput(req.body);
    if (validationError) {
      return res.status(400).json({ error: validationError });
    }

    const tenantId = req.user.perfil === 'superadmin'
      ? (req.body.tenant_id || null)
      : req.user.tenant_id;

    if (!tenantId) {
      return res.status(400).json({ error: 'tenant_id é obrigatório' });
    }

    const nome = String(req.body.nome).trim();
    const email = req.body.email ? normalizeEmail(req.body.email) : null;
    const telefone = req.body.telefone ? String(req.body.telefone).trim() : null;

    const result = await pool.query(
      'INSERT INTO customers (nome, email, telefone, tenant_id) VALUES ($1, $2, $3, $4) RETURNING *',
      [nome, email, telefone, tenantId]
    );

    res.json(result.rows[0]);
  } catch (error) {
    return internalError(res, error);
  }
});

app.put('/api/v1/customers/:id', authMiddleware, async (req, res) => {
  try {
    const validationError = validateCustomerInput(req.body);
    if (validationError) {
      return res.status(400).json({ error: validationError });
    }

    const filtro = getTenantFilter(req);
    const { id } = req.params;
    const nome = String(req.body.nome).trim();
    const email = req.body.email ? normalizeEmail(req.body.email) : null;
    const telefone = req.body.telefone ? String(req.body.telefone).trim() : null;

    let query = `
      UPDATE customers
      SET nome = $1, email = $2, telefone = $3
      WHERE id = $4
    `;
    let params = [nome, email, telefone, id];

    if (filtro.clause) {
      query += ' AND tenant_id = $5';
      params.push(req.user.tenant_id);
    }

    query += ' RETURNING *';

    const result = await pool.query(query, params);

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Cliente nao encontrado' });
    }

    res.json(result.rows[0]);
  } catch (error) {
    return internalError(res, error);
  }
});

app.delete('/api/v1/customers/:id', authMiddleware, async (req, res) => {
  try {
    const filtro = getTenantFilter(req);
    const { id } = req.params;

    let query = 'DELETE FROM customers WHERE id = $1';
    let params = [id];

    if (filtro.clause) {
      query += ' AND tenant_id = $2';
      params.push(req.user.tenant_id);
    }

    query += ' RETURNING *';

    const result = await pool.query(query, params);

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Cliente nao encontrado' });
    }

    res.json({ ok: true, deleted: result.rows[0] });
  } catch (error) {
    return internalError(res, error);
  }
});

// ========== CRUD - USERS ==========
app.post('/api/v1/users', authMiddleware, requirePerfil('superadmin', 'admin'), async (req, res) => {
  try {
    const validationError = validateUserInput(req.body);
    if (validationError) {
      return res.status(400).json({ error: validationError });
    }

    const nome = String(req.body.nome).trim();
    const email = normalizeEmail(req.body.email);
    const senha = String(req.body.senha);
    const perfil = req.body.perfil || 'user';
    const ativo = req.body.ativo !== false;

    let tenant_id = req.body.tenant_id;

    if (req.user.perfil !== 'superadmin') {
      tenant_id = req.user.tenant_id;
      if (perfil === 'superadmin') {
        return res.status(403).json({ error: 'Acesso negado para criar superadmin' });
      }
    }

    if (!tenant_id) {
      return res.status(400).json({ error: 'tenant_id é obrigatório' });
    }

    if (!canManageTenantId(req, tenant_id)) {
      return res.status(403).json({ error: 'Acesso negado para este tenant' });
    }

    const emailCheck = await pool.query(
      'SELECT id FROM users WHERE email = $1 LIMIT 1',
      [email]
    );

    if (emailCheck.rows.length > 0) {
      return res.status(409).json({ error: 'Já existe um usuário com este email' });
    }

    const senha_hash = await bcrypt.hash(senha, 10);

    const result = await pool.query(
      `INSERT INTO users (nome, email, senha_hash, perfil, tenant_id, ativo)
       VALUES ($1, $2, $3, $4, $5, $6)
       RETURNING id, nome, email, perfil, tenant_id, ativo`,
      [nome, email, senha_hash, perfil, tenant_id, ativo]
    );

    res.json(result.rows[0]);
  } catch (error) {
    return internalError(res, error);
  }
});

app.put('/api/v1/users/:id', authMiddleware, requirePerfil('superadmin', 'admin'), async (req, res) => {
  try {
    const validationError = validateUserInput(req.body, { isUpdate: true });
    if (validationError) {
      return res.status(400).json({ error: validationError });
    }

    const { id } = req.params;
    const nome = String(req.body.nome).trim();
    const email = normalizeEmail(req.body.email);
    const perfil = req.body.perfil || 'user';
    const ativo = req.body.ativo !== false;

    const userCheck = await pool.query(
      'SELECT id, tenant_id, perfil FROM users WHERE id = $1 LIMIT 1',
      [id]
    );

    if (userCheck.rows.length === 0) {
      return res.status(404).json({ error: 'Usuario nao encontrado' });
    }

    const targetUser = userCheck.rows[0];

    if (!canManageTenantId(req, targetUser.tenant_id)) {
      return res.status(403).json({ error: 'Acesso negado para este tenant' });
    }

    if (req.user.perfil !== 'superadmin' && perfil === 'superadmin') {
      return res.status(403).json({ error: 'Acesso negado para definir superadmin' });
    }

    const emailCheck = await pool.query(
      'SELECT id FROM users WHERE email = $1 AND id <> $2 LIMIT 1',
      [email, id]
    );

    if (emailCheck.rows.length > 0) {
      return res.status(409).json({ error: 'Já existe um usuário com este email' });
    }

    let query = 'UPDATE users SET nome=$1, email=$2, perfil=$3, ativo=$4';
    const params = [nome, email, perfil, ativo];

    if (req.body.senha) {
      const senha_hash = await bcrypt.hash(String(req.body.senha), 10);
      query += ', senha_hash=$5 WHERE id=$6 RETURNING id, nome, email, perfil, tenant_id, ativo';
      params.push(senha_hash, id);
    } else {
      query += ' WHERE id=$5 RETURNING id, nome, email, perfil, tenant_id, ativo';
      params.push(id);
    }

    const result = await pool.query(query, params);

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Usuario nao encontrado' });
    }

    res.json(result.rows[0]);
  } catch (error) {
    return internalError(res, error);
  }
});

app.delete('/api/v1/users/:id', authMiddleware, requirePerfil('superadmin', 'admin'), async (req, res) => {
  try {
    const { id } = req.params;

    const userCheck = await pool.query(
      'SELECT id, tenant_id, perfil FROM users WHERE id = $1 LIMIT 1',
      [id]
    );

    if (userCheck.rows.length === 0) {
      return res.status(404).json({ error: 'Usuario nao encontrado' });
    }

    const targetUser = userCheck.rows[0];

    if (!canManageTenantId(req, targetUser.tenant_id)) {
      return res.status(403).json({ error: 'Acesso negado para este tenant' });
    }

    if (req.user.perfil !== 'superadmin' && targetUser.perfil === 'superadmin') {
      return res.status(403).json({ error: 'Acesso negado para excluir superadmin' });
    }

    const result = await pool.query(
      'DELETE FROM users WHERE id=$1 RETURNING id, nome, email, perfil, tenant_id, ativo',
      [id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Usuario nao encontrado' });
    }

    res.json({ ok: true, deleted: result.rows[0] });
  } catch (error) {
    return internalError(res, error);
  }
});

// Tratamento de erro de CORS e fallback
app.use((err, req, res, next) => {
  if (err && err.message === 'Origem não permitida pelo CORS') {
    return res.status(403).json({ error: 'Origem não permitida' });
  }
  return internalError(res, err);
});

const port = process.env.PORT || process.env.APP_PORT || 3000;
app.listen(port, () => {
  console.log(`Gevox API running on port ${port}`);
});
