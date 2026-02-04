/**
 * server.js — IVPLAST Reclamações (Express + EJS + Session + Postgres)
 *
 * Regras implantadas:
 * - Cargos oficiais: atendimento | comercial | financeiro | admin | diretor
 * - Status oficiais (fluxo): Aberto | Em análise | Aguardando cliente | Aguardando fábrica | Finalizado – Financeiro | Diretoria
 * - Permissões:
 *   Comercial: cria/comenta; vê só o que criou; não altera status
 *   Atendimento: vê tudo; cria/comenta; altera status até "Finalizado – Financeiro"
 *   Financeiro: vê só status "Finalizado – Financeiro"; vê custo; comenta; pode devolver para status anteriores ou enviar para "Diretoria"
 *   Diretor(a): vê tudo; comenta; só altera status quando status atual = "Diretoria"
 *   Admin: tudo (inclui alterar status sempre e gerir usuários)
 */

const path = require("path");
const fs = require("fs");
const express = require("express");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const multer = require("multer");

let pg;
try {
  pg = require("pg");
} catch (_) {
  pg = null;
}

const app = express();
app.set("trust proxy", 1);

/* -----------------------------
   Config básica
----------------------------- */
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

/* -----------------------------
   Uploads
----------------------------- */
const UPLOAD_DIR = process.env.UPLOAD_DIR ? path.resolve(process.env.UPLOAD_DIR) : path.join(__dirname, "uploads");
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });

const upload = multer({
  storage: multer.diskStorage({
    destination: (req, file, cb) => cb(null, UPLOAD_DIR),
    filename: (req, file, cb) => {
      const safe = String(file.originalname || "arquivo").replace(/[^\w.\-]+/g, "_");
      cb(null, `${Date.now()}_${safe}`);
    },
  }),
  limits: { fileSize: 10 * 1024 * 1024 },
});

/* -----------------------------
   Sessão
----------------------------- */
app.use(
  session({
    name: "ivplast.sid",
    secret: process.env.SESSION_SECRET || "dev_secret_change_me",
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: "lax",
      secure: "auto",
      maxAge: 1000 * 60 * 60 * 12,
    },
  })
);

/* -----------------------------
   Postgres
----------------------------- */
function envBool(v) {
  if (typeof v !== "string") return false;
  return ["true", "1", "yes", "y", "on"].includes(v.toLowerCase().trim());
}

const USE_DB = !!process.env.DATABASE_URL && !!pg;
let pool = null;

if (USE_DB) {
  const sslEnabled = envBool(process.env.DATABASE_SSL);
  pool = new pg.Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: sslEnabled ? { rejectUnauthorized: false } : false,
  });
}

/* -----------------------------
   Constantes de negócio
----------------------------- */
const ROLES = Object.freeze({
  ATENDIMENTO: "atendimento",
  COMERCIAL: "comercial",
  FINANCEIRO: "financeiro",
  ADMIN: "admin",
  DIRETOR: "diretor",
});

const ALLOWED_ROLES = new Set(Object.values(ROLES));

const STATUS = Object.freeze({
  ABERTO: "Aberto",
  EM_ANALISE: "Em análise",
  AGUARD_CLIENTE: "Aguardando cliente",
  AGUARD_FABRICA: "Aguardando fábrica",
  FINALIZADO_FIN: "Finalizado – Financeiro",
  DIRETORIA: "Diretoria",
});

const STATUS_FLOW = [
  STATUS.ABERTO,
  STATUS.EM_ANALISE,
  STATUS.AGUARD_CLIENTE,
  STATUS.AGUARD_FABRICA,
  STATUS.FINALIZADO_FIN,
  STATUS.DIRETORIA,
];

const STATUS_SET = new Set(STATUS_FLOW);

/* -----------------------------
   Helpers
----------------------------- */
function isAuthed(req) {
  return req.session && req.session.user && req.session.user.id;
}
function requireAuth(req, res, next) {
  if (!isAuthed(req)) return res.redirect("/login");
  next();
}

function userRole(req) {
  const r = String(req.session?.user?.role || "").toLowerCase().trim();
  return ALLOWED_ROLES.has(r) ? r : ROLES.COMERCIAL; // fallback seguro
}
function isDirector(req) {
  return userRole(req) === ROLES.DIRETOR;
}
function isAdmin(req) {
  return userRole(req) === ROLES.ADMIN;
}
function isAtendimento(req) {
  return userRole(req) === ROLES.ATENDIMENTO;
}
function isFinanceiro(req) {
  return userRole(req) === ROLES.FINANCEIRO;
}
function isComercial(req) {
  return userRole(req) === ROLES.COMERCIAL;
}

function requireAdminOrDirector(req, res, next) {
  if (!isAuthed(req)) return res.redirect("/login");
  if (!(isAdmin(req) || isDirector(req))) return res.status(403).send("Acesso negado. Apenas Admin ou Diretor(a).");
  next();
}

function nowISO() {
  return new Date().toISOString();
}
function safeInt(v, fallback = 0) {
  const n = parseInt(v, 10);
  return Number.isFinite(n) ? n : fallback;
}
function safeFloat(v, fallback = 0) {
  if (v === null || v === undefined) return fallback;
  const cleaned = String(v).replace(/\./g, "").replace(",", ".");
  const n = Number(cleaned);
  return Number.isFinite(n) ? n : fallback;
}
function daysAgoText(dateISO) {
  try {
    const d = new Date(dateISO);
    const diffMs = Date.now() - d.getTime();
    const days = Math.floor(diffMs / (1000 * 60 * 60 * 24));
    if (days <= 0) return "hoje";
    if (days === 1) return "há 1 dia";
    return `há ${days} dias`;
  } catch {
    return "-";
  }
}
function hoursBetween(aISO, bISO) {
  const a = new Date(aISO).getTime();
  const b = new Date(bISO).getTime();
  if (!Number.isFinite(a) || !Number.isFinite(b)) return 0;
  return Math.max(0, Math.round((b - a) / (1000 * 60 * 60)));
}
function cleanEmail(v) {
  return String(v || "").trim().toLowerCase();
}
function cleanStr(v) {
  return String(v || "").trim();
}
function pickFirst(...values) {
  for (const v of values) {
    if (v === undefined || v === null) continue;
    const s = String(v);
    if (s.trim().length) return s;
  }
  return "";
}

function normalizeStatusToOfficial(input) {
  const s = String(input || "").trim();
  if (STATUS_SET.has(s)) return s;

  // compat legada
  const low = s.toLowerCase();
  if (low === "resolvido") return STATUS.DIRETORIA;
  if (low === "em andamento") return STATUS.EM_ANALISE;
  if (low === "em transporte") return STATUS.AGUARD_FABRICA;

  // fallback
  return STATUS.ABERTO;
}

function canSeeCost(req) {
  // Financeiro vê custo; Admin e Diretor também.
  return isFinanceiro(req) || isAdmin(req) || isDirector(req);
}

function canViewOcorrenciaByStatus(req, status) {
  const st = normalizeStatusToOfficial(status);

  if (isAdmin(req) || isDirector(req) || isAtendimento(req)) return true;

  if (isFinanceiro(req)) {
    // Financeiro só vê quando estiver em Finalizado – Financeiro.
    return st === STATUS.FINALIZADO_FIN;
  }

  // Comercial: a regra de "ver" é por created_by (tratada nas queries),
  // então aqui deixamos true para não bloquear o próprio chamado.
  return true;
}

function allowedNextStatuses(req, currentStatus) {
  const cur = normalizeStatusToOfficial(currentStatus);

  if (isAdmin(req)) return STATUS_FLOW.slice();

  if (isComercial(req)) {
    // não altera status
    return [cur];
  }

  if (isAtendimento(req)) {
    // até Finalizado – Financeiro
    return [STATUS.ABERTO, STATUS.EM_ANALISE, STATUS.AGUARD_CLIENTE, STATUS.AGUARD_FABRICA, STATUS.FINALIZADO_FIN];
  }

  if (isFinanceiro(req)) {
    // só atua quando estiver em Finalizado – Financeiro
    if (cur !== STATUS.FINALIZADO_FIN) return [cur];
    return [STATUS.ABERTO, STATUS.EM_ANALISE, STATUS.AGUARD_CLIENTE, STATUS.AGUARD_FABRICA, STATUS.FINALIZADO_FIN, STATUS.DIRETORIA];
  }

  if (isDirector(req)) {
    // só altera quando estiver em Diretoria
    if (cur !== STATUS.DIRETORIA) return [cur];
    return [STATUS.ABERTO, STATUS.EM_ANALISE, STATUS.AGUARD_CLIENTE, STATUS.AGUARD_FABRICA, STATUS.FINALIZADO_FIN, STATUS.DIRETORIA];
  }

  return [cur];
}

function canChangeStatus(req, currentStatus) {
  const cur = normalizeStatusToOfficial(currentStatus);

  if (isAdmin(req)) return true;
  if (isComercial(req)) return false;
  if (isAtendimento(req)) return true;
  if (isFinanceiro(req)) return cur === STATUS.FINALIZADO_FIN;
  if (isDirector(req)) return cur === STATUS.DIRETORIA;
  return false;
}

function isStatusAllowedForUser(req, newStatus, currentStatus) {
  const allowed = new Set(allowedNextStatuses(req, currentStatus));
  return allowed.has(normalizeStatusToOfficial(newStatus));
}

/* -----------------------------
   MOCK (sem DB)
----------------------------- */
const mock = { users: [], settings: {}, ocorrencias: [], auditoria: [] };

function ensureMockUserFromEnv(kind) {
  const emailEnv = kind === "director" ? "DIRECTOR_EMAIL" : "ADMIN_EMAIL";
  const passEnv = kind === "director" ? "DIRECTOR_PASSWORD" : "ADMIN_PASSWORD";
  const nameEnv = kind === "director" ? "DIRECTOR_NAME" : "ADMIN_NAME";
  const role = kind === "director" ? ROLES.DIRETOR : ROLES.ADMIN;

  const email = String(process.env[emailEnv] || "").trim().toLowerCase();
  const pass = String(process.env[passEnv] || "");
  const name = process.env[nameEnv] || (kind === "director" ? "Diretor(a)" : "Admin");
  if (!email || !pass) return;

  const exists = mock.users.find((u) => String(u.email).toLowerCase() === email);
  if (!exists) {
    const hash = bcrypt.hashSync(pass, 10);
    const id = mock.users.length ? Math.max(...mock.users.map((u) => u.id)) + 1 : 1;
    mock.users.push({ id, nome: name, email, senha_hash: hash, role, active: true, created_at: nowISO() });
  }
}
ensureMockUserFromEnv("admin");
ensureMockUserFromEnv("director");

/* -----------------------------
   Legacy detection (DB)
----------------------------- */
let LEGACY = { hasName: false, hasPasswordHash: false };

async function detectLegacyColumns() {
  if (!USE_DB) return;
  const r = await pool.query(`
    SELECT column_name
    FROM information_schema.columns
    WHERE table_schema='public' AND table_name='users'
  `);
  const cols = new Set(r.rows.map((x) => String(x.column_name).toLowerCase()));
  LEGACY.hasName = cols.has("name");
  LEGACY.hasPasswordHash = cols.has("password_hash");
  console.log("LEGACY_COLS:", LEGACY);
}

async function dropNotNullIfExists(columnName) {
  const r = await pool.query(
    `
    SELECT is_nullable
    FROM information_schema.columns
    WHERE table_schema='public' AND table_name='users' AND column_name=$1
  `,
    [columnName]
  );
  if (!r.rowCount) return;
  const isNullable = String(r.rows[0].is_nullable || "").toUpperCase() === "YES";
  if (!isNullable) {
    await pool.query(`ALTER TABLE users ALTER COLUMN ${columnName} DROP NOT NULL;`);
    console.log(`✅ DROP NOT NULL em users.${columnName}`);
  }
}

/* -----------------------------
   Settings/Auditoria (DB/MOCK)
----------------------------- */
async function upsertSetting(key, value) {
  if (!USE_DB) {
    mock.settings[key] = value;
    return;
  }
  await pool.query(
    `INSERT INTO settings (key,value) VALUES ($1,$2)
     ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value`,
    [key, String(value)]
  );
}
async function getSetting(key, fallback = "") {
  if (!USE_DB) return mock.settings[key] ?? fallback;
  const r = await pool.query(`SELECT value FROM settings WHERE key=$1`, [key]);
  return r.rowCount ? r.rows[0].value : fallback;
}
async function auditLog(usuario, acao, alvo) {
  if (!USE_DB) {
    mock.auditoria.unshift({
      quando: new Date().toISOString().slice(0, 16).replace("T", " "),
      usuario,
      acao,
      alvo,
    });
    return;
  }
  await pool.query(`INSERT INTO auditoria (usuario,acao,alvo) VALUES ($1,$2,$3)`, [usuario, acao, alvo]);
}

async function listUsers() {
  if (USE_DB) {
    const r = await pool.query(
      `
      SELECT
        id,
        COALESCE(nome, name) AS nome,
        email,
        role,
        active,
        created_at
      FROM users
      ORDER BY COALESCE(nome, name) ASC NULLS LAST, id ASC
    `
    );
    return r.rows.map((u) => ({
      ...u,
      role: ALLOWED_ROLES.has(String(u.role || "").toLowerCase()) ? String(u.role || "").toLowerCase() : ROLES.COMERCIAL,
    }));
  }
  return mock.users
    .slice()
    .sort((a, b) => String(a.nome || "").localeCompare(String(b.nome || "")))
    .map((u) => ({
      id: u.id,
      nome: u.nome,
      email: u.email,
      role: ALLOWED_ROLES.has(String(u.role || "").toLowerCase()) ? String(u.role || "").toLowerCase() : ROLES.COMERCIAL,
      active: u.active === undefined ? true : !!u.active,
      created_at: u.created_at,
    }));
}

/* -----------------------------
   DB Init + Migração automática
----------------------------- */
async function dbInit() {
  if (!USE_DB) return;

  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      nome TEXT,
      email TEXT UNIQUE NOT NULL,
      senha_hash TEXT,
      role TEXT NOT NULL DEFAULT 'comercial',
      active BOOLEAN NOT NULL DEFAULT TRUE,
      created_at TIMESTAMP NOT NULL DEFAULT NOW()
    );
  `);

  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS nome TEXT;`);
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS senha_hash TEXT;`);
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS role TEXT NOT NULL DEFAULT 'comercial';`);
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS active BOOLEAN NOT NULL DEFAULT TRUE;`);
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS created_at TIMESTAMP NOT NULL DEFAULT NOW();`);

  await detectLegacyColumns();
  if (LEGACY.hasName) await dropNotNullIfExists("name");
  if (LEGACY.hasPasswordHash) await dropNotNullIfExists("password_hash");

  if (LEGACY.hasName) {
    await pool.query(`UPDATE users SET nome = COALESCE(nome, name) WHERE nome IS NULL;`);
    await pool.query(`UPDATE users SET name = COALESCE(name, nome) WHERE name IS NULL;`);
  }
  if (LEGACY.hasPasswordHash) {
    await pool.query(`UPDATE users SET senha_hash = COALESCE(senha_hash, password_hash) WHERE senha_hash IS NULL;`);
    await pool.query(`UPDATE users SET password_hash = COALESCE(password_hash, senha_hash) WHERE password_hash IS NULL;`);
  }

  // ⚠️ Normaliza roles antigas para o conjunto permitido (seguro)
  await pool.query(`
    UPDATE users
    SET role = CASE
      WHEN LOWER(role) IN ('admin') THEN 'admin'
      WHEN LOWER(role) IN ('diretor','diretoria') THEN 'diretor'
      WHEN LOWER(role) IN ('financeiro') THEN 'financeiro'
      WHEN LOWER(role) IN ('atendimento') THEN 'atendimento'
      WHEN LOWER(role) IN ('comercial') THEN 'comercial'
      ELSE 'comercial'
    END
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS settings (
      key TEXT PRIMARY KEY,
      value TEXT NOT NULL
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS ocorrencias (
      id SERIAL PRIMARY KEY,
      razao_social TEXT NOT NULL,
      cnpj TEXT,
      numero_pedido TEXT,
      numero_nf TEXT,
      empresa TEXT NOT NULL DEFAULT 'IVPLAST',
      motivo TEXT NOT NULL,
      descricao TEXT NOT NULL,
      cliente_emitiu_nfd BOOLEAN NOT NULL DEFAULT FALSE,
      nfd_numero TEXT,
      custo_estimado NUMERIC(14,2) NOT NULL DEFAULT 0,
      responsavel TEXT NOT NULL DEFAULT 'Atendimento',
      status TEXT NOT NULL DEFAULT 'Aberto',
      created_by INTEGER REFERENCES users(id),
      created_at TIMESTAMP NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMP NOT NULL DEFAULT NOW()
    );
  `);

  await pool.query(`ALTER TABLE ocorrencias ADD COLUMN IF NOT EXISTS empresa TEXT NOT NULL DEFAULT 'IVPLAST';`);
  await pool.query(`ALTER TABLE ocorrencias ADD COLUMN IF NOT EXISTS cliente_emitiu_nfd BOOLEAN NOT NULL DEFAULT FALSE;`);
  await pool.query(`ALTER TABLE ocorrencias ADD COLUMN IF NOT EXISTS nfd_numero TEXT;`);

  // LEGADO: tipo
  await pool.query(`ALTER TABLE ocorrencias ADD COLUMN IF NOT EXISTS tipo TEXT;`);
  await pool.query(`UPDATE ocorrencias SET tipo = COALESCE(tipo, 'Comercial') WHERE tipo IS NULL;`);
  await pool.query(`ALTER TABLE ocorrencias ALTER COLUMN tipo SET DEFAULT 'Comercial';`);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS ocorrencia_atividades (
      id SERIAL PRIMARY KEY,
      ocorrencia_id INTEGER REFERENCES ocorrencias(id) ON DELETE CASCADE,
      quem TEXT NOT NULL,
      texto TEXT NOT NULL,
      created_at TIMESTAMP NOT NULL DEFAULT NOW()
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS ocorrencia_anexos (
      id SERIAL PRIMARY KEY,
      ocorrencia_id INTEGER REFERENCES ocorrencias(id) ON DELETE CASCADE,
      filename TEXT NOT NULL,
      originalname TEXT NOT NULL,
      mimetype TEXT,
      size INTEGER,
      created_at TIMESTAMP NOT NULL DEFAULT NOW()
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS ocorrencia_itens (
      id SERIAL PRIMARY KEY,
      ocorrencia_id INTEGER REFERENCES ocorrencias(id) ON DELETE CASCADE,
      descricao TEXT NOT NULL,
      quantidade INTEGER,
      created_at TIMESTAMP NOT NULL DEFAULT NOW()
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS auditoria (
      id SERIAL PRIMARY KEY,
      quando TIMESTAMP NOT NULL DEFAULT NOW(),
      usuario TEXT NOT NULL,
      acao TEXT NOT NULL,
      alvo TEXT NOT NULL
    );
  `);

  // Seed/Repair ADMIN
  const adminEmail = cleanEmail(process.env.ADMIN_EMAIL || "");
  const adminPass = String(process.env.ADMIN_PASSWORD || "");
  const adminName = process.env.ADMIN_NAME || "Admin";

  if (adminEmail && adminPass) {
    const hash = await bcrypt.hash(adminPass, 10);
    const existing = await pool.query(`SELECT id FROM users WHERE LOWER(email)=$1 LIMIT 1`, [adminEmail]);

    if (existing.rowCount === 0) {
      if (LEGACY.hasName && LEGACY.hasPasswordHash) {
        await pool.query(
          `INSERT INTO users (nome,name,email,senha_hash,password_hash,role,active) VALUES ($1,$1,$2,$3,$3,'admin',true)`,
          [adminName, adminEmail, hash]
        );
      } else if (LEGACY.hasName) {
        await pool.query(`INSERT INTO users (nome,name,email,senha_hash,role,active) VALUES ($1,$1,$2,$3,'admin',true)`, [
          adminName,
          adminEmail,
          hash,
        ]);
      } else if (LEGACY.hasPasswordHash) {
        await pool.query(
          `INSERT INTO users (nome,email,senha_hash,password_hash,role,active) VALUES ($1,$2,$3,$3,'admin',true)`,
          [adminName, adminEmail, hash]
        );
      } else {
        await pool.query(`INSERT INTO users (nome,email,senha_hash,role,active) VALUES ($1,$2,$3,'admin',true)`, [
          adminName,
          adminEmail,
          hash,
        ]);
      }
      console.log("✅ Admin criado via ENV.");
    } else {
      const id = existing.rows[0].id;
      if (LEGACY.hasName) {
        await pool.query(`UPDATE users SET nome=COALESCE(nome,$1), name=COALESCE(name,$1) WHERE id=$2`, [adminName, id]);
      } else {
        await pool.query(`UPDATE users SET nome=COALESCE(nome,$1) WHERE id=$2`, [adminName, id]);
      }
      if (LEGACY.hasPasswordHash) {
        await pool.query(`UPDATE users SET senha_hash=$1, password_hash=$1 WHERE id=$2`, [hash, id]);
      } else {
        await pool.query(`UPDATE users SET senha_hash=$1 WHERE id=$2`, [hash, id]);
      }
      await pool.query(`UPDATE users SET role='admin', active=true WHERE id=$1`, [id]);
      console.log("✅ Admin atualizado via ENV (senha reset).");
    }
  }

  // Seed/Repair DIRECTOR
  const dirEmail = cleanEmail(process.env.DIRECTOR_EMAIL || "");
  const dirPass = String(process.env.DIRECTOR_PASSWORD || "");
  const dirName = process.env.DIRECTOR_NAME || "Diretor(a)";

  if (dirEmail && dirPass) {
    const hash = await bcrypt.hash(dirPass, 10);
    const existing = await pool.query(`SELECT id FROM users WHERE LOWER(email)=$1 LIMIT 1`, [dirEmail]);

    if (existing.rowCount === 0) {
      if (LEGACY.hasName && LEGACY.hasPasswordHash) {
        await pool.query(
          `INSERT INTO users (nome,name,email,senha_hash,password_hash,role,active) VALUES ($1,$1,$2,$3,$3,'diretor',true)`,
          [dirName, dirEmail, hash]
        );
      } else if (LEGACY.hasName) {
        await pool.query(`INSERT INTO users (nome,name,email,senha_hash,role,active) VALUES ($1,$1,$2,$3,'diretor',true)`, [
          dirName,
          dirEmail,
          hash,
        ]);
      } else if (LEGACY.hasPasswordHash) {
        await pool.query(
          `INSERT INTO users (nome,email,senha_hash,password_hash,role,active) VALUES ($1,$2,$3,$3,'diretor',true)`,
          [dirName, dirEmail, hash]
        );
      } else {
        await pool.query(`INSERT INTO users (nome,email,senha_hash,role,active) VALUES ($1,$2,$3,'diretor',true)`, [
          dirName,
          dirEmail,
          hash,
        ]);
      }
      console.log("✅ Diretor criado via ENV.");
    } else {
      const id = existing.rows[0].id;
      if (LEGACY.hasName) {
        await pool.query(`UPDATE users SET nome=COALESCE(nome,$1), name=COALESCE(name,$1) WHERE id=$2`, [dirName, id]);
      } else {
        await pool.query(`UPDATE users SET nome=COALESCE(nome,$1) WHERE id=$2`, [dirName, id]);
      }
      if (LEGACY.hasPasswordHash) {
        await pool.query(`UPDATE users SET senha_hash=$1, password_hash=$1 WHERE id=$2`, [hash, id]);
      } else {
        await pool.query(`UPDATE users SET senha_hash=$1 WHERE id=$2`, [hash, id]);
      }
      await pool.query(`UPDATE users SET role='diretor', active=true WHERE id=$1`, [id]);
      console.log("✅ Diretor atualizado via ENV (senha reset).");
    }
  }

  await upsertSetting("adminEmail", process.env.ADMIN_EMAIL || "");
  await upsertSetting("adminName", process.env.ADMIN_NAME || "");
  await upsertSetting("databaseSSL", String(envBool(process.env.DATABASE_SSL)));
}

/* -----------------------------
   Locals
----------------------------- */
app.use((req, res, next) => {
  res.locals.usuario = req.session.user || null;
  res.locals.userRole = userRole(req);
  res.locals.isAdmin = isAdmin(req);
  res.locals.isDirector = isDirector(req);
  res.locals.isFinanceiro = isFinanceiro(req);
  res.locals.isAtendimento = isAtendimento(req);
  res.locals.isComercial = isComercial(req);
  next();
});

/* -----------------------------
   Rotas públicas
----------------------------- */
app.get("/", (req, res) => res.render("index"));

app.get("/login", (req, res) => {
  if (isAuthed(req)) return res.redirect("/dashboard");
  res.render("login", { error: null });
});

app.post("/login", async (req, res) => {
  const email = cleanEmail(req.body.email);
  const senha = String(req.body.senha || "");
  if (!email || !senha) return res.status(400).render("login", { error: "Informe email e senha." });

  try {
    let user = null;

    if (USE_DB) {
      const r = await pool.query(
        `
        SELECT
          id,
          COALESCE(nome, name) AS nome,
          email,
          COALESCE(senha_hash, password_hash) AS senha_hash,
          role,
          active
        FROM users
        WHERE LOWER(email)=$1
        LIMIT 1
      `,
        [email]
      );
      user = r.rowCount ? r.rows[0] : null;
    } else {
      user = mock.users.find((u) => String(u.email).toLowerCase() === email);
    }

    if (!user || !user.senha_hash) return res.status(401).render("login", { error: "Usuário ou senha inválidos." });

    const isActive = user.active === undefined ? true : !!user.active;
    if (!isActive) return res.status(403).render("login", { error: "Usuário inativo. Fale com o administrador." });

    const ok = await bcrypt.compare(senha, user.senha_hash);
    if (!ok) return res.status(401).render("login", { error: "Usuário ou senha inválidos." });

    const role = ALLOWED_ROLES.has(String(user.role || "").toLowerCase()) ? String(user.role || "").toLowerCase() : ROLES.COMERCIAL;

    req.session.user = { id: user.id, nome: user.nome || "Usuário", email: user.email, role };
    await auditLog(req.session.user.nome, "Login", `email=${user.email}, role=${role}`);
    return res.redirect("/dashboard");
  } catch (err) {
    console.error("LOGIN_ERR:", err);
    return res.status(500).render("login", { error: "Erro ao efetuar login. Tente novamente." });
  }
});

app.get("/logout", async (req, res) => {
  try {
    if (req.session.user) await auditLog(req.session.user.nome, "Logout", req.session.user.email);
  } catch (_) {}
  req.session.destroy(() => res.redirect("/login"));
});

// ✅ remove auto-cadastro (se você quiser manter, me avisa)
// app.get("/register", ...)
// app.post("/register", ...)

app.get("/esqueci-senha", (req, res) => res.redirect("/login"));

/* -----------------------------
   Dashboard / Ocorrências
----------------------------- */
app.get("/dashboard", requireAuth, async (req, res) => {
  try {
    let total = 0;
    let abertas = 0;
    let custoTotal = 0;
    let tempoMedioHoras = 0;

    const serieSemanal = Array(11).fill(0);
    const motivos = { IVPLAST: 0, Cliente: 0, Transportadora: 0, Vendedor: 0 };

    // Base visibility
    const role = userRole(req);

    if (USE_DB) {
      let q = `SELECT motivo, status, custo_estimado, created_at, updated_at, created_by FROM ocorrencias`;
      const params = [];

      if (role === ROLES.COMERCIAL) {
        q += ` WHERE created_by=$1`;
        params.push(req.session.user.id);
      } else if (role === ROLES.FINANCEIRO) {
        q += ` WHERE status=$1`;
        params.push(STATUS.FINALIZADO_FIN);
      }

      const r = await pool.query(q, params);
      const rows = r.rows;

      total = rows.length;
      abertas = rows.filter((o) => normalizeStatusToOfficial(o.status) !== STATUS.DIRETORIA).length;

      // custo só entra no KPI se tiver permissão de ver custo
      custoTotal = canSeeCost(req) ? rows.reduce((acc, o) => acc + Number(o.custo_estimado || 0), 0) : 0;

      const tempos = rows.map((o) => hoursBetween(o.created_at, o.updated_at)).filter((n) => n > 0);
      tempoMedioHoras = tempos.length ? Math.round(tempos.reduce((a, b) => a + b, 0) / tempos.length) : 0;

      rows.forEach((o) => {
        const diffDays = Math.floor((Date.now() - new Date(o.created_at).getTime()) / (1000 * 60 * 60 * 24));
        const idx = 10 - Math.min(10, Math.floor(diffDays / 7));
        if (idx >= 0 && idx <= 10) serieSemanal[idx] += 1;

        const m = String(o.motivo || "");
        if (motivos[m] !== undefined) motivos[m] += 1;
      });
    } else {
      // mock
      let base = mock.ocorrencias;
      if (role === ROLES.COMERCIAL) base = base.filter((o) => o.created_by === req.session.user.id);
      if (role === ROLES.FINANCEIRO) base = base.filter((o) => normalizeStatusToOfficial(o.status) === STATUS.FINALIZADO_FIN);

      total = base.length || 0;
      abertas = base.filter((o) => normalizeStatusToOfficial(o.status) !== STATUS.DIRETORIA).length || 0;
      custoTotal = canSeeCost(req) ? base.reduce((acc, o) => acc + Number(o.custo_estimado || 0), 0) : 0;

      const tempos = base.map((o) => hoursBetween(o.created_at, o.updated_at)).filter((n) => n > 0);
      tempoMedioHoras = tempos.length ? Math.round(tempos.reduce((a, b) => a + b, 0) / tempos.length) : 0;
    }

    res.render("dashboard", {
      usuario: req.session.user,
      kpis: { totalOcorrencias: total || 0, abertas: abertas || 0, tempoMedioHoras: tempoMedioHoras || 0, valorEstimado: custoTotal || 0 },
      serieSemanal,
      motivosOcorrencia: motivos,
      canSeeCost: canSeeCost(req),
    });
  } catch (err) {
    console.error("DASH_ERR:", err);
    res.status(500).send("Erro ao carregar dashboard.");
  }
});

app.get("/ocorrencias", requireAuth, async (req, res) => {
  const q = String(req.query.q || "").trim().toLowerCase();
  const statusFilter = normalizeStatusToOfficial(req.query.status || "");

  try {
    let lista = [];
    const role = userRole(req);

    if (USE_DB) {
      let sql = `SELECT id, razao_social, created_at, updated_at, status, created_by FROM ocorrencias`;
      const params = [];
      const where = [];

      if (role === ROLES.COMERCIAL) {
        where.push(`created_by=$${params.length + 1}`);
        params.push(req.session.user.id);
      } else if (role === ROLES.FINANCEIRO) {
        where.push(`status=$${params.length + 1}`);
        params.push(STATUS.FINALIZADO_FIN);
      }

      if (statusFilter && STATUS_SET.has(statusFilter)) {
        where.push(`status=$${params.length + 1}`);
        params.push(statusFilter);
      }

      if (where.length) sql += ` WHERE ` + where.join(" AND ");
      sql += ` ORDER BY id DESC LIMIT 200`;

      const r = await pool.query(sql, params);
      lista = r.rows.map((o) => {
        const st = normalizeStatusToOfficial(o.status);
        return {
          id: o.id,
          cliente: o.razao_social,
          criadoEm: daysAgoText(o.created_at),
          ultimaAtividade: daysAgoText(o.updated_at),
          status: st,
          situacao: st,
        };
      });
    } else {
      let base = mock.ocorrencias;

      if (role === ROLES.COMERCIAL) base = base.filter((o) => o.created_by === req.session.user.id);
      if (role === ROLES.FINANCEIRO) base = base.filter((o) => normalizeStatusToOfficial(o.status) === STATUS.FINALIZADO_FIN);

      lista = base
        .slice()
        .sort((a, b) => b.id - a.id)
        .slice(0, 200)
        .map((o) => {
          const st = normalizeStatusToOfficial(o.status);
          return {
            id: o.id,
            cliente: o.razao_social,
            criadoEm: daysAgoText(o.created_at),
            ultimaAtividade: daysAgoText(o.updated_at),
            status: st,
            situacao: st,
          };
        });

      if (statusFilter && STATUS_SET.has(statusFilter)) lista = lista.filter((o) => o.status === statusFilter);
    }

    if (q) lista = lista.filter((o) => String(o.cliente).toLowerCase().includes(q) || String(o.id).includes(q));

    res.render("ocorrencias", {
      usuario: req.session.user,
      ocorrencias: lista,
      q,
      status: statusFilter || "",
      canSeeCost: canSeeCost(req),
    });
  } catch (err) {
    console.error("OCORRENCIAS_ERR:", err);
    res.status(500).send("Erro ao listar ocorrências.");
  }
});

/* -------- /novo (GET) -------- */
app.get("/novo", requireAuth, (req, res) => {
  // comercial pode criar; atendimento pode criar; admin/diretor pode criar; financeiro NÃO precisa criar
  if (isFinanceiro(req)) return res.status(403).send("Financeiro não cria ocorrência.");
  res.render("novo", { usuario: req.session.user, canSeeCost: canSeeCost(req), error: null, success: null });
});

/* -------- /novo (POST) -------- */
app.post("/novo", requireAuth, upload.array("anexos", 10), async (req, res) => {
  try {
    if (isFinanceiro(req)) return res.status(403).send("Financeiro não cria ocorrência.");

    const itensDescricao = []
      .concat(req.body["itens_descricao[]"] || req.body.itens_descricao || [])
      .map((v) => String(v || "").trim())
      .filter((v) => v.length > 0);

    const itensQuantidadeRaw = []
      .concat(req.body["itens_quantidade[]"] || req.body.itens_quantidade || [])
      .map((v) => String(v || "").trim());

    const itemErrado = String(req.body.item_errado || "nao") === "sim";

    // ✅ regras: comercial sempre cria ABERTO e responsável ATENDIMENTO
    const creatorRole = userRole(req);

    const data = {
      razao_social: String(req.body.razao_social || "").trim(),
      cnpj: String(req.body.cnpj || "").trim(),
      numero_pedido: String(req.body.numero_pedido || "").trim(),
      numero_nf: String(req.body.numero_nf || "").trim(),
      empresa: String(req.body.empresa || "IVPLAST").trim(),
      motivo: String(req.body.motivo || "IVPLAST").trim(),
      cliente_emitiu_nfd: String(req.body.cliente_emitiu_nfd || "nao") === "sim",
      nfd_numero: String(req.body.nfd_numero || "").trim(),
      tipo: "Comercial",
      descricao: String(req.body.descricao || "").trim(),
      custo_estimado: safeFloat(req.body.custo_estimado, 0),

      responsavel: "Atendimento",
      status: STATUS.ABERTO,
    };

    const item_obs = String(req.body.item_obs || "").trim();

    if (!data.razao_social || !data.descricao) {
      return res.status(400).render("novo", { usuario: req.session.user, canSeeCost: canSeeCost(req), error: "Preencha Razão social e Descrição.", success: null });
    }
    if (!data.cliente_emitiu_nfd) data.nfd_numero = "";

    // se atendimento/admin/diretor criou, pode respeitar responsavel enviado, mas LIMITA a lista oficial
    const respIn = cleanStr(req.body.responsavel || "Atendimento");
    const respAllowed = new Set(["Atendimento", "Comercial", "Financeiro", "Diretoria"]);
    if (creatorRole !== ROLES.COMERCIAL && respAllowed.has(respIn)) data.responsavel = respIn;

    let newId = null;

    if (USE_DB) {
      const r = await pool.query(
        `
        INSERT INTO ocorrencias
          (razao_social, cnpj, numero_pedido, numero_nf,
           empresa, motivo, tipo, descricao,
           cliente_emitiu_nfd, nfd_numero,
           custo_estimado, responsavel, status, created_by)
        VALUES
          ($1,$2,$3,$4,
           $5,$6,$7,$8,
           $9,$10,
           $11,$12,$13,$14)
        RETURNING id
      `,
        [
          data.razao_social,
          data.cnpj || null,
          data.numero_pedido || null,
          data.numero_nf || null,
          data.empresa,
          data.motivo,
          data.tipo,
          data.descricao,
          data.cliente_emitiu_nfd,
          data.nfd_numero || null,
          data.custo_estimado,
          data.responsavel,
          data.status,
          req.session.user.id,
        ]
      );

      newId = r.rows[0].id;

      await pool.query(`INSERT INTO ocorrencia_atividades (ocorrencia_id,quem,texto) VALUES ($1,$2,$3)`, [
        newId,
        req.session.user.nome,
        "Ocorrência criada.",
      ]);

      if (itemErrado) {
        const max = Math.min(10, itensDescricao.length);
        for (let i = 0; i < max; i++) {
          const desc = itensDescricao[i];
          let qtd = parseInt(itensQuantidadeRaw[i] || "", 10);
          if (!Number.isFinite(qtd)) qtd = null;
          if (qtd !== null) {
            if (qtd < 1) qtd = 1;
            if (qtd > 10000) qtd = 10000;
          }
          await pool.query(`INSERT INTO ocorrencia_itens (ocorrencia_id, descricao, quantidade) VALUES ($1,$2,$3)`, [newId, desc, qtd]);
        }
        if (item_obs) {
          await pool.query(`INSERT INTO ocorrencia_atividades (ocorrencia_id,quem,texto) VALUES ($1,$2,$3)`, [
            newId,
            req.session.user.nome,
            `Obs. itens: ${item_obs}`,
          ]);
        }
      }

      const files = req.files || [];
      for (const f of files) {
        await pool.query(
          `INSERT INTO ocorrencia_anexos (ocorrencia_id,filename,originalname,mimetype,size) VALUES ($1,$2,$3,$4,$5)`,
          [newId, f.filename, f.originalname, f.mimetype, f.size]
        );
      }
    } else {
      newId = mock.ocorrencias.length ? Math.max(...mock.ocorrencias.map((o) => o.id)) + 1 : 11000;
      mock.ocorrencias.push({
        id: newId,
        ...data,
        created_by: req.session.user.id,
        created_at: nowISO(),
        updated_at: nowISO(),
        itens: itemErrado
          ? itensDescricao.slice(0, 10).map((desc, i) => ({
              descricao: desc,
              quantidade: Math.min(10000, Math.max(1, parseInt(itensQuantidadeRaw[i] || "1", 10) || 1)),
            }))
          : [],
        atividades: [
          { quando: "agora", quem: req.session.user.nome, texto: "Ocorrência criada." },
          ...(itemErrado && item_obs ? [{ quando: "agora", quem: req.session.user.nome, texto: `Obs. itens: ${item_obs}` }] : []),
        ],
        anexos: (req.files || []).map((f, idx) => ({ id: idx + 1, filename: f.filename, originalname: f.originalname, mimetype: f.mimetype, size: f.size })),
      });
    }

    await auditLog(req.session.user.nome, "Criou ocorrência", `#${newId}`);
    return res.redirect(`/ocorrencias/${newId}`);
  } catch (err) {
    console.error("NOVO_POST_ERR:", err);
    return res.status(500).send("Erro ao salvar ocorrência.");
  }
});

/* -------- Download de anexo -------- */
app.get("/ocorrencias/:id/anexos/:anexoId", requireAuth, async (req, res) => {
  const ocorrenciaId = safeInt(req.params.id, 0);
  const anexoId = safeInt(req.params.anexoId, 0);
  if (!ocorrenciaId || !anexoId) return res.status(400).send("Parâmetros inválidos.");

  try {
    // permissão por role/status
    if (USE_DB) {
      const r = await pool.query(`SELECT id, created_by, status FROM ocorrencias WHERE id=$1 LIMIT 1`, [ocorrenciaId]);
      if (!r.rowCount) return res.status(404).send("Ocorrência não encontrada.");

      const occ = r.rows[0];
      const st = normalizeStatusToOfficial(occ.status);

      if (!canViewOcorrenciaByStatus(req, st)) return res.status(403).send("Acesso negado.");
      if (isComercial(req) && occ.created_by !== req.session.user.id) return res.status(403).send("Acesso negado.");
    } else {
      const occ = mock.ocorrencias.find((o) => o.id === ocorrenciaId);
      if (!occ) return res.status(404).send("Ocorrência não encontrada.");
      const st = normalizeStatusToOfficial(occ.status);

      if (!canViewOcorrenciaByStatus(req, st)) return res.status(403).send("Acesso negado.");
      if (isComercial(req) && occ.created_by !== req.session.user.id) return res.status(403).send("Acesso negado.");
    }

    let anexo = null;
    if (USE_DB) {
      const r = await pool.query(`SELECT id, ocorrencia_id, filename, originalname FROM ocorrencia_anexos WHERE id=$1 AND ocorrencia_id=$2 LIMIT 1`, [
        anexoId,
        ocorrenciaId,
      ]);
      anexo = r.rowCount ? r.rows[0] : null;
    } else {
      const oc = mock.ocorrencias.find((o) => o.id === ocorrenciaId);
      anexo = oc ? (oc.anexos || []).find((a) => a.id === anexoId) : null;
      if (anexo) anexo.ocorrencia_id = ocorrenciaId;
    }

    if (!anexo) return res.status(404).send("Anexo não encontrado.");

    const filePath = path.join(UPLOAD_DIR, anexo.filename);
    if (!fs.existsSync(filePath)) {
      return res.status(404).send("Arquivo não está disponível no servidor. (Provável falta de disco persistente no Render).");
    }

    return res.download(filePath, anexo.originalname);
  } catch (err) {
    console.error("ANEXO_DOWNLOAD_ERR:", err);
    return res.status(500).send("Erro ao baixar anexo.");
  }
});

/* -------- Detalhe -------- */
app.get("/ocorrencias/:id", requireAuth, async (req, res) => {
  const id = safeInt(req.params.id, 0);
  if (!id) return res.redirect("/ocorrencias");

  try {
    let ocorrencia = null;
    let itens = [];
    let anexos = [];
    let createdBy = null;
    let currentStatus = STATUS.ABERTO;

    if (USE_DB) {
      const r = await pool.query(`SELECT * FROM ocorrencias WHERE id=$1`, [id]);
      if (!r.rowCount) return res.redirect("/ocorrencias");
      const o = r.rows[0];
      createdBy = o.created_by;
      currentStatus = normalizeStatusToOfficial(o.status);

      // perms
      if (!canViewOcorrenciaByStatus(req, currentStatus)) return res.status(403).send("Acesso negado.");
      if (isComercial(req) && createdBy !== req.session.user.id) return res.status(403).send("Acesso negado.");

      const acts = await pool.query(`SELECT quem, texto, created_at FROM ocorrencia_atividades WHERE ocorrencia_id=$1 ORDER BY id DESC LIMIT 50`, [id]);
      const itensR = await pool.query(`SELECT descricao, quantidade FROM ocorrencia_itens WHERE ocorrencia_id=$1 ORDER BY id ASC`, [id]);
      itens = itensR.rows || [];
      const anexosR = await pool.query(`SELECT id, originalname, size, created_at FROM ocorrencia_anexos WHERE ocorrencia_id=$1 ORDER BY id DESC`, [id]);
      anexos = anexosR.rows || [];

      ocorrencia = {
        id: o.id,
        cliente: o.razao_social,
        criadoEm: new Date(o.created_at).toISOString().slice(0, 10),
        status: currentStatus,
        motivo: o.motivo,
        empresa: o.empresa,
        pedido: o.numero_pedido || "-",
        nf: o.numero_nf || "-",
        nfd: o.nfd_numero || "-",
        custo: Number(o.custo_estimado || 0),
        responsavel: o.responsavel,
        descricao: o.descricao,
        atividades: acts.rows.map((a) => ({ quando: daysAgoText(a.created_at), quem: a.quem, texto: a.texto })),
      };
    } else {
      const found = mock.ocorrencias.find((x) => x.id === id);
      if (!found) return res.redirect("/ocorrencias");
      createdBy = found.created_by;
      currentStatus = normalizeStatusToOfficial(found.status);

      if (!canViewOcorrenciaByStatus(req, currentStatus)) return res.status(403).send("Acesso negado.");
      if (isComercial(req) && createdBy !== req.session.user.id) return res.status(403).send("Acesso negado.");

      itens = found.itens || [];
      anexos = (found.anexos || []).map((a) => ({ id: a.id, originalname: a.originalname, size: a.size, created_at: found.created_at || nowISO() }));

      ocorrencia = {
        id: found.id,
        cliente: found.razao_social,
        criadoEm: (found.created_at || "").slice(0, 10) || "2026-02-04",
        status: currentStatus,
        motivo: found.motivo,
        empresa: found.empresa || "IVPLAST",
        pedido: found.numero_pedido || "-",
        nf: found.numero_nf || "-",
        nfd: found.nfd_numero || "-",
        custo: Number(found.custo_estimado || 0),
        responsavel: found.responsavel,
        descricao: found.descricao,
        atividades: found.atividades || [],
      };
    }

    res.render("ocorrencia_detalhe", {
      usuario: req.session.user,
      ocorrencia,
      itens,
      anexos,
      id,
      canSeeCost: canSeeCost(req),
      role: userRole(req),
      canEditStatus: canChangeStatus(req, currentStatus),
      allowedStatuses: allowedNextStatuses(req, currentStatus),
    });
  } catch (err) {
    console.error("DETALHE_ERR:", err);
    res.status(500).send("Erro ao carregar ocorrência.");
  }
});

/* -------- Atualiza status/responsável -------- */
app.post("/ocorrencias/:id/atualizar", requireAuth, async (req, res) => {
  const id = safeInt(req.params.id, 0);
  if (!id) return res.redirect("/ocorrencias");

  const statusIn = normalizeStatusToOfficial(req.body.status || STATUS.ABERTO);
  const responsavelIn = cleanStr(req.body.responsavel || "Atendimento");

  try {
    // carrega status atual e dono (pra regra)
    let occ = null;
    if (USE_DB) {
      const r = await pool.query(`SELECT id, created_by, status FROM ocorrencias WHERE id=$1 LIMIT 1`, [id]);
      if (!r.rowCount) return res.redirect("/ocorrencias");
      occ = r.rows[0];
    } else {
      occ = mock.ocorrencias.find((x) => x.id === id);
      if (!occ) return res.redirect("/ocorrencias");
    }

    const currentStatus = normalizeStatusToOfficial(occ.status);
    const createdBy = occ.created_by;

    // permissão de ver
    if (!canViewOcorrenciaByStatus(req, currentStatus)) return res.status(403).send("Acesso negado.");
    if (isComercial(req) && createdBy !== req.session.user.id) return res.status(403).send("Acesso negado.");

    // permissão de alterar
    if (!canChangeStatus(req, currentStatus)) {
      return res.status(403).send("Seu cargo não permite alterar status neste momento.");
    }
    if (!isStatusAllowedForUser(req, statusIn, currentStatus)) {
      return res.status(403).send("Transição de status não permitida para seu cargo.");
    }

    // responsavel: limita opções oficiais (não inventa áreas)
    const respAllowed = new Set(["Atendimento", "Comercial", "Financeiro", "Diretoria"]);
    const responsavel = respAllowed.has(responsavelIn) ? responsavelIn : "Atendimento";

    if (USE_DB) {
      await pool.query(`UPDATE ocorrencias SET status=$1, responsavel=$2, updated_at=NOW() WHERE id=$3`, [statusIn, responsavel, id]);
      await pool.query(`INSERT INTO ocorrencia_atividades (ocorrencia_id,quem,texto) VALUES ($1,$2,$3)`, [
        id,
        req.session.user.nome,
        `Atualizou: status=${statusIn}, responsável=${responsavel}.`,
      ]);
    } else {
      occ.status = statusIn;
      occ.responsavel = responsavel;
      occ.updated_at = nowISO();
      occ.atividades = occ.atividades || [];
      occ.atividades.unshift({ quando: "agora", quem: req.session.user.nome, texto: `Atualizou: status=${statusIn}, responsável=${responsavel}.` });
    }

    await auditLog(req.session.user.nome, "Alterou status/responsável", `#${id} (${statusIn})`);
    return res.redirect(`/ocorrencias/${id}`);
  } catch (err) {
    console.error("ATUALIZAR_ERR:", err);
    return res.status(500).send("Erro ao atualizar ocorrência.");
  }
});

/* -------- Comentário -------- */
app.post("/ocorrencias/:id/comentario", requireAuth, async (req, res) => {
  const id = safeInt(req.params.id, 0);
  const comentario = String(req.body.comentario || "").trim();
  if (!id) return res.redirect("/ocorrencias");
  if (!comentario) return res.redirect(`/ocorrencias/${id}`);

  try {
    // carrega dono/status pra permissão de visão
    let occ = null;
    if (USE_DB) {
      const r = await pool.query(`SELECT id, created_by, status FROM ocorrencias WHERE id=$1 LIMIT 1`, [id]);
      if (!r.rowCount) return res.redirect("/ocorrencias");
      occ = r.rows[0];
    } else {
      occ = mock.ocorrencias.find((x) => x.id === id);
      if (!occ) return res.redirect("/ocorrencias");
    }

    const currentStatus = normalizeStatusToOfficial(occ.status);
    if (!canViewOcorrenciaByStatus(req, currentStatus)) return res.status(403).send("Acesso negado.");
    if (isComercial(req) && occ.created_by !== req.session.user.id) return res.status(403).send("Acesso negado.");

    if (USE_DB) {
      await pool.query(`UPDATE ocorrencias SET updated_at=NOW() WHERE id=$1`, [id]);
      await pool.query(`INSERT INTO ocorrencia_atividades (ocorrencia_id,quem,texto) VALUES ($1,$2,$3)`, [id, req.session.user.nome, comentario]);
    } else {
      occ.updated_at = nowISO();
      occ.atividades = occ.atividades || [];
      occ.atividades.unshift({ quando: "agora", quem: req.session.user.nome, texto: comentario });
    }

    await auditLog(req.session.user.nome, "Comentário", `#${id}`);
    return res.redirect(`/ocorrencias/${id}`);
  } catch (err) {
    console.error("COMENTARIO_ERR:", err);
    return res.status(500).send("Erro ao salvar comentário.");
  }
});

app.get("/relatorios", requireAuth, async (req, res) => {
  try {
    res.render("relatorios", { usuario: req.session.user });
  } catch (err) {
    console.error("RELATORIOS_ERR:", err);
    res.status(500).send("Erro ao carregar relatórios.");
  }
});

/* -----------------------------
   Configurações / Usuários / Auditoria
   (mantive igual seu fluxo, mas travando os cargos)
----------------------------- */
app.get("/configuracoes", requireAdminOrDirector, async (req, res) => {
  try {
    const config = {
      adminEmail: await getSetting("adminEmail", process.env.ADMIN_EMAIL || ""),
      adminName: await getSetting("adminName", process.env.ADMIN_NAME || ""),
      databaseSSL: envBool(await getSetting("databaseSSL", String(envBool(process.env.DATABASE_SSL)))),
    };

    const users = await listUsers();
    const success = req.query.success ? String(req.query.success) : null;
    const error = req.query.error ? String(req.query.error) : null;

    res.render("configuracoes", { usuario: req.session.user, config, users, success, error });
  } catch (err) {
    console.error("CFG_GET_ERR:", err);
    res.status(500).send("Erro ao carregar configurações.");
  }
});

app.post("/configuracoes/admin", requireAdminOrDirector, async (req, res) => {
  try {
    const adminEmail = String(req.body.adminEmail || "").trim();
    const adminName = String(req.body.adminName || "").trim();
    await upsertSetting("adminEmail", adminEmail);
    await upsertSetting("adminName", adminName);
    await auditLog(req.session.user.nome, "Atualizou configurações", "Admin (email/nome)");
    return res.redirect(`/configuracoes?success=${encodeURIComponent("Admin atualizado.")}`);
  } catch (err) {
    console.error("CFG_ADMIN_POST_ERR:", err);
    return res.redirect(`/configuracoes?error=${encodeURIComponent("Erro ao salvar configurações.")}`);
  }
});

app.post("/configuracoes/senha", requireAdminOrDirector, async (req, res) => {
  try {
    const novaSenha = String(req.body.novaSenha || "");
    const novaSenha2 = String(req.body.novaSenha2 || "");
    if (!novaSenha || novaSenha.length < 6) return res.redirect(`/configuracoes?error=${encodeURIComponent("Senha muito curta (mínimo 6).")}`);
    if (novaSenha !== novaSenha2) return res.redirect(`/configuracoes?error=${encodeURIComponent("As senhas não conferem.")}`);

    const hash = await bcrypt.hash(novaSenha, 10);

    if (USE_DB) {
      if (LEGACY.hasPasswordHash) await pool.query(`UPDATE users SET senha_hash=$1, password_hash=$1 WHERE id=$2`, [hash, req.session.user.id]);
      else await pool.query(`UPDATE users SET senha_hash=$1 WHERE id=$2`, [hash, req.session.user.id]);
    } else {
      const u = mock.users.find((x) => x.id === req.session.user.id);
      if (u) u.senha_hash = hash;
    }

    await auditLog(req.session.user.nome, "Alterou a própria senha", `userId=${req.session.user.id}`);
    return res.redirect(`/configuracoes?success=${encodeURIComponent("Senha alterada.")}`);
  } catch (err) {
    console.error("CFG_SENHA_POST_ERR:", err);
    return res.redirect(`/configuracoes?error=${encodeURIComponent("Erro ao alterar senha.")}`);
  }
});

// criar usuário (TRAVA ROLE)
app.post("/configuracoes/usuarios/criar", requireAdminOrDirector, async (req, res) => {
  try {
    const nome = cleanStr(pickFirst(req.body.nome, req.body.name));
    const email = cleanEmail(pickFirst(req.body.email, req.body.userEmail, req.body.mail));
    const senha = String(pickFirst(req.body.senha, req.body.password, req.body.pass) || "");
    const roleIn = cleanStr(pickFirst(req.body.role, req.body.cargo, req.body.perfil, ROLES.COMERCIAL)).toLowerCase();
    const role = ALLOWED_ROLES.has(roleIn) ? roleIn : ROLES.COMERCIAL;

    if (!nome || !email || !senha) return res.redirect(`/configuracoes?error=${encodeURIComponent("Informe nome, email e senha.")}`);
    if (senha.length < 6) return res.redirect(`/configuracoes?error=${encodeURIComponent("Senha muito curta (mínimo 6).")}`);

    const hash = await bcrypt.hash(senha, 10);

    if (USE_DB) {
      const exists = await pool.query(`SELECT id FROM users WHERE LOWER(email)=$1`, [email]);
      if (exists.rowCount) return res.redirect(`/configuracoes?error=${encodeURIComponent("Email já cadastrado.")}`);

      if (LEGACY.hasName && LEGACY.hasPasswordHash) {
        await pool.query(`INSERT INTO users (nome,name,email,senha_hash,password_hash,role,active) VALUES ($1,$1,$2,$3,$3,$4,true)`, [nome, email, hash, role]);
      } else if (LEGACY.hasName) {
        await pool.query(`INSERT INTO users (nome,name,email,senha_hash,role,active) VALUES ($1,$1,$2,$3,$4,true)`, [nome, email, hash, role]);
      } else if (LEGACY.hasPasswordHash) {
        await pool.query(`INSERT INTO users (nome,email,senha_hash,password_hash,role,active) VALUES ($1,$2,$3,$3,$4,true)`, [nome, email, hash, role]);
      } else {
        await pool.query(`INSERT INTO users (nome,email,senha_hash,role,active) VALUES ($1,$2,$3,$4,true)`, [nome, email, hash, role]);
      }
    } else {
      const exists = mock.users.find((u) => String(u.email).toLowerCase() === email);
      if (exists) return res.redirect(`/configuracoes?error=${encodeURIComponent("Email já cadastrado.")}`);
      const id = mock.users.length ? Math.max(...mock.users.map((u) => u.id)) + 1 : 1;
      mock.users.push({ id, nome, email, senha_hash: hash, role, active: true, created_at: nowISO() });
    }

    await auditLog(req.session.user.nome, "Criou usuário", `email=${email}, role=${role}`);
    return res.redirect(`/configuracoes?success=${encodeURIComponent("Usuário criado.")}`);
  } catch (err) {
    console.error("USR_CREATE_ERR:", err);
    return res.redirect(`/configuracoes?error=${encodeURIComponent("Erro ao criar usuário.")}`);
  }
});

// trocar cargo (TRAVA ROLE)
app.post("/configuracoes/usuarios/:id/role", requireAdminOrDirector, async (req, res) => {
  try {
    const id = safeInt(req.params.id, 0);
    const roleIn = cleanStr(pickFirst(req.body.role, req.body.cargo, ROLES.COMERCIAL)).toLowerCase();
    const role = ALLOWED_ROLES.has(roleIn) ? roleIn : ROLES.COMERCIAL;
    if (!id) return res.redirect(`/configuracoes?error=${encodeURIComponent("ID inválido.")}`);

    if (USE_DB) await pool.query(`UPDATE users SET role=$1 WHERE id=$2`, [role, id]);
    else {
      const u = mock.users.find((x) => x.id === id);
      if (u) u.role = role;
    }

    await auditLog(req.session.user.nome, "Alterou cargo", `userId=${id} -> ${role}`);
    return res.redirect(`/configuracoes?success=${encodeURIComponent("Cargo atualizado.")}`);
  } catch (err) {
    console.error("USR_ROLE_ERR:", err);
    return res.redirect(`/configuracoes?error=${encodeURIComponent("Erro ao alterar cargo.")}`);
  }
});

// ativar/desativar
app.post("/configuracoes/usuarios/:id/active", requireAdminOrDirector, async (req, res) => {
  try {
    const id = safeInt(req.params.id, 0);
    const active = String(req.body.active || "true") === "true";
    if (!id) return res.redirect(`/configuracoes?error=${encodeURIComponent("ID inválido.")}`);
    if (id === req.session.user.id && !active) return res.redirect(`/configuracoes?error=${encodeURIComponent("Você não pode desativar o próprio usuário.")}`);

    if (USE_DB) await pool.query(`UPDATE users SET active=$1 WHERE id=$2`, [active, id]);
    else {
      const u = mock.users.find((x) => x.id === id);
      if (u) u.active = active;
    }

    await auditLog(req.session.user.nome, "Alterou status do usuário", `userId=${id}, active=${active}`);
    return res.redirect(`/configuracoes?success=${encodeURIComponent("Status do usuário atualizado.")}`);
  } catch (err) {
    console.error("USR_ACTIVE_ERR:", err);
    return res.redirect(`/configuracoes?error=${encodeURIComponent("Erro ao ativar/desativar usuário.")}`);
  }
});

// resetar senha
app.post("/configuracoes/usuarios/:id/reset-senha", requireAdminOrDirector, async (req, res) => {
  try {
    const id = safeInt(req.params.id, 0);
    const novaSenha = String(req.body.novaSenha || "");
    if (!id) return res.redirect(`/configuracoes?error=${encodeURIComponent("ID inválido.")}`);
    if (!novaSenha || novaSenha.length < 6) return res.redirect(`/configuracoes?error=${encodeURIComponent("Senha muito curta (mínimo 6).")}`);

    const hash = await bcrypt.hash(novaSenha, 10);

    if (USE_DB) {
      if (LEGACY.hasPasswordHash) await pool.query(`UPDATE users SET senha_hash=$1, password_hash=$1 WHERE id=$2`, [hash, id]);
      else await pool.query(`UPDATE users SET senha_hash=$1 WHERE id=$2`, [hash, id]);
    } else {
      const u = mock.users.find((x) => x.id === id);
      if (u) u.senha_hash = hash;
    }

    await auditLog(req.session.user.nome, "Resetou senha", `userId=${id}`);
    return res.redirect(`/configuracoes?success=${encodeURIComponent("Senha resetada.")}`);
  } catch (err) {
    console.error("USR_RESET_ERR:", err);
    return res.redirect(`/configuracoes?error=${encodeURIComponent("Erro ao resetar senha.")}`);
  }
});

app.get("/auditoria", requireAdminOrDirector, async (req, res) => {
  try {
    let auditoria = [];
    if (USE_DB) {
      const r = await pool.query(`SELECT quando, usuario, acao, alvo FROM auditoria ORDER BY id DESC LIMIT 200`);
      auditoria = r.rows.map((x) => ({
        quando: new Date(x.quando).toISOString().slice(0, 16).replace("T", " "),
        usuario: x.usuario,
        acao: x.acao,
        alvo: x.alvo,
      }));
    } else {
      auditoria = mock.auditoria.slice(0, 200);
    }
    res.render("auditoria", { usuario: req.session.user, auditoria });
  } catch (err) {
    console.error("AUDIT_ERR:", err);
    res.status(500).send("Erro ao carregar auditoria.");
  }
});

/* Static */
app.use("/uploads", express.static(UPLOAD_DIR));

/* Boot */
const PORT = process.env.PORT || 3000;

(async () => {
  try {
    console.log("DIAG:", {
      useDb: USE_DB,
      hasPg: !!pg,
      databaseSsl: String(process.env.DATABASE_SSL || ""),
      nodeEnv: process.env.NODE_ENV || "dev",
      port: PORT,
    });

    if (USE_DB) {
      await dbInit();
      console.log("✅ DB conectado e inicializado (roles/status controlados).");
    } else {
      console.log("⚠️ Rodando em modo MOCK (sem DATABASE_URL).");
    }

    app.listen(PORT, () => console.log(`🚀 Server rodando na porta ${PORT}`));
  } catch (err) {
    console.error("BOOT_ERR:", err);
    process.exit(1);
  }
})();
