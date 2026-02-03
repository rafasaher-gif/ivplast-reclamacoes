/**
 * server.js — IVPLAST Reclamações (Express + EJS + Session + Postgres opcional)
 *
 * Dependências:
 *   npm i express ejs express-session bcryptjs pg multer
 *
 * ENV (Render):
 *   SESSION_SECRET=...
 *   DATABASE_URL=postgres://...
 *   DATABASE_SSL=true
 *   ADMIN_EMAIL=...
 *   ADMIN_NAME=...
 *   ADMIN_PASSWORD=...
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
const UPLOAD_DIR = path.join(__dirname, "uploads");
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });

const upload = multer({
  storage: multer.diskStorage({
    destination: (req, file, cb) => cb(null, UPLOAD_DIR),
    filename: (req, file, cb) => {
      const safe = String(file.originalname || "arquivo").replace(/[^\w.\-]+/g, "_");
      cb(null, `${Date.now()}_${safe}`);
    },
  }),
  limits: { fileSize: 10 * 1024 * 1024 }, // 10MB
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
      secure: false,
      maxAge: 1000 * 60 * 60 * 12, // 12h
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
   Helpers
----------------------------- */
function isAuthed(req) {
  return req.session && req.session.user && req.session.user.id;
}
function requireAuth(req, res, next) {
  if (!isAuthed(req)) return res.redirect("/login");
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

/* -----------------------------
   MOCK (sem DB)
----------------------------- */
const mock = {
  users: [],
  settings: {},
  ocorrencias: [],
  auditoria: [],
};

function ensureMockAdmin() {
  const adminEmail = String(process.env.ADMIN_EMAIL || "").trim().toLowerCase();
  const adminPass = String(process.env.ADMIN_PASSWORD || "");
  const adminName = process.env.ADMIN_NAME || "Admin";
  if (!adminEmail || !adminPass) return;

  const exists = mock.users.find((u) => u.email.toLowerCase() === adminEmail);
  if (!exists) {
    const hash = bcrypt.hashSync(adminPass, 10);
    mock.users.push({
      id: 1,
      nome: adminName,
      email: adminEmail,
      senha_hash: hash,
      role: "admin",
      created_at: nowISO(),
    });
  }
}
ensureMockAdmin();

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

/* -----------------------------
   DB: migração automática SEM SHELL
   (resolve: name->nome, password_hash->senha_hash)
----------------------------- */
async function dbInit() {
  if (!USE_DB) return;

  // 1) Garante que a tabela users existe (com colunas modernas opcionais)
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      nome TEXT,
      email TEXT UNIQUE NOT NULL,
      senha_hash TEXT,
      role TEXT NOT NULL DEFAULT 'user',
      created_at TIMESTAMP NOT NULL DEFAULT NOW()
    );
  `);

  // 2) MIGRAÇÃO FORTE: garante colunas essenciais (não depende do estado antigo)
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS nome TEXT;`);
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS senha_hash TEXT;`);
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS role TEXT NOT NULL DEFAULT 'user';`);
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS created_at TIMESTAMP NOT NULL DEFAULT NOW();`);

  // 3) Copia colunas antigas -> novas, se existirem (sem quebrar)
  await pool.query(`
    DO $$
    BEGIN
      -- name -> nome
      IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema='public' AND table_name='users' AND column_name='name'
      ) THEN
        EXECUTE 'UPDATE users SET nome = COALESCE(nome, name) WHERE nome IS NULL';
      END IF;

      -- password_hash -> senha_hash
      IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema='public' AND table_name='users' AND column_name='password_hash'
      ) THEN
        EXECUTE 'UPDATE users SET senha_hash = COALESCE(senha_hash, password_hash) WHERE senha_hash IS NULL';
      END IF;
    END $$;
  `);

  // 4) Outras tabelas do sistema
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
      tipo TEXT NOT NULL,
      motivo TEXT NOT NULL,
      descricao TEXT NOT NULL,
      custo_estimado NUMERIC(14,2) NOT NULL DEFAULT 0,
      responsavel TEXT NOT NULL DEFAULT 'Atendimento',
      status TEXT NOT NULL DEFAULT 'Aberto',
      created_by INTEGER REFERENCES users(id),
      created_at TIMESTAMP NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMP NOT NULL DEFAULT NOW()
    );
  `);

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
    CREATE TABLE IF NOT EXISTS auditoria (
      id SERIAL PRIMARY KEY,
      quando TIMESTAMP NOT NULL DEFAULT NOW(),
      usuario TEXT NOT NULL,
      acao TEXT NOT NULL,
      alvo TEXT NOT NULL
    );
  `);

  // 5) Seed/Repair do ADMIN:
  //    - se não existir: cria
  //    - se existir: FORÇA atualizar senha_hash para a senha do ENV
  const adminEmail = String(process.env.ADMIN_EMAIL || "").trim().toLowerCase();
  const adminPass = String(process.env.ADMIN_PASSWORD || "");
  const adminName = process.env.ADMIN_NAME || "Admin";

  if (adminEmail && adminPass) {
    const hash = await bcrypt.hash(adminPass, 10);

    const existing = await pool.query(`SELECT id FROM users WHERE LOWER(email)=$1 LIMIT 1`, [adminEmail]);

    if (existing.rowCount === 0) {
      await pool.query(`INSERT INTO users (nome,email,senha_hash,role) VALUES ($1,$2,$3,'admin')`, [
        adminName,
        adminEmail,
        hash,
      ]);
      console.log("✅ Admin criado via ENV.");
    } else {
      const id = existing.rows[0].id;
      await pool.query(`UPDATE users SET nome = COALESCE(nome,$1) WHERE id=$2`, [adminName, id]);
      await pool.query(`UPDATE users SET senha_hash = $1 WHERE id=$2`, [hash, id]); // FORÇA
      await pool.query(`UPDATE users SET role = 'admin' WHERE id=$1`, [id]);
      console.log("✅ Admin atualizado via ENV (senha reset).");
    }
  }

  await upsertSetting("adminEmail", process.env.ADMIN_EMAIL || "");
  await upsertSetting("adminName", process.env.ADMIN_NAME || "");
  await upsertSetting("databaseSSL", String(envBool(process.env.DATABASE_SSL)));
}

/* -----------------------------
   Middlewares template
----------------------------- */
app.use((req, res, next) => {
  res.locals.usuario = req.session.user || null;
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
  const email = String(req.body.email || "").trim().toLowerCase();
  const senha = String(req.body.senha || "");

  if (!email || !senha) return res.status(400).render("login", { error: "Informe email e senha." });

  try {
    let user = null;

    if (USE_DB) {
      const r = await pool.query(
        `SELECT id, nome, email, senha_hash, role
         FROM users
         WHERE LOWER(email)=$1
         LIMIT 1`,
        [email]
      );
      user = r.rowCount ? r.rows[0] : null;
    } else {
      user = mock.users.find((u) => u.email.toLowerCase() === email);
    }

    if (!user || !user.senha_hash) return res.status(401).render("login", { error: "Usuário ou senha inválidos." });

    const ok = await bcrypt.compare(senha, user.senha_hash);
    if (!ok) return res.status(401).render("login", { error: "Usuário ou senha inválidos." });

    req.session.user = { id: user.id, nome: user.nome || "Usuário", email: user.email, role: user.role || "user" };
    await auditLog(req.session.user.nome, "Login", `email=${user.email}`);
    return res.redirect("/dashboard");
  } catch (err) {
    console.error("LOGIN_ERR:", err);
    return res.status(500).render("login", { error: "Erro ao efetuar login. Tente novamente." });
  }
});

app.get("/register", (req, res) => {
  if (isAuthed(req)) return res.redirect("/dashboard");
  res.render("register", { error: null, success: null });
});

app.post("/register", async (req, res) => {
  const nome = String(req.body.nome || "").trim();
  const email = String(req.body.email || "").trim().toLowerCase();
  const senha = String(req.body.senha || "");
  const senha2 = String(req.body.senha2 || "");

  if (!nome || !email || !senha) {
    return res.status(400).render("register", { error: "Preencha nome, email e senha.", success: null });
  }
  if (senha !== senha2) {
    return res.status(400).render("register", { error: "As senhas não conferem.", success: null });
  }
  if (senha.length < 6) {
    return res.status(400).render("register", { error: "Senha muito curta (mínimo 6 caracteres).", success: null });
  }

  try {
    const hash = await bcrypt.hash(senha, 10);

    if (USE_DB) {
      const exists = await pool.query(`SELECT id FROM users WHERE LOWER(email)=$1`, [email]);
      if (exists.rowCount > 0) {
        return res.status(409).render("register", { error: "Este email já está cadastrado.", success: null });
      }
      await pool.query(`INSERT INTO users (nome,email,senha_hash,role) VALUES ($1,$2,$3,'user')`, [nome, email, hash]);
    } else {
      const exists = mock.users.find((u) => u.email.toLowerCase() === email);
      if (exists) return res.status(409).render("register", { error: "Este email já está cadastrado.", success: null });
      const id = mock.users.length ? Math.max(...mock.users.map((u) => u.id)) + 1 : 1;
      mock.users.push({ id, nome, email, senha_hash: hash, role: "user", created_at: nowISO() });
    }

    await auditLog(nome, "Registro", `email=${email}`);
    return res.render("register", { error: null, success: "Conta criada! Agora faça login." });
  } catch (err) {
    console.error("REGISTER_ERR:", err);
    return res.status(500).render("register", { error: "Erro ao registrar. Tente novamente.", success: null });
  }
});

app.get("/logout", async (req, res) => {
  try {
    if (req.session.user) await auditLog(req.session.user.nome, "Logout", req.session.user.email);
  } catch (_) {}
  req.session.destroy(() => res.redirect("/login"));
});

app.get("/esqueci-senha", (req, res) => res.redirect("/login"));

/* -----------------------------
   Rotas protegidas
----------------------------- */
app.get("/dashboard", requireAuth, async (req, res) => {
  try {
    let total = 0;
    let abertas = 0;
    let custoTotal = 0;
    let tempoMedioHoras = 0;

    const serieSemanal = Array(11).fill(0);
    const motivos = { IVPLAST: 0, Cliente: 0, Transportadora: 0, Vendedor: 0 };

    if (USE_DB) {
      const r = await pool.query(`SELECT motivo, status, custo_estimado, created_at, updated_at FROM ocorrencias`);
      const rows = r.rows;

      total = rows.length;
      abertas = rows.filter((o) => String(o.status).toLowerCase() !== "resolvido").length;
      custoTotal = rows.reduce((acc, o) => acc + Number(o.custo_estimado || 0), 0);

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
      total = mock.ocorrencias.length || 17;
      abertas = mock.ocorrencias.filter((o) => String(o.status).toLowerCase() !== "resolvido").length || 2;
      custoTotal = mock.ocorrencias.reduce((acc, o) => acc + Number(o.custo_estimado || 0), 0) || 35340;

      const tempos = mock.ocorrencias.map((o) => hoursBetween(o.created_at, o.updated_at)).filter((n) => n > 0);
      tempoMedioHoras = tempos.length ? Math.round(tempos.reduce((a, b) => a + b, 0) / tempos.length) : 26;

      const fallback = [0, 0, 1, 2, 6, 3, 5, 2, 2, 2, 4];
      for (let i = 0; i < 11; i++) serieSemanal[i] = fallback[i];

      motivos.IVPLAST = 6;
      motivos.Cliente = 5;
      motivos.Transportadora = 4;
      motivos.Vendedor = 2;
    }

    res.render("dashboard", {
      usuario: req.session.user,
      kpis: {
        totalOcorrencias: total || 17,
        abertas: abertas || 2,
        tempoMedioHoras: tempoMedioHoras || 26,
        valorEstimado: custoTotal || 35340,
      },
      serieSemanal,
      motivosOcorrencia: motivos,
    });
  } catch (err) {
    console.error("DASH_ERR:", err);
    res.status(500).send("Erro ao carregar dashboard.");
  }
});

app.get("/ocorrencias", requireAuth, async (req, res) => {
  const q = String(req.query.q || "").trim().toLowerCase();
  const statusFilter = String(req.query.status || "").trim();

  try {
    let lista = [];

    if (USE_DB) {
      const r = await pool.query(`
        SELECT id, razao_social, created_at, updated_at, status
        FROM ocorrencias
        ORDER BY id DESC
        LIMIT 200
      `);

      lista = r.rows.map((o) => ({
        id: o.id,
        cliente: o.razao_social,
        criadoEm: daysAgoText(o.created_at),
        ultimaAtividade: daysAgoText(o.updated_at),
        status: o.status,
        situacao: o.status,
      }));
    } else {
      lista = mock.ocorrencias
        .slice()
        .sort((a, b) => b.id - a.id)
        .slice(0, 200)
        .map((o) => ({
          id: o.id,
          cliente: o.razao_social,
          criadoEm: daysAgoText(o.created_at),
          ultimaAtividade: daysAgoText(o.updated_at),
          status: o.status,
          situacao: o.status,
        }));
    }

    if (q) lista = lista.filter((o) => String(o.cliente).toLowerCase().includes(q) || String(o.id).includes(q));
    if (statusFilter) lista = lista.filter((o) => String(o.status) === statusFilter);

    res.render("ocorrencias", { usuario: req.session.user, ocorrencias: lista, q });
  } catch (err) {
    console.error("OCORRENCIAS_ERR:", err);
    res.status(500).send("Erro ao listar ocorrências.");
  }
});

app.get("/novo", requireAuth, (req, res) => {
  const role = String((req.session.user && req.session.user.role) ? req.session.user.role : "").toLowerCase();
  const canSeeCost = ["admin", "financeiro", "diretoria"].includes(role);

  res.render("novo", {
    usuario: req.session.user,
    canSeeCost,
    error: null,
    success: null
  });
});


app.post("/novo", requireAuth, upload.array("anexos", 10), async (req, res) => {
  try {
    const data = {
      razao_social: String(req.body.razao_social || "").trim(),
      cnpj: String(req.body.cnpj || "").trim(),
      numero_pedido: String(req.body.numero_pedido || "").trim(),
      numero_nf: String(req.body.numero_nf || "").trim(),
      tipo: String(req.body.tipo || "Outros").trim(),
      motivo: String(req.body.motivo || "IVPLAST").trim(),
      descricao: String(req.body.descricao || "").trim(),
      custo_estimado: safeFloat(req.body.custo_estimado, 0),
      responsavel: String(req.body.responsavel || "Atendimento").trim(),
    };

    if (!data.razao_social || !data.descricao) {
      return res.status(400).render("novo", {
        usuario: req.session.user,
        error: "Preencha Razão social e Descrição.",
        success: null,
      });
    }

    let newId = null;

    if (USE_DB) {
      const r = await pool.query(
        `
        INSERT INTO ocorrencias
          (razao_social, cnpj, numero_pedido, numero_nf, tipo, motivo, descricao, custo_estimado, responsavel, status, created_by)
        VALUES
          ($1,$2,$3,$4,$5,$6,$7,$8,$9,'Aberto',$10)
        RETURNING id
      `,
        [
          data.razao_social,
          data.cnpj || null,
          data.numero_pedido || null,
          data.numero_nf || null,
          data.tipo,
          data.motivo,
          data.descricao,
          data.custo_estimado,
          data.responsavel,
          req.session.user.id,
        ]
      );

      newId = r.rows[0].id;

      await pool.query(
        `INSERT INTO ocorrencia_atividades (ocorrencia_id,quem,texto) VALUES ($1,$2,$3)`,
        [newId, req.session.user.nome, "Ocorrência criada."]
      );

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
        status: "Aberto",
        created_by: req.session.user.id,
        created_at: nowISO(),
        updated_at: nowISO(),
        atividades: [{ quando: "agora", quem: req.session.user.nome, texto: "Ocorrência criada." }],
        anexos: (req.files || []).map((f) => ({
          filename: f.filename,
          originalname: f.originalname,
          mimetype: f.mimetype,
          size: f.size,
        })),
      });
    }

    await auditLog(req.session.user.nome, "Criou ocorrência", `#${newId}`);
    return res.redirect(`/ocorrencias/${newId}`);
  } catch (err) {
    console.error("NOVO_POST_ERR:", err);
    return res.status(500).render("novo", {
      usuario: req.session.user,
      error: "Erro ao salvar ocorrência.",
      success: null,
    });
  }
});

app.get("/ocorrencias/:id", requireAuth, async (req, res) => {
  const id = safeInt(req.params.id, 0);
  if (!id) return res.redirect("/ocorrencias");

  try {
    let ocorrencia = null;

    if (USE_DB) {
      const r = await pool.query(`SELECT * FROM ocorrencias WHERE id=$1`, [id]);
      if (r.rowCount === 0) return res.redirect("/ocorrencias");
      const o = r.rows[0];

      const acts = await pool.query(
        `SELECT quem, texto, created_at FROM ocorrencia_atividades WHERE ocorrencia_id=$1 ORDER BY id DESC LIMIT 50`,
        [id]
      );

      ocorrencia = {
        id: o.id,
        cliente: o.razao_social,
        criadoEm: new Date(o.created_at).toISOString().slice(0, 10),
        status: o.status,
        motivo: o.motivo,
        tipo: o.tipo,
        pedido: o.numero_pedido || "-",
        nf: o.numero_nf || "-",
        custo: Number(o.custo_estimado || 0),
        responsavel: o.responsavel,
        descricao: o.descricao,
        atividades: acts.rows.map((a) => ({
          quando: daysAgoText(a.created_at),
          quem: a.quem,
          texto: a.texto,
        })),
      };
    } else {
      const found = mock.ocorrencias.find((x) => x.id === id);
      if (!found) return res.redirect("/ocorrencias");

      ocorrencia = {
        id: found.id,
        cliente: found.razao_social,
        criadoEm: (found.created_at || "").slice(0, 10) || "2026-02-03",
        status: found.status,
        motivo: found.motivo,
        tipo: found.tipo,
        pedido: found.numero_pedido || "-",
        nf: found.numero_nf || "-",
        custo: Number(found.custo_estimado || 0),
        responsavel: found.responsavel,
        descricao: found.descricao,
        atividades: found.atividades || [],
      };
    }

    res.render("ocorrencia_detalhe", { usuario: req.session.user, ocorrencia, id });
  } catch (err) {
    console.error("DETALHE_ERR:", err);
    res.status(500).send("Erro ao carregar ocorrência.");
  }
});

app.post("/ocorrencias/:id/atualizar", requireAuth, async (req, res) => {
  const id = safeInt(req.params.id, 0);
  if (!id) return res.redirect("/ocorrencias");

  const status = String(req.body.status || "").trim() || "Aberto";
  const responsavel = String(req.body.responsavel || "").trim() || "Atendimento";

  try {
    if (USE_DB) {
      await pool.query(`UPDATE ocorrencias SET status=$1, responsavel=$2, updated_at=NOW() WHERE id=$3`, [
        status,
        responsavel,
        id,
      ]);
      await pool.query(
        `INSERT INTO ocorrencia_atividades (ocorrencia_id,quem,texto) VALUES ($1,$2,$3)`,
        [id, req.session.user.nome, `Atualizou: status=${status}, responsável=${responsavel}.`]
      );
    } else {
      const o = mock.ocorrencias.find((x) => x.id === id);
      if (o) {
        o.status = status;
        o.responsavel = responsavel;
        o.updated_at = nowISO();
        o.atividades = o.atividades || [];
        o.atividades.unshift({
          quando: "agora",
          quem: req.session.user.nome,
          texto: `Atualizou: status=${status}, responsável=${responsavel}.`,
        });
      }
    }

    await auditLog(req.session.user.nome, "Alterou status/responsável", `#${id} (${status})`);
    res.redirect(`/ocorrencias/${id}`);
  } catch (err) {
    console.error("ATUALIZAR_ERR:", err);
    res.status(500).send("Erro ao atualizar ocorrência.");
  }
});

app.post("/ocorrencias/:id/comentario", requireAuth, async (req, res) => {
  const id = safeInt(req.params.id, 0);
  const comentario = String(req.body.comentario || "").trim();
  if (!id) return res.redirect("/ocorrencias");
  if (!comentario) return res.redirect(`/ocorrencias/${id}`);

  try {
    if (USE_DB) {
      await pool.query(`UPDATE ocorrencias SET updated_at=NOW() WHERE id=$1`, [id]);
      await pool.query(
        `INSERT INTO ocorrencia_atividades (ocorrencia_id,quem,texto) VALUES ($1,$2,$3)`,
        [id, req.session.user.nome, comentario]
      );
    } else {
      const o = mock.ocorrencias.find((x) => x.id === id);
      if (o) {
        o.updated_at = nowISO();
        o.atividades = o.atividades || [];
        o.atividades.unshift({ quando: "agora", quem: req.session.user.nome, texto: comentario });
      }
    }

    await auditLog(req.session.user.nome, "Comentário", `#${id}`);
    res.redirect(`/ocorrencias/${id}`);
  } catch (err) {
    console.error("COMENTARIO_ERR:", err);
    res.status(500).send("Erro ao salvar comentário.");
  }
});

app.get("/relatorios", requireAuth, async (req, res) => {
  const de = String(req.query.de || "").trim();
  const ate = String(req.query.ate || "").trim();
  const motivo = String(req.query.motivo || "").trim();

  try {
    let rows = [];

    if (USE_DB) {
      const where = [];
      const params = [];
      let idx = 1;

      if (de) {
        where.push(`created_at >= $${idx++}`);
        params.push(`${de} 00:00:00`);
      }
      if (ate) {
        where.push(`created_at <= $${idx++}`);
        params.push(`${ate} 23:59:59`);
      }
      if (motivo) {
        where.push(`motivo = $${idx++}`);
        params.push(motivo);
      }

      const sql = `
        SELECT motivo, status, custo_estimado
        FROM ocorrencias
        ${where.length ? "WHERE " + where.join(" AND ") : ""}
      `;
      const r = await pool.query(sql, params);
      rows = r.rows;
    } else {
      rows = mock.ocorrencias.map((o) => ({ motivo: o.motivo, status: o.status, custo_estimado: o.custo_estimado }));
    }

    const abertas = rows.filter((o) => String(o.status).toLowerCase() !== "resolvido").length;
    const resolvidas = rows.filter((o) => String(o.status).toLowerCase() === "resolvido").length;
    const custoTotal = rows.reduce((acc, o) => acc + Number(o.custo_estimado || 0), 0);

    const porMotivo = { IVPLAST: 0, Cliente: 0, Transportadora: 0, Vendedor: 0 };
    rows.forEach((o) => {
      const m = String(o.motivo || "");
      if (porMotivo[m] !== undefined) porMotivo[m] += 1;
    });

    res.render("relatorios", {
      usuario: req.session.user,
      resumoRelatorio: {
        abertas: abertas || 2,
        resolvidas: resolvidas || 15,
        custoTotal: custoTotal || 35340,
        porMotivo,
      },
      de,
      ate,
      motivo,
    });
  } catch (err) {
    console.error("RELATORIOS_ERR:", err);
    res.status(500).send("Erro ao carregar relatórios.");
  }
});

app.get("/configuracoes", requireAuth, async (req, res) => {
  try {
    const config = {
      adminEmail: await getSetting("adminEmail", process.env.ADMIN_EMAIL || ""),
      adminName: await getSetting("adminName", process.env.ADMIN_NAME || ""),
      databaseSSL: envBool(await getSetting("databaseSSL", String(envBool(process.env.DATABASE_SSL)))),
    };
    res.render("configuracoes", { usuario: req.session.user, config, success: null, error: null });
  } catch (err) {
    console.error("CFG_GET_ERR:", err);
    res.status(500).send("Erro ao carregar configurações.");
  }
});

app.post("/configuracoes/admin", requireAuth, async (req, res) => {
  try {
    const adminEmail = String(req.body.adminEmail || "").trim();
    const adminName = String(req.body.adminName || "").trim();

    await upsertSetting("adminEmail", adminEmail);
    await upsertSetting("adminName", adminName);

    await auditLog(req.session.user.nome, "Alterou configurações", "admin");

    const config = {
      adminEmail: await getSetting("adminEmail", ""),
      adminName: await getSetting("adminName", ""),
      databaseSSL: envBool(await getSetting("databaseSSL", "false")),
    };
    res.render("configuracoes", { usuario: req.session.user, config, success: "Configurações salvas.", error: null });
  } catch (err) {
    console.error("CFG_ADMIN_ERR:", err);
    res.status(500).send("Erro ao salvar configurações.");
  }
});

app.post("/configuracoes/senha", requireAuth, async (req, res) => {
  try {
    const novaSenha = String(req.body.novaSenha || "");
    const novaSenha2 = String(req.body.novaSenha2 || "");

    const config = {
      adminEmail: await getSetting("adminEmail", ""),
      adminName: await getSetting("adminName", ""),
      databaseSSL: envBool(await getSetting("databaseSSL", "false")),
    };

    if (!novaSenha || novaSenha.length < 6) {
      return res.render("configuracoes", {
        usuario: req.session.user,
        config,
        success: null,
        error: "Senha inválida (mínimo 6 caracteres).",
      });
    }
    if (novaSenha !== novaSenha2) {
      return res.render("configuracoes", {
        usuario: req.session.user,
        config,
        success: null,
        error: "As senhas não conferem.",
      });
    }

    const hash = await bcrypt.hash(novaSenha, 10);

    if (USE_DB) {
      await pool.query(`UPDATE users SET senha_hash=$1 WHERE id=$2`, [hash, req.session.user.id]);
    } else {
      const u = mock.users.find((x) => x.id === req.session.user.id);
      if (u) u.senha_hash = hash;
    }

    await auditLog(req.session.user.nome, "Alterou senha", `user_id=${req.session.user.id}`);
    res.render("configuracoes", { usuario: req.session.user, config, success: "Senha alterada com sucesso.", error: null });
  } catch (err) {
    console.error("CFG_PASS_ERR:", err);
    res.status(500).send("Erro ao alterar senha.");
  }
});

app.get("/auditoria", requireAuth, async (req, res) => {
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

/* -----------------------------
   Static
----------------------------- */
app.use("/uploads", express.static(UPLOAD_DIR));

/* -----------------------------
   Boot
----------------------------- */
const PORT = process.env.PORT || 3000;

(async () => {
  try {
    if (USE_DB) {
      await dbInit();
      console.log("✅ DB conectado e inicializado.");
    } else {
      console.log("⚠️ Rodando em modo MOCK (sem DATABASE_URL).");
    }

    app.listen(PORT, () => console.log(`🚀 Server rodando na porta ${PORT}`));
  } catch (err) {
    console.error("BOOT_ERR:", err);
    process.exit(1);
  }
})();

