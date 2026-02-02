import express from "express";
import session from "express-session";
import bcrypt from "bcryptjs";
import pg from "pg";

const { Pool } = pg;
const app = express();

app.set("view engine", "ejs");
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

app.use(
  session({
    secret: process.env.SESSION_SECRET || "troque-essa-chave",
    resave: false,
    saveUninitialized: false,
    cookie: { sameSite: "lax" }
  })
);

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_SSL === "true" ? { rejectUnauthorized: false } : false
});

// ---------- Helpers ----------
function requireAuth(req, res, next) {
  if (!req.session.user) return res.redirect("/login");
  next();
}

function isStrongPassword(pw) {
  // mínimo 8, 1 maiúscula, 1 minúscula, 1 número, 1 símbolo
  if (!pw || pw.length < 8) return false;
  if (!/[A-Z]/.test(pw)) return false;
  if (!/[a-z]/.test(pw)) return false;
  if (!/[0-9]/.test(pw)) return false;
  if (!/[^A-Za-z0-9]/.test(pw)) return false;
  return true;
}

// ---------- DB init ----------
async function initDb() {
  await pool.query(`
    create table if not exists users (
      id serial primary key,
      name text not null,
      email text unique not null,
      password_hash text not null,
      role text not null default 'DIRETORIA', -- VENDEDOR | OPERACIONAL | FINANCEIRO | DIRETORIA
      created_at timestamptz not null default now()
    );
  `);

  // cria usuário master (se não existir)
  const adminEmail = (process.env.ADMIN_EMAIL || "").toLowerCase().trim();
  const adminName = (process.env.ADMIN_NAME || "Admin").trim();
  const adminPass = (process.env.ADMIN_PASSWORD || "").trim();

  if (adminEmail && adminPass) {
    const r = await pool.query("select id from users where email=$1", [adminEmail]);
    if (r.rows.length === 0) {
      const hash = await bcrypt.hash(adminPass, 10);
      await pool.query(
        "insert into users (name,email,password_hash,role) values ($1,$2,$3,'DIRETORIA')",
        [adminName, adminEmail, hash]
      );
      console.log("Usuário master criado:", adminEmail);
    }
  }
}

// ---------- Pages ----------
app.get("/", (req, res) => {
  if (!req.session.user) return res.redirect("/login");
  res.send(`Logado como: ${req.session.user.email} (${req.session.user.role})`);
});

app.get("/login", (req, res) => {
  res.render("login", { error: null, systemName: "SOLUÇÕES DE BUCHAS IVPLAST" });
});

app.post("/login", async (req, res) => {
  const email = String(req.body.email || "").toLowerCase().trim();
  const password = String(req.body.password || "");

  const r = await pool.query("select * from users where email=$1", [email]);
  if (r.rows.length === 0) {
    return res.render("login", { error: "Login inválido", systemName: "SOLUÇÕES DE BUCHAS IVPLAST" });
  }

  const user = r.rows[0];
  const ok = await bcrypt.compare(password, user.password_hash);
  if (!ok) {
    return res.render("login", { error: "Login inválido", systemName: "SOLUÇÕES DE BUCHAS IVPLAST" });
  }

  req.session.user = { email: user.email, name: user.name, role: user.role };
  return res.redirect("/");
});

app.post("/logout", (req, res) => {
  req.session.destroy(() => res.redirect("/login"));
});

app.get("/register", (req, res) => {
  res.render("register", { error: null, systemName: "SOLUÇÕES DE BUCHAS IVPLAST" });
});

// OBS: por enquanto qualquer um consegue cadastrar.
// No próximo passo vamos travar para só DIRETORIA criar usuários (senha master).
app.post("/register", async (req, res) => {
  const name = String(req.body.name || "").trim();
  const email = String(req.body.email || "").toLowerCase().trim();
  const password = String(req.body.password || "");

  if (!name || !email || !password) {
    return res.render("register", { error: "Preencha todos os campos", systemName: "SOLUÇÕES DE BUCHAS IVPLAST" });
  }

  if (!isStrongPassword(password)) {
    return res.render("register", {
      error: "Senha fraca: mínimo 8, maiúscula, minúscula, número e símbolo.",
      systemName: "SOLUÇÕES DE BUCHAS IVPLAST"
    });
  }

  const exists = await pool.query("select id from users where email=$1", [email]);
  if (exists.rows.length) {
    return res.render("register", { error: "Este e-mail já existe", systemName: "SOLUÇÕES DE BUCHAS IVPLAST" });
  }

  const hash = await bcrypt.hash(password, 10);

  // por enquanto, role default = VENDEDOR (vamos mudar no próximo passo)
  await pool.query(
    "insert into users (name,email,password_hash,role) values ($1,$2,$3,'VENDEDOR')",
    [name, email, hash]
  );

  return res.redirect("/login");
});

// ---------- Start ----------
const port = process.env.PORT || 10000;
initDb()
  .then(() => app.listen(port, () => console.log("Rodando na porta", port)))
  .catch((e) => {
    console.error("Erro initDb", e);
    process.exit(1);
  });
