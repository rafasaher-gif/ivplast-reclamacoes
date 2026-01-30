import express from "express";
import session from "express-session";
import bcrypt from "bcryptjs";
import pg from "pg";

const { Pool } = pg;

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

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

async function initDb() {
  await pool.query(`
    create table if not exists users (
      id serial primary key,
      name text not null,
      email text unique not null,
      password_hash text not null,
      role text not null default 'ADMIN',
      created_at timestamptz not null default now()
    );

    create table if not exists cases (
      id serial primary key,
      case_number text unique not null,
      requester_email text not null,
      company_name text not null,
      cnpj text not null,
      order_number text not null,
      return_type text not null,
      has_nfd boolean not null,
      invoice_number text,
      return_reason text not null,
      error_reason text not null,
      error_details text not null,
      solution_suggestion text not null,
      status text not null default 'NOVO',
      owner_email text,
      created_at timestamptz not null default now(),
      updated_at timestamptz not null default now(),
      closed_at timestamptz
    );
  `);

  const adminEmail = (process.env.ADMIN_EMAIL || "").toLowerCase().trim();
  const adminName = (process.env.ADMIN_NAME || "Admin").trim();
  const adminPass = (process.env.ADMIN_PASSWORD || "").trim();

  if (adminEmail && adminPass) {
    const { rows } = await pool.query("select id from users where email=$1", [adminEmail]);
    if (!rows.length) {
      const hash = await bcrypt.hash(adminPass, 10);
      await pool.query(
        "insert into users (name,email,password_hash,role) values ($1,$2,$3,'ADMIN')",
        [adminName, adminEmail, hash]
      );
    }
  }
}

function auth(req, res, next) {
  if (!req.session.user) return res.status(401).json({ error: "não autenticado" });
  next();
}

function nextCaseNumber() {
  const year = new Date().getFullYear();
  const seq = String(Date.now()).slice(-6);
  return `DEV-${year}-${seq}`;
}

app.get("/", (req, res) =>
  res.send("IVPLAST | Gestão de Ocorrências (API online)")
);

app.post("/auth/login", async (req, res) => {
  const email = (req.body.email || "").toLowerCase().trim();
  const password = (req.body.password || "").trim();
  const { rows } = await pool.query("select * from users where email=$1", [email]);
  if (!rows.length) return res.status(401).json({ error: "login inválido" });

  const ok = await bcrypt.compare(password, rows[0].password_hash);
  if (!ok) return res.status(401).json({ error: "login inválido" });

  req.session.user = { email: rows[0].email, role: rows[0].role, name: rows[0].name };
  res.json({ ok: true, user: req.session.user });
});

app.get("/cases", auth, async (req, res) => {
  const { rows } = await pool.query("select * from cases order by id desc limit 200");
  res.json(rows);
});

app.post("/cases", auth, async (req, res) => {
  const b = req.body;
  if (b.has_nfd === true && !b.invoice_number) {
    return res.status(400).json({ error: "Número da NF é obrigatório quando NFD = Sim" });
  }

  const caseNumber = nextCaseNumber();
  const { rows } = await pool.query(
    `insert into cases
     (case_number, requester_email, company_name, cnpj, order_number, return_type,
      has_nfd, invoice_number, return_reason, error_reason, error_details,
      solution_suggestion, owner_email)
     values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
     returning *`,
    [
      caseNumber,
      b.requester_email,
      b.company_name,
      b.cnpj,
      b.order_number,
      b.return_type,
      b.has_nfd,
      b.invoice_number || null,
      b.return_reason,
      b.error_reason,
      b.error_details,
      b.solution_suggestion,
      process.env.ADMIN_EMAIL || null
    ]
  );
  res.json(rows[0]);
});

const port = process.env.PORT || 3000;
initDb()
  .then(() => app.listen(port, () => console.log("Rodando na porta", port)))
  .catch((e) => {
    console.error("Erro initDb", e);
    process.exit(1);
  });
