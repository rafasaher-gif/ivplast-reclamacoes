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

const STATUS = ["NOVO", "EM_ANALISE", "FINANCEIRO", "AGUARDANDO_CLIENTE", "CONCLUIDO"];
const ERROR_REASON = ["IVPLAST", "VENDEDOR", "CLIENTE", "TRANSPORTADORA"];
const RETURN_TYPE = ["PARCIAL", "TOTAL"];

function requireAuth(req, res, next) {
  if (!req.session.user) return res.redirect("/login");
  next();
}

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

    create table if not exists case_counters (
      year int primary key,
      last_num int not null default 0
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

    create table if not exists case_comments (
      id serial primary key,
      case_id int not null references cases(id) on delete cascade,
      user_email text not null,
      comment text not null,
      created_at timestamptz not null default now()
    );

    create table if not exists case_logs (
      id serial primary key,
      case_id int not null references cases(id) on delete cascade,
      user_email text not null,
      action text not null,
      from_value text,
      to_value text,
      created_at timestamptz not null default now()
    );
  `);

  // cria admin inicial (se não existir)
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
      console.log("Admin criado:", adminEmail);
    }
  }
}

async function nextCaseNumber() {
  const year = new Date().getFullYear();
  const client = await pool.connect();
  try {
    await client.query("begin");
    await client.query("insert into case_counters(year,last_num) values($1,0) on conflict (year) do nothing", [year]);
    const r = await client.query("update case_counters set last_num = last_num + 1 where year=$1 returning last_num", [year]);
    const n = r.rows[0].last_num;
    await client.query("commit");
    return `DEV-${year}-${String(n).padStart(6, "0")}`;
  } catch (e) {
    await client.query("rollback");
    throw e;
  } finally {
    client.release();
  }
}

// ---------- PÁGINAS ----------
app.get("/", (req, res) => (req.session.user ? res.redirect("/cases") : res.redirect("/login")));

app.get("/login", (req, res) => res.render("login", { error: null }));

app.post("/login", async (req, res) => {
  const email = (req.body.email || "").toLowerCase().trim();
  const password = (req.body.password || "").trim();

  const { rows } = await pool.query("select * from users where email=$1", [email]);
  if (!rows.length) return res.render("login", { error: "Login inválido" });

  const ok = await bcrypt.compare(password, rows[0].password_hash);
  if (!ok) return res.render("login", { error: "Login inválido" });

  req.session.user = { email: rows[0].email, name: rows[0].name, role: rows[0].role };
  res.redirect("/cases");
});

app.post("/logout", (req, res) => req.session.destroy(() => res.redirect("/login")));

app.get("/cases", requireAuth, async (req, res) => {
  const { status = "" } = req.query;
  const params = [];
  let where = "";
  if (status && STATUS.includes(status)) {
    params.push(status);
    where = `where status=$1`;
  }
  const { rows } = await pool.query(`select * from cases ${where} order by id desc limit 300`, params);
  res.render("cases", { user: req.session.user, rows, STATUS, filterStatus: status });
});

app.get("/cases/new", requireAuth, (req, res) => {
  res.render("new_case", { user: req.session.user, STATUS, ERROR_REASON, RETURN_TYPE, error: null });
});

app.post("/cases/new", requireAuth, async (req, res) => {
  const b = req.body;

  try {
    const has_nfd = b.has_nfd === "SIM";
    if (has_nfd && !b.invoice_number) {
      return res.render("new_case", { user: req.session.user, STATUS, ERROR_REASON, RETURN_TYPE, error: "Número da NF é obrigatório quando NFD = Sim" });
    }
    if (!RETURN_TYPE.includes(b.return_type)) throw new Error("Tipo de devolução inválido");
    if (!ERROR_REASON.includes(b.error_reason)) throw new Error("Motivo do erro inválido");

    const case_number = await nextCaseNumber();
    const owner_email = process.env.ADMIN_EMAIL || req.session.user.email;

    const { rows } = await pool.query(
      `insert into cases (
        case_number, requester_email, company_name, cnpj, order_number,
        return_type, has_nfd, invoice_number,
        return_reason, error_reason, error_details, solution_suggestion,
        status, owner_email
      ) values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,'NOVO',$13)
      returning *`,
      [
        case_number,
        (b.requester_email || "").trim(),
        (b.company_name || "").trim(),
        (b.cnpj || "").trim(),
        (b.order_number || "").trim(),
        b.return_type,
        has_nfd,
        (b.invoice_number || "").trim() || null,
        (b.return_reason || "").trim(),
        b.error_reason,
        (b.error_details || "").trim(),
        (b.solution_suggestion || "").trim(),
        owner_email
      ]
    );

    await pool.query(
      "insert into case_logs(case_id,user_email,action,to_value) values($1,$2,'CREATE',$3)",
      [rows[0].id, req.session.user.email, "NOVO"]
    );

    res.redirect(`/cases/${rows[0].id}`);
  } catch (e) {
    res.render("new_case", { user: req.session.user, STATUS, ERROR_REASON, RETURN_TYPE, error: e.message || "Erro ao criar" });
  }
});

app.get("/cases/:id", requireAuth, async (req, res) => {
  const id = Number(req.params.id);
  const c = await pool.query("select * from cases where id=$1", [id]);
  if (!c.rows.length) return res.status(404).send("Não encontrado");

  const comments = await pool.query("select * from case_comments where case_id=$1 order by id desc", [id]);
  const logs = await pool.query("select * from case_logs where case_id=$1 order by id desc", [id]);

  res.render("case_detail", {
    user: req.session.user,
    c: c.rows[0],
    comments: comments.rows,
    logs: logs.rows,
    STATUS
  });
});

app.post("/cases/:id/status", requireAuth, async (req, res) => {
  const id = Number(req.params.id);
  const newStatus = String(req.body.status || "").trim();
  if (!STATUS.includes(newStatus)) return res.status(400).send("Status inválido");

  const current = await pool.query("select status from cases where id=$1", [id]);
  if (!current.rows.length) return res.status(404).send("Não encontrado");

  await pool.query(
    `update cases
     set status=$1, updated_at=now(),
     closed_at = case when $1='CONCLUIDO' then now() else closed_at end
     where id=$2`,
    [newStatus, id]
  );

  await pool.query(
    "insert into case_logs(case_id,user_email,action,from_value,to_value) values($1,$2,'STATUS_CHANGE',$3,$4)",
    [id, req.session.user.email, current.rows[0].status, newStatus]
  );

  res.redirect(`/cases/${id}`);
});

app.post("/cases/:id/comment", requireAuth, async (req, res) => {
  const id = Number(req.params.id);
  const comment = String(req.body.comment || "").trim();
  if (!comment) return res.redirect(`/cases/${id}`);

  await pool.query(
    "insert into case_comments(case_id,user_email,comment) values($1,$2,$3)",
    [id, req.session.user.email, comment]
  );
  await pool.query(
    "insert into case_logs(case_id,user_email,action,to_value) values($1,$2,'COMMENT',$3)",
    [id, req.session.user.email, comment.slice(0, 120)]
  );

  res.redirect(`/cases/${id}`);
});

// ---------- START ----------
const port = process.env.PORT || 10000;
initDb()
  .then(() => app.listen(port, () => console.log("Rodando na porta", port)))
  .catch((e) => {
    console.error("Erro initDb", e);
    process.exit(1);
  });
// Páginas
app.get("/", (req, res) => {
  res.render("index");
});

app.get("/login", (req, res) => {
  res.render("login");
});

app.get("/register", (req, res) => {
  res.render("register");
});

// Ações (por enquanto só redireciona)
app.post("/login", (req, res) => {
  res.redirect("/");
});

app.post("/register", (req, res) => {
  res.redirect("/login");
});
