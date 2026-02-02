import express from "express";
import session from "express-session";
import path from "path";
import { fileURLToPath } from "url";

const app = express();
const PORT = process.env.PORT || 3000;

/* ===== CONFIG ===== */
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

app.use(express.urlencoded({ extended: true }));
app.use(express.static("public"));

app.use(
  session({
    secret: "ivplast-secret",
    resave: false,
    saveUninitialized: false,
  })
);

/* ===== USUÁRIOS (temporário, depois vai para banco) ===== */
const users = [
  {
    email: "raphael@ivplast.com.br",
    password: "123456",
    role: "VENDEDOR",
  },
  {
    email: "diretor@ivplast.com.br",
    password: "123456",
    role: "DIRETORIA",
  },
];

/* ===== ROTAS ===== */

// LOGIN PAGE
app.get("/login", (req, res) => {
  res.render("login");
});

// LOGIN POST
app.post("/login", (req, res) => {
  const { email, password } = req.body;

  const user = users.find(
    (u) => u.email === email && u.password === password
  );

  if (!user) {
    return res.send("Login inválido");
  }

  req.session.user = user;
  res.redirect("/dashboard");
});

// DASHBOARD
app.get("/dashboard", (req, res) => {
  if (!req.session.user) return res.redirect("/login");

  res.render("dashboard", {
    user: req.session.user,
  });
});

// LOGOUT
app.get("/logout", (req, res) => {
  req.session.destroy(() => {
    res.redirect("/login");
  });
});

// HOME
app.get("/", (req, res) => {
  if (!req.session.user) return res.redirect("/login");
  res.redirect("/dashboard");
});

/* ===== SERVER ===== */
app.listen(PORT, () => {
  console.log("Servidor rodando na porta " + PORT);
});
