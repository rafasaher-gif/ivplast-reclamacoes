import express from "express";
import session from "express-session";

const app = express();
const PORT = process.env.PORT || 3000;

// -------- CONFIG --------
app.set("view engine", "ejs");
app.set("views", "./views");

app.use(express.urlencoded({ extended: true }));
app.use(express.json());

app.use(
  session({
    secret: "ivplast-secret",
    resave: false,
    saveUninitialized: false
  })
);

// -------- ROTAS --------

// LOGIN (TELA)
app.get("/login", (req, res) => {
  res.render("login", {
    error: null,
    systemName: "SOLUÇÕES DE BUCHAS IVPLAST"
  });
});

// LOGIN (AÇÃO)
app.post("/login", (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.render("login", {
      error: "Preencha email e senha",
      systemName: "SOLUÇÕES DE BUCHAS IVPLAST"
    });
  }

  // login fake por enquanto
  req.session.user = {
    email,
    role: "diretoria"
  };

  res.redirect("/dashboard");
});

// CADASTRO (TELA)
app.get("/register", (req, res) => {
  res.render("register");
});

// CADASTRO (AÇÃO)
app.post("/register", (req, res) => {
  res.redirect("/login");
});

// DASHBOARD
app.get("/dashboard", (req, res) => {
  if (!req.session.user) {
    return res.redirect("/login");
  }

  res.render("dashboard", {
    user: req.session.user
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
  res.redirect("/login");
});

// START
app.listen(PORT, () => {
  console.log("Servidor rodando na porta", PORT);
});
