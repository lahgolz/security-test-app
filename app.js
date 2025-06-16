import "dotenv/config";
import express from "express";
import session from "express-session";
import path from "path";
import Database from "better-sqlite3";
import { fileURLToPath } from "url";
import bcrypt from "bcrypt";
import crypto from "crypto";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;

const SESSION_SECRET =
  process.env.SESSION_SECRET || crypto.randomBytes(64).toString("hex");

const db = new Database(":memory:");

async function initDatabase() {
  console.log("Initializing database...");

  db.exec(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role TEXT NOT NULL
  )`);

  const user1Password = await bcrypt.hash("password1", 12);
  const adminPassword = await bcrypt.hash(
    process.env.ADMIN_PASSWORD || "admin",
    12
  );

  const insertUser = db.prepare(
    `INSERT OR IGNORE INTO users (username, password, role) VALUES (?, ?, ?)`
  );
  insertUser.run("user1", user1Password, "user");
  insertUser.run(process.env.ADMIN_USERNAME || "admin", adminPassword, "admin");

  console.log("Database initialized successfully!");
}

await initDatabase();

app.use(express.urlencoded({ extended: true }));
app.use(express.static("public"));

app.use(
  session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    name: "sessionId", // Don't use default session name
    cookie: {
      secure: process.env.NODE_ENV === "production", // Secure in production
      httpOnly: true, // Prevent XSS access to cookies
      maxAge: 30 * 60 * 1000, // 30 minutes instead of 1 year
      sameSite: "strict", // CSRF protection
    },
  })
);

app.get("/debug", (req, res) => {
  if (process.env.NODE_ENV !== "development") {
    return res.sendStatus(404);
  }

  res.json({
    environment: process.env,
    session: req.session,
    headers: req.headers,
    userAgent: req.get("User-Agent"),
  });
});

app.get("/", (req, res) => {
  if (req.session.user) {
    return req.session.user.role === "admin"
      ? res.redirect("/admin")
      : res.redirect("/user");
  }

  res.redirect("/login");
});

app.get("/login", (req, res) => {
  res.sendFile(path.join(__dirname, "views", "login.html"));
});

app.post("/login", async (req, res) => {
  const { username, password } = req.body;

  try {
    const user = db
      .prepare("SELECT * FROM users WHERE username = ?")
      .get(username);

    if (!user) {
      return res.redirect("/login?error=1");
    }

    const isValidPassword = await bcrypt.compare(password, user.password);

    if (!isValidPassword) {
      return res.redirect("/login?error=1");
    }

    req.session.regenerate((err) => {
      if (err) {
        console.error("Session regeneration error:", err);
        return res.redirect("/login?error=1");
      }

      req.session.user = {
        id: user.id,
        username: user.username,
        role: user.role,
      };

      req.session.save((err) => {
        if (err) {
          console.error("Session save error:", err);
          return res.redirect("/login?error=1");
        }

        return user.role === "admin"
          ? res.redirect("/admin")
          : res.redirect("/user");
      });
    });
  } catch (err) {
    console.error("Login error:", err);
    res.redirect("/login?error=1");
  }
});

app.get("/user", (req, res) => {
  if (!req.session.user || req.session.user.role !== "user") {
    return res.redirect("/login");
  }

  res.sendFile(path.join(__dirname, "views", "user.html"));
});

app.get("/admin", (req, res) => {
  if (!req.session.user || req.session.user.role !== "admin") {
    return res.redirect("/login");
  }

  res.sendFile(path.join(__dirname, "views", "admin.html"));
});

app.get("/logout", (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error("Session destruction error:", err);
    }
    res.clearCookie("sessionId");
    res.redirect("/login");
  });
});

app.get("/reset-password", (req, res) => {
  res.sendFile(path.join(__dirname, "views", "reset-password.html"));
});

app.post("/reset-password", async (req, res) => {
  const { username, password } = req.body;

  try {
    const user = db
      .prepare("SELECT * FROM users WHERE username = ?")
      .get(username);
    if (!user) {
      return res.redirect("/reset-password?error=1");
    }

    const hashedPassword = await bcrypt.hash(password, 12);

    db.prepare("UPDATE users SET password = ? WHERE username = ?").run(
      hashedPassword,
      username
    );

    res.redirect("/reset-password?success=1");
  } catch (err) {
    console.error("Reset password error:", err);
    res.redirect("/reset-password?error=1");
  }
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
