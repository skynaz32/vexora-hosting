
const express = require("express");
const crypto = require("node:crypto");
const { promisify } = require("node:util");
const { query, pool } = require("./db");

const app = express();
const PORT = process.env.PORT || 3000;
const TOKEN_SECRET = process.env.TOKEN_SECRET;
const scrypt = promisify(crypto.scrypt);

app.disable("x-powered-by");
app.use(express.json({ limit: "100kb" }));

if (!TOKEN_SECRET || TOKEN_SECRET.length < 32) {
  console.error("Set TOKEN_SECRET to a random secret of at least 32 characters.");
  process.exit(1);
}

const plans = [
  {
    id: "free",
    name: "Free",
    prices: { MYR: 0, USD: 0 },
    ramMB: null
  },
  {
    id: "paid",
    name: "Paid",
    prices: { MYR: null, USD: null },
    ramMB: null,
    requiresDiscordMembership: true
  }
];

function signToken(user) {
  const payload = Buffer.from(JSON.stringify({
    id: user.id,
    role: user.role,
    exp: Date.now() + 24 * 60 * 60 * 1000
  })).toString("base64url");

  const signature = crypto
    .createHmac("sha256", TOKEN_SECRET)
    .update(payload)
    .digest("base64url");

  return `${payload}.${signature}`;
}

function auth(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ")
    ? header.slice(7)
    : "";

  const parts = token.split(".");
  if (parts.length !== 2) {
    return res.status(401).json({ error: "Login required." });
  }

  const expected = crypto
    .createHmac("sha256", TOKEN_SECRET)
    .update(parts[0])
    .digest();

  let actual;
  try {
    actual = Buffer.from(parts[1], "base64url");
  } catch {
    return res.status(401).json({ error: "Invalid token." });
  }

  if (
    actual.length !== expected.length ||
    !crypto.timingSafeEqual(actual, expected)
  ) {
    return res.status(401).json({ error: "Invalid token." });
  }

  let data;
  try {
    data = JSON.parse(
      Buffer.from(parts[0], "base64url").toString()
    );
  } catch {
    return res.status(401).json({ error: "Invalid token." });
  }

  if (!data.id || data.exp < Date.now()) {
    return res.status(401).json({ error: "Token expired." });
  }

  req.user = data;
  next();
}

async function currentUser(req, res, next) {
  try {
    const result = await query(
      "SELECT id, username, email, role, banned FROM users WHERE id = $1",
      [req.user.id]
    );

    const user = result.rows[0];
    if (!user || user.banned) {
      return res.status(403).json({ error: "Account unavailable." });
    }

    req.account = user;
    next();
  } catch (error) {
    next(error);
  }
}

function roles(...allowed) {
  return (req, res, next) => {
    if (!allowed.includes(req.account.role)) {
      return res.status(403).json({ error: "Permission denied." });
    }
    next();
  };
}

async function initializeDatabase() {
  await query(`
    CREATE TABLE IF NOT EXISTS users (
      id BIGSERIAL PRIMARY KEY,
      username VARCHAR(50) UNIQUE NOT NULL,
      email VARCHAR(255) UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role VARCHAR(20) NOT NULL DEFAULT 'customer'
        CHECK (role IN ('customer','staff','admin')),
      banned BOOLEAN NOT NULL DEFAULT FALSE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS access_grants (
      id BIGSERIAL PRIMARY KEY,
      user_id BIGINT NOT NULL REFERENCES users(id),
      feature VARCHAR(100) NOT NULL,
      granted_by BIGINT REFERENCES users(id),
      expires_at TIMESTAMPTZ,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      UNIQUE(user_id, feature)
    );

    CREATE TABLE IF NOT EXISTS news_posts (
      id BIGSERIAL PRIMARY KEY,
      title VARCHAR(200) NOT NULL,
      content TEXT NOT NULL,
      author_id BIGINT NOT NULL REFERENCES users(id),
      published BOOLEAN NOT NULL DEFAULT FALSE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS assets (
      id BIGSERIAL PRIMARY KEY,
      title VARCHAR(200) NOT NULL,
      description TEXT,
      file_url TEXT NOT NULL,
      uploaded_by BIGINT NOT NULL REFERENCES users(id),
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS advertisements (
      id BIGSERIAL PRIMARY KEY,
      title VARCHAR(200) NOT NULL,
      image_url TEXT,
      target_url TEXT,
      active BOOLEAN NOT NULL DEFAULT FALSE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS embeds (
      id BIGSERIAL PRIMARY KEY,
      owner_id BIGINT NOT NULL REFERENCES users(id),
      title VARCHAR(256) NOT NULL,
      description TEXT NOT NULL DEFAULT '',
      color VARCHAR(7) NOT NULL DEFAULT '#8b5cf6',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS hosting_servers (
      id BIGSERIAL PRIMARY KEY,
      owner_id BIGINT NOT NULL REFERENCES users(id),
      name VARCHAR(100) NOT NULL,
      ram_mb INTEGER NOT NULL DEFAULT 128,
      status VARCHAR(20) NOT NULL DEFAULT 'stopped',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);
}

app.get("/", (req, res) => {
  res.json({
    name: "VEXORA HOSTING",
    status: "online",
    version: "0.2.0"
  });
});

app.get("/api/health", async (req, res, next) => {
  try {
    await query("SELECT 1");
    res.json({ status: "ok", database: "connected" });
  } catch (error) {
    next(error);
  }
});

app.get("/api/panel", (req, res) => {
  res.json({
    panels: ["customer", "staff", "admin"],
    features: [
      "bot-hosting",
      "embed-builder",
      "access-management",
      "new-assets",
      "news",
      "advertisements"
    ],
    status: "development"
  });
});

app.get("/api/plans", (req, res) => {
  const currency = String(req.query.currency || "MYR").toUpperCase();

  if (!["MYR", "USD"].includes(currency)) {
    return res.status(400).json({
      error: "Currency must be MYR or USD."
    });
  }

  res.json({
    currency,
    plans: plans.map(plan => ({
      ...plan,
      price: plan.prices[currency]
    }))
  });
});

app.post("/api/register", async (req, res, next) => {
  try {
    const { username, email, password } = req.body || {};

    if (
      typeof username !== "string" ||
      !/^[a-zA-Z0-9_-]{3,50}$/.test(username) ||
      typeof email !== "string" ||
      !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) ||
      typeof password !== "string" ||
      password.length < 12 ||
      password.length > 128
    ) {
      return res.status(400).json({
        error: "Use a valid username/email and a password of 12–128 characters."
      });
    }

    const salt = crypto.randomBytes(16).toString("hex");
    const hash = await scrypt(password, salt, 64);
    const passwordHash = `${salt}:${hash.toString("hex")}`;

    const result = await query(
      `INSERT INTO users (username, email, password_hash)
       VALUES ($1, $2, $3)
       RETURNING id, username, email, role`,
      [username, email.toLowerCase(), passwordHash]
    );

    const user = result.rows[0];
    res.status(201).json({
      user,
      token: signToken(user)
    });
  } catch (error) {
    if (error.code === "23505") {
      return res.status(409).json({
        error: "Username or email already exists."
      });
    }
    next(error);
  }
});

app.post("/api/login", async (req, res, next) => {
  try {
    const { email, password } = req.body || {};

    if (typeof email !== "string" || typeof password !== "string") {
      return res.status(400).json({ error: "Email and password required." });
    }

    const result = await query(
      `SELECT id, username, email, role, banned, password_hash
       FROM users WHERE email = $1`,
      [email.toLowerCase()]
    );

    const user = result.rows[0];
    if (!user || user.banned) {
      return res.status(401).json({ error: "Invalid login." });
    }

    const [salt, storedHex] = user.password_hash.split(":");
    const stored = Buffer.from(storedHex || "", "hex");
    const derived = await scrypt(password, salt, 64);

    if (
      stored.length !== derived.length ||
      !crypto.timingSafeEqual(stored, derived)
    ) {
      return res.status(401).json({ error: "Invalid login." });
    }

    res.json({
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        role: user.role
      },
      token: signToken(user)
    });
  } catch (error) {
    next(error);
  }
});

app.get("/api/me", auth, currentUser, (req, res) => {
  res.json({ user: req.account });
});

app.get("/api/access", auth, currentUser, async (req, res, next) => {
  try {
    const result = await query(
      `SELECT feature, expires_at FROM access_grants
       WHERE user_id = $1
       AND (expires_at IS NULL OR expires_at > NOW())`,
      [req.account.id]
    );
    res.json({ grants: result.rows });
  } catch (error) {
    next(error);
  }
});

app.post(
  "/api/access/grant",
  auth, currentUser, roles("staff", "admin"),
  async (req, res, next) => {
    try {
      const { userId, feature } = req.body || {};
      if (!userId || typeof feature !== "string" ||
          !/^[a-z0-9_-]{2,100}$/.test(feature)) {
        return res.status(400).json({ error: "Invalid user or feature." });
      }

      const result = await query(
        `INSERT INTO access_grants (user_id, feature, granted_by)
         VALUES ($1, $2, $3)
         ON CONFLICT (user_id, feature)
         DO UPDATE SET granted_by = EXCLUDED.granted_by,
                       expires_at = NULL
         RETURNING *`,
        [userId, feature, req.account.id]
      );
      res.status(201).json({ grant: result.rows[0] });
    } catch (error) {
      next(error);
    }
  }
);

app.delete(
  "/api/access/:userId/:feature",
  auth, currentUser, roles("staff", "admin"),
  async (req, res, next) => {
    try {
      await query(
        "DELETE FROM access_grants WHERE user_id = $1 AND feature = $2",
        [req.params.userId, req.params.feature]
      );
      res.json({ success: true });
    } catch (error) {
      next(error);
    }
  }
);

app.get("/api/news", async (req, res, next) => {
  try {
    const result = await query(
      `SELECT id, title, content, created_at
       FROM news_posts WHERE published = TRUE
       ORDER BY created_at DESC LIMIT 50`
    );
    res.json({ news: result.rows });
  } catch (error) {
    next(error);
  }
});

app.post(
  "/api/news",
  auth, currentUser, roles("staff", "admin"),
  async (req, res, next) => {
    try {
      const { title, content, published = true } = req.body || {};
      if (typeof title !== "string" || !title.trim() ||
          title.length > 200 || typeof content !== "string" ||
          !content.trim()) {
        return res.status(400).json({ error: "Valid title and content required." });
      }

      const result = await query(
        `INSERT INTO news_posts (title, content, author_id, published)
         VALUES ($1, $2, $3, $4) RETURNING *`,
        [title.trim(), content, req.account.id, Boolean(published)]
      );
      res.status(201).json({ news: result.rows[0] });
    } catch (error) {
      next(error);
    }
  }
);

app.get("/api/assets", async (req, res, next) => {
  try {
    const result = await query(
      `SELECT id, title, description, file_url, created_at
       FROM assets ORDER BY created_at DESC LIMIT 100`
    );
    res.json({ assets: result.rows });
  } catch (error) {
    next(error);
  }
});

app.post(
  "/api/assets",
  auth, currentUser, roles("staff", "admin"),
  async (req, res, next) => {
    try {
      const { title, description = "", fileUrl } = req.body || {};
      let parsedUrl;
      try {
        parsedUrl = new URL(fileUrl);
      } catch {
        return res.status(400).json({ error: "Valid HTTPS file URL required." });
      }

      if (parsedUrl.protocol !== "https:" ||
          typeof title !== "string" || !title.trim() ||
          title.length > 200) {
        return res.status(400).json({ error: "Invalid asset details." });
      }

      const result = await query(
        `INSERT INTO assets (title, description, file_url, uploaded_by)
         VALUES ($1, $2, $3, $4) RETURNING *`,
        [title.trim(), description, parsedUrl.toString(), req.account.id]
      );
      res.status(201).json({ asset: result.rows[0] });
    } catch (error) {
      next(error);
    }
  }
);

app.get("/api/ads", async (req, res, next) => {
  try {
    const result = await query(
      `SELECT id, title, image_url, target_url
       FROM advertisements WHERE active = TRUE
       ORDER BY created_at DESC LIMIT 30`
    );
    res.json({ advertisements: result.rows });
  } catch (error) {
    next(error);
  }
});

app.post(
  "/api/ads",
  auth, currentUser, roles("staff", "admin"),
  async (req, res, next) => {
    try {
      const { title, imageUrl = null, targetUrl = null } = req.body || {};
      if (typeof title !== "string" || !title.trim() || title.length > 200) {
        return res.status(400).json({ error: "Valid title required." });
      }

      for (const value of [imageUrl, targetUrl]) {
        if (value !== null) {
          try {
            if (new URL(value).protocol !== "https:") throw new Error();
          } catch {
            return res.status(400).json({ error: "URLs must use HTTPS." });
          }
        }
      }

      const result = await query(
        `INSERT INTO advertisements (title, image_url, target_url, active)
         VALUES ($1, $2, $3, TRUE) RETURNING *`,
        [title.trim(), imageUrl, targetUrl]
      );
      res.status(201).json({ advertisement: result.rows[0] });
    } catch (error) {
      next(error);
    }
  }
);

app.get("/api/embeds", auth, currentUser, async (req, res, next) => {
  try {
    const result = await query(
      `SELECT id, title, description, color, created_at
       FROM embeds WHERE owner_id = $1 ORDER BY created_at DESC`,
      [req.account.id]
    );
    res.json({ embeds: result.rows });
  } catch (error) {
    next(error);
  }
});

app.post("/api/embeds", auth, currentUser, async (req, res, next) => {
  try {
    const { title, description = "", color = "#8b5cf6" } = req.body || {};
    const allowed =
      req.account.role !== "customer" ||
      (await query(
        `SELECT 1 FROM access_grants
         WHERE user_id = $1 AND feature = 'embed-builder'
         AND (expires_at IS NULL OR expires_at > NOW())`,
        [req.account.id]
      )).rowCount > 0;

    if (!allowed) {
      return res.status(403).json({ error: "Embed Builder access not granted." });
    }

    if (typeof title !== "string" || !title.trim() || title.length > 256 ||
        typeof description !== "string" || description.length > 4000 ||
        !/^#[0-9a-fA-F]{6}$/.test(color)) {
      return res.status(400).json({ error: "Invalid embed details." });
    }

    const result = await query(
      `INSERT INTO embeds (owner_id, title, description, color)
       VALUES ($1, $2, $3, $4) RETURNING *`,
      [req.account.id, title.trim(), description, color]
    );
    res.status(201).json({ embed: result.rows[0] });
  } catch (error) {
    next(error);
  }
});

app.get("/api/hosting/status", (req, res) => {
  res.json({
    engine: "not-connected",
    message: "Real bot execution engine is not connected yet.",
    ramUsage: null,
    runningServers: null
  });
});

app.get("/api/hosting/servers", auth, currentUser, async (req, res, next) => {
  try {
    const result = await query(
      `SELECT id, name, ram_mb, status, created_at
       FROM hosting_servers WHERE owner_id = $1 ORDER BY id DESC`,
      [req.account.id]
    );
    res.json({ servers: result.rows });
  } catch (error) {
    next(error);
  }
});

app.post("/api/admin/users/:id/role", auth, currentUser, roles("admin"),
  async (req, res, next) => {
    try {
      const { role } = req.body || {};
      if (!["customer", "staff", "admin"].includes(role)) {
        return res.status(400).json({ error: "Invalid role." });
      }

      const result = await query(
        "UPDATE users SET role = $1 WHERE id = $2 RETURNING id, username, role",
        [role, req.params.id]
      );
      if (!result.rowCount) {
        return res.status(404).json({ error: "User not found." });
      }
      res.json({ user: result.rows[0] });
    } catch (error) {
      next(error);
    }
  }
);

app.post("/api/admin/users/:id/ban", auth, currentUser, roles("admin"),
  async (req, res, next) => {
    try {
      const banned = req.body?.banned;
      if (typeof banned !== "boolean") {
        return res.status(400).json({ error: "banned must be true or false." });
      }

      const result = await query(
        "UPDATE users SET banned = $1 WHERE id = $2 RETURNING id, username, banned",
        [banned, req.params.id]
      );
      if (!result.rowCount) {
        return res.status(404).json({ error: "User not found." });
      }
      res.json({ user: result.rows[0] });
    } catch (error) {
      next(error);
    }
  }
);

app.use((error, req, res, next) => {
  console.error("VEXORA API error:", error.message);
  if (res.headersSent) return next(error);
  res.status(500).json({ error: "Internal server error." });
});

async function start() {
  await initializeDatabase();
  app.listen(PORT, "0.0.0.0", () => {
    console.log(`VEXORA HOSTING API listening on port ${PORT}`);
  });
}

start().catch(error => {
  console.error("VEXORA startup failed:", error.message);
  process.exit(1);
});

process.on("SIGTERM", async () => {
  await pool.end();
  process.exit(0);
});
  
