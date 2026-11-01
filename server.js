const express = require("express");
const path = require("path");
const fs = require("fs");
const bcrypt = require("bcryptjs");
const multer = require("multer");
const sqlite3 = require("sqlite3").verbose();
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");

const app = express();
const PORT = process.env.PORT || 3000;
const DB_PATH = path.join(__dirname, "unico.db");
const UPLOADS_DIR = path.join(__dirname, "uploads");
const AVATAR_DIR = path.join(UPLOADS_DIR, "avatars");
const ADMIN_INVITE = process.env.ADMIN_INVITE || "181202";
const JWT_SECRET = process.env.JWT_SECRET || "savi123";
const AUTH_COOKIE = "unico_token";

if (!fs.existsSync(UPLOADS_DIR)) fs.mkdirSync(UPLOADS_DIR, { recursive: true });
if (!fs.existsSync(AVATAR_DIR)) fs.mkdirSync(AVATAR_DIR, { recursive: true });
const db = new sqlite3.Database(DB_PATH);

const run = (sql, params = []) =>
  new Promise((resolve, reject) => {
    db.run(sql, params, function runStatement(err) {
      if (err) return reject(err);
      return resolve(this);
    });
  });
const get = (sql, params = []) =>
  new Promise((resolve, reject) => {
    db.get(sql, params, (err, row) => {
      if (err) return reject(err);
      return resolve(row);
    });
  });
const all = (sql, params = []) =>
  new Promise((resolve, reject) => {
    db.all(sql, params, (err, rows) => {
      if (err) return reject(err);
      return resolve(rows);
    });
  });

const sanitize = (value = "") => String(value).trim().replace(/\s+/g, " ");
const canManage = (ownerId, user) => user.role === "admin" || ownerId === user.id;

async function initDb() {
  await run("PRAGMA foreign_keys = ON");
  await run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      name TEXT NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL CHECK(role IN ('student', 'admin')),
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);
  await run(`
    CREATE TABLE IF NOT EXISTS topics (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      title TEXT NOT NULL,
      description TEXT,
      created_by INTEGER NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(created_by) REFERENCES users(id) ON DELETE CASCADE
    )
  `);
  await run(`
    CREATE TABLE IF NOT EXISTS discussion_posts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      topic_id INTEGER NOT NULL,
      user_id INTEGER NOT NULL,
      content TEXT NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(topic_id) REFERENCES topics(id) ON DELETE CASCADE,
      FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    )
  `);
  await run(`
    CREATE TABLE IF NOT EXISTS broadcasts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      title TEXT NOT NULL,
      message TEXT NOT NULL,
      created_by INTEGER NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(created_by) REFERENCES users(id) ON DELETE CASCADE
    )
  `);
  await run(`
    CREATE TABLE IF NOT EXISTS assignments (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      title TEXT NOT NULL,
      file_name TEXT NOT NULL,
      file_path TEXT NOT NULL,
      uploaded_by INTEGER NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(uploaded_by) REFERENCES users(id) ON DELETE CASCADE
    )
  `);
  const userColumns = await all("PRAGMA table_info(users)");
  const hasBio = userColumns.some((col) => col.name === "bio");
  const hasProfileImage = userColumns.some((col) => col.name === "profile_image");
  if (!hasBio) await run("ALTER TABLE users ADD COLUMN bio TEXT DEFAULT ''");
  if (!hasProfileImage) await run("ALTER TABLE users ADD COLUMN profile_image TEXT DEFAULT ''");
}

const upload = multer({
  storage: multer.diskStorage({
    destination: (_req, _file, cb) => cb(null, UPLOADS_DIR),
    filename: (_req, file, cb) => {
      const safeName = file.originalname.replace(/[^a-zA-Z0-9._-]/g, "_");
      cb(null, `${Date.now()}_${safeName}`);
    },
  }),
  limits: { fileSize: 10 * 1024 * 1024 },
});

const avatarUpload = multer({
  storage: multer.diskStorage({
    destination: (_req, _file, cb) => cb(null, AVATAR_DIR),
    filename: (_req, file, cb) => {
      const extension = path.extname(file.originalname || ".png");
      cb(null, `${Date.now()}_${Math.random().toString(36).slice(2)}${extension}`);
    },
  }),
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (_req, file, cb) => {
    if (!file.mimetype.startsWith("image/")) {
      return cb(new Error("Only image files are allowed."));
    }
    return cb(null, true);
  },
});

app.set("trust proxy", 1);
app.use(
  helmet({
    contentSecurityPolicy: false,
    crossOriginEmbedderPolicy: false,
  })
);
app.use(cookieParser());
app.use(express.json({ limit: "1mb" }));
app.use(express.static("public"));
app.use("/uploads", express.static(UPLOADS_DIR));

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 50,
  standardHeaders: true,
  legacyHeaders: false,
  message: { message: "Too many auth attempts. Try again later." },
});

const signToken = (user) =>
  jwt.sign(
    { sub: user.id, username: user.username, name: user.name, role: user.role },
    JWT_SECRET,
    { expiresIn: "1d" }
  );

const setAuthCookie = (res, token) => {
  res.cookie(AUTH_COOKIE, token, {
    httpOnly: true,
    sameSite: "lax",
    secure: false,
    maxAge: 24 * 60 * 60 * 1000,
  });
};

const clearAuthCookie = (res) => {
  res.clearCookie(AUTH_COOKIE, { httpOnly: true, sameSite: "lax", secure: false });
};

const requireAuth = async (req, res, next) => {
  try {
    const token = req.cookies[AUTH_COOKIE];
    if (!token) return res.status(401).json({ message: "Authentication required." });
    const payload = jwt.verify(token, JWT_SECRET);
    const user = await get("SELECT id, username, name, role, bio, profile_image FROM users WHERE id = ?", [payload.sub]);
    if (!user) return res.status(401).json({ message: "Invalid session." });
    req.user = user;
    return next();
  } catch (_error) {
    return res.status(401).json({ message: "Invalid session." });
  }
};

const requireAdmin = (req, res, next) => {
  if (!req.user || req.user.role !== "admin") {
    return res.status(403).json({ message: "Admin access required." });
  }
  return next();
};

const registerHandler = async (req, res) => {
  try {
    const name = sanitize(req.body.name);
    const username = sanitize(req.body.username).toLowerCase();
    const password = String(req.body.password || "");
    const role = req.body.role === "admin" ? "admin" : "student";
    const adminCode = sanitize(req.body.adminCode);

    if (!username || !password) {
      return res.status(400).json({ message: "Username and password are required." });
    }
    if (!/^[a-z0-9_.-]{3,30}$/.test(username)) {
      return res.status(400).json({ message: "Username must be 3-30 chars and use a-z, 0-9, _, -, ." });
    }
    if (password.length < 8) {
      return res.status(400).json({ message: "Password must be at least 8 characters." });
    }
    if (role === "admin" && adminCode !== ADMIN_INVITE) {
      return res.status(403).json({ message: "Invalid admin invite code." });
    }

    const existing = await get("SELECT id FROM users WHERE username = ?", [username]);
    if (existing) return res.status(409).json({ message: "Username already exists." });

    const hash = await bcrypt.hash(password, 12);
    const displayName = name || username;
    await run("INSERT INTO users (username, name, password_hash, role) VALUES (?, ?, ?, ?)", [
      username,
      displayName,
      hash,
      role,
    ]);
    return res.status(201).json({ message: "Registration successful." });
  } catch (error) {
    return res.status(500).json({ message: "Registration failed.", error: error.message });
  }
};

const loginHandler = async (req, res) => {
  try {
    const username = sanitize(req.body.username).toLowerCase();
    const password = String(req.body.password || "");
    if (!username || !password) {
      return res.status(400).json({ message: "Username and password are required." });
    }
    const user = await get("SELECT * FROM users WHERE username = ?", [username]);
    if (!user) return res.status(401).json({ message: "Invalid credentials." });

    const matches = await bcrypt.compare(password, user.password_hash);
    if (!matches) return res.status(401).json({ message: "Invalid credentials." });

    const safeUser = {
      id: user.id,
      username: user.username,
      name: user.name,
      role: user.role,
      bio: user.bio || "",
      profile_image: user.profile_image || "",
    };
    const token = signToken(safeUser);
    setAuthCookie(res, token);
    return res.json({ message: "Login successful.", user: safeUser });
  } catch (error) {
    return res.status(500).json({ message: "Login failed.", error: error.message });
  }
};

const logoutHandler = (_req, res) => {
  clearAuthCookie(res);
  res.json({ message: "Logged out." });
};

app.post("/api/auth/register", authLimiter, registerHandler);
app.post("/api/auth/login", authLimiter, loginHandler);
app.post("/api/auth/logout", logoutHandler);

app.get("/api/auth/me", requireAuth, (req, res) => {
  res.json(req.user);
});

app.get("/api/profile", requireAuth, async (req, res) => {
  try {
    const profile = await get(
      "SELECT id, username, name, role, bio, profile_image, created_at FROM users WHERE id = ?",
      [req.user.id]
    );
    if (!profile) return res.status(404).json({ message: "Profile not found." });
    res.json(profile);
  } catch (error) {
    res.status(500).json({ message: "Could not load profile.", error: error.message });
  }
});

app.put("/api/profile", requireAuth, async (req, res) => {
  try {
    const name = sanitize(req.body.name);
    const bio = sanitize(req.body.bio);
    if (!name) return res.status(400).json({ message: "Name is required." });
    await run("UPDATE users SET name = ?, bio = ? WHERE id = ?", [name, bio, req.user.id]);
    res.json({ message: "Profile updated." });
  } catch (error) {
    res.status(500).json({ message: "Could not update profile.", error: error.message });
  }
});

app.post("/api/profile/avatar", requireAuth, avatarUpload.single("avatar"), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ message: "Avatar file is required." });
    const existing = await get("SELECT profile_image FROM users WHERE id = ?", [req.user.id]);
    if (existing && existing.profile_image) {
      const oldPath = path.join(__dirname, existing.profile_image.replace(/^\//, ""));
      if (fs.existsSync(oldPath)) fs.unlinkSync(oldPath);
    }
    const relativePath = `/uploads/avatars/${path.basename(req.file.path)}`;
    await run("UPDATE users SET profile_image = ? WHERE id = ?", [relativePath, req.user.id]);
    res.json({ message: "Avatar updated.", profile_image: relativePath });
  } catch (error) {
    res.status(500).json({ message: "Could not upload avatar.", error: error.message });
  }
});

// Legacy compatibility routes
app.post("/signup", authLimiter, registerHandler);
app.post("/login", authLimiter, loginHandler);
app.get("/user", requireAuth, (req, res) => res.json(req.user));
app.get("/logout", (_req, res) => {
  clearAuthCookie(res);
  res.redirect("/login.html");
});

app.get("/dashboard", (_req, res) => {
  res.sendFile(path.join(__dirname, "public", "dashboard.html"));
});

app.get("/api/topics", requireAuth, async (_req, res) => {
  try {
    const rows = await all(`
      SELECT t.id, t.title, t.description, t.created_at, t.created_by AS created_by_id, u.username AS created_by
      FROM topics t
      JOIN users u ON u.id = t.created_by
      ORDER BY t.created_at DESC
    `);
    res.json(rows);
  } catch (error) {
    res.status(500).json({ message: "Could not fetch topics.", error: error.message });
  }
});

app.post("/api/topics", requireAuth, async (req, res) => {
  try {
    const title = sanitize(req.body.title);
    const description = sanitize(req.body.description);
    if (!title) return res.status(400).json({ message: "Topic title is required." });
    await run("INSERT INTO topics (title, description, created_by) VALUES (?, ?, ?)", [
      title,
      description,
      req.user.id,
    ]);
    res.status(201).json({ message: "Topic created." });
  } catch (error) {
    res.status(500).json({ message: "Could not create topic.", error: error.message });
  }
});

app.put("/api/topics/:id", requireAuth, async (req, res) => {
  try {
    const topicId = Number(req.params.id);
    const title = sanitize(req.body.title);
    const description = sanitize(req.body.description);
    if (!topicId || !title) return res.status(400).json({ message: "Valid topic id and title are required." });
    const topic = await get("SELECT id, created_by FROM topics WHERE id = ?", [topicId]);
    if (!topic) return res.status(404).json({ message: "Topic not found." });
    if (!canManage(topic.created_by, req.user)) return res.status(403).json({ message: "Not allowed to edit this topic." });
    await run("UPDATE topics SET title = ?, description = ? WHERE id = ?", [title, description, topicId]);
    res.json({ message: "Topic updated." });
  } catch (error) {
    res.status(500).json({ message: "Could not update topic.", error: error.message });
  }
});

app.delete("/api/topics/:id", requireAuth, async (req, res) => {
  try {
    const topicId = Number(req.params.id);
    if (!topicId) return res.status(400).json({ message: "Valid topic id is required." });
    const topic = await get("SELECT id, created_by FROM topics WHERE id = ?", [topicId]);
    if (!topic) return res.status(404).json({ message: "Topic not found." });
    if (!canManage(topic.created_by, req.user)) return res.status(403).json({ message: "Not allowed to delete this topic." });
    await run("DELETE FROM topics WHERE id = ?", [topicId]);
    res.json({ message: "Topic deleted." });
  } catch (error) {
    res.status(500).json({ message: "Could not delete topic.", error: error.message });
  }
});

app.get("/api/discussions", requireAuth, async (req, res) => {
  try {
    const topicId = Number(req.query.topicId);
    if (!topicId) return res.status(400).json({ message: "topicId is required." });
    const rows = await all(
      `SELECT p.id, p.content, p.created_at, p.user_id, u.username
       FROM discussion_posts p JOIN users u ON u.id = p.user_id
       WHERE p.topic_id = ? ORDER BY p.created_at ASC`,
      [topicId]
    );
    res.json(rows);
  } catch (error) {
    res.status(500).json({ message: "Could not fetch discussions.", error: error.message });
  }
});

app.post("/api/discussions", requireAuth, async (req, res) => {
  try {
    const topicId = Number(req.body.topicId);
    const content = sanitize(req.body.content);
    if (!topicId || !content) return res.status(400).json({ message: "topicId and content are required." });
    const topic = await get("SELECT id FROM topics WHERE id = ?", [topicId]);
    if (!topic) return res.status(404).json({ message: "Topic not found." });
    await run("INSERT INTO discussion_posts (topic_id, user_id, content) VALUES (?, ?, ?)", [
      topicId,
      req.user.id,
      content,
    ]);
    res.status(201).json({ message: "Message posted." });
  } catch (error) {
    res.status(500).json({ message: "Could not post message.", error: error.message });
  }
});

app.put("/api/discussions/:id", requireAuth, async (req, res) => {
  try {
    const postId = Number(req.params.id);
    const content = sanitize(req.body.content);
    if (!postId || !content) return res.status(400).json({ message: "Valid post id and content are required." });
    const post = await get("SELECT id, user_id FROM discussion_posts WHERE id = ?", [postId]);
    if (!post) return res.status(404).json({ message: "Discussion post not found." });
    if (!canManage(post.user_id, req.user)) return res.status(403).json({ message: "Not allowed to edit this message." });
    await run("UPDATE discussion_posts SET content = ? WHERE id = ?", [content, postId]);
    res.json({ message: "Message updated." });
  } catch (error) {
    res.status(500).json({ message: "Could not update message.", error: error.message });
  }
});

app.delete("/api/discussions/:id", requireAuth, async (req, res) => {
  try {
    const postId = Number(req.params.id);
    if (!postId) return res.status(400).json({ message: "Valid post id is required." });
    const post = await get("SELECT id, user_id FROM discussion_posts WHERE id = ?", [postId]);
    if (!post) return res.status(404).json({ message: "Discussion post not found." });
    if (!canManage(post.user_id, req.user)) return res.status(403).json({ message: "Not allowed to delete this message." });
    await run("DELETE FROM discussion_posts WHERE id = ?", [postId]);
    res.json({ message: "Message deleted." });
  } catch (error) {
    res.status(500).json({ message: "Could not delete message.", error: error.message });
  }
});

app.get("/api/broadcasts", requireAuth, async (_req, res) => {
  try {
    const rows = await all(`
      SELECT b.id, b.title, b.message, b.created_at, b.created_by AS created_by_id, u.username AS created_by
      FROM broadcasts b
      JOIN users u ON u.id = b.created_by
      ORDER BY b.created_at DESC
    `);
    res.json(rows);
  } catch (error) {
    res.status(500).json({ message: "Could not fetch broadcasts.", error: error.message });
  }
});

app.post("/api/broadcasts", requireAuth, requireAdmin, async (req, res) => {
  try {
    const title = sanitize(req.body.title);
    const message = sanitize(req.body.message);
    if (!title || !message) return res.status(400).json({ message: "title and message are required." });
    await run("INSERT INTO broadcasts (title, message, created_by) VALUES (?, ?, ?)", [
      title,
      message,
      req.user.id,
    ]);
    res.status(201).json({ message: "Broadcast published." });
  } catch (error) {
    res.status(500).json({ message: "Could not publish broadcast.", error: error.message });
  }
});

app.put("/api/broadcasts/:id", requireAuth, requireAdmin, async (req, res) => {
  try {
    const broadcastId = Number(req.params.id);
    const title = sanitize(req.body.title);
    const message = sanitize(req.body.message);
    if (!broadcastId || !title || !message) {
      return res.status(400).json({ message: "Valid id, title and message are required." });
    }
    const existing = await get("SELECT id FROM broadcasts WHERE id = ?", [broadcastId]);
    if (!existing) return res.status(404).json({ message: "Broadcast not found." });
    await run("UPDATE broadcasts SET title = ?, message = ? WHERE id = ?", [title, message, broadcastId]);
    res.json({ message: "Broadcast updated." });
  } catch (error) {
    res.status(500).json({ message: "Could not update broadcast.", error: error.message });
  }
});

app.delete("/api/broadcasts/:id", requireAuth, requireAdmin, async (req, res) => {
  try {
    const broadcastId = Number(req.params.id);
    if (!broadcastId) return res.status(400).json({ message: "Valid id is required." });
    const existing = await get("SELECT id FROM broadcasts WHERE id = ?", [broadcastId]);
    if (!existing) return res.status(404).json({ message: "Broadcast not found." });
    await run("DELETE FROM broadcasts WHERE id = ?", [broadcastId]);
    res.json({ message: "Broadcast deleted." });
  } catch (error) {
    res.status(500).json({ message: "Could not delete broadcast.", error: error.message });
  }
});

app.get("/api/assignments", requireAuth, async (_req, res) => {
  try {
    const rows = await all(`
      SELECT a.id, a.title, a.file_name, a.file_path, a.created_at, a.uploaded_by AS uploaded_by_id, u.username AS uploaded_by
      FROM assignments a
      JOIN users u ON u.id = a.uploaded_by
      ORDER BY a.created_at DESC
    `);
    res.json(rows);
  } catch (error) {
    res.status(500).json({ message: "Could not fetch assignments.", error: error.message });
  }
});

app.post("/api/assignments", requireAuth, upload.single("file"), async (req, res) => {
  try {
    const title = sanitize(req.body.title);
    if (!title || !req.file) return res.status(400).json({ message: "title and file are required." });
    await run("INSERT INTO assignments (title, file_name, file_path, uploaded_by) VALUES (?, ?, ?, ?)", [
      title,
      req.file.originalname,
      req.file.path,
      req.user.id,
    ]);
    res.status(201).json({ message: "Assignment uploaded." });
  } catch (error) {
    res.status(500).json({ message: "Could not upload assignment.", error: error.message });
  }
});

app.put("/api/assignments/:id", requireAuth, async (req, res) => {
  try {
    const assignmentId = Number(req.params.id);
    const title = sanitize(req.body.title);
    if (!assignmentId || !title) return res.status(400).json({ message: "Valid id and title are required." });
    const assignment = await get("SELECT id, uploaded_by FROM assignments WHERE id = ?", [assignmentId]);
    if (!assignment) return res.status(404).json({ message: "Assignment not found." });
    if (!canManage(assignment.uploaded_by, req.user)) return res.status(403).json({ message: "Not allowed to edit this assignment." });
    await run("UPDATE assignments SET title = ? WHERE id = ?", [title, assignmentId]);
    res.json({ message: "Assignment title updated." });
  } catch (error) {
    res.status(500).json({ message: "Could not update assignment.", error: error.message });
  }
});

app.delete("/api/assignments/:id", requireAuth, async (req, res) => {
  try {
    const assignmentId = Number(req.params.id);
    if (!assignmentId) return res.status(400).json({ message: "Valid id is required." });
    const assignment = await get("SELECT id, file_path, uploaded_by FROM assignments WHERE id = ?", [assignmentId]);
    if (!assignment) return res.status(404).json({ message: "Assignment not found." });
    if (!canManage(assignment.uploaded_by, req.user)) return res.status(403).json({ message: "Not allowed to delete this assignment." });
    await run("DELETE FROM assignments WHERE id = ?", [assignmentId]);
    if (assignment.file_path && fs.existsSync(assignment.file_path)) fs.unlinkSync(assignment.file_path);
    res.json({ message: "Assignment deleted." });
  } catch (error) {
    res.status(500).json({ message: "Could not delete assignment.", error: error.message });
  }
});

app.get("/api/assignments/:id/download", requireAuth, async (req, res) => {
  try {
    const assignment = await get("SELECT * FROM assignments WHERE id = ?", [Number(req.params.id)]);
    if (!assignment) return res.status(404).json({ message: "Assignment not found." });
    res.download(assignment.file_path, assignment.file_name);
  } catch (error) {
    res.status(500).json({ message: "Could not download assignment.", error: error.message });
  }
});

app.use((err, _req, res, _next) => {
  if (err instanceof multer.MulterError) {
    return res.status(400).json({ message: "File upload failed.", error: err.message });
  }
  return res.status(500).json({ message: "Unexpected error.", error: err.message });
});

initDb()
  .then(() => {
    app.listen(PORT, () => console.log(`Running on http://localhost:${PORT}`));
  })
  .catch((error) => {
    console.error("Failed to initialize DB:", error);
    process.exit(1);
  });