"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const { DatabaseSync } = require("node:sqlite");
const express = require("express");
const helmet = require("helmet");
const { rateLimit } = require("express-rate-limit");

const PORT = Number(process.env.PORT || 3000);
const SESSION_DAYS = 30;
const SESSION_COOKIE = "gfg_session";
const DB_PATH = path.resolve(process.env.DB_PATH || path.join(__dirname, "data", "app.sqlite"));

fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });
const db = new DatabaseSync(DB_PATH);
db.exec("PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON;");

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    email TEXT NOT NULL COLLATE NOCASE UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'learner' CHECK (role IN ('learner', 'admin')),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at INTEGER NOT NULL
  );
  CREATE INDEX IF NOT EXISTS sessions_expiry_idx ON sessions(expires_at);
  CREATE TABLE IF NOT EXISTS courses (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT NOT NULL,
    duration TEXT NOT NULL,
    syllabus_json TEXT NOT NULL DEFAULT '[]',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS enrollments (
    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    course_id INTEGER NOT NULL REFERENCES courses(id) ON DELETE CASCADE,
    enrolled_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(user_id, course_id)
  );
  CREATE TABLE IF NOT EXISTS bookmarks (
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    article_id INTEGER NOT NULL CHECK (article_id > 0),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY(user_id, article_id)
  );
  CREATE TABLE IF NOT EXISTS newsletter_subscribers (
    email TEXT PRIMARY KEY COLLATE NOCASE,
    subscribed_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS quizzes (
    id INTEGER PRIMARY KEY,
    title TEXT NOT NULL,
    category TEXT NOT NULL,
    questions_json TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS quiz_attempts (
    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    quiz_id INTEGER NOT NULL REFERENCES quizzes(id) ON DELETE CASCADE,
    score INTEGER NOT NULL,
    total INTEGER NOT NULL,
    attempted_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );
`);

const seedCourses = [
  ["DSA to Development", "Beginner-friendly structured problem solving and projects.", "16 weeks", ["Arrays and strings", "Trees and graphs", "Dynamic programming", "Development project"]],
  ["Full Stack Web Development", "Build production-style applications from frontend to backend.", "20 weeks", ["HTML, CSS, and JavaScript", "React fundamentals", "Node.js and REST APIs", "Database-backed project"]],
  ["System Design Masterclass", "Learn scalable architecture and distributed systems.", "8 weeks", ["Requirements and estimation", "Caching and databases", "Queues and reliability", "Architecture case studies"]],
  ["Machine Learning Foundations", "Learn practical machine learning using Python.", "12 weeks", ["Python data tools", "Supervised learning", "Model evaluation", "End-to-end project"]]
];
const insertCourse = db.prepare(`
  INSERT OR IGNORE INTO courses (id, name, description, duration, syllabus_json)
  VALUES (?, ?, ?, ?, ?)
`);
seedCourses.forEach((course, index) => {
  insertCourse.run(index + 1, ...course.slice(0, 3), JSON.stringify(course[3]));
});

const seedQuizzes = [
  {
    id: 1,
    title: "DSA Fundamentals",
    category: "DSA",
    questions: [
      { prompt: "What is the time complexity of binary search on a sorted array?", options: ["O(n)", "O(log n)", "O(n log n)", "O(1)"], answer: 1 },
      { prompt: "Which data structure follows LIFO order?", options: ["Queue", "Heap", "Stack", "Graph"], answer: 2 },
      { prompt: "Which traversal of a binary search tree yields sorted values?", options: ["Preorder", "Inorder", "Postorder", "Level order"], answer: 1 }
    ]
  },
  {
    id: 2,
    title: "Web Development Basics",
    category: "Web Dev",
    questions: [
      { prompt: "Which HTTP method is commonly used to retrieve a resource?", options: ["GET", "PATCH", "DELETE", "POST"], answer: 0 },
      { prompt: "Which CSS layout system is designed for two-dimensional layouts?", options: ["Float", "Grid", "Inline", "Position"], answer: 1 },
      { prompt: "What does JSON stand for?", options: ["Java Syntax Object Notation", "JavaScript Object Notation", "Joined Standard Object Names", "Java Serialized Output Network"], answer: 1 }
    ]
  }
];
const insertQuiz = db.prepare(`
  INSERT OR IGNORE INTO quizzes (id, title, category, questions_json)
  VALUES (?, ?, ?, ?)
`);
seedQuizzes.forEach((quiz) => {
  insertQuiz.run(quiz.id, quiz.title, quiz.category, JSON.stringify(quiz.questions));
});

function hashToken(token) {
  return crypto.createHash("sha256").update(token).digest("hex");
}

function createPasswordHash(password) {
  const salt = crypto.randomBytes(16).toString("hex");
  return new Promise((resolve, reject) => {
    crypto.scrypt(password, salt, 64, (error, derivedKey) => {
      if (error) return reject(error);
      resolve(`${salt}:${derivedKey.toString("hex")}`);
    });
  });
}

function checkPassword(password, storedHash) {
  const [salt, hash] = storedHash.split(":");
  if (!salt || !hash) return false;
  return new Promise((resolve, reject) => {
    crypto.scrypt(password, salt, 64, (error, derivedKey) => {
      if (error) return reject(error);
      const actual = Buffer.from(hash, "hex");
      resolve(actual.length === derivedKey.length && crypto.timingSafeEqual(actual, derivedKey));
    });
  });
}

function setSessionCookie(res, token, maxAgeSeconds) {
  const flags = [
    `${SESSION_COOKIE}=${encodeURIComponent(token)}`,
    "Path=/",
    "HttpOnly",
    "SameSite=Lax",
    `Max-Age=${maxAgeSeconds}`
  ];
  if (process.env.NODE_ENV === "production") flags.push("Secure");
  res.setHeader("Set-Cookie", flags.join("; "));
}

function readCookie(req, name) {
  const cookieHeader = req.headers.cookie || "";
  for (const part of cookieHeader.split(";")) {
    const separator = part.indexOf("=");
    if (separator < 0) continue;
    if (part.slice(0, separator).trim() === name) {
      return part.slice(separator + 1).trim();
    }
  }
  return null;
}

function publicUser(user) {
  return { id: user.id, email: user.email, role: user.role };
}

function requireAuth(req, res, next) {
  const token = readCookie(req, SESSION_COOKIE);
  if (!token) return res.status(401).json({ error: "Sign in to continue." });
  const session = db.prepare(`
    SELECT users.id, users.email, users.role
    FROM sessions JOIN users ON users.id = sessions.user_id
    WHERE sessions.token_hash = ? AND sessions.expires_at > ?
  `).get(hashToken(token), Date.now());
  if (!session) return res.status(401).json({ error: "Your session has expired. Please sign in again." });
  req.user = session;
  next();
}

function requireAdmin(req, res, next) {
  if (req.user.role !== "admin") return res.status(403).json({ error: "Administrator access is required." });
  next();
}

function validateEmail(value) {
  return typeof value === "string" && value.trim().length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value.trim());
}

function validateCourseInput(body) {
  const { name, description, duration, syllabus } = body;
  if (typeof name !== "string" || !name.trim() ||
      typeof description !== "string" || !description.trim() ||
      typeof duration !== "string" || !duration.trim() ||
      (syllabus !== undefined && (!Array.isArray(syllabus) || syllabus.some((item) => typeof item !== "string")))) {
    return null;
  }
  return {
    name: name.trim(),
    description: description.trim(),
    duration: duration.trim(),
    syllabus: JSON.stringify(syllabus || [])
  };
}

const app = express();
app.disable("x-powered-by");
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: "32kb" }));
app.use((req, _res, next) => {
  if (!req.body || typeof req.body !== "object" || Array.isArray(req.body)) req.body = {};
  next();
});
app.use("/api/auth", rateLimit({ windowMs: 15 * 60 * 1000, limit: 30, standardHeaders: "draft-7", legacyHeaders: false }));

app.get("/api/health", (_req, res) => res.json({ status: "ok" }));

app.post("/api/auth/register", async (req, res) => {
  const email = typeof req.body.email === "string" ? req.body.email.trim().toLowerCase() : "";
  const password = req.body.password;
  if (!validateEmail(email)) return res.status(400).json({ error: "Enter a valid email address." });
  if (typeof password !== "string" || password.length < 8 || password.length > 128) {
    return res.status(400).json({ error: "Password must be between 8 and 128 characters." });
  }
  const result = db.prepare("INSERT INTO users (email, password_hash) VALUES (?, ?)").run(email, await createPasswordHash(password));
  const user = db.prepare("SELECT id, email, role FROM users WHERE id = ?").get(result.lastInsertRowid);
  const token = crypto.randomBytes(32).toString("base64url");
  const expiresAt = Date.now() + SESSION_DAYS * 24 * 60 * 60 * 1000;
  db.prepare("INSERT INTO sessions (token_hash, user_id, expires_at) VALUES (?, ?, ?)").run(hashToken(token), user.id, expiresAt);
  setSessionCookie(res, token, SESSION_DAYS * 24 * 60 * 60);
  res.status(201).json({ user: publicUser(user) });
});

app.post("/api/auth/login", async (req, res) => {
  const email = typeof req.body.email === "string" ? req.body.email.trim().toLowerCase() : "";
  const password = req.body.password;
  if (!validateEmail(email) || typeof password !== "string") {
    return res.status(400).json({ error: "Enter a valid email address and password." });
  }
  const user = db.prepare("SELECT id, email, password_hash, role FROM users WHERE email = ?").get(email);
  if (!user || !(await checkPassword(password, user.password_hash))) {
    return res.status(401).json({ error: "Email or password is incorrect." });
  }
  const token = crypto.randomBytes(32).toString("base64url");
  const expiresAt = Date.now() + SESSION_DAYS * 24 * 60 * 60 * 1000;
  db.prepare("INSERT INTO sessions (token_hash, user_id, expires_at) VALUES (?, ?, ?)").run(hashToken(token), user.id, expiresAt);
  setSessionCookie(res, token, SESSION_DAYS * 24 * 60 * 60);
  res.json({ user: publicUser(user) });
});

app.post("/api/auth/logout", (req, res) => {
  const token = readCookie(req, SESSION_COOKIE);
  if (token) db.prepare("DELETE FROM sessions WHERE token_hash = ?").run(hashToken(token));
  setSessionCookie(res, "", 0);
  res.json({ success: true });
});

app.get("/api/auth/me", requireAuth, (req, res) => res.json({ user: publicUser(req.user) }));

app.get("/api/courses", (_req, res) => {
  const courses = db.prepare("SELECT id, name, description, duration, syllabus_json FROM courses ORDER BY id").all()
    .map((course) => ({ ...course, syllabus: JSON.parse(course.syllabus_json) }));
  res.json({ courses });
});

app.post("/api/courses/:courseId/enroll", requireAuth, (req, res) => {
  const courseId = Number(req.params.courseId);
  if (!Number.isSafeInteger(courseId) || courseId < 1) return res.status(400).json({ error: "Invalid course ID." });
  const course = db.prepare("SELECT id, name FROM courses WHERE id = ?").get(courseId);
  if (!course) return res.status(404).json({ error: "Course not found." });
  db.prepare("INSERT OR IGNORE INTO enrollments (user_id, course_id) VALUES (?, ?)").run(req.user.id, courseId);
  res.status(200).json({ course });
});

app.get("/api/me/courses", requireAuth, (req, res) => {
  const courses = db.prepare(`
    SELECT courses.id, courses.name, courses.description, courses.duration, enrollments.enrolled_at
    FROM enrollments JOIN courses ON courses.id = enrollments.course_id
    WHERE enrollments.user_id = ? ORDER BY enrollments.enrolled_at DESC
  `).all(req.user.id);
  res.json({ courses });
});

app.get("/api/me/bookmarks", requireAuth, (req, res) => {
  const bookmarks = db.prepare("SELECT article_id FROM bookmarks WHERE user_id = ? ORDER BY created_at DESC")
    .all(req.user.id).map((row) => row.article_id);
  res.json({ articleIds: bookmarks });
});

app.post("/api/me/bookmarks/:articleId", requireAuth, (req, res) => {
  const articleId = Number(req.params.articleId);
  if (!Number.isSafeInteger(articleId) || articleId < 1) return res.status(400).json({ error: "Invalid article ID." });
  db.prepare("INSERT OR IGNORE INTO bookmarks (user_id, article_id) VALUES (?, ?)").run(req.user.id, articleId);
  res.status(201).json({ articleId, saved: true });
});

app.delete("/api/me/bookmarks/:articleId", requireAuth, (req, res) => {
  const articleId = Number(req.params.articleId);
  if (!Number.isSafeInteger(articleId) || articleId < 1) return res.status(400).json({ error: "Invalid article ID." });
  db.prepare("DELETE FROM bookmarks WHERE user_id = ? AND article_id = ?").run(req.user.id, articleId);
  res.json({ articleId, saved: false });
});

app.post("/api/newsletter/subscribe", (req, res) => {
  const email = typeof req.body.email === "string" ? req.body.email.trim().toLowerCase() : "";
  if (!validateEmail(email)) return res.status(400).json({ error: "Enter a valid email address." });
  const result = db.prepare("INSERT OR IGNORE INTO newsletter_subscribers (email) VALUES (?)").run(email);
  res.status(result.changes ? 201 : 200).json({ success: true });
});

app.get("/api/quizzes", (_req, res) => {
  const quizzes = db.prepare("SELECT id, title, category, questions_json FROM quizzes ORDER BY id").all()
    .map((quiz) => ({
      id: quiz.id,
      title: quiz.title,
      category: quiz.category,
      questions: JSON.parse(quiz.questions_json).map(({ prompt, options }, index) => ({ id: index + 1, prompt, options }))
    }));
  res.json({ quizzes });
});

app.post("/api/quizzes/:quizId/attempts", requireAuth, (req, res) => {
  const quizId = Number(req.params.quizId);
  const quiz = db.prepare("SELECT id, title, questions_json FROM quizzes WHERE id = ?").get(quizId);
  if (!quiz) return res.status(404).json({ error: "Quiz not found." });
  const questions = JSON.parse(quiz.questions_json);
  const answers = req.body.answers;
  if (!Array.isArray(answers) || answers.length !== questions.length ||
      answers.some((answer, index) => !Number.isInteger(answer) || answer < 0 || answer >= questions[index].options.length)) {
    return res.status(400).json({ error: "Provide one valid option index for every question." });
  }
  const score = questions.reduce((total, question, index) => total + (answers[index] === question.answer ? 1 : 0), 0);
  db.prepare("INSERT INTO quiz_attempts (user_id, quiz_id, score, total) VALUES (?, ?, ?, ?)")
    .run(req.user.id, quizId, score, questions.length);
  res.status(201).json({ quizId, title: quiz.title, score, total: questions.length, percentage: Math.round((score / questions.length) * 100) });
});

app.get("/api/me/progress", requireAuth, (req, res) => {
  const coursesEnrolled = db.prepare("SELECT COUNT(*) AS count FROM enrollments WHERE user_id = ?").get(req.user.id).count;
  const attempts = db.prepare(`
    SELECT quiz_attempts.id, quiz_attempts.score, quiz_attempts.total, quiz_attempts.attempted_at,
      quizzes.id AS quiz_id, quizzes.title
    FROM quiz_attempts JOIN quizzes ON quizzes.id = quiz_attempts.quiz_id
    WHERE quiz_attempts.user_id = ? ORDER BY quiz_attempts.attempted_at DESC
  `).all(req.user.id);
  res.json({
    coursesEnrolled,
    quizzesAttempted: attempts.length,
    averageScore: attempts.length
      ? Math.round(attempts.reduce((sum, attempt) => sum + (attempt.score / attempt.total) * 100, 0) / attempts.length)
      : 0,
    attempts
  });
});

app.get("/api/admin/users", requireAuth, requireAdmin, (_req, res) => {
  const users = db.prepare("SELECT id, email, role, created_at FROM users ORDER BY id").all();
  res.json({ users });
});

app.post("/api/admin/courses", requireAuth, requireAdmin, (req, res) => {
  const course = validateCourseInput(req.body);
  if (!course) return res.status(400).json({ error: "Name, description, duration, and a string-array syllabus are required." });
  const result = db.prepare("INSERT INTO courses (name, description, duration, syllabus_json) VALUES (?, ?, ?, ?)")
    .run(course.name, course.description, course.duration, course.syllabus);
  res.status(201).json({ id: result.lastInsertRowid, ...course, syllabus: JSON.parse(course.syllabus) });
});

app.put("/api/admin/courses/:courseId", requireAuth, requireAdmin, (req, res) => {
  const courseId = Number(req.params.courseId);
  const course = validateCourseInput(req.body);
  if (!Number.isSafeInteger(courseId) || courseId < 1 || !course) {
    return res.status(400).json({ error: "Provide a valid course ID and course details." });
  }
  const result = db.prepare(`
    UPDATE courses SET name = ?, description = ?, duration = ?, syllabus_json = ? WHERE id = ?
  `).run(course.name, course.description, course.duration, course.syllabus, courseId);
  if (!result.changes) return res.status(404).json({ error: "Course not found." });
  res.json({ id: courseId, ...course, syllabus: JSON.parse(course.syllabus) });
});

app.delete("/api/admin/courses/:courseId", requireAuth, requireAdmin, (req, res) => {
  const courseId = Number(req.params.courseId);
  if (!Number.isSafeInteger(courseId) || courseId < 1) return res.status(400).json({ error: "Invalid course ID." });
  const result = db.prepare("DELETE FROM courses WHERE id = ?").run(courseId);
  if (!result.changes) return res.status(404).json({ error: "Course not found." });
  res.json({ success: true });
});

app.get("/", (_req, res) => res.sendFile(path.join(__dirname, "geeksforgeeks-clone.html")));
app.get("/geeksforgeeks-clone.html", (_req, res) => res.sendFile(path.join(__dirname, "geeksforgeeks-clone.html")));
app.use("/api", (_req, res) => res.status(404).json({ error: "API route not found." }));
app.use((error, _req, res, _next) => {
  if (error.errcode === 2067) {
    return res.status(409).json({ error: "An account with that email already exists." });
  }
  if (error instanceof SyntaxError && error.status === 400) {
    return res.status(400).json({ error: "Request body must contain valid JSON." });
  }
  console.error(error);
  res.status(500).json({ error: "An unexpected server error occurred." });
});

let server;
async function start() {
  const adminEmail = process.env.ADMIN_EMAIL;
  const adminPassword = process.env.ADMIN_PASSWORD;
  if (adminEmail || adminPassword) {
    if (!validateEmail(adminEmail) || typeof adminPassword !== "string" || adminPassword.length < 12) {
      throw new Error("Set both ADMIN_EMAIL and an ADMIN_PASSWORD of at least 12 characters.");
    }
    const adminHash = await createPasswordHash(adminPassword);
    db.prepare(`
      INSERT INTO users (email, password_hash, role) VALUES (?, ?, 'admin')
      ON CONFLICT(email) DO UPDATE SET password_hash = excluded.password_hash, role = 'admin'
    `).run(adminEmail.trim().toLowerCase(), adminHash);
  }
  server = app.listen(PORT, () => {
    console.log(`Learning portal server listening on http://localhost:${PORT}`);
  });
}

start().catch((error) => {
  console.error("Failed to start the learning portal server:", error);
  db.close();
  process.exitCode = 1;
});

function shutdown() {
  if (!server) {
    db.close();
    return;
  }
  server.close(() => {
    db.close();
    process.exit(0);
  });
}
process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);
