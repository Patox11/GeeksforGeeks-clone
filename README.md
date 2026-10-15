# Learning Portal Clone

This project runs as a Node.js web app with an Express API and a local SQLite database.

## Run locally

Install Node.js 22.5 or later, then run these commands from the project folder:

```powershell
npm.cmd install
npm.cmd start
```

Open <http://localhost:3000>. The SQLite database is created at `data/app.sqlite` on first launch. Set `PORT` to change the listening port or `DB_PATH` to store the database elsewhere.

To provision an administrator, set both environment variables before starting the server. The configured account is created or its password and role are updated each time the server starts with these values:

```powershell
$env:ADMIN_EMAIL = "admin@example.com"
$env:ADMIN_PASSWORD = "use-a-unique-password-of-at-least-12-characters"
npm.cmd start
```

User accounts are created through the sign-up form. Passwords are stored using Node's `scrypt`; sessions use random, HttpOnly cookies and are stored in SQLite. In production, serve the app over HTTPS and set `NODE_ENV=production` so session cookies use the `Secure` flag.

## API

All endpoints return JSON. The browser UI uses same-origin cookie sessions.

| Method | Endpoint | Access | Purpose |
| --- | --- | --- | --- |
| `GET` | `/api/health` | Public | Health check |
| `POST` | `/api/auth/register` | Public | Create an account (`email`, `password`) |
| `POST` | `/api/auth/login` | Public | Sign in (`email`, `password`) |
| `POST` | `/api/auth/logout` | Public | End the current session |
| `GET` | `/api/auth/me` | Signed in | Get the current account |
| `GET` | `/api/courses` | Public | List courses and syllabus |
| `POST` | `/api/courses/:courseId/enroll` | Signed in | Enroll in a course |
| `GET` | `/api/me/courses` | Signed in | List enrolled courses |
| `GET` | `/api/me/bookmarks` | Signed in | List saved article IDs |
| `POST` / `DELETE` | `/api/me/bookmarks/:articleId` | Signed in | Save or remove a bookmark |
| `POST` | `/api/newsletter/subscribe` | Public | Subscribe an email address |
| `GET` | `/api/quizzes` | Public | List quizzes without answer keys |
| `POST` | `/api/quizzes/:quizId/attempts` | Signed in | Submit option indexes in an `answers` array |
| `GET` | `/api/me/progress` | Signed in | View enrollment and quiz progress |
| `GET` | `/api/admin/users` | Admin | List account metadata |
| `POST`, `PUT`, `DELETE` | `/api/admin/courses[/:courseId]` | Admin | Manage courses |

Run the backend integration tests with `npm.cmd test`.
