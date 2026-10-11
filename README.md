# Our Family Home

A private family portal built with Node.js, Express, SQLite and a responsive frontend.

## Features
- Persistent sign-in cookie (up to 30 days) and SQLite-backed sessions
- Admin-only account approval, member role management and password reset requests
- Admin announcements, pinning and family-space settings
- Family group chat (messages are stored and refresh on page visits/sends)
- Family calendar, cookbook, memories, shared to-do list and polls
- Password hashing, login rate limiting, security headers and server-side role checks

## Run locally
1. Install Node.js 20 or newer.
2. Copy `.env.example` to `.env`.
3. Set a strong `ADMIN_PASSWORD` and a long random `SESSION_SECRET` in `.env` before the first run.
4. Install dependencies and start:
   ```bash
   npm install
   npm start
   ```
5. Visit `http://localhost:3000`.

If you do not set `ADMIN_PASSWORD`, the first run creates the admin account `admin` with the temporary password `admin`. Change it immediately in **My settings**. The initial admin is only created if that username doesn't already exist in the database; changing `.env` later does not reset an existing admin password.

## Account flow
- Family members use **Request an account**. The admin approves the request in **Admin studio**.
- Forgot-password requests appear in **Admin studio**. The admin sets a temporary password and must share it privately with the member; this project does not send email or SMS.
- The admin can promote trusted members to admin or remove accounts.

## Deployment notes
- This is a starter project, not a hosted website. You must deploy it to a Node.js host to make it available outside your computer.
- Use HTTPS in production and set `NODE_ENV=production`, `SESSION_SECRET`, and `ADMIN_PASSWORD` securely. Keep the `data/` folder persistent and backed up.
- The default admin password `admin` is for local first-run convenience only and is not safe for public deployment.
- Family pages require sign-in, but use HTTPS and a trusted host before entering private family information.
- Chat currently refreshes when the page is loaded or after sending; it does not use WebSockets for instant live updates.
- Memories support an HTTPS image URL; direct image uploads, email delivery, and external social logins are not included in this version.
