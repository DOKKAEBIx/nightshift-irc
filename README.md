# Nightshift server

A small real-time chat server with accounts, channels, live presence, pictures, reactions, pins, and admin tools.

## Run it

Requires Node.js 18 or newer.

    npm install
    ADMIN_USERS=yourname npm start

Open http://localhost:3000 and create an account. Accounts listed in `ADMIN_USERS` are admins, both now and when they register later.

To let other people on your network connect, give them your computer's local address, such as http://192.168.1.20:3000.

## Settings

| Variable      | Default | Purpose |
|---------------|---------|---------|
| PORT          | 3000    | Port to listen on |
| HOST          | 0.0.0.0 | Address to listen on (use 127.0.0.1 to keep it local) |
| ADMIN_USERS   | (none)  | Comma-separated admin usernames |
| TRUST_PROXY   | (off)   | Set to 1 only when behind your own reverse proxy, so the real client address is read from X-Forwarded-For |

## How it works

- Passwords are hashed with scrypt. Only a SHA-256 hash of each session token is stored.
- The session token lives in an HTTP-only, SameSite=Strict cookie, so page scripts cannot read it.
- Channel messages go only to people who have joined that channel. Others get an activity ping with no text.
- Admin actions (bans, clears, deletions) are written to `data/audit.log`.

## Data

Everything is in `data/`:

- `db.json`: accounts, sessions, channels, and messages. Created with owner-only permissions.
- `db.json.bak`: a backup, refreshed at most once an hour. The server restores from it if `db.json` is unreadable.
- `audit.log`: admin actions.

Back up the `data` folder regularly.

## Limits built in

- 5 failed logins for one account from one address locks that pair for a minute.
- 20 authentication requests per address per minute.
- 20 open connections per address.
- 4 password hashes at a time, to protect the CPU.
- 5,000 accounts, 50 channels, 500 messages per channel.
- Pictures: 30 uploads per user per hour, and about 110 MB of pictures in total.

## Before putting it on the internet

- Serve it over HTTPS with a reverse proxy such as Caddy or nginx, and set TRUST_PROXY=1 when you do.
- Keep the server's data folder private.
- This uses one JSON file, which suits a small group. For many users, move the data into a real database.
- There is no password reset or email verification yet.
