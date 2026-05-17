# Hacker vs System

A cybersecurity education web application built with Flask that simulates real-world vulnerabilities in a hacker-themed interface. This is a full interactive simulation platform with live flow visualizations, security scoring, brute-force simulation, and learning panels throughout.

## Architecture

- **Backend**: Python 3.11 + Flask
- **Database**: SQLite (`hacker_vs_system.db`)
- **Frontend**: HTML/CSS/Bootstrap + custom hacker-themed CSS
- **Port**: 5000 (0.0.0.0)
- **Dependencies**: Flask, bcrypt, PyJWT, gunicorn

## Project Structure

```
main.py                   # Full backend — all routes, APIs, security logic
requirements.txt          # Python dependencies
hacker_vs_system.db       # SQLite database (auto-created)
templates/
  base.html               # Base layout with nav, loading screen
  login.html              # Login with attempt meter, brute-force sim, escalation detection
  register.html           # Registration with secure/insecure modes
  dashboard.html          # SOC dashboard with security score circle, live logs
  levels.html             # Mission selection (8 vulnerability levels)
  admin.html              # Admin panel (RBAC demo, user management)
  access_denied.html      # 403 page
  security_dashboard.html # SecOps dashboard (mod/admin only)
  parameter_tamper.html   # Level 3: parameter tampering demo
  session_demo.html       # Level 4: session hijacking + timeline + actor panels
  api_lab.html            # Level 8: JWT lab, API tester, token breakdown
  rbac_demo.html          # Level 2: role source comparison, permission matrix
  xss_demo.html           # Level 5: XSS injection, flow steps, payload samples
  sqli_demo.html          # Level 6: SQL injection, query flow, live results
  csrf_demo.html          # Level 7: CSRF flow visualization, victim vs attacker
  crypto_lab.html         # Crypto lab: bcrypt, Caesar, Base64, JWT, rainbow table
static/
  css/style.css           # Full hacker-themed stylesheet (all component classes)
  js/main.js              # Loading screen, matrix rain, toggleLearn, score animations
```

## Features

### Security Simulation Levels
- **Level 1** — Weak Authentication: plain text vs bcrypt + lockout + CSRF
- **Level 2** — Broken Access Control (RBAC): cookie role vs server-side session role vs DB role
- **Level 3** — Parameter Tampering: no validation vs range/type checks
- **Level 4** — Session Hijacking: cookie flags, IP binding, session timeline
- **Level 5** — XSS: reflected injection, flow steps, payload samples
- **Level 6** — SQL Injection: string concat vs parameterized queries, live query flow
- **Level 7** — CSRF: victim vs attacker panels, token validation flow
- **Level 8** — API Security: JWT structure breakdown, bypass tokens, live API tester

### Core Security Features
- **Account Lockout**: 3 failed attempts → 15-minute lockout (secure mode)
- **Brute-Force Simulation**: `/api/brute-force` — live log of each password attempt
- **CSRF Protection**: Token generated per session, validated on every POST
- **RBAC**: 4-tier role hierarchy (guest/user/moderator/admin) with permission sets
- **Escalation Detection**: Switching insecure→secure restores DB role, logs tamper
- **Security Score**: Live 0–100 score based on mode, recent danger events, lockouts
- **Session IP Binding**: Secure mode binds session to login IP; mismatch invalidates
- **JWT API Lab**: Full token issuance, signature verification, bypass tokens in attack mode

### UI/UX
- Dark cybersecurity theme (`#0a0a0f`, neon green `#00ff88`, red `#ff2244`, blue `#00aaff`)
- Monospace fonts throughout
- Animated loading screen with matrix rain on auth pages
- Glitch effects, scanline overlay, pulse animations
- SVG security score circle with animated fill
- Flow-step visualizations on every exploit demo
- Collapsible learning panels on every level
- Live log streaming on dashboard (5s auto-refresh)

### API Endpoints
- `GET  /api/logs`              — Recent security logs (JSON)
- `GET  /api/anomalies`         — Threat anomaly feed
- `GET  /api/security-score`    — Security score calculation
- `POST /api/token`             — Issue JWT (secure) or weak token (insecure)
- `GET  /api/protected`         — JWT-protected endpoint demo
- `GET  /api/stats`             — System stats
- `POST /api/brute-force`       — Brute-force simulation
- `POST /api/crypto`            — Interactive crypto operations

### Routes
- `/`                           → redirects to login
- `/login`                      → login page
- `/register`                   → registration
- `/dashboard`                  → SOC control panel with security score
- `/admin`                      → admin panel (admin only)
- `/levels`                     → mission selection
- `/security-dashboard`         → SecOps view (mod/admin)
- `/toggle-mode`                → POST — switch secure/insecure
- `/exploit/parameter-tamper`   → Level 3 demo
- `/exploit/xss-demo`           → Level 5 demo
- `/exploit/sqli-demo`          → Level 6 demo
- `/exploit/csrf-demo`          → Level 7 demo
- `/exploit/rbac-demo`          → Level 2 demo
- `/exploit/session-demo`       → Level 4 demo
- `/crypto-lab`                 → Crypto lab
- `/api-lab`                    → API/JWT lab
- `/logout`                     → clears session

## Default Credentials
- Admin: `admin` / `admin123`
- Moderator: `moderator` / `mod123`
- Demo user: `demo` / `demo123`

## Running
```bash
python -m gunicorn --bind 0.0.0.0:5000 --reuse-port --reload main:app
```

## User Preferences
- Keep dark hacker/cyberpunk theme — never change color palette
- All templates extend `base.html`
- Use `toggleLearn()` for collapsible learning panels
- CSRF tokens always present on POST forms in secure mode
- Never use Flask-SQLAlchemy — use raw sqlite3 with `get_db()`
