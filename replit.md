# Hacker vs System

A cybersecurity education web application built with Flask that simulates real-world vulnerabilities in a hacker-themed interface.

## Architecture

- **Backend**: Python 3.11 + Flask
- **Database**: SQLite (`hacker_vs_system.db`)
- **Frontend**: HTML/CSS/Bootstrap + custom hacker-themed CSS
- **Port**: 5000 (0.0.0.0)

## Project Structure

```
app.py                  # Main Flask application
requirements.txt        # Python dependencies
hacker_vs_system.db     # SQLite database (auto-created)
templates/
  base.html             # Base layout with nav, loading screen
  login.html            # Login page with vulnerability demo
  register.html         # Registration with secure/insecure modes
  dashboard.html        # SOC-style dashboard
  levels.html           # Mission selection (4 vulnerability levels)
  admin.html            # Admin panel (RBAC demo)
  access_denied.html    # 403 page
  parameter_tamper.html # Level 3: parameter tampering demo
  session_demo.html     # Level 4: session hijacking demo
static/
  css/style.css         # Full hacker-themed stylesheet
  js/main.js            # Loading screen, matrix rain, typing effects
```

## Features

### Core Functionality
- **Authentication System**: Login/register with session management
- **Role-Based Access Control (RBAC)**: Admin and User roles
- **Mode Toggle**: Switch between Insecure (Attack) and Secure (Defense) modes
- **4 Security Levels / Missions**:
  - Level 1: Weak Authentication (plain text vs hashed passwords)
  - Level 2: Broken Access Control (cookie role vs server-side role)
  - Level 3: Parameter Tampering (no validation vs validated inputs)
  - Level 4: Session Hijacking (weak cookies vs secure cookie flags)

### UI/UX
- Dark cybersecurity theme (black/deep gray + neon green/red/blue)
- Monospace fonts throughout
- Animated loading screen with matrix rain on auth pages
- Glitch effects, scanline overlay, pulse animations
- SOC-style dashboard with live log streaming
- Security layer status indicators

### Routes
- `/` → redirects to login
- `/login` → login page
- `/register` → registration
- `/dashboard` → main SOC control panel
- `/admin` → admin panel (RBAC demo)
- `/levels` → mission selection
- `/toggle-mode` → POST to switch secure/insecure mode
- `/exploit/parameter-tamper` → Level 3 demo
- `/exploit/session-demo` → Level 4 demo
- `/api/logs` → JSON log feed
- `/logout` → clears session

## Default Credentials
- Admin: `admin` / `admin123`
- Demo user: `demo` / `demo123`

## Running
```bash
python3 app.py
```
Starts on `0.0.0.0:5000`.
