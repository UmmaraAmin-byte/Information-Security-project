import os
import re
import sqlite3
import hashlib
import secrets
import html
import json
import base64
import jwt
import bcrypt
from datetime import datetime, timedelta
from functools import wraps
from flask import (
    Flask, render_template, request, redirect, url_for,
    session, g, jsonify, make_response
)

app = Flask(__name__)
app.secret_key = os.environ.get('SESSION_SECRET', secrets.token_hex(32))
app.permanent_session_lifetime = timedelta(minutes=30)

DATABASE = 'hacker_vs_system.db'
JWT_SECRET = os.environ.get('JWT_SECRET', secrets.token_hex(32))

ROLE_HIERARCHY = {'guest': 0, 'user': 1, 'moderator': 2, 'admin': 3}

ROLE_PERMISSIONS = {
    'guest':     [],
    'user':      ['view_dashboard', 'view_levels', 'use_exploits'],
    'moderator': ['view_dashboard', 'view_levels', 'use_exploits', 'view_logs', 'view_security_dashboard'],
    'admin':     ['view_dashboard', 'view_levels', 'use_exploits', 'view_logs',
                  'view_security_dashboard', 'manage_users', 'manage_roles',
                  'access_admin', 'access_api', 'access_crypto_lab']
}

MAX_FAILED_ATTEMPTS = 3
LOCKOUT_MINUTES = 15

# ─────────────────────────── Database helpers ──────────────────────────────

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def init_db():
    with app.app_context():
        db = get_db()
        db.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                username        TEXT    NOT NULL UNIQUE,
                password        TEXT    NOT NULL,
                role            TEXT    NOT NULL DEFAULT 'user',
                failed_attempts INTEGER NOT NULL DEFAULT 0,
                locked_until    DATETIME,
                created_at      DATETIME DEFAULT CURRENT_TIMESTAMP,
                last_login      DATETIME,
                last_ip         TEXT
            )
        ''')
        db.execute('''
            CREATE TABLE IF NOT EXISTS logs (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                message    TEXT     NOT NULL,
                level      TEXT     NOT NULL DEFAULT 'INFO',
                category   TEXT     NOT NULL DEFAULT 'GENERAL',
                ip_address TEXT,
                username   TEXT,
                timestamp  DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        db.execute('''
            CREATE TABLE IF NOT EXISTS api_tokens (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id    INTEGER NOT NULL,
                token      TEXT    NOT NULL UNIQUE,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                expires_at DATETIME NOT NULL,
                last_used  DATETIME,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        ''')
        db.execute('''
            CREATE TABLE IF NOT EXISTS csrf_log (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT,
                endpoint   TEXT,
                blocked    INTEGER DEFAULT 1,
                timestamp  DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        db.execute('''
            CREATE TABLE IF NOT EXISTS session_events (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                username   TEXT,
                event_type TEXT,
                ip_address TEXT,
                detail     TEXT,
                timestamp  DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        existing = db.execute("SELECT id FROM users WHERE username='admin'").fetchone()
        if not existing:
            pw = bcrypt.hashpw('admin123'.encode(), bcrypt.gensalt()).decode()
            db.execute("INSERT INTO users (username, password, role) VALUES (?,?,?)",
                       ('admin', pw, 'admin'))
            pw_mod = bcrypt.hashpw('mod123'.encode(), bcrypt.gensalt()).decode()
            db.execute("INSERT INTO users (username, password, role) VALUES (?,?,?)",
                       ('moderator', pw_mod, 'moderator'))
            pw_demo = bcrypt.hashpw('demo123'.encode(), bcrypt.gensalt()).decode()
            db.execute("INSERT INTO users (username, password, role) VALUES (?,?,?)",
                       ('demo', pw_demo, 'user'))
        db.commit()

def add_log(message, level='INFO', category='GENERAL', username=None, ip=None):
    try:
        if ip is None:
            try:
                ip = request.remote_addr
            except RuntimeError:
                ip = None
        if username is None:
            try:
                username = session.get('username')
            except RuntimeError:
                username = None
        db = get_db()
        db.execute(
            "INSERT INTO logs (message, level, category, ip_address, username) VALUES (?,?,?,?,?)",
            (message, level, category, ip, username)
        )
        db.commit()
    except Exception:
        pass

def add_session_event(username, event_type, detail='', ip=None):
    try:
        if ip is None:
            try:
                ip = request.remote_addr
            except RuntimeError:
                ip = None
        db = get_db()
        db.execute(
            "INSERT INTO session_events (username, event_type, ip_address, detail) VALUES (?,?,?,?)",
            (username, event_type, ip, detail)
        )
        db.commit()
    except Exception:
        pass

def get_secure_mode():
    return session.get('secure_mode', False)

def get_effective_role():
    """In secure mode, trust only the server-side session role.
    In insecure mode, trust the client cookie — demonstrating privilege escalation."""
    if get_secure_mode():
        return session.get('role', 'user')
    return request.cookies.get('role', session.get('role', 'user'))

def get_client_ip():
    return request.headers.get('X-Forwarded-For', request.remote_addr)

@app.context_processor
def inject_role_context():
    """Inject role breakdown into every template automatically."""
    if 'user_id' not in session:
        return {}
    secure = get_secure_mode()
    session_role = session.get('role', 'user')
    db_role = session.get('db_role', session_role)
    cookie_role = request.cookies.get('role', session_role)
    effective_role = session_role if secure else cookie_role
    role_tampered = (not secure) and (cookie_role != session_role)
    return dict(
        effective_role=effective_role,
        session_role=session_role,
        db_role=db_role,
        cookie_role=cookie_role,
        role_tampered=role_tampered,
    )

# ─────────────────────────── Permission Decorators ─────────────────────────

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            add_log(f'Unauthenticated access to {request.path}', 'DANGER', 'ACCESS_CONTROL')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

def permission_required(permission):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if 'user_id' not in session:
                return redirect(url_for('login'))
            secure = get_secure_mode()
            session_role = session.get('role', 'user')
            db_role = session.get('db_role', session_role)
            cookie_role = request.cookies.get('role', session_role)
            effective_role = session_role if secure else cookie_role
            username = session.get('username', 'unknown')

            if secure:
                user_perms = ROLE_PERMISSIONS.get(effective_role, [])
                if permission not in user_perms:
                    add_log(
                        f'[SECURE] Permission denied: {permission} | '
                        f'db_role={db_role} session_role={session_role} '
                        f'effective_role={effective_role} | user={username}',
                        'DANGER', 'ACCESS_CONTROL')
                    return render_template('access_denied.html', secure=secure,
                                           required_permission=permission,
                                           user_role=effective_role), 403
            else:
                user_perms = ROLE_PERMISSIONS.get(effective_role, [])
                if permission not in user_perms:
                    add_log(
                        f'[INSECURE] Permission denied: {permission} | '
                        f'db_role={db_role} session_role={session_role} '
                        f'cookie_role={cookie_role} effective_role={effective_role} | user={username}',
                        'DANGER', 'ACCESS_CONTROL')
                    return render_template('access_denied.html', secure=secure,
                                           required_permission=permission,
                                           user_role=effective_role), 403
                add_log(
                    f'[INSECURE] Permission GRANTED: {permission} | '
                    f'db_role={db_role} session_role={session_role} '
                    f'cookie_role={cookie_role} effective_role={effective_role} | user={username}'
                    + (' [ESCALATED via cookie tamper]' if cookie_role != session_role else ''),
                    'WARNING', 'ACCESS_CONTROL')
            return f(*args, **kwargs)
        return decorated
    return decorator

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization', '').replace('Bearer ', '').strip()
        secure = session.get('secure_mode', False)

        if not token:
            if not secure:
                add_log('[INSECURE] API accessed with NO token — allowed in attack mode', 'DANGER', 'API')
                g.token_user = {'sub': 'anonymous', 'role': 'none', 'insecure': True,
                                 'note': 'No token required in insecure mode'}
                return f(*args, **kwargs)
            return jsonify({'error': 'Token required', 'hint': 'Include Authorization: Bearer <token>'}), 401

        if not secure:
            # Insecure mode: accept any token, no signature verification
            HARDCODED_BYPASS = ['admin', 'password', '00000000', 'bypass', 'token', 'secret']
            if token in HARDCODED_BYPASS:
                g.token_user = {'sub': 'admin_bypass', 'role': 'admin', 'insecure': True,
                                 'note': f'Hardcoded bypass token accepted: {token}'}
                add_log(f'[INSECURE] Hardcoded bypass token used: {token}', 'DANGER', 'API')
            else:
                # Try JWT but don't fail — just decode without verification
                try:
                    payload = jwt.decode(token, options={"verify_signature": False}, algorithms=['HS256', 'none'])
                    g.token_user = {**payload, 'insecure': True, 'note': 'Signature NOT verified (insecure mode)'}
                    add_log(f'[INSECURE] JWT accepted without signature check', 'DANGER', 'API')
                except Exception:
                    g.token_user = {'sub': 'unknown', 'role': 'user', 'insecure': True,
                                     'note': f'Any token accepted in insecure mode: {token[:20]}'}
                    add_log(f'[INSECURE] Arbitrary token accepted: {token[:20]}', 'WARNING', 'API')
            return f(*args, **kwargs)

        try:
            payload = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
            g.token_user = payload
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token expired', 'hint': 'Request a new token'}), 401
        except jwt.InvalidTokenError as e:
            return jsonify({'error': 'Invalid token', 'detail': str(e)}), 401
        return f(*args, **kwargs)
    return decorated

# ─────────────────────────── Account lockout helpers ───────────────────────

def is_account_locked(user):
    if user['locked_until']:
        locked_until = datetime.fromisoformat(str(user['locked_until']))
        if datetime.utcnow() < locked_until:
            return True, locked_until
    return False, None

def record_failed_login(user_id, username):
    db = get_db()
    user = db.execute("SELECT failed_attempts FROM users WHERE id=?", (user_id,)).fetchone()
    attempts = (user['failed_attempts'] or 0) + 1
    if attempts >= MAX_FAILED_ATTEMPTS:
        locked_until = datetime.utcnow() + timedelta(minutes=LOCKOUT_MINUTES)
        db.execute("UPDATE users SET failed_attempts=?, locked_until=? WHERE id=?",
                   (attempts, locked_until.isoformat(), user_id))
        add_log(f'Account LOCKED: {username} after {attempts} failed attempts — brute force protection triggered',
                'DANGER', 'AUTH', username=username)
    else:
        db.execute("UPDATE users SET failed_attempts=? WHERE id=?", (attempts, user_id))
        remaining = MAX_FAILED_ATTEMPTS - attempts
        add_log(f'Failed login attempt {attempts}/{MAX_FAILED_ATTEMPTS}: {username} — {remaining} attempt(s) remaining',
                'WARNING', 'AUTH', username=username)
    db.commit()
    return attempts

def reset_failed_login(user_id):
    db = get_db()
    db.execute("UPDATE users SET failed_attempts=0, locked_until=NULL WHERE id=?", (user_id,))
    db.commit()

def get_failed_attempts(user_id):
    db = get_db()
    row = db.execute("SELECT failed_attempts FROM users WHERE id=?", (user_id,)).fetchone()
    return row['failed_attempts'] if row else 0

# ─────────────────────────── CSRF helpers ──────────────────────────────────

def generate_csrf_token():
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(32)
    return session['csrf_token']

def validate_csrf(form_token):
    return form_token and form_token == session.get('csrf_token')

app.jinja_env.globals['csrf_token'] = generate_csrf_token
app.jinja_env.globals['now'] = datetime.utcnow
app.jinja_env.globals['role_permissions'] = ROLE_PERMISSIONS
app.jinja_env.globals['MAX_FAILED_ATTEMPTS'] = MAX_FAILED_ATTEMPTS

# ─────────────────────────── Input sanitization ────────────────────────────

def sanitize_input(value):
    return html.escape(str(value)) if value else ''

def check_password_strength(password):
    score = 0
    feedback = []
    checks = [
        (len(password) >= 8,              'At least 8 characters'),
        (bool(re.search(r'[A-Z]', password)), 'At least one uppercase letter'),
        (bool(re.search(r'[0-9]', password)), 'At least one number'),
        (bool(re.search(r'[^a-zA-Z0-9]', password)), 'At least one special character'),
    ]
    for passed, hint in checks:
        if passed:
            score += 1
        else:
            feedback.append(hint)
    labels = {0: 'VERY WEAK', 1: 'WEAK', 2: 'MODERATE', 3: 'STRONG', 4: 'VERY STRONG'}
    entropy = len(set(password)) * len(password) * 0.5
    return score, labels.get(score, 'WEAK'), feedback, round(entropy, 1)

# ─────────────────────────── Security Score ────────────────────────────────

def compute_security_score():
    score = 100
    deductions = []
    db = get_db()
    secure = get_secure_mode()

    if not secure:
        score -= 30
        deductions.append({'item': 'Insecure mode active', 'points': -30, 'color': 'danger'})

    cutoff = (datetime.utcnow() - timedelta(hours=1)).isoformat()
    danger_count = db.execute(
        "SELECT COUNT(*) as c FROM logs WHERE level='DANGER' AND timestamp > ?", (cutoff,)
    ).fetchone()['c']
    if danger_count > 0:
        pts = min(danger_count * 3, 25)
        score -= pts
        deductions.append({'item': f'{danger_count} danger events (last hour)', 'points': -pts, 'color': 'danger'})

    locked = db.execute(
        "SELECT COUNT(*) as c FROM users WHERE locked_until > ?", (datetime.utcnow().isoformat(),)
    ).fetchone()['c']
    if locked > 0:
        score -= 5
        deductions.append({'item': f'{locked} account(s) currently locked', 'points': -5, 'color': 'warning'})

    csrf_blocks = db.execute(
        "SELECT COUNT(*) as c FROM logs WHERE category='CSRF' AND level='DANGER' AND timestamp > ?", (cutoff,)
    ).fetchone()['c']
    if csrf_blocks > 0:
        score -= min(csrf_blocks * 2, 10)
        deductions.append({'item': f'{csrf_blocks} CSRF attacks (last hour)', 'points': -min(csrf_blocks*2,10), 'color': 'warning'})

    score = max(score, 0)
    if score >= 80:
        risk = 'LOW'
        risk_color = 'green'
    elif score >= 50:
        risk = 'MEDIUM'
        risk_color = 'yellow'
    else:
        risk = 'HIGH'
        risk_color = 'red'

    return {'score': score, 'risk': risk, 'risk_color': risk_color, 'deductions': deductions}

# ─────────────────────────── Anomaly detection ─────────────────────────────

def get_anomalies():
    db = get_db()
    cutoff = (datetime.utcnow() - timedelta(minutes=15)).isoformat()
    failed_by_ip = db.execute('''
        SELECT ip_address, COUNT(*) as cnt FROM logs
        WHERE category='AUTH' AND level='WARNING'
        AND timestamp > ? AND ip_address IS NOT NULL
        GROUP BY ip_address HAVING cnt >= 3
        ORDER BY cnt DESC LIMIT 10
    ''', (cutoff,)).fetchall()
    failed_by_user = db.execute('''
        SELECT username, COUNT(*) as cnt FROM logs
        WHERE category='AUTH' AND level='WARNING'
        AND timestamp > ? AND username IS NOT NULL
        GROUP BY username HAVING cnt >= 3
        ORDER BY cnt DESC LIMIT 10
    ''', (cutoff,)).fetchall()
    locked_accounts = db.execute(
        "SELECT username, locked_until FROM users WHERE locked_until IS NOT NULL AND locked_until > ?",
        (datetime.utcnow().isoformat(),)
    ).fetchall()
    return {
        'suspicious_ips': [dict(r) for r in failed_by_ip],
        'targeted_users': [dict(r) for r in failed_by_user],
        'locked_accounts': [dict(r) for r in locked_accounts]
    }

# ─────────────────────────── Caesar cipher ─────────────────────────────────

def caesar_cipher(text, shift, decrypt=False):
    if decrypt:
        shift = -shift
    result = []
    steps = []
    for ch in text:
        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')
            orig_pos = ord(ch) - base
            new_pos = (orig_pos + shift) % 26
            new_ch = chr(new_pos + base)
            steps.append({'char': ch, 'pos': orig_pos, 'shift': shift % 26, 'new_pos': new_pos, 'result': new_ch})
            result.append(new_ch)
        else:
            result.append(ch)
    return ''.join(result), steps

# ─────────────────────────── Routes ────────────────────────────────────────

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    lockout_remaining = None
    lockout_until_ts = None
    failed_attempts = 0
    remaining_attempts = MAX_FAILED_ATTEMPTS

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        csrf_form = request.form.get('csrf_token', '')
        secure = get_secure_mode()
        ip = get_client_ip()

        db = get_db()
        user = db.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()

        if secure:
            if not validate_csrf(csrf_form):
                add_log(f'[SECURE] CSRF token mismatch from {ip}', 'DANGER', 'CSRF')
                error = 'Invalid request (CSRF token mismatch)'
                return render_template('login.html', error=error, secure=secure,
                                       lockout_remaining=None, remaining_attempts=MAX_FAILED_ATTEMPTS,
                                       failed_attempts=0)

            if not user:
                add_log(f'[SECURE] Unknown user login attempt: {username}', 'WARNING', 'AUTH', username=username)
                error = 'Invalid credentials'
            else:
                locked, locked_until = is_account_locked(user)
                if locked:
                    remaining_secs = int((locked_until - datetime.utcnow()).total_seconds())
                    remaining_mins = remaining_secs // 60 + 1
                    lockout_remaining = remaining_mins
                    lockout_until_ts = int(locked_until.timestamp() * 1000)
                    add_log(f'[SECURE] Login attempted on locked account: {username}', 'DANGER', 'AUTH', username=username)
                    error = f'Account locked. Try again in {remaining_mins} minute(s).'
                else:
                    try:
                        pw_ok = bcrypt.checkpw(password.encode(), user['password'].encode())
                    except Exception:
                        pw_ok = False
                    if pw_ok:
                        reset_failed_login(user['id'])
                        session.clear()
                        session.permanent = True
                        session['user_id'] = user['id']
                        session['username'] = user['username']
                        session['role'] = user['role']
                        session['bound_ip'] = ip
                        session['login_time'] = datetime.utcnow().isoformat()
                        db.execute("UPDATE users SET last_login=?, last_ip=? WHERE id=?",
                                   (datetime.utcnow().isoformat(), ip, user['id']))
                        db.commit()
                        add_session_event(username, 'LOGIN', f'Secure login from {ip}', ip)
                        add_log(f'[SECURE] Successful login: {username}', 'SUCCESS', 'AUTH', username=username)
                        return redirect(url_for('dashboard'))
                    else:
                        attempts = record_failed_login(user['id'], username)
                        failed_attempts = attempts
                        remaining_attempts = max(MAX_FAILED_ATTEMPTS - attempts, 0)
                        error = f'Invalid credentials — {remaining_attempts} attempt(s) remaining before lockout'
        else:
            # INSECURE MODE
            if not user:
                error = 'Invalid credentials'
            else:
                try:
                    pw_ok = bcrypt.checkpw(password.encode(), user['password'].encode())
                except Exception:
                    pw_ok = False
                if pw_ok:
                    session['user_id'] = user['id']
                    session['username'] = user['username']
                    session['role'] = request.form.get('role', user['role'])
                    session['db_role'] = user['role']
                    session['login_time'] = datetime.utcnow().isoformat()
                    add_log(f'[INSECURE] Login: {username} role={session["role"]} db_role={user["role"]} (no lockout, no CSRF)',
                            'WARNING', 'AUTH', username=username)
                    return redirect(url_for('dashboard'))
                else:
                    add_log(f'[INSECURE] Failed login: {username} (no lockout applied)', 'WARNING', 'AUTH', username=username)
                    error = 'Invalid credentials (no lockout in attack mode)'

    return render_template('login.html', error=error, secure=get_secure_mode(),
                           lockout_remaining=lockout_remaining,
                           lockout_until_ts=lockout_until_ts,
                           failed_attempts=failed_attempts,
                           remaining_attempts=remaining_attempts,
                           max_attempts=MAX_FAILED_ATTEMPTS)


@app.route('/register', methods=['GET', 'POST'])
def register():
    error = None
    success = None
    secure = get_secure_mode()

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        csrf_form = request.form.get('csrf_token', '')

        if secure:
            if not validate_csrf(csrf_form):
                error = 'Invalid request (CSRF protection)'
                return render_template('register.html', error=error, success=None, secure=secure)
            if len(username) < 3 or len(username) > 20:
                error = 'Username must be 3–20 characters'
            elif not re.match(r'^[a-zA-Z0-9_]+$', username):
                error = 'Username: letters, numbers, underscores only'
            else:
                score, label, feedback, entropy = check_password_strength(password)
                if score < 3:
                    error = f'Password too weak ({label}): {", ".join(feedback)}'
                else:
                    pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
                    try:
                        db = get_db()
                        db.execute("INSERT INTO users (username, password, role) VALUES (?,?,?)",
                                   (username, pw_hash, 'user'))
                        db.commit()
                        add_log(f'[SECURE] Registered: {username} (bcrypt, strength={label})',
                                'SUCCESS', 'AUTH', username=username)
                        success = f'Account created! Password strength: {label}'
                    except sqlite3.IntegrityError:
                        error = 'Username already taken'
        else:
            try:
                pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
                db = get_db()
                db.execute("INSERT INTO users (username, password, role) VALUES (?,?,?)",
                           (username, pw_hash, 'user'))
                db.commit()
                add_log(f'[INSECURE] Registered: {username} (no validation, no strength check)',
                        'WARNING', 'AUTH', username=username)
                success = f'Account created! (No validation — username: {username})'
            except sqlite3.IntegrityError:
                error = 'Username already taken'

    return render_template('register.html', error=error, success=success, secure=secure)


@app.route('/dashboard')
@login_required
def dashboard():
    secure = get_secure_mode()
    if secure:
        bound_ip = session.get('bound_ip')
        current_ip = get_client_ip()
        if bound_ip and bound_ip != current_ip:
            add_log(f'[SECURE] Session IP mismatch — bound={bound_ip} current={current_ip}',
                    'DANGER', 'SESSION')
            session.clear()
            return redirect(url_for('login'))

    db = get_db()
    logs = db.execute("SELECT * FROM logs ORDER BY timestamp DESC LIMIT 30").fetchall()
    users_count = db.execute("SELECT COUNT(*) as c FROM users").fetchone()['c']
    eff_role = get_effective_role()
    perms = ROLE_PERMISSIONS.get(eff_role, [])
    anomalies = get_anomalies()
    threat_count = len(anomalies['suspicious_ips']) + len(anomalies['locked_accounts'])
    sec_score = compute_security_score()

    return render_template('dashboard.html',
                           username=session.get('username'),
                           role=eff_role,
                           permissions=perms,
                           secure=secure,
                           logs=logs,
                           users_count=users_count,
                           threat_count=threat_count,
                           anomalies=anomalies,
                           role_hierarchy=ROLE_HIERARCHY,
                           sec_score=sec_score)


@app.route('/admin')
@login_required
@permission_required('access_admin')
def admin():
    secure = get_secure_mode()
    db = get_db()
    users = db.execute("SELECT id, username, role, failed_attempts, locked_until, last_login, last_ip FROM users").fetchall()
    add_log(f'Admin panel accessed by {session.get("username")}', 'INFO', 'ADMIN')
    return render_template('admin.html', users=users, secure=secure,
                           role_hierarchy=ROLE_HIERARCHY,
                           all_roles=list(ROLE_HIERARCHY.keys()))


@app.route('/admin/manage-user', methods=['POST'])
@login_required
@permission_required('manage_users')
def manage_user():
    secure = get_secure_mode()
    action = request.form.get('action')
    target_id = request.form.get('user_id')
    new_role = request.form.get('role')
    csrf_form = request.form.get('csrf_token', '')

    if secure and not validate_csrf(csrf_form):
        add_log('[SECURE] CSRF blocked on user management', 'DANGER', 'CSRF')
        return redirect(url_for('admin'))

    db = get_db()
    target = db.execute("SELECT * FROM users WHERE id=?", (target_id,)).fetchone()
    if not target:
        return redirect(url_for('admin'))

    if action == 'change_role' and new_role in ROLE_HIERARCHY:
        old_role = target['role']
        db.execute("UPDATE users SET role=? WHERE id=?", (new_role, target_id))
        db.commit()
        add_log(f'Role change: {target["username"]} {old_role}→{new_role} by {session.get("username")}',
                'INFO', 'ADMIN')
    elif action == 'unlock':
        db.execute("UPDATE users SET failed_attempts=0, locked_until=NULL WHERE id=?", (target_id,))
        db.commit()
        add_log(f'Account unlocked: {target["username"]} by {session.get("username")}',
                'INFO', 'ADMIN')
    elif action == 'lock':
        locked_until = (datetime.utcnow() + timedelta(hours=1)).isoformat()
        db.execute("UPDATE users SET locked_until=? WHERE id=?", (locked_until, target_id))
        db.commit()
        add_log(f'Account locked: {target["username"]} by {session.get("username")}',
                'WARNING', 'ADMIN')

    return redirect(url_for('admin'))


@app.route('/levels')
@login_required
def levels():
    return render_template('levels.html', secure=get_secure_mode(),
                           username=session.get('username'),
                           role=get_effective_role())


@app.route('/security-dashboard')
@login_required
@permission_required('view_security_dashboard')
def security_dashboard():
    secure = get_secure_mode()
    db = get_db()
    anomalies = get_anomalies()
    recent_danger = db.execute(
        "SELECT * FROM logs WHERE level IN ('DANGER','WARNING') ORDER BY timestamp DESC LIMIT 50"
    ).fetchall()
    stats = {
        'total_logins': db.execute("SELECT COUNT(*) as c FROM logs WHERE category='AUTH' AND level='SUCCESS'").fetchone()['c'],
        'failed_logins': db.execute("SELECT COUNT(*) as c FROM logs WHERE category='AUTH' AND level='WARNING'").fetchone()['c'],
        'csrf_blocks': db.execute("SELECT COUNT(*) as c FROM logs WHERE category='CSRF'").fetchone()['c'],
        'access_denied': db.execute("SELECT COUNT(*) as c FROM logs WHERE category='ACCESS_CONTROL' AND level='DANGER'").fetchone()['c'],
    }
    category_counts = db.execute(
        "SELECT category, COUNT(*) as cnt FROM logs GROUP BY category ORDER BY cnt DESC"
    ).fetchall()
    add_log(f'Security dashboard viewed by {session.get("username")}', 'INFO', 'ADMIN')
    return render_template('security_dashboard.html',
                           secure=secure, anomalies=anomalies,
                           recent_danger=recent_danger, stats=stats,
                           category_counts=category_counts)


@app.route('/crypto-lab', methods=['GET', 'POST'])
@login_required
def crypto_lab():
    secure = get_secure_mode()
    sample = request.args.get('sample', 'admin123')
    sample_clean = sample[:64]

    sha256_hash = hashlib.sha256(sample_clean.encode()).hexdigest()
    sha512_hash = hashlib.sha512(sample_clean.encode()).hexdigest()
    md5_hash = hashlib.md5(sample_clean.encode()).hexdigest()
    sha1_hash = hashlib.sha1(sample_clean.encode()).hexdigest()
    bcrypt_hash = bcrypt.hashpw(sample_clean.encode(), bcrypt.gensalt(rounds=10)).decode()

    payload = {'sub': session.get('username'), 'role': get_effective_role(),
               'exp': datetime.utcnow() + timedelta(hours=1)}
    jwt_token = jwt.encode(payload, JWT_SECRET, algorithm='HS256')

    b64_encoded = base64.b64encode(sample_clean.encode()).decode()
    b64_decoded_try = ''
    try:
        b64_decoded_try = base64.b64decode(sample_clean + '==').decode('utf-8', errors='replace')
    except Exception:
        b64_decoded_try = '(not valid base64)'

    caesar_shift = int(request.args.get('shift', 3))
    caesar_encrypted, caesar_steps = caesar_cipher(sample_clean, caesar_shift)
    caesar_decrypted, _ = caesar_cipher(caesar_encrypted, caesar_shift, decrypt=True)

    # Rainbow table demo (pre-computed hashes for common passwords)
    rainbow_table = [
        {'password': 'password', 'md5': hashlib.md5(b'password').hexdigest(), 'sha256': hashlib.sha256(b'password').hexdigest()},
        {'password': '123456',   'md5': hashlib.md5(b'123456').hexdigest(),   'sha256': hashlib.sha256(b'123456').hexdigest()},
        {'password': 'admin',    'md5': hashlib.md5(b'admin').hexdigest(),    'sha256': hashlib.sha256(b'admin').hexdigest()},
        {'password': 'letmein',  'md5': hashlib.md5(b'letmein').hexdigest(),  'sha256': hashlib.sha256(b'letmein').hexdigest()},
        {'password': 'qwerty',   'md5': hashlib.md5(b'qwerty').hexdigest(),   'sha256': hashlib.sha256(b'qwerty').hexdigest()},
    ]
    rainbow_match = None
    for entry in rainbow_table:
        if entry['md5'] == md5_hash or entry['sha256'] == sha256_hash:
            rainbow_match = entry['password']
            break

    pw_score, pw_label, pw_feedback, pw_entropy = check_password_strength(sample_clean)

    return render_template('crypto_lab.html',
                           secure=secure,
                           sample=sample_clean,
                           sha256=sha256_hash,
                           sha512=sha512_hash,
                           sha1=sha1_hash,
                           md5=md5_hash,
                           bcrypt_hash=bcrypt_hash,
                           jwt_token=jwt_token,
                           jwt_payload=json.dumps(payload, indent=2, default=str),
                           b64_encoded=b64_encoded,
                           b64_decoded=b64_decoded_try,
                           caesar_shift=caesar_shift,
                           caesar_encrypted=caesar_encrypted,
                           caesar_decrypted=caesar_decrypted,
                           caesar_steps=caesar_steps[:8],
                           rainbow_table=rainbow_table,
                           rainbow_match=rainbow_match,
                           pw_score=pw_score,
                           pw_label=pw_label,
                           pw_feedback=pw_feedback,
                           pw_entropy=pw_entropy)


@app.route('/exploit/parameter-tamper', methods=['GET', 'POST'])
@login_required
def parameter_tamper():
    result = None
    secure = get_secure_mode()
    if request.method == 'POST':
        amount = request.form.get('amount', '0')
        if secure:
            try:
                amount_val = float(amount)
                if amount_val < 0 or amount_val > 10000:
                    result = {'status': 'BLOCKED', 'msg': f'Amount {amount_val} out of range (0–10000)', 'color': 'danger',
                              'steps': ['Input received', 'Type check: PASS (numeric)', f'Range check: FAIL ({amount_val} not in 0–10000)', 'Request REJECTED']}
                    add_log(f'[SECURE] Parameter tamper blocked: amount={amount}', 'SUCCESS', 'ATTACK')
                else:
                    result = {'status': 'ACCEPTED', 'msg': f'Transaction: ${amount_val:.2f}', 'color': 'success',
                              'steps': ['Input received', 'Type check: PASS', 'Range check: PASS (0–10000)', 'Transaction processed']}
            except ValueError:
                result = {'status': 'BLOCKED', 'msg': f'Non-numeric input rejected: {sanitize_input(amount)}', 'color': 'danger',
                          'steps': ['Input received', f'Type check: FAIL (not numeric: {sanitize_input(amount)})', 'Request REJECTED']}
                add_log(f'[SECURE] Injection blocked: amount={amount}', 'SUCCESS', 'ATTACK')
        else:
            add_log(f'[INSECURE] Unvalidated transaction: amount={amount}', 'WARNING', 'ATTACK')
            result = {'status': 'EXPLOITED', 'msg': f'Accepted without validation: ${amount}', 'color': 'warning',
                      'steps': ['Input received', 'No type check', 'No range check', f'Value accepted as-is: {amount}', 'Transaction processed (EXPLOITED!)']}
    return render_template('parameter_tamper.html', result=result, secure=secure)


@app.route('/exploit/xss-demo', methods=['GET', 'POST'])
@login_required
def xss_demo():
    secure = get_secure_mode()
    result = None
    user_input = ''
    if request.method == 'POST':
        user_input = request.form.get('comment', '')
        has_script = bool(re.search(r'<script|<img|<svg|javascript:|onerror|onload', user_input, re.I))
        if secure:
            safe = sanitize_input(user_input)
            result = {'raw': user_input, 'rendered': safe, 'status': 'SANITIZED', 'color': 'success',
                      'has_payload': has_script,
                      'steps': [
                          f'Input received: {user_input[:40]}',
                          'html.escape() applied',
                          f'< → &lt;, > → &gt;, " → &quot;',
                          f'Output: {safe[:40]}',
                          'Safe to render — script neutralized'
                      ]}
            add_log(f'[SECURE] XSS payload sanitized: {user_input[:60]}', 'SUCCESS', 'ATTACK')
        else:
            result = {'raw': user_input, 'rendered': user_input, 'status': 'VULNERABLE', 'color': 'danger',
                      'has_payload': has_script,
                      'steps': [
                          f'Input received: {user_input[:40]}',
                          'No sanitization applied',
                          'Raw HTML passed to template',
                          '{{ result.rendered | safe }} used in Jinja',
                          'Script executes in victim browser!' if has_script else 'Input rendered as-is'
                      ]}
            add_log(f'[INSECURE] XSS payload rendered raw: {user_input[:60]}', 'WARNING', 'ATTACK')
    return render_template('xss_demo.html', secure=secure, result=result, user_input=user_input)


@app.route('/exploit/sqli-demo', methods=['GET', 'POST'])
@login_required
def sqli_demo():
    secure = get_secure_mode()
    result = None
    user_input = ''
    if request.method == 'POST':
        user_input = request.form.get('username', '')
        db = get_db()
        if secure:
            try:
                rows = db.execute("SELECT id, username, role FROM users WHERE username=?",
                                  (user_input,)).fetchall()
                result = {
                    'status': 'SECURE',
                    'query': f"SELECT id, username, role FROM users WHERE username=?",
                    'param': user_input,
                    'rows': [dict(r) for r in rows],
                    'color': 'success',
                    'note': 'Parameterized query — input treated as data, not SQL',
                    'steps': [
                        f'Input received: {user_input}',
                        'Prepared statement created with ? placeholder',
                        'Input bound as parameter (literal string)',
                        'No SQL interpretation of input',
                        f'Query executed safely — {len(rows)} row(s) returned'
                    ]
                }
                add_log(f'[SECURE] SQL query parameterized for input: {user_input[:40]}', 'SUCCESS', 'ATTACK')
            except Exception as e:
                result = {'status': 'ERROR', 'query': str(e), 'rows': [], 'color': 'danger', 'note': str(e), 'steps': []}
        else:
            raw_query = f"SELECT id, username, role FROM users WHERE username='{user_input}'"
            try:
                rows = db.execute(raw_query).fetchall()
                is_injection = len(rows) > 1 or "'" in user_input or '--' in user_input or 'UNION' in user_input.upper()
                result = {
                    'status': 'EXPLOITED' if is_injection else 'EXECUTED',
                    'query': raw_query,
                    'param': None,
                    'rows': [dict(r) for r in rows],
                    'color': 'warning' if is_injection else 'danger',
                    'note': 'String concatenation — SQL injection successful!' if is_injection else 'String concatenation — vulnerable to injection',
                    'steps': [
                        f'Input received: {user_input}',
                        'Input concatenated directly into SQL string',
                        f'Final query: {raw_query[:80]}',
                        'Database executes modified query',
                        f'{"INJECTION SUCCESSFUL — " + str(len(rows)) + " row(s) leaked!" if is_injection else "Query executed without validation"}'
                    ]
                }
                add_log(f'[INSECURE] Raw SQL executed: {raw_query[:80]}', 'WARNING', 'ATTACK')
            except Exception as e:
                result = {
                    'status': 'ERROR', 'query': raw_query, 'param': None,
                    'rows': [], 'color': 'danger',
                    'note': f'SQL Error: {str(e)}',
                    'steps': [f'SQL Error: {str(e)}']
                }
    return render_template('sqli_demo.html', secure=secure, result=result, user_input=user_input)


@app.route('/exploit/csrf-demo', methods=['GET', 'POST'])
@login_required
def csrf_demo():
    secure = get_secure_mode()
    result = None
    flow_steps = []

    if request.method == 'POST':
        csrf_form = request.form.get('csrf_token', '')
        action = request.form.get('action', 'transfer')
        amount = request.form.get('amount', '500')
        is_forged = request.form.get('forged', '0') == '1'

        flow_steps = [
            {'step': 'Incoming Request', 'detail': f'POST /exploit/csrf-demo — action={action}, amount=${amount}',
             'status': 'info'},
            {'step': 'Request Origin', 'detail': 'Same-origin (legit page)' if not is_forged else 'Cross-origin (forged/attacker page)',
             'status': 'success' if not is_forged else 'danger'},
            {'step': 'CSRF Token Present', 'detail': f'Token: {csrf_form[:20]}...' if csrf_form and csrf_form != 'FORGED_INVALID_TOKEN_12345' else 'FORGED or MISSING token',
             'status': 'success' if (csrf_form and csrf_form != 'FORGED_INVALID_TOKEN_12345') else 'danger'},
        ]

        if secure:
            token_valid = validate_csrf(csrf_form)
            flow_steps.append({
                'step': 'Session Token Comparison',
                'detail': 'Token matches session: YES' if token_valid else 'Token matches session: NO — MISMATCH!',
                'status': 'success' if token_valid else 'danger'
            })
            if token_valid:
                flow_steps.append({'step': 'Server Decision', 'detail': 'ALLOW — valid CSRF token', 'status': 'success'})
                result = {'status': 'ALLOWED', 'msg': f'CSRF token valid — {action} of ${amount} processed.',
                          'color': 'success', 'attack': False}
                add_log(f'[SECURE] CSRF validated — action={action}, amount={amount}', 'SUCCESS', 'CSRF')
            else:
                flow_steps.append({'step': 'Server Decision', 'detail': 'BLOCK — CSRF token invalid. Request rejected!', 'status': 'danger'})
                result = {'status': 'BLOCKED', 'msg': 'CSRF token missing or invalid — request rejected!',
                          'color': 'danger', 'attack': True}
                add_log(f'[SECURE] CSRF attack blocked — forged token from {get_client_ip()}', 'DANGER', 'CSRF')
        else:
            flow_steps.append({'step': 'Session Token Comparison', 'detail': 'No comparison performed — CSRF not checked!', 'status': 'warning'})
            flow_steps.append({'step': 'Server Decision', 'detail': 'ALLOW — no CSRF protection in insecure mode', 'status': 'warning'})
            result = {'status': 'EXPLOITED',
                      'msg': f'No CSRF check — {action} of ${amount} executed from forged request!',
                      'color': 'warning', 'attack': True}
            add_log(f'[INSECURE] CSRF not checked — {action}=${amount}', 'WARNING', 'CSRF')

    return render_template('csrf_demo.html', secure=secure, result=result, flow_steps=flow_steps)


@app.route('/exploit/rbac-demo', methods=['GET', 'POST'])
@login_required
def rbac_demo():
    secure = get_secure_mode()
    session_role = session.get('role', 'user')
    db_role = session.get('db_role', session_role)
    cookie_role = request.cookies.get('role', session_role)
    eff_role = get_effective_role()
    result = None

    if request.method == 'POST':
        requested_perm = request.form.get('permission', 'access_admin')
        if secure:
            granted = requested_perm in ROLE_PERMISSIONS.get(eff_role, [])
            result = {
                'role': eff_role, 'permission': requested_perm,
                'granted': granted, 'source': 'server-side session (tamper-proof)',
                'color': 'success' if granted else 'danger',
                'status': 'GRANTED' if granted else 'DENIED',
                'cookie_role': cookie_role,
                'session_role': session_role,
                'db_role': db_role,
                'effective_role': eff_role,
                'tampered': cookie_role != session_role
            }
            add_log(
                f'[SECURE] RBAC check: {requested_perm} = {"GRANT" if granted else "DENY"} | '
                f'db_role={db_role} session_role={session_role} '
                f'cookie_role={cookie_role} effective_role={eff_role}',
                'INFO' if granted else 'DANGER', 'ACCESS_CONTROL')
        else:
            granted = requested_perm in ROLE_PERMISSIONS.get(eff_role, [])
            escalated = cookie_role != session_role
            result = {
                'role': eff_role, 'permission': requested_perm,
                'granted': granted, 'source': 'client cookie (tamperable!)',
                'color': 'warning' if granted else 'danger',
                'status': ('GRANTED [ESCALATED via cookie]' if escalated else 'GRANTED (via cookie)') if granted else 'DENIED',
                'cookie_role': cookie_role,
                'session_role': session_role,
                'db_role': db_role,
                'effective_role': eff_role,
                'tampered': escalated
            }
            add_log(
                f'[INSECURE] RBAC check: {requested_perm} = {"GRANT" if granted else "DENY"} | '
                f'db_role={db_role} session_role={session_role} '
                f'cookie_role={cookie_role} effective_role={eff_role}'
                + (' [ESCALATED via cookie tamper]' if escalated else ''),
                'WARNING', 'ACCESS_CONTROL')

    return render_template('rbac_demo.html', secure=secure, role=eff_role,
                           cookie_role=cookie_role, db_role=db_role,
                           result=result, role_permissions=ROLE_PERMISSIONS,
                           role_hierarchy=ROLE_HIERARCHY)


@app.route('/exploit/session-demo')
@login_required
def session_demo():
    secure = get_secure_mode()
    db = get_db()
    username = session.get('username')

    session_events = db.execute(
        "SELECT * FROM session_events WHERE username=? ORDER BY timestamp DESC LIMIT 10",
        (username,)
    ).fetchall()

    login_time = session.get('login_time')
    session_age_secs = None
    if login_time:
        try:
            lt = datetime.fromisoformat(login_time)
            session_age_secs = int((datetime.utcnow() - lt).total_seconds())
        except Exception:
            pass

    session_info = {
        'session_id': request.cookies.get('session', 'N/A'),
        'user': username,
        'role': session.get('role'),
        'db_role': session.get('db_role', session.get('role')),
        'bound_ip': session.get('bound_ip', 'N/A'),
        'current_ip': get_client_ip(),
        'secure': secure,
        'login_time': login_time,
        'session_age_secs': session_age_secs,
    }
    if secure:
        add_session_event(username, 'SESSION_VIEW', 'Secure session inspected', get_client_ip())
        resp = make_response(render_template('session_demo.html', info=session_info, secure=secure,
                                             session_events=session_events))
        resp.set_cookie('demo_secure', 'true', httponly=True, samesite='Strict', max_age=300)
        add_log('[SECURE] Session demo — secure cookies applied, IP-bound session', 'SUCCESS', 'SESSION')
        return resp
    else:
        add_session_event(username, 'SESSION_VIEW_INSECURE', 'Insecure session exposed', get_client_ip())
        add_log('[INSECURE] Session demo — weak session handling exposed to inspection', 'WARNING', 'SESSION')
        return render_template('session_demo.html', info=session_info, secure=secure,
                               session_events=session_events)


@app.route('/api-lab')
@login_required
def api_lab():
    secure = get_secure_mode()
    return render_template('api_lab.html', secure=secure,
                           username=session.get('username'),
                           role=get_effective_role())


@app.route('/toggle-mode', methods=['POST'])
def toggle_mode():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    was_insecure = not session.get('secure_mode', False)
    session['secure_mode'] = not session.get('secure_mode', False)
    mode = 'SECURE' if session['secure_mode'] else 'INSECURE'

    # FIX: When switching insecure → secure, revalidate role from database
    escalation_detected = False
    if session['secure_mode'] and was_insecure:
        db = get_db()
        user = db.execute("SELECT role FROM users WHERE id=?", (session.get('user_id'),)).fetchone()
        if user:
            db_role = user['role']
            session_role = session.get('role')
            if session_role != db_role:
                escalation_detected = True
                add_log(
                    f'[SECURE] Privilege escalation detected on mode switch: '
                    f'session_role={session_role} → restored db_role={db_role} for {session.get("username")}',
                    'DANGER', 'ACCESS_CONTROL'
                )
            session['role'] = db_role
            session['db_role'] = db_role

    session['escalation_detected'] = escalation_detected
    add_log(f'System mode → {mode} by {session.get("username", "guest")}', 'INFO', 'GENERAL')
    return redirect(request.referrer or url_for('dashboard'))


# ─────────────────────────── JSON API ──────────────────────────────────────

@app.route('/api/logs')
@login_required
def api_logs():
    db = get_db()
    limit = int(request.args.get('limit', 50))
    category = request.args.get('category', None)
    if category:
        logs = db.execute(
            "SELECT message, level, category, ip_address, username, timestamp FROM logs WHERE category=? ORDER BY timestamp DESC LIMIT ?",
            (category, limit)
        ).fetchall()
    else:
        logs = db.execute(
            "SELECT message, level, category, ip_address, username, timestamp FROM logs ORDER BY timestamp DESC LIMIT ?",
            (limit,)
        ).fetchall()
    return jsonify([dict(r) for r in logs])


@app.route('/api/anomalies')
@login_required
def api_anomalies():
    return jsonify(get_anomalies())


@app.route('/api/security-score')
@login_required
def api_security_score():
    return jsonify(compute_security_score())


@app.route('/api/token', methods=['POST'])
@login_required
def api_get_token():
    secure = get_secure_mode()
    username = session.get('username')
    role = session.get('role', 'user')
    if secure:
        perms = ROLE_PERMISSIONS.get(role, [])
        if 'access_api' not in perms:
            return jsonify({'error': 'Insufficient permissions', 'hint': 'Only admin role can generate API tokens'}), 403
        payload = {
            'sub': username,
            'role': role,
            'permissions': perms,
            'iat': datetime.utcnow(),
            'exp': datetime.utcnow() + timedelta(hours=1)
        }
        token = jwt.encode(payload, JWT_SECRET, algorithm='HS256')
        parts = token.split('.')
        add_log(f'[SECURE] JWT issued for {username} with role={role}', 'SUCCESS', 'API')
        return jsonify({
            'token': token,
            'expires_in': 3600,
            'type': 'Bearer',
            'structure': {
                'header': parts[0] if len(parts) > 0 else '',
                'payload': parts[1] if len(parts) > 1 else '',
                'signature': parts[2] if len(parts) > 2 else ''
            },
            'decoded_header': {'alg': 'HS256', 'typ': 'JWT'},
            'decoded_payload': payload,
            'security_notes': [
                'Signed with HMAC-SHA256',
                'Contains role & permission claims',
                'Expires in 1 hour',
                'Signature verified on every request'
            ]
        })
    else:
        weak_token = secrets.token_hex(8)
        bypass_tokens = ['admin', 'password', '00000000', 'bypass']
        add_log(f'[INSECURE] Weak token issued for {username} — no signature, no expiry', 'WARNING', 'API')
        return jsonify({
            'token': weak_token,
            'note': 'INSECURE — short random token, no signature, no expiry, no claims',
            'bypass_tokens': bypass_tokens,
            'vulnerabilities': [
                'No cryptographic signature',
                'No expiration time',
                'No role/permission claims',
                'Hardcoded bypass tokens work',
                'Any token accepted in insecure mode'
            ]
        })


@app.route('/api/protected')
@token_required
def api_protected():
    user = g.token_user
    secure = session.get('secure_mode', False)
    insecure_flag = user.get('insecure', False)

    response = {
        'message': f'Hello {user.get("sub", "unknown")}! Protected endpoint accessed.',
        'role': user.get('role'),
        'permissions': user.get('permissions', []),
        'server_time': datetime.utcnow().isoformat(),
        'mode': 'SECURE' if secure else 'INSECURE',
        'validation': {
            'signature_verified': not insecure_flag,
            'expiry_checked': not insecure_flag,
            'note': user.get('note', 'Proper JWT validation applied')
        }
    }
    if insecure_flag:
        add_log(f'[INSECURE] /api/protected accessed without proper token verification', 'DANGER', 'API')
        response['warning'] = 'This access was granted WITHOUT proper signature verification!'
    else:
        add_log(f'[SECURE] /api/protected accessed by {user.get("sub")} with valid JWT', 'SUCCESS', 'API')

    return jsonify(response)


@app.route('/api/stats')
@login_required
def api_stats():
    db = get_db()
    data = {
        'users': db.execute("SELECT COUNT(*) as c FROM users").fetchone()['c'],
        'logs': db.execute("SELECT COUNT(*) as c FROM logs").fetchone()['c'],
        'danger_events': db.execute("SELECT COUNT(*) as c FROM logs WHERE level='DANGER'").fetchone()['c'],
        'anomalies': get_anomalies(),
        'security_score': compute_security_score()
    }
    return jsonify(data)


@app.route('/api/brute-force', methods=['POST'])
@login_required
def api_brute_force():
    """Simulated brute-force attack for educational demo"""
    target = request.json.get('target', 'demo') if request.is_json else 'demo'
    secure = get_secure_mode()
    ip = get_client_ip()
    results = []
    passwords = ['123456', 'password', 'admin', 'letmein', 'qwerty', 'demo123']

    db = get_db()
    user = db.execute("SELECT * FROM users WHERE username=?", (target,)).fetchone()

    if not user:
        return jsonify({'error': 'Target user not found', 'attempts': []})

    for pw in passwords:
        if secure:
            locked, locked_until = is_account_locked(user)
            if locked:
                remaining = int((locked_until - datetime.utcnow()).total_seconds())
                results.append({
                    'password': pw, 'status': 'BLOCKED',
                    'reason': f'Account locked — {remaining}s remaining',
                    'color': 'danger'
                })
                add_log(f'[SECURE] Brute force attempt blocked on locked account: {target}', 'DANGER', 'BRUTE_FORCE', username=target, ip=ip)
                break
            try:
                pw_ok = bcrypt.checkpw(pw.encode(), user['password'].encode())
            except Exception:
                pw_ok = False
            if pw_ok:
                results.append({'password': pw, 'status': 'SUCCESS — but lockout triggered after 3 fails', 'color': 'success'})
                break
            else:
                attempts = record_failed_login(user['id'], target)
                user = db.execute("SELECT * FROM users WHERE username=?", (target,)).fetchone()
                results.append({
                    'password': pw, 'status': 'FAILED',
                    'reason': f'Wrong password — attempt {attempts}/{MAX_FAILED_ATTEMPTS}',
                    'color': 'warning'
                })
                add_log(f'[SECURE] Brute force: attempt {attempts}/{MAX_FAILED_ATTEMPTS} on {target} with "{pw}"', 'WARNING', 'BRUTE_FORCE', username=target, ip=ip)
        else:
            try:
                pw_ok = bcrypt.checkpw(pw.encode(), user['password'].encode())
            except Exception:
                pw_ok = False
            if pw_ok:
                results.append({'password': pw, 'status': 'CRACKED — no lockout protection!', 'color': 'danger'})
                add_log(f'[INSECURE] Brute force SUCCESS: cracked {target} with "{pw}" — no lockout!', 'DANGER', 'BRUTE_FORCE', username=target, ip=ip)
            else:
                results.append({'password': pw, 'status': 'FAILED — trying next', 'color': 'warning'})
                add_log(f'[INSECURE] Brute force attempt: {target} / {pw} — no lockout applied', 'WARNING', 'BRUTE_FORCE', username=target, ip=ip)

    return jsonify({'target': target, 'mode': 'SECURE' if secure else 'INSECURE', 'attempts': results})


@app.route('/api/crypto', methods=['POST'])
@login_required
def api_crypto():
    """Interactive crypto operations"""
    data = request.get_json(force=True)
    op = data.get('op', 'hash')
    text = str(data.get('text', ''))[:128]

    if op == 'base64_encode':
        return jsonify({'result': base64.b64encode(text.encode()).decode(), 'op': op})
    elif op == 'base64_decode':
        try:
            decoded = base64.b64decode(text + '==').decode('utf-8', errors='replace')
            return jsonify({'result': decoded, 'op': op})
        except Exception as e:
            return jsonify({'result': f'Error: {str(e)}', 'op': op})
    elif op == 'caesar':
        shift = int(data.get('shift', 3))
        encrypted, steps = caesar_cipher(text, shift)
        return jsonify({'result': encrypted, 'steps': steps[:5], 'op': op})
    elif op == 'hash_md5':
        return jsonify({'result': hashlib.md5(text.encode()).hexdigest(), 'op': op})
    elif op == 'hash_sha256':
        return jsonify({'result': hashlib.sha256(text.encode()).hexdigest(), 'op': op})
    elif op == 'strength':
        score, label, feedback, entropy = check_password_strength(text)
        return jsonify({'score': score, 'label': label, 'feedback': feedback, 'entropy': entropy, 'op': op})
    else:
        return jsonify({'error': 'Unknown operation'}), 400


@app.route('/logout')
def logout():
    username = session.get('username', 'unknown')
    add_log(f'User logged out: {username}', 'INFO', 'AUTH', username=username)
    add_session_event(username, 'LOGOUT', 'User logged out', get_client_ip())
    session.clear()
    return redirect(url_for('login'))


# ─────────────────────────── Entry point ───────────────────────────────────

init_db()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
