import os
import re
import sqlite3
import hashlib
import secrets
import html
import json
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

# ─────────────────────────── Role & Permission System ──────────────────────

ROLE_HIERARCHY = {'guest': 0, 'user': 1, 'moderator': 2, 'admin': 3}

ROLE_PERMISSIONS = {
    'guest':     [],
    'user':      ['view_dashboard', 'view_levels', 'use_exploits'],
    'moderator': ['view_dashboard', 'view_levels', 'use_exploits', 'view_logs', 'view_security_dashboard'],
    'admin':     ['view_dashboard', 'view_levels', 'use_exploits', 'view_logs',
                  'view_security_dashboard', 'manage_users', 'manage_roles',
                  'access_admin', 'access_api', 'access_crypto_lab']
}

MAX_FAILED_ATTEMPTS = 5
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

        # Seed admin
        existing = db.execute("SELECT id FROM users WHERE username='admin'").fetchone()
        if not existing:
            pw = bcrypt.hashpw('admin123'.encode(), bcrypt.gensalt()).decode()
            db.execute("INSERT INTO users (username, password, role) VALUES (?,?,?)",
                       ('admin', pw, 'admin'))
            # Moderator
            pw_mod = bcrypt.hashpw('mod123'.encode(), bcrypt.gensalt()).decode()
            db.execute("INSERT INTO users (username, password, role) VALUES (?,?,?)",
                       ('moderator', pw_mod, 'moderator'))
            # Demo user
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

def get_secure_mode():
    return session.get('secure_mode', False)

def get_client_ip():
    return request.headers.get('X-Forwarded-For', request.remote_addr)

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
            role = session.get('role', 'user')
            if secure:
                user_perms = ROLE_PERMISSIONS.get(role, [])
                if permission not in user_perms:
                    add_log(f'Permission denied: {permission} for {session.get("username")}',
                            'DANGER', 'ACCESS_CONTROL')
                    return render_template('access_denied.html', secure=secure,
                                           required_permission=permission,
                                           user_role=role), 403
            else:
                cookie_role = request.cookies.get('role', role)
                user_perms = ROLE_PERMISSIONS.get(cookie_role, [])
                if permission not in user_perms:
                    add_log(f'[INSECURE] Cookie role {cookie_role} lacks {permission}',
                            'DANGER', 'ACCESS_CONTROL')
                    return render_template('access_denied.html', secure=secure,
                                           required_permission=permission,
                                           user_role=cookie_role), 403
                add_log(f'[INSECURE] Granted {permission} via cookie role={cookie_role}',
                        'WARNING', 'ACCESS_CONTROL')
            return f(*args, **kwargs)
        return decorated
    return decorator

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization', '').replace('Bearer ', '')
        if not token:
            return jsonify({'error': 'Token required'}), 401
        try:
            payload = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
            g.token_user = payload
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Invalid token'}), 401
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
        add_log(f'Account LOCKED: {username} after {attempts} failed attempts',
                'DANGER', 'AUTH', username=username)
    else:
        db.execute("UPDATE users SET failed_attempts=? WHERE id=?", (attempts, user_id))
        add_log(f'Failed login attempt {attempts}/{MAX_FAILED_ATTEMPTS}: {username}',
                'WARNING', 'AUTH', username=username)
    db.commit()

def reset_failed_login(user_id):
    db = get_db()
    db.execute("UPDATE users SET failed_attempts=0, locked_until=NULL WHERE id=?", (user_id,))
    db.commit()

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

# ─────────────────────────── Input sanitization ────────────────────────────

def sanitize_input(value):
    return html.escape(str(value)) if value else ''

def check_password_strength(password):
    score = 0
    feedback = []
    if len(password) >= 8:
        score += 1
    else:
        feedback.append('At least 8 characters')
    if re.search(r'[A-Z]', password):
        score += 1
    else:
        feedback.append('At least one uppercase letter')
    if re.search(r'[0-9]', password):
        score += 1
    else:
        feedback.append('At least one number')
    if re.search(r'[^a-zA-Z0-9]', password):
        score += 1
    else:
        feedback.append('At least one special character')
    labels = {0: 'VERY WEAK', 1: 'WEAK', 2: 'MODERATE', 3: 'STRONG', 4: 'VERY STRONG'}
    return score, labels.get(score, 'WEAK'), feedback

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
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        csrf_form = request.form.get('csrf_token', '')
        secure = get_secure_mode()
        ip = get_client_ip()

        db = get_db()
        user = db.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()

        if secure:
            # CSRF check
            if not validate_csrf(csrf_form):
                add_log(f'[SECURE] CSRF token mismatch from {ip}', 'DANGER', 'CSRF')
                error = 'Invalid request (CSRF token mismatch)'
                return render_template('login.html', error=error, secure=secure,
                                       lockout_remaining=None)

            if not user:
                add_log(f'[SECURE] Unknown user login attempt: {username}', 'WARNING', 'AUTH', username=username)
                error = 'Invalid credentials'
            else:
                locked, locked_until = is_account_locked(user)
                if locked:
                    remaining = int((locked_until - datetime.utcnow()).total_seconds() / 60) + 1
                    lockout_remaining = remaining
                    add_log(f'[SECURE] Login attempted on locked account: {username}', 'DANGER', 'AUTH', username=username)
                    error = f'Account locked. Try again in {remaining} minute(s).'
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
                        db.execute("UPDATE users SET last_login=?, last_ip=? WHERE id=?",
                                   (datetime.utcnow().isoformat(), ip, user['id']))
                        db.commit()
                        add_log(f'[SECURE] Successful login: {username}', 'SUCCESS', 'AUTH', username=username)
                        return redirect(url_for('dashboard'))
                    else:
                        record_failed_login(user['id'], username)
                        error = 'Invalid credentials'
        else:
            # INSECURE MODE — no CSRF, no lockout, role from form
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
                    add_log(f'[INSECURE] Login: {username} role={session["role"]} (no lockout, no CSRF)',
                            'WARNING', 'AUTH', username=username)
                    return redirect(url_for('dashboard'))
                else:
                    add_log(f'[INSECURE] Failed login: {username}', 'WARNING', 'AUTH', username=username)
                    error = 'Invalid credentials'

    return render_template('login.html', error=error, secure=get_secure_mode(),
                           lockout_remaining=lockout_remaining)


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
                score, label, feedback = check_password_strength(password)
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
                success = f'Account created! (No validation — username: {username}, pw stored: *** [bcrypt])'
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
    role = session.get('role', 'user')
    perms = ROLE_PERMISSIONS.get(role, [])
    anomalies = get_anomalies()
    threat_count = len(anomalies['suspicious_ips']) + len(anomalies['locked_accounts'])

    return render_template('dashboard.html',
                           username=session.get('username'),
                           role=role,
                           permissions=perms,
                           secure=secure,
                           logs=logs,
                           users_count=users_count,
                           threat_count=threat_count,
                           anomalies=anomalies,
                           role_hierarchy=ROLE_HIERARCHY)


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
                           role=session.get('role'))


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
        'locked_accounts': db.execute("SELECT COUNT(*) as c FROM users WHERE locked_until > ?",
                                      (datetime.utcnow().isoformat(),)).fetchone()['c'],
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


@app.route('/crypto-lab')
@login_required
def crypto_lab():
    secure = get_secure_mode()
    sample = request.args.get('sample', 'admin123')
    sample_clean = sample[:64]
    sha256_hash = hashlib.sha256(sample_clean.encode()).hexdigest()
    sha512_hash = hashlib.sha512(sample_clean.encode()).hexdigest()
    md5_hash = hashlib.md5(sample_clean.encode()).hexdigest()
    bcrypt_hash = bcrypt.hashpw(sample_clean.encode(), bcrypt.gensalt(rounds=10)).decode()
    payload = {'sub': session.get('username'), 'role': session.get('role'), 'exp': datetime.utcnow() + timedelta(hours=1)}
    jwt_token = jwt.encode(payload, JWT_SECRET, algorithm='HS256')
    return render_template('crypto_lab.html',
                           secure=secure,
                           sample=sample_clean,
                           sha256=sha256_hash,
                           sha512=sha512_hash,
                           md5=md5_hash,
                           bcrypt_hash=bcrypt_hash,
                           jwt_token=jwt_token,
                           jwt_payload=json.dumps(payload, indent=2, default=str))


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
                    result = {'status': 'BLOCKED', 'msg': f'Amount {amount_val} out of range (0–10000)', 'color': 'danger'}
                    add_log(f'[SECURE] Parameter tamper blocked: amount={amount}', 'SUCCESS', 'ATTACK')
                else:
                    result = {'status': 'ACCEPTED', 'msg': f'Transaction: ${amount_val:.2f}', 'color': 'success'}
            except ValueError:
                result = {'status': 'BLOCKED', 'msg': f'Non-numeric input rejected: {sanitize_input(amount)}', 'color': 'danger'}
                add_log(f'[SECURE] Injection blocked: amount={amount}', 'SUCCESS', 'ATTACK')
        else:
            add_log(f'[INSECURE] Unvalidated transaction: amount={amount}', 'WARNING', 'ATTACK')
            result = {'status': 'EXPLOITED', 'msg': f'Accepted: ${amount} (no validation!)', 'color': 'warning'}
    return render_template('parameter_tamper.html', result=result, secure=secure)


@app.route('/exploit/xss-demo', methods=['GET', 'POST'])
@login_required
def xss_demo():
    secure = get_secure_mode()
    result = None
    user_input = ''
    if request.method == 'POST':
        user_input = request.form.get('comment', '')
        if secure:
            safe = sanitize_input(user_input)
            result = {'raw': user_input, 'rendered': safe, 'status': 'SANITIZED', 'color': 'success'}
            add_log(f'[SECURE] XSS payload sanitized: {user_input[:60]}', 'SUCCESS', 'ATTACK')
        else:
            result = {'raw': user_input, 'rendered': user_input, 'status': 'VULNERABLE', 'color': 'danger'}
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
            # Parameterized query
            try:
                rows = db.execute("SELECT id, username, role FROM users WHERE username=?",
                                  (user_input,)).fetchall()
                result = {
                    'status': 'SECURE',
                    'query': f"SELECT id, username, role FROM users WHERE username=? -- param: {user_input}",
                    'rows': [dict(r) for r in rows],
                    'color': 'success',
                    'note': 'Parameterized query — input treated as data, not SQL'
                }
                add_log(f'[SECURE] SQL query parameterized for input: {user_input[:40]}', 'SUCCESS', 'ATTACK')
            except Exception as e:
                result = {'status': 'ERROR', 'query': str(e), 'rows': [], 'color': 'danger', 'note': str(e)}
        else:
            # Vulnerable string concatenation
            raw_query = f"SELECT id, username, role FROM users WHERE username='{user_input}'"
            try:
                rows = db.execute(raw_query).fetchall()
                result = {
                    'status': 'EXPLOITED',
                    'query': raw_query,
                    'rows': [dict(r) for r in rows],
                    'color': 'warning',
                    'note': 'String concatenation — SQL injection possible!'
                }
                add_log(f'[INSECURE] Raw SQL executed: {raw_query[:80]}', 'WARNING', 'ATTACK')
            except Exception as e:
                result = {
                    'status': 'ERROR',
                    'query': raw_query,
                    'rows': [],
                    'color': 'danger',
                    'note': f'SQL Error: {str(e)}'
                }
    return render_template('sqli_demo.html', secure=secure, result=result, user_input=user_input)


@app.route('/exploit/csrf-demo', methods=['GET', 'POST'])
@login_required
def csrf_demo():
    secure = get_secure_mode()
    result = None
    if request.method == 'POST':
        csrf_form = request.form.get('csrf_token', '')
        action = request.form.get('action', 'transfer')
        amount = request.form.get('amount', '500')
        if secure:
            if validate_csrf(csrf_form):
                result = {'status': 'ALLOWED', 'msg': f'CSRF token valid — {action} of ${amount} processed.',
                          'color': 'success', 'attack': False}
                add_log(f'[SECURE] CSRF validated — action={action}, amount={amount}', 'SUCCESS', 'CSRF')
            else:
                result = {'status': 'BLOCKED', 'msg': 'CSRF token missing or invalid — request rejected!',
                          'color': 'danger', 'attack': True}
                add_log(f'[SECURE] CSRF attack blocked — forged token from {get_client_ip()}',
                        'DANGER', 'CSRF')
        else:
            result = {'status': 'EXPLOITED',
                      'msg': f'No CSRF check — {action} of ${amount} executed from forged request!',
                      'color': 'warning', 'attack': True}
            add_log(f'[INSECURE] CSRF not checked — {action}=${amount}', 'WARNING', 'CSRF')
    return render_template('csrf_demo.html', secure=secure, result=result)


@app.route('/exploit/rbac-demo', methods=['GET', 'POST'])
@login_required
def rbac_demo():
    secure = get_secure_mode()
    role = session.get('role', 'user')
    result = None
    if request.method == 'POST':
        requested_perm = request.form.get('permission', 'access_admin')
        if secure:
            server_role = session.get('role', 'user')
            granted = requested_perm in ROLE_PERMISSIONS.get(server_role, [])
            result = {
                'role': server_role,
                'permission': requested_perm,
                'granted': granted,
                'source': 'server-side session',
                'color': 'success' if granted else 'danger',
                'status': 'GRANTED' if granted else 'DENIED'
            }
            add_log(f'[SECURE] RBAC check: {server_role} → {requested_perm} = {"GRANT" if granted else "DENY"}',
                    'INFO' if granted else 'DANGER', 'ACCESS_CONTROL')
        else:
            cookie_role = request.cookies.get('role', role)
            granted = requested_perm in ROLE_PERMISSIONS.get(cookie_role, [])
            result = {
                'role': cookie_role,
                'permission': requested_perm,
                'granted': granted,
                'source': 'client cookie (tamperable!)',
                'color': 'warning' if granted else 'danger',
                'status': 'GRANTED (via cookie)' if granted else 'DENIED'
            }
            add_log(f'[INSECURE] Cookie RBAC: role={cookie_role} → {requested_perm} = {"GRANT" if granted else "DENY"}',
                    'WARNING', 'ACCESS_CONTROL')
    return render_template('rbac_demo.html', secure=secure, role=role,
                           result=result, role_permissions=ROLE_PERMISSIONS,
                           role_hierarchy=ROLE_HIERARCHY)


@app.route('/exploit/session-demo')
@login_required
def session_demo():
    secure = get_secure_mode()
    session_info = {
        'session_id': request.cookies.get('session', 'N/A'),
        'user': session.get('username'),
        'role': session.get('role'),
        'bound_ip': session.get('bound_ip', 'N/A'),
        'current_ip': get_client_ip(),
        'secure': secure
    }
    if secure:
        resp = make_response(render_template('session_demo.html', info=session_info, secure=secure))
        resp.set_cookie('demo_secure', 'true', httponly=True, samesite='Strict', max_age=300)
        add_log('[SECURE] Session demo — secure cookies applied', 'SUCCESS', 'SESSION')
        return resp
    else:
        add_log('[INSECURE] Session demo — weak session handling exposed', 'WARNING', 'SESSION')
        return render_template('session_demo.html', info=session_info, secure=secure)


@app.route('/api-lab')
@login_required
def api_lab():
    secure = get_secure_mode()
    return render_template('api_lab.html', secure=secure,
                           username=session.get('username'),
                           role=session.get('role'))


@app.route('/toggle-mode', methods=['POST'])
def toggle_mode():
    current = session.get('secure_mode', False)
    session['secure_mode'] = not current
    mode = 'SECURE' if session['secure_mode'] else 'INSECURE'
    add_log(f'System mode → {mode} by {session.get("username", "guest")}', 'INFO', 'GENERAL')
    return redirect(request.referrer or url_for('dashboard'))


# ─────────────────────────── JSON API ──────────────────────────────────────

@app.route('/api/logs')
@login_required
def api_logs():
    db = get_db()
    logs = db.execute(
        "SELECT message, level, category, ip_address, username, timestamp FROM logs ORDER BY timestamp DESC LIMIT 50"
    ).fetchall()
    return jsonify([dict(r) for r in logs])


@app.route('/api/anomalies')
@login_required
def api_anomalies():
    return jsonify(get_anomalies())


@app.route('/api/token', methods=['POST'])
@login_required
def api_get_token():
    secure = get_secure_mode()
    username = session.get('username')
    role = session.get('role', 'user')
    if secure:
        perms = ROLE_PERMISSIONS.get(role, [])
        if 'access_api' not in perms:
            return jsonify({'error': 'Insufficient permissions'}), 403
        payload = {
            'sub': username,
            'role': role,
            'permissions': perms,
            'iat': datetime.utcnow(),
            'exp': datetime.utcnow() + timedelta(hours=1)
        }
        token = jwt.encode(payload, JWT_SECRET, algorithm='HS256')
        add_log(f'[SECURE] JWT issued for {username}', 'SUCCESS', 'API')
        return jsonify({'token': token, 'expires_in': 3600, 'type': 'Bearer'})
    else:
        weak_token = secrets.token_hex(8)
        add_log(f'[INSECURE] Weak token issued for {username}', 'WARNING', 'API')
        return jsonify({'token': weak_token, 'note': 'Insecure — short, no expiry, no claims'})


@app.route('/api/protected')
@token_required
def api_protected():
    user = g.token_user
    return jsonify({
        'message': f'Hello {user["sub"]}! You have authenticated via JWT.',
        'role': user.get('role'),
        'permissions': user.get('permissions', []),
        'server_time': datetime.utcnow().isoformat()
    })


@app.route('/api/stats')
@login_required
def api_stats():
    db = get_db()
    data = {
        'users': db.execute("SELECT COUNT(*) as c FROM users").fetchone()['c'],
        'logs': db.execute("SELECT COUNT(*) as c FROM logs").fetchone()['c'],
        'danger_events': db.execute("SELECT COUNT(*) as c FROM logs WHERE level='DANGER'").fetchone()['c'],
        'anomalies': get_anomalies()
    }
    return jsonify(data)


@app.route('/logout')
def logout():
    username = session.get('username', 'unknown')
    add_log(f'User logged out: {username}', 'INFO', 'AUTH', username=username)
    session.clear()
    return redirect(url_for('login'))


# ─────────────────────────── Entry point ───────────────────────────────────

init_db()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
