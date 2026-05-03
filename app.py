import os
import sqlite3
import hashlib
import secrets
from datetime import timedelta
from flask import (
    Flask, render_template, request, redirect, url_for,
    session, g, jsonify, make_response
)

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)
app.permanent_session_lifetime = timedelta(minutes=30)

DATABASE = 'hacker_vs_system.db'

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
                id       INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT    NOT NULL UNIQUE,
                password TEXT    NOT NULL,
                role     TEXT    NOT NULL DEFAULT 'user'
            )
        ''')
        db.execute('''
            CREATE TABLE IF NOT EXISTS logs (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                message   TEXT    NOT NULL,
                level     TEXT    NOT NULL DEFAULT 'INFO',
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        # Seed an admin account (plain text in insecure mode demo)
        existing = db.execute("SELECT id FROM users WHERE username='admin'").fetchone()
        if not existing:
            hashed = hashlib.sha256('admin123'.encode()).hexdigest()
            db.execute(
                "INSERT INTO users (username, password, role) VALUES (?,?,?)",
                ('admin', hashed, 'admin')
            )
            db.execute(
                "INSERT INTO users (username, password, role) VALUES (?,?,?)",
                ('demo', hashlib.sha256('demo123'.encode()).hexdigest(), 'user')
            )
        db.commit()

def add_log(message, level='INFO'):
    try:
        db = get_db()
        db.execute("INSERT INTO logs (message, level) VALUES (?,?)", (message, level))
        db.commit()
    except Exception:
        pass

def get_secure_mode():
    return session.get('secure_mode', False)

# ─────────────────────────── Routes ────────────────────────────────────────

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        secure = get_secure_mode()

        db = get_db()
        user = db.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()

        if secure:
            # SECURE MODE – compare bcrypt/sha256 hash
            pw_hash = hashlib.sha256(password.encode()).hexdigest()
            if user and user['password'] == pw_hash:
                session.permanent = True
                session['user_id'] = user['id']
                session['username'] = user['username']
                session['role'] = user['role']          # role stored server-side
                add_log(f"[SECURE] Successful login: {username}", 'SUCCESS')
                return redirect(url_for('dashboard'))
            else:
                add_log(f"[SECURE] Failed login attempt: {username}", 'WARNING')
                error = 'Invalid credentials'
        else:
            # INSECURE MODE – plain-text password comparison (vulnerability demo)
            # VULNERABILITY: passwords stored & compared as plain text
            pw_plain = hashlib.sha256(password.encode()).hexdigest()   # still hashed in DB seeding
            if user and user['password'] == pw_plain:
                session['user_id'] = user['id']
                session['username'] = user['username']
                # VULNERABILITY: role taken from form / cookie, not server-side DB
                session['role'] = request.form.get('role', user['role'])
                add_log(f"[INSECURE] Login: {username} – role from client: {session['role']}", 'WARNING')
                return redirect(url_for('dashboard'))
            else:
                add_log(f"[INSECURE] Failed login: {username}", 'WARNING')
                error = 'Invalid credentials'

    return render_template('login.html', error=error, secure=get_secure_mode())


@app.route('/register', methods=['GET', 'POST'])
def register():
    error = None
    success = None
    secure = get_secure_mode()

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        if secure:
            # SECURE MODE – validate input, hash password
            if len(username) < 3 or len(username) > 20:
                error = 'Username must be 3–20 characters'
            elif not username.isalnum():
                error = 'Username must be alphanumeric'
            elif len(password) < 6:
                error = 'Password must be at least 6 characters'
            else:
                pw_hash = hashlib.sha256(password.encode()).hexdigest()
                try:
                    db = get_db()
                    db.execute(
                        "INSERT INTO users (username, password, role) VALUES (?,?,?)",
                        (username, pw_hash, 'user')
                    )
                    db.commit()
                    add_log(f"[SECURE] Registered user: {username}", 'SUCCESS')
                    success = 'Account created! You can now log in.'
                except sqlite3.IntegrityError:
                    error = 'Username already taken'
        else:
            # INSECURE MODE – no input validation, stores plain text password
            # VULNERABILITY: no validation, password stored as-is (shown as concept)
            pw_store = password   # plain text demo concept
            try:
                db = get_db()
                # Actually store sha256 so login still works, but conceptually "plain"
                db.execute(
                    "INSERT INTO users (username, password, role) VALUES (?,?,?)",
                    (username, hashlib.sha256(password.encode()).hexdigest(), 'user')
                )
                db.commit()
                add_log(f"[INSECURE] Registered user: {username} – no validation applied", 'WARNING')
                success = f'Account created (insecure)! Password stored: {pw_store[:3]}*** (plain text)'
            except sqlite3.IntegrityError:
                error = 'Username already taken'

    return render_template('register.html', error=error, success=success, secure=secure)


@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        add_log('Unauthenticated dashboard access attempt', 'DANGER')
        return redirect(url_for('login'))

    db = get_db()
    logs = db.execute(
        "SELECT * FROM logs ORDER BY timestamp DESC LIMIT 20"
    ).fetchall()
    users_count = db.execute("SELECT COUNT(*) as c FROM users").fetchone()['c']

    return render_template(
        'dashboard.html',
        username=session.get('username'),
        role=session.get('role'),
        secure=get_secure_mode(),
        logs=logs,
        users_count=users_count
    )


@app.route('/admin')
def admin():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    secure = get_secure_mode()

    if secure:
        # SECURE MODE – role validated server-side
        if session.get('role') != 'admin':
            add_log(f"[SECURE] Unauthorized admin access by {session.get('username')}", 'DANGER')
            return render_template('access_denied.html', secure=secure), 403
    else:
        # INSECURE MODE – role read from client cookie (can be tampered)
        # VULNERABILITY: if attacker changes cookie role to 'admin' they get in
        cookie_role = request.cookies.get('role', session.get('role', 'user'))
        if cookie_role != 'admin':
            add_log(f"[INSECURE] Admin access blocked (cookie role={cookie_role})", 'DANGER')
            return render_template('access_denied.html', secure=secure), 403
        add_log(f"[INSECURE] Admin access via cookie role={cookie_role}", 'WARNING')

    db = get_db()
    users = db.execute("SELECT id, username, role FROM users").fetchall()
    add_log(f"Admin panel accessed by {session.get('username')}", 'INFO')
    return render_template('admin.html', users=users, secure=secure)


@app.route('/levels')
def levels():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('levels.html', secure=get_secure_mode(),
                           username=session.get('username'),
                           role=session.get('role'))


@app.route('/toggle-mode', methods=['POST'])
def toggle_mode():
    current = session.get('secure_mode', False)
    session['secure_mode'] = not current
    mode = 'SECURE' if session['secure_mode'] else 'INSECURE'
    add_log(f"System mode switched to {mode} by {session.get('username', 'guest')}", 'INFO')
    return redirect(request.referrer or url_for('dashboard'))


@app.route('/exploit/parameter-tamper', methods=['GET', 'POST'])
def parameter_tamper():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    result = None
    secure = get_secure_mode()

    if request.method == 'POST':
        amount = request.form.get('amount', '0')

        if secure:
            # SECURE MODE – validate input
            try:
                amount_val = float(amount)
                if amount_val < 0 or amount_val > 10000:
                    result = {'status': 'BLOCKED', 'msg': 'Invalid amount: out of range (0–10,000)', 'color': 'danger'}
                    add_log(f"[SECURE] Parameter tamper blocked: amount={amount}", 'SUCCESS')
                else:
                    result = {'status': 'ACCEPTED', 'msg': f'Transaction processed: ${amount_val:.2f}', 'color': 'success'}
            except ValueError:
                result = {'status': 'BLOCKED', 'msg': 'Invalid input: not a number', 'color': 'danger'}
                add_log(f"[SECURE] Injection attempt blocked: amount={amount}", 'SUCCESS')
        else:
            # INSECURE MODE – no validation
            # VULNERABILITY: amount accepted as-is, can be negative, string, etc.
            add_log(f"[INSECURE] Unvalidated transaction: amount={amount}", 'WARNING')
            result = {'status': 'EXPLOITED', 'msg': f'Transaction accepted: ${amount} (no validation!)', 'color': 'warning'}

    return render_template('parameter_tamper.html', result=result, secure=secure)


@app.route('/exploit/session-demo')
def session_demo():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    secure = get_secure_mode()
    session_info = {
        'session_id': request.cookies.get('session', 'N/A'),
        'user': session.get('username'),
        'role': session.get('role'),
        'secure': secure
    }

    if secure:
        # SECURE MODE – regenerate session, set secure cookie flags
        resp = make_response(render_template('session_demo.html',
                                             info=session_info, secure=secure))
        resp.set_cookie('demo_secure', 'true', httponly=True, samesite='Strict',
                        max_age=300)
        add_log('[SECURE] Session demo: secure cookie flags applied', 'SUCCESS')
        return resp
    else:
        add_log('[INSECURE] Session demo: weak session handling exposed', 'WARNING')
        return render_template('session_demo.html', info=session_info, secure=secure)


@app.route('/api/logs')
def api_logs():
    if 'user_id' not in session:
        return jsonify({'error': 'unauthorized'}), 401
    db = get_db()
    logs = db.execute(
        "SELECT message, level, timestamp FROM logs ORDER BY timestamp DESC LIMIT 30"
    ).fetchall()
    return jsonify([dict(r) for r in logs])


@app.route('/logout')
def logout():
    username = session.get('username', 'unknown')
    add_log(f"User logged out: {username}", 'INFO')
    session.clear()
    return redirect(url_for('login'))


# ─────────────────────────── Entry point ───────────────────────────────────

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5000, debug=True)

init_db()
