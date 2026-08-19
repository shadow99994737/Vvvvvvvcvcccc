from flask import Flask, render_template, request, redirect, url_for, session, jsonify, send_file
import json
import os
import subprocess
import random
import string
import uuid
from datetime import datetime, timedelta
import sys
import shutil
import threading
import time
import zipfile
import psutil
import secrets
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

app = Flask(__name__)
# SECURITY: never hardcode the secret key. Falls back to a random key per-process
# (which will invalidate sessions on restart) unless SECRET_KEY is set in the environment.
app.secret_key = os.environ.get('SECRET_KEY') or secrets.token_hex(32)
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024

# File extensions that are never needed to run a Python bot and are common malware
# droppers. We do NOT blocklist scripting extensions (.py/.sh/.js) because the whole
# point of this panel is to run user-supplied code — see scan_uploaded_source() below
# for the content-level check instead of relying on extensions alone.
BLOCKED_UPLOAD_EXTENSIONS = {'.exe', '.dll', '.msi', '.scr', '.com', '.bat', '.cmd', '.ps1', '.vbs', '.jar'}

USERS_FILE = 'users.json'
BOTS_DIR = 'bots'
CPU_HISTORY = {}
CRASH_COUNT = {}
NET_STATS = {}

# Port hosting range - each server gets its own port from this pool
PORT_RANGE_START = int(os.environ.get('PORT_RANGE_START', 20000))
PORT_RANGE_END = int(os.environ.get('PORT_RANGE_END', 20999))

os.makedirs(BOTS_DIR, exist_ok=True)

# ============================================
# পোর্ট হোস্টিং
# ============================================

import socket

def is_port_free(port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.5)
        return s.connect_ex(('127.0.0.1', port)) != 0

def get_used_ports():
    used = set()
    users = load_users()
    for uname, data in users.items():
        if uname == 'admin':
            continue
        servers = data.get('servers', [])
        if not isinstance(servers, list):
            continue
        for s in servers:
            if isinstance(s, dict) and s.get('port'):
                used.add(int(s['port']))
    return used

def get_available_port():
    used = get_used_ports()
    for port in range(PORT_RANGE_START, PORT_RANGE_END + 1):
        if port in used:
            continue
        if is_port_free(port):
            return port
    return None

# ============================================
# রেট লিমিট
# ============================================

class RateLimiter:
    def check_rate(self, server_id, limit_percent):
        if server_id not in CPU_HISTORY:
            CPU_HISTORY[server_id] = []
        users = load_users()
        server = None
        for uname, data in users.items():
            if uname == 'admin': continue
            servers = data.get('servers', [])
            if not isinstance(servers, list): continue
            for s in servers:
                if isinstance(s, dict) and s.get('server_id') == server_id:
                    server = s
                    break
        if not server or server.get('status') != 'running':
            return False, 0
        pid = server.get('pid')
        if not pid: return False, 0
        try:
            proc = psutil.Process(pid)
            cpu = proc.cpu_percent(interval=1)
            now = time.time()
            CPU_HISTORY[server_id].append({'time': now, 'cpu': cpu})
            CPU_HISTORY[server_id] = [h for h in CPU_HISTORY[server_id] if now - h['time'] < 30]
            recent = [h['cpu'] for h in CPU_HISTORY[server_id] if now - h['time'] < 10]
            if recent:
                avg_cpu = sum(recent) / len(recent)
                if avg_cpu > limit_percent:
                    return True, avg_cpu
        except: pass
        return False, 0

rate_limiter = RateLimiter()

# ============================================
# অটো-রিস্টার্ট
# ============================================

def should_auto_restart(server_id):
    if server_id not in CRASH_COUNT:
        CRASH_COUNT[server_id] = {'count': 0, 'last_crash': time.time()}
    crash_info = CRASH_COUNT[server_id]
    if time.time() - crash_info['last_crash'] < 60:
        if crash_info['count'] >= 3:
            return False
    else:
        crash_info['count'] = 0
    crash_info['count'] += 1
    crash_info['last_crash'] = time.time()
    return True

# ============================================
# হেল্পার
# ============================================

def generate_random_password(length=10):
    chars = string.ascii_letters + string.digits
    return ''.join(random.choices(chars, k=length))

def load_users():
    if not os.path.exists(USERS_FILE):
        # SECURITY: no more hardcoded 'admin123'. A strong random password is
        # generated on first run and printed once to the server console/log.
        initial_pw = os.environ.get('ADMIN_PASSWORD') or generate_random_password(14)
        default = {"admin": {"password": generate_password_hash(initial_pw), "role": "admin"}}
        save_users(default)
        print("=" * 60)
        print(f"FIRST RUN: admin password is: {initial_pw}")
        print("Save this now — it will not be shown again. Change it after login.")
        print("=" * 60)
        return default
    with open(USERS_FILE, 'r', encoding='utf-8') as f:
        data = json.load(f)
    if 'admin' not in data:
        initial_pw = os.environ.get('ADMIN_PASSWORD') or generate_random_password(14)
        data['admin'] = {"password": generate_password_hash(initial_pw), "role": "admin"}
        save_users(data)
        print(f"FIRST RUN: admin password is: {initial_pw}")
    return data

def save_users(data):
    with open(USERS_FILE, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=4, ensure_ascii=False)

def get_server_dir(server_id):
    server_dir = os.path.join(BOTS_DIR, server_id)
    os.makedirs(server_dir, exist_ok=True)
    return server_dir

# ============================================
# SECURITY: access control + path-safety helpers
# ============================================

def get_server_owner_username(server_id):
    users = load_users()
    for uname, data in users.items():
        if uname == 'admin':
            continue
        servers = data.get('servers', [])
        if not isinstance(servers, list):
            continue
        for s in servers:
            if isinstance(s, dict) and s.get('server_id') == server_id:
                return uname
    return None

def current_user_can_access_server(server_id):
    if 'user' not in session:
        return False
    if session.get('role') == 'admin':
        return True
    owner = get_server_owner_username(server_id)
    if owner is None:
        return False
    return session.get('user') == owner and session.get('current_server_id') == server_id

def require_server_access(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        server_id = kwargs.get('server_id')
        if server_id is None:
            data = request.get_json(silent=True) or {}
            server_id = data.get('server_id') or request.args.get('server_id') or request.form.get('server_id')
        if not server_id or not current_user_can_access_server(server_id):
            return jsonify({'status': 'error', 'error': 'Unauthorized', 'msg': 'Unauthorized'}), 403
        return f(*args, **kwargs)
    return wrapper

def require_admin(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if 'user' not in session or session.get('role') != 'admin':
            return jsonify({'error': 'Unauthorized'}), 403
        return f(*args, **kwargs)
    return wrapper

def safe_join(base_dir, *relative_parts):
    base_abs = os.path.abspath(base_dir)
    candidate = base_abs
    for part in relative_parts:
        part = (part or '').replace('\\', '/')
        candidate = os.path.abspath(os.path.join(candidate, part))
    if candidate != base_abs and not candidate.startswith(base_abs + os.sep):
        return None
    return candidate

def is_zip_member_safe(base_dir, member_name):
    if member_name.startswith('/') or member_name.startswith('\\'):
        return False
    if ':' in member_name:
        return False
    target = os.path.abspath(os.path.join(base_dir, member_name))
    base_abs = os.path.abspath(base_dir)
    return target == base_abs or target.startswith(base_abs + os.sep)

# ============================================
# BEST-EFFORT malware / credential-stealer scan for uploaded .py source
# ============================================
# HONESTY NOTE: this is a speed bump, not a guarantee. Static pattern
# matching can be evaded (obfuscation, string-splitting, downloading a
# second-stage payload at runtime, etc). It catches the common, low-effort
# "grabber" scripts that are the most frequent abuse case on bot-hosting
# panels like this one. Real protection against a determined attacker
# requires running each bot in an isolated container / restricted OS
# account with no access to other users' data.

import re as _re

_CREDENTIAL_TARGET_PATTERNS = [
    r'Local\s+State',
    r'Login\s+Data',
    r'leveldb',
    r'AppData[\\/]+Roaming[\\/]+Discord',
    r'AppData[\\/]+Local[\\/]+Google[\\/]+Chrome',
    r'\.session["\']?\s*\)',
    r'tdata[\\/]',
    r'os\.environ\s*\)',
    r'\.\.[\\/]\.\.[\\/].*users\.json',
]

def scan_uploaded_source(content, filename):
    """Returns (verdict, reasons). verdict is 'block' or 'ok'. Only applied to .py files."""
    if not filename.lower().endswith('.py'):
        return 'ok', []
    reasons = []
    for pat in _CREDENTIAL_TARGET_PATTERNS:
        if _re.search(pat, content, _re.IGNORECASE):
            reasons.append(pat)
    if reasons:
        return 'block', reasons
    return 'ok', reasons

def check_server_valid(server_id):
    users = load_users()
    for uname, data in users.items():
        if uname == 'admin': continue
        servers = data.get('servers', [])
        if not isinstance(servers, list): continue
        for s in servers:
            if isinstance(s, dict) and s.get('server_id') == server_id:
                expiry = s.get('expiry', '')
                if expiry:
                    try:
                        exp_date = datetime.strptime(expiry, '%Y-%m-%d %H:%M:%S.%f')
                        if datetime.now() > exp_date:
                            return False, "expired"
                    except: pass
                return True, s
    return False, "deleted"

def get_server_by_id(server_id):
    users = load_users()
    for uname, data in users.items():
        if uname == 'admin': continue
        servers = data.get('servers', [])
        if not isinstance(servers, list): continue
        for s in servers:
            if isinstance(s, dict) and s.get('server_id') == server_id:
                return s, uname
    return None, None

def create_default_files(server_dir):
    main_py = os.path.join(server_dir, 'main.py')
    if not os.path.exists(main_py):
        with open(main_py, 'w', encoding='utf-8') as f:
            f.write('''# JUBAYER HOSTING - Default Bot
import time

print("=" * 40)
print("Bot is running on JUBAYER HOSTING")
print("Server is ready!")
print("=" * 40)

counter = 0
while True:
    counter += 1
    print(f"[{time.strftime('%H:%M:%S')}] Heartbeat #{counter} | Server active")
    time.sleep(10)
''')
    
    req_file = os.path.join(server_dir, 'requirements.txt')
    if not os.path.exists(req_file):
        with open(req_file, 'w', encoding='utf-8') as f:
            f.write('# Add your pip packages here\n')

# ============================================
# বট রান
# ============================================

def run_bot(server_id, main_file='main.py', requirements_file='requirements.txt'):
    server_dir = get_server_dir(server_id)
    main_path = os.path.join(server_dir, main_file)
    log_file = os.path.join(server_dir, 'output.log')
    python_exe = sys.executable
    
    def log(msg):
        try:
            with open(log_file, 'a', encoding='utf-8') as f:
                f.write(f"{msg}\n")
                f.flush()
        except: pass
    
    if not os.path.exists(main_path):
        return None, f"ERROR: {main_file} not found!"
    
    if os.path.exists(log_file):
        try: os.remove(log_file)
        except: open(log_file, 'w').close()
    
    ts = lambda: datetime.now().strftime('%I:%M:%S %p')
    
    server, _ = get_server_by_id(server_id)
    cpu_limit = server.get('cpu_limit', 80) if server else 80
    log(f"[{ts()}] Checking rate limit...")
    log(f"[{ts()}] Rate limit: {cpu_limit}%")
    log("")
    
    if requirements_file and requirements_file.strip():
        req_path = os.path.join(server_dir, requirements_file.strip())
        log(f"[{ts()}] Run: pip install -r {requirements_file}")
        log("")
        
        if os.path.exists(req_path):
            with open(req_path, 'r', encoding='utf-8') as f:
                content = f.read().strip()
            
            lines = [l.strip() for l in content.split('\n') if l.strip() and not l.strip().startswith('#')]
            
            if lines:
                try:
                    proc = subprocess.Popen(
                        [python_exe, '-m', 'pip', 'install', '-r', os.path.abspath(req_path), '--disable-pip-version-check'],
                        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                        text=True, bufsize=1, universal_newlines=True,
                        creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == 'win32' else 0
                    )
                    
                    for line in iter(proc.stdout.readline, ''):
                        if line.strip():
                            log(f"[{ts()}] {line.rstrip()}")
                    
                    proc.wait()
                    log("")
                    
                    if proc.returncode != 0:
                        log(f"[{ts()}] Some packages failed to install")
                    else:
                        log(f"[{ts()}] Requirements installation complete!")
                except Exception as e:
                    log(f"[{ts()}] pip error: {str(e)}")
            else:
                log(f"[{ts()}] {requirements_file} is empty, skipping...")
        else:
            log(f"[{ts()}] {requirements_file} not found, skipping...")
    else:
        log(f"[{ts()}] No requirements file set, skipping...")
    
    log("")
    log(f"[{ts()}] Run: python {main_file}")
    log(f"[{ts()}] Python {sys.version.split()[0]}")
    log("")
    
    try:
        main_path_abs = os.path.abspath(main_path)
        # SECURITY: previously this was `env = os.environ.copy()`, which handed
        # every hosted bot a full copy of THIS APP's environment variables —
        # including SECRET_KEY, ADMIN_PASSWORD, and anything else set on the
        # host. Any bot could read them with a single line: `print(os.environ)`.
        # That is a very plausible way user data/credentials leaked before.
        # Bots now only get a minimal, explicit allowlist of variables.
        SAFE_ENV_ALLOWLIST = ('PATH', 'SYSTEMROOT', 'WINDIR', 'TEMP', 'TMP', 'HOME',
                               'LANG', 'LC_ALL', 'HOSTNAME')
        env = {k: v for k, v in os.environ.items() if k.upper() in SAFE_ENV_ALLOWLIST}
        env['PYTHONIOENCODING'] = 'utf-8'
        env['PYTHONUNBUFFERED'] = '1'
        if server and server.get('port'):
            env['PORT'] = str(server['port'])
            env['BOT_PORT'] = str(server['port'])
            log(f"[{ts()}] Assigned port: {server['port']}")
            log("")
        
        proc = subprocess.Popen(
            [python_exe, main_path_abs],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            cwd=server_dir,
            text=True, encoding='utf-8', errors='replace',
            bufsize=1, env=env, universal_newlines=True,
            creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == 'win32' else 0
        )
        
        log(f"[{ts()}] Server marked as running")
        log(f"[{ts()}] PID: {proc.pid}")
        log("")
        
        def rate_monitor():
            while proc.poll() is None:
                time.sleep(5)
                exceeded, avg_cpu = rate_limiter.check_rate(server_id, cpu_limit)
                if exceeded:
                    log(f"[{datetime.now().strftime('%I:%M:%S %p')}] CPU Limit! {avg_cpu:.1f}% > {cpu_limit}%")
                    proc.terminate()
                    time.sleep(2)
                    if proc.poll() is None: proc.kill()
                    
                    users = load_users()
                    for uname, data in users.items():
                        if uname == 'admin': continue
                        servers = data.get('servers', [])
                        if not isinstance(servers, list): continue
                        for s in servers:
                            if isinstance(s, dict) and s.get('server_id') == server_id:
                                s['status'] = 'stopped'
                                s['pid'] = None
                                s['rate_limit_exceeded'] = True
                                s['stopped_by_user'] = False
                                save_users(users)
                                break
                    break
        
        threading.Thread(target=rate_monitor, daemon=True).start()
        
        def stream_output():
            try:
                with open(log_file, 'a', encoding='utf-8') as f:
                    for line in iter(proc.stdout.readline, ''):
                        if line:
                            line = line.rstrip('\n\r')
                            if line:
                                f.write(f"[{datetime.now().strftime('%I:%M:%S %p')}] {line}\n")
                                f.flush()
            except: pass
        
        threading.Thread(target=stream_output, daemon=True).start()
        
        return proc.pid, None
        
    except Exception as e:
        log(f"[{ts()}] Error: {str(e)}")
        return None, str(e)

def stop_bot_process(pid):
    try:
        if sys.platform == 'win32':
            subprocess.run(['taskkill', '/F', '/PID', str(pid)], capture_output=True)
        else:
            os.kill(pid, 15)
        return True
    except: return False

def monitor_bot(server_id, pid):
    while True:
        try:
            if sys.platform == 'win32':
                result = subprocess.run(['tasklist', '/FI', f'PID eq {pid}'], capture_output=True, text=True)
                if str(pid) not in result.stdout:
                    break
            else:
                try: os.kill(pid, 0)
                except: break
        except: break
        time.sleep(5)
    
    server, _ = get_server_by_id(server_id)
    if not server: return
    if server.get('stopped_by_user'): return
    if server.get('rate_limit_exceeded'): return
    
    if should_auto_restart(server_id):
        time.sleep(3)
        new_pid, error = run_bot(server_id, server.get('main_file', 'main.py'), 
                                 server.get('requirements_file', 'requirements.txt'))
        if new_pid:
            users = load_users()
            for uname, data in users.items():
                if uname == 'admin': continue
                servers = data.get('servers', [])
                if not isinstance(servers, list): continue
                for s in servers:
                    if isinstance(s, dict) and s.get('server_id') == server_id:
                        s['status'] = 'running'
                        s['pid'] = new_pid
                        s['started_at'] = str(datetime.now())
                        s['rate_limit_exceeded'] = False
                        s['stopped_by_user'] = False
                        save_users(users)
                        break
            threading.Thread(target=monitor_bot, args=(server_id, new_pid), daemon=True).start()
    else:
        users = load_users()
        for uname, data in users.items():
            if uname == 'admin': continue
            servers = data.get('servers', [])
            if not isinstance(servers, list): continue
            for s in servers:
                if isinstance(s, dict) and s.get('server_id') == server_id:
                    s['status'] = 'stopped'
                    s['pid'] = None
                    save_users(users)
                    return

def get_process_stats(pid):
    try:
        proc = psutil.Process(pid)
        cpu = proc.cpu_percent(interval=0.5)
        mem = proc.memory_info()
        ram = mem.rss / (1024 * 1024)
        return {
            'cpu_percent': round(cpu, 1),
            'ram_mb': round(ram, 1),
            'ram_display': f"{ram:.1f} MB" if ram < 1024 else f"{ram/1024:.1f} GB",
        }
    except:
        return {'cpu_percent': 0, 'ram_mb': 0, 'ram_display': '0 MB'}

def get_network_stats(psutil_pid):
    try:
        proc = psutil.Process(psutil_pid)
        io = proc.io_counters()
        if io:
            read_kb = io.read_bytes / 1024
            write_kb = io.write_bytes / 1024
            return format_bytes(read_kb), format_bytes(write_kb)
    except: pass
    return "0 KB", "0 KB"

def format_bytes(kb):
    if kb < 1024: return f"{kb:.1f} KB"
    mb = kb / 1024
    if mb < 1024: return f"{mb:.1f} MB"
    gb = mb / 1024
    return f"{gb:.2f} GB"

# ============================================
# 🔥 পাবলিক API - সার্ভার তৈরি
# ============================================

@app.route('/api/create', methods=['GET'])
def api_create_server():
    # Only the admin can provision new hosting accounts - prevents anonymous
    # strangers from spinning up arbitrary public code-execution servers.
    if 'user' not in session or session.get('role') != 'admin':
        return jsonify({'status': 'error', 'message': 'Admin login required to create a server.'}), 403

    username = request.args.get('username', '').strip()
    password = request.args.get('password', '').strip()
    server_type = request.args.get('type', 'python').strip()
    ram = request.args.get('ram', '1GB').strip()
    disk = request.args.get('disk', '1GB').strip()
    cpu_limit = int(request.args.get('cpu', '30'))
    days = int(request.args.get('days', '3'))
    
    if not password:
        password = generate_random_password(10)
    
    if not username:
        username = f"JUBAYER_CODEX{random.randint(10000, 99999)}"
    
    if len(username) < 3:
        return jsonify({'status': 'error', 'message': 'Username must be at least 3 characters!'}), 400
    
    if len(password) < 4:
        return jsonify({'status': 'error', 'message': 'Password must be at least 4 characters!'}), 400
    
    if cpu_limit < 10 or cpu_limit > 100:
        return jsonify({'status': 'error', 'message': 'CPU limit must be between 10 and 100!'}), 400
    
    if days < 1 or days > 365:
        return jsonify({'status': 'error', 'message': 'Days must be between 1 and 365!'}), 400
    
    users = load_users()
    
    if username in users:
        return jsonify({'status': 'error', 'message': f"Username '{username}' already exists!"}), 400
    
    server_id = str(uuid.uuid4())[:8]
    expiry_date = datetime.now() + timedelta(days=days)
    
    create_default_files(get_server_dir(server_id))
    
    port = get_available_port()
    if port is None:
        return jsonify({'status': 'error', 'message': 'No free ports available right now, try again later.'}), 503
    
    host_only = request.host.split(':')[0]
    full_url = f"{host_only}:{port}"
    
    new_server = {
        'server_id': server_id,
        'login_url': f"/{server_id}/login",
        'dashboard_url': f"/{server_id}/home",
        'full_link': full_url,
        'port': port,
        'type': server_type,
        'ram': ram, 'disk': disk,
        'status': 'stopped', 'pid': None,
        'created': str(datetime.now()),
        'expiry': str(expiry_date),
        'main_file': 'main.py',
        'requirements_file': 'requirements.txt',
        'cpu_limit': cpu_limit,
        'rate_limit_exceeded': False,
        'stopped_by_user': False
    }
    
    users[username] = {'password': generate_password_hash(password), 'role': 'user', 'servers': [new_server]}
    save_users(users)
    
    return jsonify({
        'status': 'success',
        'message': 'Panel created successfully!',
        'username': username,
        'password': password,
        'server_type': server_type,
        'ram': ram,
        'disk': disk,
        'cpu_limit': cpu_limit,
        'validity': f'{days} days',
        'expiry_date': expiry_date.strftime('%Y-%m-%d'),
        'port': port,
        'full_url': full_url,
        'server_id': server_id
    }), 200

# ============================================
# রাউটস
# ============================================

@app.route('/')
def index():
    return render_template('landing.html')

@app.route('/landing')
def landing():
    return render_template('landing.html')

LOGIN_ATTEMPTS = {}
LOGIN_MAX_ATTEMPTS = 6
LOGIN_WINDOW_SECONDS = 300

def _client_ip():
    return request.headers.get('X-Forwarded-For', request.remote_addr or 'unknown').split(',')[0].strip()

def _login_is_rate_limited(key):
    now = time.time()
    attempts = [t for t in LOGIN_ATTEMPTS.get(key, []) if now - t < LOGIN_WINDOW_SECONDS]
    LOGIN_ATTEMPTS[key] = attempts
    return len(attempts) >= LOGIN_MAX_ATTEMPTS

def _login_record_failure(key):
    LOGIN_ATTEMPTS.setdefault(key, []).append(time.time())

def _verify_password(stored, provided):
    """Support both new hashed passwords and legacy plaintext ones already in users.json."""
    if not stored:
        return False
    if stored.startswith('pbkdf2:') or stored.startswith('scrypt:'):
        return check_password_hash(stored, provided)
    return stored == provided

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        key = _client_ip()
        if _login_is_rate_limited(key):
            return render_template('login.html', error="Too many attempts. Try again in a few minutes."), 429
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        users = load_users()
        if username == 'admin' and _verify_password(users.get('admin', {}).get('password'), password):
            session.clear()
            session['user'] = 'admin'
            session['role'] = 'admin'
            return redirect(url_for('admin_dashboard'))
        _login_record_failure(key)
        return render_template('login.html', error="Invalid credentials!")
    return render_template('login.html', error=None)

@app.route('/<server_id>/login', methods=['GET', 'POST'])
def server_login(server_id):
    valid, result = check_server_valid(server_id)
    if not valid:
        return render_template('error.html', error_type=result if result else "deleted", server_link=server_id)
    
    if request.method == 'POST':
        key = _client_ip()
        if _login_is_rate_limited(key):
            return render_template('login.html', error="Too many attempts. Try again in a few minutes."), 429
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        users = load_users()
        for uname, data in users.items():
            if uname == 'admin': continue
            servers = data.get('servers', [])
            if not isinstance(servers, list): continue
            for s in servers:
                if isinstance(s, dict) and s.get('server_id') == server_id:
                    if username == uname and _verify_password(data.get('password'), password):
                        session.clear()
                        session['user'] = uname
                        session['role'] = 'user'
                        session['current_server_id'] = server_id
                        return redirect(url_for('server_home', server_id=server_id))
                    else:
                        _login_record_failure(key)
                        return render_template('login.html', error="Invalid credentials!")
        _login_record_failure(key)
        return render_template('login.html', error="Invalid login!")
    return render_template('login.html', error=None)

@app.route('/<server_id>/home')
def server_home(server_id):
    if 'user' not in session or session.get('role') != 'user':
        return redirect(url_for('server_login', server_id=server_id))
    if session.get('current_server_id') != server_id:
        session.clear()
        return redirect(url_for('server_login', server_id=server_id))
    
    valid, result = check_server_valid(server_id)
    if not valid:
        session.clear()
        return render_template('error.html', error_type=result if result else "deleted", server_link=server_id)
    
    return render_template('home.html', username=session['user'], current_server=result)

@app.route('/logout')
def logout():
    server_id = session.get('current_server_id')
    session.clear()
    if server_id:
        return redirect(url_for('server_login', server_id=server_id))
    return redirect(url_for('login'))

# ============================================
# অ্যাডমিন
# ============================================

@app.route('/admin')
def admin_dashboard():
    if 'user' not in session or session.get('role') != 'admin':
        return redirect(url_for('login'))
    users = load_users()
    user_list = []
    total_servers = 0
    total_running = 0
    for uname, data in users.items():
        if uname == 'admin': continue
        servers = data.get('servers', [])
        if not isinstance(servers, list): servers = []
        running = sum(1 for s in servers if isinstance(s, dict) and s.get('status') == 'running')
        total_servers += len(servers)
        total_running += running
        user_list.append({
            'username': uname, 'password': data.get('password', ''),
            'servers': servers, 'server_count': len(servers), 'running_count': running
        })
    return render_template('admin.html', users=user_list, total_servers=total_servers, total_running=total_running)

@app.route('/admin/create_server', methods=['POST'])
def create_server():
    if 'user' not in session or session.get('role') != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
    
    data = request.get_json()
    username = data.get('username', '')
    password = data.get('password', '')
    server_type = data.get('server_type', 'python')
    ram = data.get('ram', '512MB')
    disk = data.get('disk', '1GB')
    expiry_days = int(data.get('expiry_days', 30))
    cpu_limit = int(data.get('cpu_limit', 80))
    
    if not username or not password:
        return jsonify({'error': 'Required!'}), 400
    
    users = load_users()
    server_id = str(uuid.uuid4())[:8]
    expiry_date = datetime.now() + timedelta(days=expiry_days)
    
    create_default_files(get_server_dir(server_id))
    
    port = get_available_port()
    if port is None:
        return jsonify({'error': 'No free ports available right now, try again later.'}), 503
    
    host_only = request.host.split(':')[0]
    full_url = f"{host_only}:{port}"
    
    new_server = {
        'server_id': server_id, 'link': server_id,
        'login_url': f"/{server_id}/login",
        'dashboard_url': f"/{server_id}/home",
        'full_link': full_url,
        'port': port,
        'type': server_type, 'ram': ram, 'disk': disk,
        'status': 'stopped', 'pid': None,
        'created': str(datetime.now()), 'expiry': str(expiry_date),
        'main_file': 'main.py', 'requirements_file': 'requirements.txt',
        'cpu_limit': cpu_limit, 'rate_limit_exceeded': False, 'stopped_by_user': False
    }
    
    if username not in users:
        users[username] = {'password': generate_password_hash(password), 'role': 'user', 'servers': []}
    elif not _verify_password(users[username].get('password'), password):
        # existing username but admin supplied a different password for this new server:
        # update it so the returned credentials are actually correct.
        users[username]['password'] = generate_password_hash(password)
    
    users[username]['servers'].append(new_server)
    save_users(users)
    
    return jsonify({
        'success': True, 'username': username, 'password': password,
        'login_url': new_server['login_url'],
        'port': port,
        'hostname': new_server['full_link'],
        'server_id': server_id
    })

@app.route('/admin/set_rate_limit/<server_id>', methods=['POST'])
def set_rate_limit(server_id):
    if 'user' not in session or session.get('role') != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
    cpu_limit = int(request.get_json().get('cpu_limit', 80))
    users = load_users()
    for uname, udata in users.items():
        if uname == 'admin': continue
        servers = udata.get('servers', [])
        if not isinstance(servers, list): continue
        for s in servers:
            if isinstance(s, dict) and s.get('server_id') == server_id:
                s['cpu_limit'] = cpu_limit
                save_users(users)
                return jsonify({'success': True, 'cpu_limit': cpu_limit})
    return jsonify({'error': 'Not found'}), 404

@app.route('/admin/reset_password/<username>', methods=['POST'])
@require_admin
def admin_reset_password(username):
    users = load_users()
    if username not in users or username == 'admin':
        return jsonify({'status': 'error', 'msg': 'User not found'}), 404
    new_password = generate_random_password(12)
    users[username]['password'] = generate_password_hash(new_password)
    save_users(users)
    return jsonify({'status': 'success', 'new_password': new_password})

@app.route('/admin/delete_server/<username>/<server_id>', methods=['POST'])
def delete_server(username, server_id):
    if 'user' not in session or session.get('role') != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
    users = load_users()
    if username in users:
        servers = users[username].get('servers', [])
        if not isinstance(servers, list): servers = []
        for s in servers:
            if isinstance(s, dict) and s.get('server_id') == server_id:
                if s.get('pid'): stop_bot_process(s['pid'])
                try: shutil.rmtree(get_server_dir(server_id))
                except: pass
                break
        users[username]['servers'] = [s for s in servers if isinstance(s, dict) and s.get('server_id') != server_id]
        if len(users[username]['servers']) == 0:
            del users[username]
        save_users(users)
    return jsonify({'success': True})

# ============================================
# বট API
# ============================================

@app.route('/api/run/<server_id>', methods=['POST'])
@require_server_access
def api_run(server_id):
    server, _ = get_server_by_id(server_id)
    if not server: return jsonify({'status': 'error', 'msg': 'Not found'})
    if server.get('status') == 'running': return jsonify({'status': 'error', 'msg': 'Already running!'})
    
    server['rate_limit_exceeded'] = False
    server['stopped_by_user'] = False
    
    pid, error = run_bot(server_id, server.get('main_file', 'main.py'), server.get('requirements_file', 'requirements.txt'))
    
    if pid:
        users = load_users()
        for uname, data in users.items():
            if uname == 'admin': continue
            servers = data.get('servers', [])
            if not isinstance(servers, list): continue
            for s in servers:
                if isinstance(s, dict) and s.get('server_id') == server_id:
                    s['status'] = 'running'
                    s['pid'] = pid
                    s['started_at'] = str(datetime.now())
                    save_users(users)
                    break
        threading.Thread(target=monitor_bot, args=(server_id, pid), daemon=True).start()
        return jsonify({'status': 'success', 'msg': 'Started!'})
    return jsonify({'status': 'error', 'msg': error or 'Failed'})

@app.route('/api/stop/<server_id>', methods=['POST'])
@require_server_access
def api_stop(server_id):
    server, _ = get_server_by_id(server_id)
    if not server: return jsonify({'status': 'error', 'msg': 'Not found'})
    
    if server.get('pid'): stop_bot_process(server['pid'])
    
    users = load_users()
    for uname, data in users.items():
        if uname == 'admin': continue
        servers = data.get('servers', [])
        if not isinstance(servers, list): continue
        for s in servers:
            if isinstance(s, dict) and s.get('server_id') == server_id:
                s['status'] = 'stopped'
                s['pid'] = None
                s['stopped_by_user'] = True
                save_users(users)
                break
    
    log_file = os.path.join(get_server_dir(server_id), 'output.log')
    try:
        with open(log_file, 'a', encoding='utf-8') as f:
            f.write(f"\n[{datetime.now().strftime('%I:%M:%S %p')}] Server stopped by user\n")
    except: pass
    
    return jsonify({'status': 'success', 'msg': 'Stopped'})

@app.route('/api/logs/<server_id>')
@require_server_access
def api_logs(server_id):
    log_file = os.path.join(get_server_dir(server_id), 'output.log')
    if os.path.exists(log_file):
        with open(log_file, 'r', encoding='utf-8') as f: logs = f.read()
    else: logs = ""
    return jsonify({'logs': logs})

@app.route('/api/clear_logs/<server_id>', methods=['POST'])
@require_server_access
def api_clear_logs(server_id):
    log_file = os.path.join(get_server_dir(server_id), 'output.log')
    try:
        if os.path.exists(log_file):
            try: os.remove(log_file)
            except: open(log_file, 'w').close()
        return jsonify({'status': 'success', 'msg': 'Cleared'})
    except: return jsonify({'status': 'error'}), 500

@app.route('/api/command', methods=['POST'])
@require_server_access
def api_command():
    # SECURITY: this endpoint runs an arbitrary shell command and, before this fix,
    # had NO login check at all — anyone on the internet could run shell commands
    # inside ANY server's folder (including reading users.json, other users' bot
    # files, etc.) without ever logging in. It is now gated by require_server_access,
    # same as every other server-scoped API below.
    data = request.get_json()
    cmd = data.get('cmd', '')
    server_id = data.get('server_id', '')
    log_file = os.path.join(get_server_dir(server_id), 'output.log')
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, cwd=get_server_dir(server_id), timeout=30,
                              creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == 'win32' else 0)
        output = (result.stdout + result.stderr)[:2000]
        with open(log_file, 'a', encoding='utf-8') as f:
            f.write(f"[{datetime.now().strftime('%I:%M:%S %p')}] $ {cmd}\n{output}\n")
        return jsonify({'status': 'success', 'output': output})
    except: return jsonify({'status': 'error', 'msg': 'Timeout'})

@app.route('/api/stats/<server_id>')
@require_server_access
def api_stats(server_id):
    server, _ = get_server_by_id(server_id)
    if not server:
        return jsonify({'cpu': '0%', 'ram': '0 MB', 'uptime': '0h', 'status': 'unknown', 'cpu_limit': 80, 'net_in': '0 KB', 'net_out': '0 KB'})
    
    uptime, cpu, ram, net_in, net_out = "0h 0m", "0%", "0 MB", "0 KB", "0 KB"
    
    if server.get('status') == 'running' and server.get('pid'):
        stats = get_process_stats(server['pid'])
        cpu = f"{stats['cpu_percent']}%"
        ram = stats['ram_display']
        net_in, net_out = get_network_stats(server['pid'])
    
    if server.get('status') == 'running' and server.get('started_at'):
        try:
            start = datetime.strptime(server['started_at'], '%Y-%m-%d %H:%M:%S.%f')
            diff = datetime.now() - start
            if diff.days > 0: uptime = f"{diff.days}d {diff.seconds//3600}h"
            else:
                h, m, s = diff.seconds // 3600, (diff.seconds % 3600) // 60, diff.seconds % 60
                uptime = f"{h}h {m}m {s}s"
        except: pass
    
    return jsonify({'cpu': cpu, 'ram': ram, 'uptime': uptime, 'net_in': net_in, 'net_out': net_out, 'cpu_limit': server.get('cpu_limit', 80), 'status': server.get('status', 'stopped')})

# ============================================
# পাসওয়ার্ড চেঞ্জ
# ============================================

@app.route('/api/change_password/<server_id>', methods=['POST'])
@require_server_access
def api_change_password(server_id):
    data = request.get_json()
    current_password = data.get('current_password', '')
    new_password = data.get('new_password', '')
    
    if not current_password or not new_password: return jsonify({'error': 'All fields are required!'})
    if len(new_password) < 4: return jsonify({'error': 'Password must be at least 4 characters!'})
    
    users = load_users()
    username = session.get('user')
    
    if username in users:
        if _verify_password(users[username].get('password'), current_password):
            users[username]['password'] = generate_password_hash(new_password)
            save_users(users)
            return jsonify({'success': True, 'msg': 'Password changed!'})
        return jsonify({'error': 'Current password is incorrect!'})
    return jsonify({'error': 'User not found!'}), 404

# ============================================
# 🔥 GITHUB API (Git ছাড়া Python Download)
# ============================================

@app.route('/api/github/deploy/<server_id>', methods=['POST'])
@require_server_access
def api_github_deploy(server_id):
    """Download GitHub repo without git - using Python requests"""
    data = request.get_json()
    repo_url = data.get('repo_url', '').strip()
    access_token = data.get('access_token', '').strip()
    is_private = data.get('is_private', False)
    
    if not repo_url:
        return jsonify({'status': 'error', 'msg': 'Repository URL is required!'}), 400
    
    server_dir = get_server_dir(server_id)
    log_file = os.path.join(server_dir, 'github_deploy.log')
    
    # Clear old deploy log
    try:
        with open(log_file, 'w', encoding='utf-8') as f:
            f.write(f"[{datetime.now().strftime('%I:%M:%S %p')}] Starting GitHub deployment...\n")
            f.write(f"[{datetime.now().strftime('%I:%M:%S %p')}] Repository: {repo_url}\n")
            f.write(f"[{datetime.now().strftime('%I:%M:%S %p')}] Type: {'Private' if is_private else 'Public'}\n")
            f.write("─" * 40 + "\n")
    except:
        pass
    
    def deploy_thread():
        try:
            import requests
            import shutil
            
            def deploy_log(msg):
                try:
                    with open(log_file, 'a', encoding='utf-8') as f:
                        f.write(f"[{datetime.now().strftime('%I:%M:%S %p')}] {msg}\n")
                        f.flush()
                except:
                    pass
            
            deploy_log("Preparing deployment...")
            
            # Parse GitHub URL → owner/repo/branch
            # Support: https://github.com/user/repo or https://github.com/user/repo.git
            # Also: https://github.com/user/repo/tree/branch
            
            clean_url = repo_url.replace('.git', '').rstrip('/')
            
            # Extract owner and repo
            if 'github.com' not in clean_url:
                deploy_log("❌ Error: Only GitHub URLs are supported!")
                return
            
            parts = clean_url.split('github.com/')[-1].split('/')
            
            if len(parts) < 2:
                deploy_log("❌ Error: Invalid GitHub URL format!")
                return
            
            owner = parts[0]
            repo = parts[1]
            branch = 'main'  # default branch
            
            # Check if branch is specified (tree/branch_name)
            if len(parts) > 3 and parts[2] == 'tree':
                branch = parts[3]
            
            deploy_log(f"Owner: {owner}")
            deploy_log(f"Repository: {repo}")
            deploy_log(f"Branch: {branch}")
            deploy_log(f"Downloading ZIP archive...")
            
            # Build API URL
            api_url = f"https://api.github.com/repos/{owner}/{repo}/zipball/{branch}"
            
            headers = {'Accept': 'application/vnd.github.v3+json'}
            if is_private and access_token:
                headers['Authorization'] = f'token {access_token}'
                deploy_log("Using access token for authentication")
            
            # Download ZIP
            response = requests.get(api_url, headers=headers, stream=True, timeout=60)
            
            if response.status_code == 200:
                deploy_log("✓ Repository downloaded successfully!")
                deploy_log("Extracting files...")
                
                # Save to temp zip
                temp_zip = os.path.join(server_dir, '_github_temp.zip')
                with open(temp_zip, 'wb') as f:
                    for chunk in response.iter_content(chunk_size=8192):
                        f.write(chunk)
                
                # Extract
                try:
                    with zipfile.ZipFile(temp_zip, 'r') as zf:
                        # GitHub zipball has a root folder like: owner-repo-commit_hash
                        # Extract everything inside that folder
                        root_folder = zf.namelist()[0].split('/')[0]
                        
                        for member in zf.namelist():
                            # Skip the root folder
                            relative_path = '/'.join(member.split('/')[1:])
                            if not relative_path:
                                continue

                            # SECURITY: zip-slip guard — reject any entry that would
                            # extract outside server_dir (e.g. via '../' in the archive).
                            if not is_zip_member_safe(server_dir, relative_path):
                                deploy_log(f"  Skipped unsafe path: {relative_path}")
                                continue

                            target_path = os.path.join(server_dir, relative_path)
                            
                            if member.endswith('/'):
                                # Directory
                                os.makedirs(target_path, exist_ok=True)
                            else:
                                # File
                                os.makedirs(os.path.dirname(target_path), exist_ok=True)
                                with zf.open(member) as source, open(target_path, 'wb') as target:
                                    shutil.copyfileobj(source, target)
                                deploy_log(f"  ✓ {relative_path}")
                    
                    deploy_log("")
                    deploy_log("✅ Deployment completed successfully!")
                    deploy_log(f"Files extracted to: {server_dir}")
                    
                except Exception as e:
                    deploy_log(f"❌ Extraction error: {str(e)}")
                finally:
                    # Clean up temp zip
                    try:
                        os.remove(temp_zip)
                    except:
                        pass
                    
            elif response.status_code == 404:
                deploy_log("❌ Error: Repository not found!")
                deploy_log("Check if the URL is correct and the repo is accessible")
            elif response.status_code == 401:
                deploy_log("❌ Error: Authentication failed!")
                deploy_log("Check your access token (for private repos)")
            elif response.status_code == 403:
                deploy_log("❌ Error: Rate limit exceeded or access denied!")
                deploy_log("Try again later or use an access token")
            else:
                deploy_log(f"❌ Error: HTTP {response.status_code}")
                deploy_log(f"Response: {response.text[:200]}")
            
        except requests.exceptions.Timeout:
            try:
                with open(log_file, 'a', encoding='utf-8') as f:
                    f.write(f"[{datetime.now().strftime('%I:%M:%S %p')}] ❌ Error: Connection timeout! Check your internet.\n")
            except:
                pass
        except Exception as e:
            try:
                with open(log_file, 'a', encoding='utf-8') as f:
                    f.write(f"[{datetime.now().strftime('%I:%M:%S %p')}] ❌ Error: {str(e)}\n")
            except:
                pass
    
    threading.Thread(target=deploy_thread, daemon=True).start()
    return jsonify({'status': 'success', 'msg': 'Deployment started! Check terminal for progress.'})

@app.route('/api/github/logs/<server_id>')
@require_server_access
def api_github_logs(server_id):
    """Get GitHub deployment logs"""
    log_file = os.path.join(get_server_dir(server_id), 'github_deploy.log')
    if os.path.exists(log_file):
        try:
            with open(log_file, 'r', encoding='utf-8') as f:
                logs = f.read()
        except:
            logs = "> Ready for deployment..."
    else:
        logs = "> Ready for deployment..."
    return jsonify({'logs': logs})

@app.route('/api/github/clear_logs/<server_id>', methods=['POST'])
@require_server_access
def api_github_clear_logs(server_id):
    """Clear GitHub deployment logs"""
    log_file = os.path.join(get_server_dir(server_id), 'github_deploy.log')
    try:
        if os.path.exists(log_file):
            os.remove(log_file)
        return jsonify({'status': 'success'})
    except:
        return jsonify({'status': 'error'}), 500

# ============================================
# ফাইল API
# ============================================

@app.route('/api/files/<server_id>')
@require_server_access
def api_files(server_id):
    folder = request.args.get('folder', '')
    base_dir = get_server_dir(server_id)
    server_dir = safe_join(base_dir, folder) if folder else base_dir
    if server_dir is None:
        return jsonify({'files': []}), 400
    if not os.path.exists(server_dir): return jsonify({'files': []})
    
    files = []
    try:
        for item in os.listdir(server_dir):
            item_path = os.path.join(server_dir, item)
            files.append({'name': item, 'is_dir': os.path.isdir(item_path), 'size': os.path.getsize(item_path) if os.path.isfile(item_path) else 0, 'modified': datetime.fromtimestamp(os.path.getmtime(item_path)).strftime('%Y-%m-%d %H:%M')})
    except: pass
    return jsonify({'files': files})

@app.route('/api/file/<server_id>', methods=['GET'])
@require_server_access
def api_get_file(server_id):
    filename = request.args.get('filename', '')
    filepath = safe_join(get_server_dir(server_id), filename)
    if filepath is None:
        return jsonify({'error': 'Invalid path'}), 400
    if os.path.exists(filepath) and os.path.isfile(filepath):
        with open(filepath, 'r', encoding='utf-8') as f: return jsonify({'content': f.read()})
    return jsonify({'error': 'Not found'}), 404

@app.route('/api/file/<server_id>', methods=['POST'])
@require_server_access
def api_save_file(server_id):
    data = request.get_json()
    filepath = safe_join(get_server_dir(server_id), data.get('filename', ''))
    if filepath is None:
        return jsonify({'error': 'Invalid path'}), 400
    content = data.get('content', '')
    verdict, reasons = scan_uploaded_source(content, data.get('filename', ''))
    if verdict == 'block':
        return jsonify({'error': 'This file was blocked: it contains code that reads a known '
                                  'credential-store location (browser/Discord/Telegram token '
                                  'storage) or tries to reach the shared users.json. If this is '
                                  'a false positive, contact the admin.', 'reasons': reasons}), 400
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    with open(filepath, 'w', encoding='utf-8') as f: f.write(content)
    return jsonify({'success': True})

@app.route('/api/file/<server_id>', methods=['DELETE'])
@require_server_access
def api_delete_file(server_id):
    data = request.get_json()
    filepath = safe_join(get_server_dir(server_id), data.get('filename', ''))
    if filepath is None:
        return jsonify({'error': 'Invalid path'}), 400
    if os.path.exists(filepath):
        if os.path.isdir(filepath): shutil.rmtree(filepath)
        else: os.remove(filepath)
    return jsonify({'success': True})

@app.route('/api/upload/<server_id>', methods=['POST'])
@require_server_access
def api_upload(server_id):
    if 'file' not in request.files: return jsonify({'error': 'No file'}), 400
    folder = request.form.get('folder', '')
    base_dir = get_server_dir(server_id)
    server_dir = safe_join(base_dir, folder) if folder else base_dir
    if server_dir is None:
        return jsonify({'error': 'Invalid path'}), 400
    os.makedirs(server_dir, exist_ok=True)
    file = request.files['file']
    # SECURITY: sanitize the filename the browser sent us — raw file.filename can
    # contain '../' or an absolute path and was previously used unmodified.
    safe_name = secure_filename(file.filename) or f"upload_{uuid.uuid4().hex[:8]}"
    ext = os.path.splitext(safe_name)[1].lower()
    if ext in BLOCKED_UPLOAD_EXTENSIONS:
        return jsonify({'error': f'File type {ext} is not allowed'}), 400
    if ext == '.py':
        try:
            raw = file.read()
            text = raw.decode('utf-8', errors='replace')
            file.seek(0)
        except Exception:
            text = ''
        verdict, reasons = scan_uploaded_source(text, safe_name)
        if verdict == 'block':
            return jsonify({'error': 'This file was blocked: it contains code that reads a known '
                                      'credential-store location (browser/Discord/Telegram token '
                                      'storage) or tries to reach the shared users.json.',
                             'reasons': reasons}), 400
    dest = safe_join(server_dir, safe_name)
    if dest is None:
        return jsonify({'error': 'Invalid filename'}), 400
    file.save(dest)
    return jsonify({'success': True})

@app.route('/api/create_folder/<server_id>', methods=['POST'])
@require_server_access
def api_create_folder(server_id):
    data = request.get_json()
    folder_path = safe_join(get_server_dir(server_id), data.get('foldername', ''))
    if folder_path is None:
        return jsonify({'error': 'Invalid path'}), 400
    os.makedirs(folder_path, exist_ok=True)
    return jsonify({'success': True})

@app.route('/api/rename/<server_id>', methods=['POST'])
@require_server_access
def api_rename(server_id):
    d = request.get_json()
    server_dir = get_server_dir(server_id)
    old_path = safe_join(server_dir, d.get('old_name', ''))
    new_path = safe_join(server_dir, d.get('new_name', ''))
    if old_path is None or new_path is None:
        return jsonify({'error': 'Invalid path'}), 400
    if os.path.exists(old_path):
        os.rename(old_path, new_path)
        return jsonify({'success': True})
    return jsonify({'error': 'Not found'}), 404

@app.route('/api/unzip/<server_id>', methods=['POST'])
@require_server_access
def api_unzip(server_id):
    data = request.get_json()
    server_dir = get_server_dir(server_id)
    zip_path = safe_join(server_dir, data.get('filename', ''))
    if zip_path is None:
        return jsonify({'status': 'error', 'msg': 'Invalid path'}), 400
    if os.path.exists(zip_path) and zip_path.endswith('.zip'):
        try:
            flagged = []
            with zipfile.ZipFile(zip_path, 'r') as zf:
                extract_dir = os.path.dirname(zip_path)
                for member in zf.namelist():
                    # SECURITY: zip-slip guard, same reasoning as the GitHub deploy path.
                    if not is_zip_member_safe(extract_dir, member):
                        continue
                    if member.lower().endswith('.py') and not member.endswith('/'):
                        try:
                            src = zf.read(member).decode('utf-8', errors='replace')
                        except Exception:
                            src = ''
                        verdict, reasons = scan_uploaded_source(src, member)
                        if verdict == 'block':
                            flagged.append(member)
                            continue  # skip extracting this specific file
                    zf.extract(member, extract_dir)
            if flagged:
                return jsonify({'status': 'warning',
                                 'msg': f"Extracted, but skipped {len(flagged)} file(s) that looked like "
                                        f"credential grabbers: {', '.join(flagged)}"})
            return jsonify({'status': 'success', 'msg': 'Extracted!'})
        except Exception as e: return jsonify({'status': 'error', 'msg': str(e)})
    return jsonify({'status': 'error', 'msg': 'Invalid zip'}), 400

@app.route('/api/download/<server_id>')
@require_server_access
def api_download(server_id):
    filename = request.args.get('filename', '')
    server_dir = get_server_dir(server_id)
    target_path = os.path.join(server_dir, filename)

    # Prevent path traversal outside the server's own directory
    if not os.path.abspath(target_path).startswith(os.path.abspath(server_dir)):
        return jsonify({'error': 'Invalid path'}), 400

    if not os.path.exists(target_path):
        return jsonify({'error': 'Not found'}), 404

    if os.path.isdir(target_path):
        # Zip the folder on the fly so folders can be downloaded too
        base_name = os.path.basename(target_path.rstrip('/\\')) or 'folder'
        temp_zip = os.path.join(server_dir, f"_download_{base_name}.zip")
        try:
            if os.path.exists(temp_zip):
                os.remove(temp_zip)
            with zipfile.ZipFile(temp_zip, 'w', zipfile.ZIP_DEFLATED) as zf:
                for root, dirs, files in os.walk(target_path):
                    for f in files:
                        fp = os.path.join(root, f)
                        if os.path.abspath(fp) == os.path.abspath(temp_zip):
                            continue
                        arcname = os.path.join(base_name, os.path.relpath(fp, target_path))
                        zf.write(fp, arcname)
            return send_file(temp_zip, as_attachment=True, download_name=f"{base_name}.zip")
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    else:
        return send_file(target_path, as_attachment=True, download_name=os.path.basename(target_path))

@app.route('/api/get_startup/<server_id>')
@require_server_access
def api_get_startup(server_id):
    server, _ = get_server_by_id(server_id)
    if server: return jsonify({'main_file': server.get('main_file', 'main.py'), 'requirements_file': server.get('requirements_file', 'requirements.txt')})
    return jsonify({'main_file': 'main.py', 'requirements_file': 'requirements.txt'})

@app.route('/api/set_startup/<server_id>', methods=['POST'])
@require_server_access
def api_set_startup(server_id):
    d = request.get_json()
    users = load_users()
    for uname, udata in users.items():
        if uname == 'admin': continue
        servers = udata.get('servers', [])
        if not isinstance(servers, list): continue
        for s in servers:
            if isinstance(s, dict) and s.get('server_id') == server_id:
                s['main_file'] = d.get('main_file', 'main.py')
                s['requirements_file'] = d.get('requirements_file')
                save_users(users)
                return jsonify({'success': True})
    return jsonify({'error': 'Not found'}), 404

# ============================================
# স্টার্ট
# ============================================

if __name__ == '__main__':
    print("\n" + "=" * 50)
    print("🚀 JUBAYER HOSTING - FINAL")
    print("=" * 50)
    print("📍 Landing: http://localhost:5000")
    print("📍 Admin: http://localhost:5000/login")
    print("🔗 API: http://localhost:5000/api/create")
    print("👤 admin password: see 'FIRST RUN' message printed above (or set ADMIN_PASSWORD env var)")
    print("=" * 50 + "\n")
    # SECURITY: debug=True exposes the Werkzeug interactive debugger, which allows
    # arbitrary remote code execution to anyone who can trigger an unhandled
    # exception on the site. It must never be on for anything reachable by users.
    # Set FLASK_DEBUG=1 explicitly only for local development.
    debug_mode = os.environ.get('FLASK_DEBUG', '0') == '1'
    app.run(debug=debug_mode, host='0.0.0.0', port=int(os.environ.get('PORT', 20022)))