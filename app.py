import base64
import hashlib
import hmac
import html
import io
import json
import os
import re
import secrets
import shutil
import ssl
import sqlite3
import subprocess
import threading
import time
import zipfile
from datetime import datetime
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse
from urllib.request import Request, urlopen
import urllib.request

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = Path(os.environ.get("DATA_DIR", "/data")).resolve()
try:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
except Exception:
    DATA_DIR = BASE_DIR
DB_PATH = DATA_DIR / "ssl_manager.db"
DEFAULT_ACME_HOME = Path(os.environ.get("ACME_HOME", str(Path.home() / ".acme.sh")))
ACME_CHALLENGE_ROOT = DATA_DIR / "acme-webroot"
NGINX_DEFAULT_CONF = Path(os.environ.get("NGINX_DEFAULT_CONF", "/www/server/panel/vhost/nginx/0.default.conf"))
ACME_PROXY_PORT = (os.environ.get("ACME_PROXY_PORT") or os.environ.get("PORT") or "8080").strip()
BATCH_LOCK = threading.Lock()
BATCH_RUNNING = False
BATCH_STATE = {}
BATCH_MAX_LINES = 200


def batch_append_line(line):
    text = (line or "").strip()
    if not text:
        return
    with BATCH_LOCK:
        if not isinstance(BATCH_STATE, dict):
            return
        lines = BATCH_STATE.get("lines")
        if not isinstance(lines, list):
            lines = []
            BATCH_STATE["lines"] = lines
        lines.append(text)
        if len(lines) > BATCH_MAX_LINES:
            del lines[: len(lines) - BATCH_MAX_LINES]
        BATCH_STATE["updated_at"] = datetime.utcnow().isoformat()


def load_app_secret():
    env = (os.environ.get("APP_SECRET") or "").strip()
    if env:
        return env.encode()
    secret_file = DATA_DIR / "app_secret"
    if secret_file.exists():
        try:
            val = secret_file.read_text("utf-8", errors="ignore").strip()
            if val:
                return val.encode()
        except Exception:
            pass
    val = secrets.token_urlsafe(48)
    try:
        secret_file.write_text(val, encoding="utf-8")
    except Exception:
        pass
    return val.encode()


APP_SECRET = load_app_secret()

EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")
DOMAIN_RE = re.compile(r"^(\*\.)?[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$")
SITE_RE = re.compile(r"^[A-Za-z0-9._-]+$")

def build_nginx_default_conf_for_acme(proxy_port):
    port = str(proxy_port or "").strip()
    if not port.isdigit():
        port = "8080"
    return (
        "server\n"
        "{\n"
        "    listen 80;\n"
        "    server_name _;\n"
        "\n"
        "    location ^~ /.well-known/acme-challenge/ {\n"
        f"        proxy_pass http://127.0.0.1:{port};\n"
        "        proxy_set_header Host $host;\n"
        "        proxy_set_header X-Real-IP $remote_addr;\n"
        "    }\n"
        "\n"
        "    index index.html;\n"
        "    root /www/server/nginx/html;\n"
        "}\n"
    )


def nginx_default_has_acme_proxy(text):
    return nginx_conf_has_acme_proxy(text)


def bt_try_reload_nginx(panel):
    if not panel:
        return False, "未配置宝塔面板 API"
    actions = [
        ("/ajax", "ReloadNginx"),
        ("/ajax", "NginxReload"),
        ("/ajax", "RestartNginx"),
        ("/ajax", "ReloadWeb"),
        ("/ajax", "RestartWeb"),
        ("/system", "RestartWeb"),
        ("/system", "ReloadWeb"),
        ("/system", "RestartNginx"),
        ("/system", "ReloadNginx"),
        ("/system", "NginxReload"),
        ("/config", "ReloadNginx"),
        ("/config", "NginxReload"),
        ("/config", "RestartWeb"),
        ("/config", "ReloadWeb"),
    ]
    for path, action in actions:
        ok, status, body, _attempted, _meta = panel_api_request(panel, path, {"action": action})
        if not ok:
            continue
        if status == 200 and (body is None or (isinstance(body, str) and body.strip() in {"", "null", "none", "true", "1"})):
            return True, action
        try:
            data = json.loads(body)
        except Exception:
            data = None
        if isinstance(data, dict) and data.get("status") is True:
            return True, action
        if status == 200 and ("success" in (body or "").lower() or "ok" in (body or "").lower()):
            return True, action
    return False, "宝塔未提供可用的重载接口（请手动重载 Nginx）"


def apply_nginx_default_acme_proxy():
    conf_path = NGINX_DEFAULT_CONF
    try:
        if not conf_path.exists():
            return False, f"未找到默认站点文件：{conf_path}"
        if not os.access(str(conf_path), os.R_OK | os.W_OK):
            return False, f"无权限写入：{conf_path}（如使用 Docker，请将 /www/server/panel/vhost/nginx 以 rw 挂载进容器）"
        old = conf_path.read_text("utf-8", errors="ignore")
        new = build_nginx_default_conf_for_acme(ACME_PROXY_PORT)
        if old.strip() == new.strip():
            ok_reload, msg_reload = reload_nginx_best_effort()
            return (True, f"配置已存在，已触发重载（{msg_reload}）" if ok_reload else f"配置已存在（请手动重载 Nginx）：{msg_reload}")
        backup_dir = DATA_DIR / "nginx-default-backups"
        backup_dir.mkdir(parents=True, exist_ok=True)
        stamp = datetime.utcnow().strftime("%Y%m%d%H%M%S")
        (backup_dir / f"0.default.conf.{stamp}.bak").write_text(old, encoding="utf-8")
        conf_path.write_text(new, encoding="utf-8")
        ok_reload, msg_reload = reload_nginx_best_effort()
        if ok_reload:
            return True, f"已写入并触发重载（{msg_reload}）"
        return True, f"已写入（请手动重载 Nginx）：{msg_reload}"
    except Exception as e:
        return False, str(e)


def _acme_location_block(port):
    p = str(port or "").strip()
    if not p.isdigit():
        p = "8080"
    return (
        "    location ^~ /.well-known/acme-challenge/ {\n"
        f"        proxy_pass http://127.0.0.1:{p};\n"
        "        proxy_set_header Host $host;\n"
        "        proxy_set_header X-Real-IP $remote_addr;\n"
        "    }\n"
    )


def nginx_conf_has_acme_proxy(text):
    if not text:
        return False
    cleaned_lines = []
    for ln in (text or "").splitlines():
        if "#" in ln:
            ln = ln.split("#", 1)[0]
        cleaned_lines.append(ln)
    cleaned = "\n".join(cleaned_lines)
    if not re.search(r"location\s+\^~\s+/.well-known/acme-challenge/", cleaned):
        return False
    if "proxy_pass" not in cleaned:
        return False
    return True


def reload_nginx_best_effort():
    ok, msg = bt_try_reload_nginx(get_local_panel_config())
    if ok:
        return True, msg
    ok2, out2 = run_command(["nginx", "-s", "reload"])
    if ok2:
        return True, "nginx -s reload"
    ok3, out3 = run_command(["systemctl", "reload", "nginx"])
    if ok3:
        return True, "systemctl reload nginx"
    detail = ""
    if out2:
        detail += f" nginx={out2.strip()}"
    if out3:
        detail += f" systemctl={out3.strip()}"
    return False, (msg or "reload failed") + (f" ({detail.strip()})" if detail.strip() else "")


def _nginx_strip_comments(text):
    out = []
    for ln in (text or "").splitlines():
        if "#" in ln:
            ln = ln.split("#", 1)[0]
        out.append(ln)
    return "\n".join(out)


def patch_nginx_conf_for_domain(text, domain):
    d = (domain or "").strip().lower()
    if not d:
        return None, 0, "no domain"
    src = text or ""
    cleaned = _nginx_strip_comments(src)
    block = _acme_location_block(ACME_PROXY_PORT)
    res = []
    i = 0
    n = len(src)
    patched = 0
    any_server = False
    matched_blocks = 0
    while i < n:
        m = re.search(r"(?m)^\s*server\s*(\{|\r?$)", src[i:])
        if not m:
            res.append(src[i:])
            break
        start = i + m.start()
        res.append(src[i:start])
        m2 = re.search(r"\{", src[start:])
        if not m2:
            res.append(src[start:])
            break
        any_server = True
        brace_pos = start + m2.start()
        depth = 0
        j = brace_pos
        while j < n:
            ch = src[j]
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    j += 1
                    break
            j += 1
        server_block = src[start:j]
        server_clean = _nginx_strip_comments(server_block)
        matched = False
        for sm in re.finditer(r"server_name\s+([^;]+);", server_clean, flags=re.IGNORECASE):
            for nm in split_domain_field(sm.group(1)):
                nml = nm.lower()
                if nml == d:
                    matched = True
                    break
                if nml.startswith("*.") and d.endswith(nml[1:]):
                    matched = True
                    break
            if matched:
                break
        if not matched:
            res.append(server_block)
            i = j
            continue
        matched_blocks += 1
        if nginx_conf_has_acme_proxy(server_clean):
            res.append(server_block)
            i = j
            continue
        ins = None
        mname = re.search(r"(?m)^[ \t]*server_name\s+[^;]+;\s*$", server_block)
        if mname:
            ins = mname.end()
        else:
            mopen = re.search(r"\{", server_block)
            if mopen:
                ins = mopen.end()
        if ins is None:
            res.append(server_block)
            i = j
            continue
        new_block = server_block[:ins] + "\n" + block + server_block[ins:]
        res.append(new_block)
        patched += 1
        i = j
    if patched:
        return "".join(res), patched, "patched"
    if matched_blocks:
        return src, 0, "exists"
    if any_server:
        return src, 0, "no matched server block"
    return src, 0, "no server block"


def inject_acme_location_into_nginx_conf(text):
    if nginx_conf_has_acme_proxy(text):
        return None, "exists"
    block = _acme_location_block(ACME_PROXY_PORT)
    m = re.search(r"(?m)^\s*server\s*\{\s*$", text)
    if m:
        insert_at = m.end()
        return text[:insert_at] + "\n" + block + text[insert_at:], "after server{"
    m = re.search(r"(?m)^\s*server\s*$\r?\n\s*\{\s*$", text)
    if m:
        insert_at = m.end()
        return text[:insert_at] + "\n" + block + text[insert_at:], "after server\\n{"
    m = re.search(r"(?m)^[ \t]*server_name\s+[^;]+;\s*$", text)
    if m:
        insert_at = m.end()
        return text[:insert_at] + "\n" + block + text[insert_at:], "after server_name"
    m = re.search(r"(?m)^[ \t]*listen\s+[^;]+;\s*$", text)
    if m:
        insert_at = m.end()
        return text[:insert_at] + "\n" + block + text[insert_at:], "after listen"
    low = (text or "").lower()
    pos = low.find("server")
    if pos >= 0:
        brace = text.find("{", pos)
        if brace >= 0:
            insert_at = brace + 1
            return text[:insert_at] + "\n" + block + text[insert_at:], "after first {"
    return None, "cannot locate insert point"


def ensure_site_acme_proxy(site_name):
    name = (site_name or "").strip()
    if not name:
        return False, "no site_name"
    conf = Path("/www/server/panel/vhost/nginx") / f"{name}.conf"
    if not conf.exists():
        return False, f"not found: {conf}"
    if not os.access(str(conf), os.R_OK | os.W_OK):
        return False, f"no permission: {conf}"
    old = conf.read_text("utf-8", errors="ignore")
    if "." in name:
        new, patched_blocks, reason = patch_nginx_conf_for_domain(old, name)
        if reason == "exists":
            ok_reload, msg_reload = reload_nginx_best_effort()
            return True, "exists_reloaded" if ok_reload else "exists"
        if reason == "patched" and patched_blocks > 0 and new:
            backup_dir = DATA_DIR / "nginx-site-backups"
            backup_dir.mkdir(parents=True, exist_ok=True)
            stamp = datetime.utcnow().strftime("%Y%m%d%H%M%S")
            (backup_dir / f"{name}.conf.{stamp}.bak").write_text(old, encoding="utf-8")
            conf.write_text(new, encoding="utf-8")
            ok_reload, msg_reload = reload_nginx_best_effort()
            return True, "reloaded" if ok_reload else "written"
    new, reason = inject_acme_location_into_nginx_conf(old)
    if not new:
        ok_reload, msg_reload = reload_nginx_best_effort()
        return (True, "exists_reloaded" if ok_reload else "exists") if reason == "exists" else (False, reason)
    backup_dir = DATA_DIR / "nginx-site-backups"
    backup_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.utcnow().strftime("%Y%m%d%H%M%S")
    (backup_dir / f"{name}.conf.{stamp}.bak").write_text(old, encoding="utf-8")
    conf.write_text(new, encoding="utf-8")
    ok_reload, msg_reload = reload_nginx_best_effort()
    return True, "reloaded" if ok_reload else "written"


def ensure_domain_acme_proxy(domain):
    d = (domain or "").strip().lower()
    if not d:
        return False, "no domain"
    conf_dir = Path("/www/server/panel/vhost/nginx")
    if not conf_dir.exists():
        return False, f"not found: {conf_dir}"
    touched = 0
    patched = 0
    errors = 0
    last_reason = ""
    for conf in sorted(conf_dir.glob("*.conf")):
        try:
            if not conf.is_file():
                continue
            txt = conf.read_text("utf-8", errors="ignore")
            txt_clean = _nginx_strip_comments(txt)
            matched = False
            for m in re.finditer(r"server_name\s+([^;]+);", txt_clean, flags=re.IGNORECASE):
                for nm in split_domain_field(m.group(1)):
                    nml = nm.lower()
                    if nml == d:
                        matched = True
                        break
                    if nml.startswith("*.") and d.endswith(nml[1:]):
                        matched = True
                        break
                if matched:
                    break
            if not matched:
                continue
            if not os.access(str(conf), os.R_OK | os.W_OK):
                errors += 1
                last_reason = f"no permission: {conf.name}"
                continue
            new, patched_blocks, reason = patch_nginx_conf_for_domain(txt, d)
            if reason in {"no matched server block", "no server block"}:
                continue
            touched += 1
            if reason == "exists":
                last_reason = f"{conf.name}: exists"
                continue
            if (not new) or patched_blocks == 0:
                last_reason = f"{conf.name}: {reason}"
                continue
            backup_dir = DATA_DIR / "nginx-site-backups"
            backup_dir.mkdir(parents=True, exist_ok=True)
            stamp = datetime.utcnow().strftime("%Y%m%d%H%M%S")
            (backup_dir / f"{conf.name}.{stamp}.bak").write_text(txt, encoding="utf-8")
            conf.write_text(new, encoding="utf-8")
            patched += patched_blocks
            last_reason = f"{conf.name}: patched={patched_blocks}"
        except Exception:
            errors += 1
            continue
    if patched:
        ok_reload, msg_reload = reload_nginx_best_effort()
        return True, f"patched={patched}/{touched} reload={'ok' if ok_reload else 'fail'}"
    if touched:
        extra = f" last={last_reason}" if last_reason else ""
        return True, f"matched={touched} patched=0 errors={errors}{extra}"
    return False, "no matching conf"


def try_fix_http01_404(cert):
    try:
        ok_default, msg_default = apply_nginx_default_acme_proxy()
    except Exception:
        ok_default, msg_default = False, ""
    try:
        ok_site, msg_site = ensure_site_acme_proxy(row_value(cert, "site_name", "") or "")
    except Exception:
        ok_site, msg_site = False, ""
    try:
        dom = primary_domain(row_value(cert, "domains", "") or "")
        ok_dom, msg_dom = ensure_domain_acme_proxy(dom)
    except Exception:
        ok_dom, msg_dom = False, ""
    ok_reload, msg_reload = reload_nginx_best_effort()
    return (ok_default or ok_site or ok_dom), f"default={msg_default}; site={msg_site}; domain={msg_dom}; reload={'ok' if ok_reload else 'fail'}:{msg_reload}"


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with get_db() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                must_change INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS panels (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                base_url TEXT NOT NULL,
                admin_path TEXT NOT NULL,
                api_token TEXT NOT NULL,
                verify_ssl INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS certs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                domains TEXT NOT NULL,
                webroot TEXT NOT NULL,
                email TEXT NOT NULL,
                panel_id INTEGER,
                site_name TEXT,
                acme_home TEXT NOT NULL,
                cert_path TEXT,
                key_path TEXT,
                last_issued_at TEXT,
                last_renew_at TEXT,
                last_error TEXT,
                last_notify_at TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                action TEXT NOT NULL,
                target TEXT,
                status TEXT NOT NULL,
                message TEXT,
                created_at TEXT NOT NULL
            )
            """
        )
        cur = conn.execute("SELECT COUNT(*) AS c FROM users")
        if cur.fetchone()["c"] == 0:
            now = datetime.utcnow().isoformat()
            conn.execute(
                "INSERT INTO users (username, password_hash, must_change, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
                ("admin", create_password_hash("admin"), 1, now, now),
            )
        ensure_panel_schema(conn)
    bootstrap_local_panel()


def bootstrap_local_panel():
    try:
        with get_db() as conn:
            cur = conn.execute("SELECT COUNT(*) AS c FROM panels")
            if cur.fetchone()["c"] != 0:
                return
    except Exception:
        return

    api_path = Path("/www/server/panel/config/api.json")
    admin_path_file = Path("/www/server/panel/data/admin_path.pl")
    if not api_path.exists() or not admin_path_file.exists():
        return

    try:
        api = json.loads(api_path.read_text("utf-8", errors="ignore") or "{}")
    except Exception:
        return

    token_crypt = (api.get("token_crypt") or "").strip()
    if not token_crypt:
        return

    admin_path = admin_path_file.read_text("utf-8", errors="ignore").strip() or "/bt"

    base_ip = ""
    for ip in api.get("limit_addr") or []:
        ip = str(ip).strip()
        if not ip:
            continue
        if ip.startswith("127.") or ip == "::1":
            continue
        if ip.startswith("10.") or ip.startswith("192.168."):
            continue
        if ip.startswith("172.") and re.match(r"^172\.(1[6-9]|2[0-9]|3[0-1])\.", ip):
            continue
        base_ip = ip
        break

    base_url = f"https://{base_ip}:22460" if base_ip else "https://127.0.0.1:22460"
    now = datetime.utcnow().isoformat()
    with get_db() as conn:
        conn.execute(
            "INSERT INTO panels (name, base_url, admin_path, api_token, verify_ssl, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            ("本机面板", base_url, admin_path, token_crypt, 0, now, now),
        )


def ensure_panel_schema(conn):
    cols = [r["name"] for r in conn.execute("PRAGMA table_info(panels)").fetchall()]
    if "verify_ssl" not in cols:
        conn.execute("ALTER TABLE panels ADD COLUMN verify_ssl INTEGER NOT NULL DEFAULT 0")


def create_password_hash(password):
    salt = secrets.token_bytes(16)
    iterations = 200000
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)
    return "pbkdf2_sha256$%d$%s$%s" % (
        iterations,
        base64.b64encode(salt).decode(),
        base64.b64encode(dk).decode(),
    )


def verify_password(password, password_hash):
    try:
        _, iter_s, salt_b64, dk_b64 = password_hash.split("$")
        iterations = int(iter_s)
        salt = base64.b64decode(salt_b64)
        dk = base64.b64decode(dk_b64)
        cand = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)
        return hmac.compare_digest(dk, cand)
    except Exception:
        return False


def sign_session(user_id, must_change, ttl=86400):
    payload = f"{user_id}.{must_change}.{int(time.time()) + ttl}"
    sig = hmac.new(APP_SECRET, payload.encode(), hashlib.sha256).digest()
    return base64.b64encode(payload.encode() + b"." + sig).decode()


def verify_session(token):
    try:
        raw = base64.b64decode(token.encode())
        payload, sig = raw.rsplit(b".", 1)
        if not hmac.compare_digest(sig, hmac.new(APP_SECRET, payload, hashlib.sha256).digest()):
            return None
        user_id_s, must_change_s, exp_s = payload.decode().split(".")
        if int(exp_s) < int(time.time()):
            return None
        return int(user_id_s), int(must_change_s)
    except Exception:
        return None


def get_current_user(handler):
    cookie = handler.headers.get("Cookie", "")
    token = None
    for part in cookie.split(";"):
        part = part.strip()
        if part.startswith("session="):
            token = part.split("=", 1)[1]
            break
    if not token:
        return None
    info = verify_session(token)
    if not info:
        return None
    user_id, _ = info
    with get_db() as conn:
        user = conn.execute("SELECT id, username, must_change FROM users WHERE id = ?", (user_id,)).fetchone()
    if not user:
        return None
    return dict(user)


def get_setting(key, default=""):
    with get_db() as conn:
        row = conn.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
    return row["value"] if row else default


def set_setting(key, value):
    with get_db() as conn:
        conn.execute(
            "INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (key, value),
        )


def get_local_bt_settings():
    base_url = (os.environ.get("BT_BASE_URL") or get_setting("bt_base_url") or "").strip()
    admin_path = (os.environ.get("BT_ADMIN_PATH") or get_setting("bt_admin_path") or "").strip()
    api_token = (os.environ.get("BT_API_TOKEN") or get_setting("bt_api_token") or "").strip()
    verify_ssl = (os.environ.get("BT_VERIFY_SSL") or get_setting("bt_verify_ssl") or "0").strip()
    try:
        verify_ssl_i = 1 if int(verify_ssl) else 0
    except Exception:
        verify_ssl_i = 0
    return {"base_url": base_url, "admin_path": admin_path, "api_token": api_token, "verify_ssl": verify_ssl_i}


def save_local_bt_settings(base_url, admin_path, api_token, verify_ssl):
    set_setting("bt_base_url", (base_url or "").strip())
    set_setting("bt_admin_path", (admin_path or "").strip())
    set_setting("bt_api_token", (api_token or "").strip())
    set_setting("bt_verify_ssl", "1" if verify_ssl else "0")


def log_action(action, target, status, message=""):
    with get_db() as conn:
        conn.execute(
            "INSERT INTO logs (action, target, status, message, created_at) VALUES (?, ?, ?, ?, ?)",
            (action, target, status, message, datetime.utcnow().isoformat()),
        )


def run_command(args, use_shell=False):
    try:
        result = subprocess.run(
            args,
            shell=use_shell,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        return result.returncode == 0, result.stdout.strip()
    except FileNotFoundError as e:
        return False, f"命令不存在: {e.filename}"


def ensure_acme_sh(acme_home, email):
    acme_sh = Path(acme_home) / "acme.sh"
    account_conf = Path(acme_home) / "account.conf"
    if acme_sh.exists():
        if account_conf.exists() and email:
            try:
                text = account_conf.read_text("utf-8", errors="ignore")
                m = re.search(r"^ACCOUNT_EMAIL='([^']*)'$", text, flags=re.M)
                if m and m.group(1).endswith("@example.com"):
                    text = re.sub(
                        r"^ACCOUNT_EMAIL='[^']*'$",
                        f"ACCOUNT_EMAIL='{email}'",
                        text,
                        flags=re.M,
                    )
                    account_conf.write_text(text)
            except Exception:
                pass
        ok, output = run_command(
            [
                "bash",
                "-lc",
                f"{acme_sh} --home {acme_home} --config-home {acme_home} --set-default-ca --server letsencrypt",
            ]
        )
        if not ok:
            return False, str(acme_sh), output
        ok, output = run_command(
            [
                "bash",
                "-lc",
                f"{acme_sh} --home {acme_home} --config-home {acme_home} --register-account --server letsencrypt",
            ]
        )
        if not ok:
            return False, str(acme_sh), output
        ok, output = run_command(
            [
                "bash",
                "-lc",
                f"{acme_sh} --home {acme_home} --config-home {acme_home} --update-account -m {email} --server letsencrypt",
            ]
        )
        if not ok:
            return False, str(acme_sh), output
        return True, str(acme_sh), ""
    if not EMAIL_RE.match(email):
        return False, str(acme_sh), "邮箱格式不正确"
    Path(acme_home).mkdir(parents=True, exist_ok=True)
    cmd = f"set -o pipefail; curl -fsSL https://get.acme.sh | sh -s email={email} --force"
    ok, output = run_command(["bash", "-lc", cmd])
    if not ok or not acme_sh.exists():
        return False, str(acme_sh), output or "acme.sh 安装失败"
    if account_conf.exists() and email:
        try:
            text = account_conf.read_text("utf-8", errors="ignore")
            m = re.search(r"^ACCOUNT_EMAIL='([^']*)'$", text, flags=re.M)
            if m and m.group(1).endswith("@example.com"):
                text = re.sub(
                    r"^ACCOUNT_EMAIL='[^']*'$",
                    f"ACCOUNT_EMAIL='{email}'",
                    text,
                    flags=re.M,
                )
                account_conf.write_text(text)
        except Exception:
            pass
    ok, output2 = run_command(
        [
            "bash",
            "-lc",
            f"{acme_sh} --home {acme_home} --config-home {acme_home} --set-default-ca --server letsencrypt",
        ]
    )
    if not ok:
        return False, str(acme_sh), output2
    ok, output3 = run_command(
        [
            "bash",
            "-lc",
            f"{acme_sh} --home {acme_home} --config-home {acme_home} --register-account --server letsencrypt",
        ]
    )
    if not ok:
        return False, str(acme_sh), output3
    ok, output4 = run_command(
        [
            "bash",
            "-lc",
            f"{acme_sh} --home {acme_home} --config-home {acme_home} --update-account -m {email} --server letsencrypt",
        ]
    )
    if not ok:
        return False, str(acme_sh), output4
    return True, str(acme_sh), output


def primary_domain(domains):
    return domains.split(",")[0].strip()


def cert_file_paths(acme_home, domains):
    domain = primary_domain(domains)
    ecc_dir = Path(acme_home) / f"{domain}_ecc"
    if (ecc_dir / "fullchain.cer").exists() and (ecc_dir / f"{domain}.key").exists():
        return str(ecc_dir / "fullchain.cer"), str(ecc_dir / f"{domain}.key")
    domain_dir = Path(acme_home) / domain
    return str(domain_dir / "fullchain.cer"), str(domain_dir / f"{domain}.key")


def find_existing_cert_files(acme_home, domains):
    cert_path, key_path = cert_file_paths(acme_home, domains)
    if Path(cert_path).exists() and Path(key_path).exists():
        return cert_path, key_path
    domain = primary_domain(domains)
    bt_dir = Path("/www/server/panel/vhost/cert") / domain
    bt_cert = bt_dir / "fullchain.pem"
    bt_key = bt_dir / "privkey.pem"
    if bt_cert.exists() and bt_key.exists():
        return str(bt_cert), str(bt_key)
    return None


def _path_within(path, root):
    try:
        p = Path(path).resolve()
        r = Path(root).resolve()
        return os.path.commonpath([str(p), str(r)]) == str(r)
    except Exception:
        return False


def _safe_remove_path(path, allowed_root):
    try:
        p = Path(path).resolve()
        if not _path_within(p, allowed_root):
            return False
        if not p.exists():
            return False
        if p.is_dir():
            shutil.rmtree(str(p), ignore_errors=True)
            return True
        p.unlink(missing_ok=True)
        return True
    except Exception:
        return False


def purge_cert_files(cert):
    domains = (row_value(cert, "domains", "") or "").strip()
    if not domains:
        return 0
    domain = primary_domain(domains)
    acme_home = (row_value(cert, "acme_home", "") or "").strip()
    if not acme_home:
        acme_home = str(DEFAULT_ACME_HOME)
    removed = 0
    base = Path(acme_home).resolve()
    for p in [base / domain, base / f"{domain}_ecc"]:
        if _safe_remove_path(p, base):
            removed += 1
    bt_root = Path("/www/server/panel/vhost/cert").resolve()
    bt_dir = bt_root / domain
    if _safe_remove_path(bt_dir, bt_root):
        removed += 1
    return removed


def parse_expiry(cert_path):
    if not cert_path or not Path(cert_path).exists():
        return None
    ok, output = run_command(["openssl", "x509", "-enddate", "-noout", "-in", cert_path])
    if not ok or "notAfter=" not in output:
        return None
    date_str = output.split("notAfter=")[-1].strip()
    try:
        return datetime.strptime(date_str, "%b %d %H:%M:%S %Y %Z")
    except ValueError:
        return None


def validate_domains(domains):
    items = [d.strip() for d in domains.split(",") if d.strip()]
    if not items:
        return False, "域名不能为空"
    invalid = [d for d in items if not DOMAIN_RE.match(d)]
    if invalid:
        return False, f"域名格式不正确: {', '.join(invalid)}"
    return True, items


def probe_http01_webroot(domain, webroot):
    d = (domain or "").strip()
    w = (webroot or "").strip()
    if not d or not w:
        return False, "参数错误"
    token = secrets.token_urlsafe(18)
    challenge_dir = Path(w) / ".well-known" / "acme-challenge"
    file_path = challenge_dir / token
    class _NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            return None
    try:
        challenge_dir.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(str(Path(w)), 0o755)
        except Exception:
            pass
        try:
            os.chmod(str(Path(w) / ".well-known"), 0o755)
        except Exception:
            pass
        try:
            os.chmod(str(challenge_dir), 0o755)
        except Exception:
            pass
        file_path.write_text(token, encoding="utf-8")
        try:
            os.chmod(str(file_path), 0o644)
        except Exception:
            pass
        url = f"http://{d}/.well-known/acme-challenge/{token}"
        first_status = ""
        first_loc = ""
        first_server = ""
        try:
            opener = urllib.request.build_opener(_NoRedirect())
            resp = opener.open(Request(url, method="GET"), timeout=12)
            first_status = str(getattr(resp, "status", "") or "")
            first_loc = resp.headers.get("Location") or ""
            first_server = resp.headers.get("Server") or ""
            resp.read(1)
        except HTTPError as e:
            first_status = str(e.code)
            first_loc = e.headers.get("Location") or ""
            first_server = e.headers.get("Server") or ""
        except Exception:
            pass

        try:
            with urlopen(Request(url, method="GET"), timeout=12) as resp2:
                body2 = resp2.read(2048).decode("utf-8", errors="ignore").strip()
                if getattr(resp2, "status", 0) == 200 and token in body2:
                    return True, ""
                status2 = str(getattr(resp2, "status", "") or "")
                extra = []
                if first_status:
                    extra.append(f"first={first_status}")
                if first_loc:
                    extra.append(f"location={first_loc}")
                if first_server:
                    extra.append(f"server={first_server}")
                return False, ("HTTP " + status2 + (f" ({', '.join(extra)})" if extra else ""))
        except HTTPError as e:
            body = ""
            try:
                body = (e.read(256) or b"").decode("utf-8", errors="ignore").strip()
            except Exception:
                body = ""
            loc = e.headers.get("Location") or ""
            server = e.headers.get("Server") or ""
            extra = []
            if first_status:
                extra.append(f"first={first_status}")
            if loc:
                extra.append(f"location={loc}")
            elif first_loc:
                extra.append(f"location={first_loc}")
            if server:
                extra.append(f"server={server}")
            elif first_server:
                extra.append(f"server={first_server}")
            if body:
                extra.append(f"body={body[:120]}")
            return False, f"HTTP Error {e.code}: {e.reason}" + (f" ({', '.join(extra)})" if extra else "")
        except Exception as e:
            return False, str(e)
    finally:
        try:
            file_path.unlink(missing_ok=True)
        except Exception:
            pass


def domains_overlap(a, b):
    set_a = {x.strip().lower() for x in (a or "").split(",") if x.strip()}
    set_b = {x.strip().lower() for x in (b or "").split(",") if x.strip()}
    return bool(set_a & set_b)


def has_cert_config_for_domains(domains):
    if not domains:
        return False
    with get_db() as conn:
        rows = conn.execute("SELECT domains FROM certs").fetchall()
    for r in rows:
        if domains_overlap(domains, r["domains"]):
            return True
    return False


def get_existing_cert_id_for_domains(domains):
    if not domains:
        return None
    with get_db() as conn:
        rows = conn.execute("SELECT id, domains FROM certs ORDER BY id DESC").fetchall()
    for r in rows:
        if domains_overlap(domains, r["domains"]):
            return r["id"]
    return None


def is_error_message(message):
    msg = (message or "").strip()
    if not msg:
        return False
    keywords = [
        "失败",
        "错误",
        "无效",
        "不存在",
        "参数错误",
        "无法",
        "拒绝",
        "已存在",
        "禁止",
        "exception",
        "traceback",
        "error",
    ]
    low = msg.lower()
    for k in keywords:
        if k in msg or k in low:
            return True
    return False


def _pem_cert_count(text):
    return (text or "").count("BEGIN CERTIFICATE")


def ensure_fullchain_file(acme_home, domains):
    try:
        home = Path(acme_home).resolve()
    except Exception:
        return False
    d = primary_domain(domains)
    candidates = [home / f"{d}_ecc", home / d]
    for base in candidates:
        try:
            full = base / "fullchain.cer"
            cert = base / "cert.cer"
            ca = base / "ca.cer"
            if not full.exists():
                continue
            full_text = full.read_text("utf-8", errors="ignore")
            if _pem_cert_count(full_text) >= 2:
                return True
            if not (cert.exists() and ca.exists()):
                continue
            cert_text = cert.read_text("utf-8", errors="ignore").strip()
            ca_text = ca.read_text("utf-8", errors="ignore").strip()
            merged = (cert_text + "\n" + ca_text + "\n").strip() + "\n"
            if _pem_cert_count(merged) >= 2:
                full.write_text(merged, encoding="utf-8")
                return True
        except Exception:
            continue
    return False


def issue_cert(cert, force=False, auto_fix=True):
    acme_home = cert["acme_home"]
    ok, acme_sh, output = ensure_acme_sh(acme_home, cert["email"])
    if not ok:
        log_action("issue", cert["domains"], "fail", output or "acme.sh 安装失败")
        return False, output or "acme.sh 安装失败"
    existing = find_existing_cert_files(acme_home, cert["domains"])
    if existing and (not force):
        log_action("issue", cert["domains"], "ok", "already issued")
        return True, existing
    valid, result = validate_domains(cert["domains"])
    if not valid:
        log_action("issue", cert["domains"], "fail", result)
        return False, result
    domain_args = []
    for d in result:
        domain_args.extend(["-d", d])

    webroot = (cert["webroot"] or "").strip()
    fallback = str(ACME_CHALLENGE_ROOT)
    try:
        (ACME_CHALLENGE_ROOT / ".well-known" / "acme-challenge").mkdir(parents=True, exist_ok=True)
    except Exception:
        pass
    if not webroot:
        webroot = fallback
    if webroot and (not Path(webroot).exists()) and Path(fallback).exists():
        old = webroot
        webroot = fallback
        try:
            with get_db() as conn:
                conn.execute(
                    "UPDATE certs SET webroot = ?, updated_at = ? WHERE id = ?",
                    (webroot, datetime.utcnow().isoformat(), cert["id"]),
                )
        except Exception:
            pass
        log_action("issue", cert["domains"], "ok", f"webroot fallback {old} -> {webroot}")
    if not webroot:
        log_action("issue", cert["domains"], "fail", "未找到可用的 Webroot")
        return False, "未找到可用的 Webroot（请确保 80 端口能访问到本面板的 ACME 挑战路径）"
    if not Path(webroot).exists():
        log_action("issue", cert["domains"], "fail", f"Webroot 不存在: {webroot}")
        return False, f"Webroot 不存在：{webroot}"
    for d in result:
        ok_probe, msg_probe = probe_http01_webroot(d, webroot)
        if not ok_probe:
            fix_msg = ""
            if auto_fix and ("404" in (msg_probe or "")):
                fixed, fix_msg = try_fix_http01_404(cert)
                log_action("issue", cert["domains"], "ok" if fixed else "fail", f"http01_fix {fixed}: {fix_msg}")
                ok_probe2, msg_probe2 = probe_http01_webroot(d, webroot)
                if ok_probe2:
                    continue
                msg_probe = msg_probe2 or msg_probe
            detail = f"域名 {d} 无法通过 HTTP 访问到当前 Webroot 的挑战文件：{msg_probe}"
            hint = f"当前 Webroot: {webroot}。请确保 Nginx 已将 /.well-known/acme-challenge/ 转发到本面板（例如 proxy_pass http://127.0.0.1:{ACME_PROXY_PORT}）。"
            if fix_msg:
                hint = hint + f"（已尝试自动修复：{fix_msg}）"
            log_action("issue", cert["domains"], "fail", f"{detail}; {hint}")
            return False, f"{detail}。{hint}"
    cmd = [
        acme_sh,
        "--home",
        acme_home,
        "--config-home",
        acme_home,
        "--server",
        "letsencrypt",
        "--issue",
        "--webroot",
        webroot,
    ]
    if force:
        cmd.append("--force")
    cmd.extend(domain_args)
    ok, output = run_command(cmd)
    if not ok:
        cert_path, key_path = cert_file_paths(acme_home, cert["domains"])
        if (
            Path(cert_path).exists()
            and Path(key_path).exists()
            and ("Skipping. Next renewal time is" in output or "Domains not changed." in output)
        ):
            log_action("issue", cert["domains"], "ok", "already issued")
            return True, (cert_path, key_path)
        log_action("issue", cert["domains"], "fail", output)
        return False, output
    cert_path, key_path = cert_file_paths(acme_home, cert["domains"])
    ensure_fullchain_file(acme_home, cert["domains"])
    log_action("issue", cert["domains"], "ok", "issued")
    return True, (cert_path, key_path)


def renew_cert(cert, force=False, auto_fix=True):
    acme_home = cert["acme_home"]
    acme_sh = Path(acme_home) / "acme.sh"
    if not acme_sh.exists():
        log_action("renew", cert["domains"], "fail", "acme.sh 未安装")
        return issue_cert(cert, force=force, auto_fix=auto_fix)
    existing = find_existing_cert_files(acme_home, cert["domains"])
    if not existing:
        log_action("renew", cert["domains"], "ok", "not issued; fallback to issue")
        return issue_cert(cert, force=force, auto_fix=auto_fix)
    domain = primary_domain(cert["domains"])
    cmd = [str(acme_sh), "--home", acme_home, "--config-home", acme_home, "--renew", "-d", domain]
    if force:
        cmd.append("--force")
    ok, output = run_command(cmd)
    low = (output or "").lower()
    if ("not an issued domain" in low) or ("is not an issued domain" in low):
        log_action("renew", cert["domains"], "ok", "not issued; fallback to issue")
        return issue_cert(cert, force=force, auto_fix=auto_fix)
    if ("skipping. next renewal time is" in low) and force:
        log_action("renew", cert["domains"], "ok", "skipped; fallback to force issue")
        return issue_cert(cert, force=True, auto_fix=auto_fix)
    if not ok:
        log_action("renew", cert["domains"], "fail", output)
        return False, output
    cert_path, key_path = cert_file_paths(acme_home, cert["domains"])
    ensure_fullchain_file(acme_home, cert["domains"])
    log_action("renew", cert["domains"], "ok", "renewed")
    return True, (cert_path, key_path)


def record_error(cert_id, error):
    with get_db() as conn:
        conn.execute(
            "UPDATE certs SET last_error = ?, updated_at = ? WHERE id = ?",
            (error, datetime.utcnow().isoformat(), cert_id),
        )


def record_issue(cert_id, cert_path, key_path):
    with get_db() as conn:
        conn.execute(
            """
            UPDATE certs
            SET cert_path = ?, key_path = ?, last_issued_at = ?, last_error = ?, updated_at = ?
            WHERE id = ?
            """,
            (cert_path, key_path, datetime.utcnow().isoformat(), None, datetime.utcnow().isoformat(), cert_id),
        )


def record_renew(cert_id, cert_path, key_path):
    with get_db() as conn:
        conn.execute(
            """
            UPDATE certs
            SET cert_path = ?, key_path = ?, last_renew_at = ?, last_error = ?, updated_at = ?
            WHERE id = ?
            """,
            (cert_path, key_path, datetime.utcnow().isoformat(), None, datetime.utcnow().isoformat(), cert_id),
        )


def record_notify(cert_id):
    with get_db() as conn:
        conn.execute(
            "UPDATE certs SET last_notify_at = ?, updated_at = ? WHERE id = ?",
            (datetime.utcnow().isoformat(), datetime.utcnow().isoformat(), cert_id),
        )


def get_certs():
    with get_db() as conn:
        return conn.execute(
            """
            SELECT c.*, p.name AS panel_name
            FROM certs c
            LEFT JOIN panels p ON c.panel_id = p.id
            ORDER BY c.id DESC
            """
        ).fetchall()


def get_certs_by_ids(cert_ids):
    ids = []
    seen = set()
    for x in cert_ids or []:
        s = str(x).strip()
        if not s.isdigit():
            continue
        if s in seen:
            continue
        seen.add(s)
        ids.append(int(s))
    if not ids:
        return []
    placeholders = ",".join(["?"] * len(ids))
    with get_db() as conn:
        rows = conn.execute(
            f"""
            SELECT c.*, p.name AS panel_name
            FROM certs c
            LEFT JOIN panels p ON c.panel_id = p.id
            WHERE c.id IN ({placeholders})
            """,
            tuple(ids),
        ).fetchall()
    index = {cid: i for i, cid in enumerate(ids)}
    rows = list(rows)
    rows.sort(key=lambda r: index.get(row_value(r, "id", -1), 10**9))
    return rows


def get_panels():
    with get_db() as conn:
        return conn.execute("SELECT * FROM panels ORDER BY id DESC").fetchall()


def api_sign(token):
    request_time = str(int(time.time()))
    secret = (token or "").strip()
    if not re.fullmatch(r"[a-fA-F0-9]{32}", secret):
        secret = hashlib.md5(secret.encode()).hexdigest()
    request_token = hashlib.md5((request_time + secret).encode()).hexdigest()
    return request_time, request_token


def ssl_context_for_url(url, verify_ssl):
    if verify_ssl:
        return None
    if not url.lower().startswith("https://"):
        return None
    return ssl._create_unverified_context()


def http_post_form(url, data, timeout=15, verify_ssl=True):
    body = urlencode(data).encode()
    req = Request(url, data=body, headers={"Content-Type": "application/x-www-form-urlencoded"})
    try:
        ctx = ssl_context_for_url(url, verify_ssl)
        with urlopen(req, timeout=timeout, context=ctx) as resp:
            return True, resp.status, resp.read().decode()
    except HTTPError as e:
        try:
            return False, e.code, e.read().decode()
        except Exception:
            return False, e.code, ""
    except URLError as e:
        return False, 0, str(e)
    except Exception as e:
        return False, 0, str(e)


def http_get(url, timeout=15, verify_ssl=True):
    req = Request(url, method="GET")
    try:
        ctx = ssl_context_for_url(url, verify_ssl)
        with urlopen(req, timeout=timeout, context=ctx) as resp:
            return True, resp.status, resp.read().decode()
    except HTTPError as e:
        try:
            return False, e.code, e.read().decode()
        except Exception:
            return False, e.code, ""
    except URLError as e:
        return False, 0, str(e)
    except Exception as e:
        return False, 0, str(e)


def normalize_admin_path(admin_path):
    if not admin_path:
        return "/bt"
    if not admin_path.startswith("/"):
        admin_path = "/" + admin_path
    return admin_path.rstrip("/")


def row_value(row, key, default=None):
    try:
        return row[key]
    except Exception:
        return default


def strip_admin_path(base_url, admin_path):
    parsed = urlparse(base_url)
    path = parsed.path.rstrip("/")
    admin_path = normalize_admin_path(admin_path)
    if path.endswith(admin_path):
        path = path[: -len(admin_path)]
    return urlunparse((parsed.scheme, parsed.netloc, path, "", "", ""))


def panel_base_roots(panel):
    base_url = panel["base_url"].strip().rstrip("/")
    admin_path = normalize_admin_path(panel["admin_path"])
    parsed = urlparse(base_url)
    origin = urlunparse((parsed.scheme, parsed.netloc, "", "", "", "")).rstrip("/")
    cleaned = strip_admin_path(base_url, admin_path).rstrip("/")
    roots = []

    if origin:
        roots.append(f"{origin}{admin_path}")
        roots.append(origin)
        roots.append(f"{origin}/bt")
    if cleaned:
        roots.append(f"{cleaned}{admin_path}")
        roots.append(cleaned)
        roots.append(f"{cleaned}/bt")
    if base_url:
        roots.append(base_url if base_url.endswith(admin_path) else f"{base_url}{admin_path}")
        roots.append(base_url)

    seen = []
    for r in roots:
        if not r:
            continue
        if r.endswith("/"):
            r = r.rstrip("/")
        if r not in seen:
            seen.append(r)
    return seen


def looks_like_html(body):
    if not body:
        return False
    head = body.lstrip()[:300].lower()
    return "<html" in head or "<!doctype html" in head or "safety entrance error" in head


def panel_api_request(panel, path, params):
    request_time, request_token = api_sign(panel["api_token"])
    payload = dict(params)
    payload["request_time"] = request_time
    payload["request_token"] = request_token
    meta = {"request_time": request_time, "request_token": request_token}
    verify_ssl = bool(int(row_value(panel, "verify_ssl", 0) or 0))
    last = (False, 0, "")
    attempted = []
    for root in panel_base_roots(panel):
        base = f"{root}{path}"
        attempted.append(base)
        ok, status, body = http_post_form(base, payload, verify_ssl=verify_ssl)
        if status == 404:
            ok2, status2, body2 = http_get(f"{base}?{urlencode(payload)}", verify_ssl=verify_ssl)
            if status2 != 404:
                ok, status, body = ok2, status2, body2
            else:
                last = (ok, status, body)
                continue
        if looks_like_html(body):
            last = (ok, status, body)
            continue
        try:
            data = json.loads(body)
            if isinstance(data, dict) and data.get("status") is False:
                msg = str(data.get("msg", ""))
                if msg in {"Secret key verification failed", "Key verification failed"}:
                    last = (ok, status, body)
                    continue
        except Exception:
            pass
        return ok, status, body, attempted, meta
    return last[0], last[1], last[2], attempted, meta


def test_panel(panel):
    ok, status, body, attempted, meta = panel_api_request(panel, "/system", {"action": "GetSystemTotal"})
    attempted_msg = f" 已尝试: {' | '.join(attempted)}" if attempted else ""
    if status == 404:
        return False, f"HTTP 404，请检查访问地址或Admin Path 是否重复.{attempted_msg}"
    if not ok and status == 0:
        if "CERTIFICATE_VERIFY_FAILED" in (body or ""):
            return (
                False,
                "HTTPS 证书校验失败：远程宝塔面板可能使用自签证书或证书链不完整。"
                "请到“宝塔面板管理”里编辑该面板，关闭“验证 HTTPS 证书”，或为面板换成有效证书。"
                + attempted_msg,
            )
        return False, (body or "无法连接") + attempted_msg
    if "Safety entrance error" in body or "安全入口" in body:
        return False, f"安全入口错误：请把宝塔“安全入口”填到 Admin Path（如 /24315b07），并确保面板地址不重复包含该路径.{attempted_msg}"
    try:
        data = json.loads(body)
    except Exception:
        return False, f"响应解析失败: HTTP {status}.{attempted_msg}"
    if data.get("status") is False:
        msg = data.get("msg", "连接失败")
        if msg == "Secret key verification failed":
            sig = (meta.get("request_token") or "")[:8]
            rt = meta.get("request_time") or ""
            msg = f"Secret key verification failed（签名不匹配）。本次签名: request_time={rt}, request_token={sig}****；宝塔校验规则为 md5(request_time + 接口密钥)"
        elif msg == "Key verification failed":
            msg = "Key verification failed（宝塔未设置/未保存接口密钥：请在宝塔面板-设置-API接口生成并保存接口密钥）"
        return False, f"{msg}{attempted_msg}"
    return True, "连接成功"


def get_local_panel_config():
    stored = get_local_bt_settings()
    if stored.get("api_token"):
        base_url = stored.get("base_url") or "https://127.0.0.1:22460"
        admin_path = stored.get("admin_path") or "/bt"
        return {
            "name": "本机面板",
            "base_url": base_url,
            "admin_path": admin_path,
            "api_token": stored.get("api_token"),
            "verify_ssl": stored.get("verify_ssl", 0),
        }

    api_path = Path("/www/server/panel/config/api.json")
    admin_path_file = Path("/www/server/panel/data/admin_path.pl")
    if not api_path.exists() or not admin_path_file.exists():
        return None
    try:
        api = json.loads(api_path.read_text("utf-8", errors="ignore") or "{}")
    except Exception:
        return None
    token_crypt = (api.get("token_crypt") or "").strip()
    if not token_crypt:
        return None
    admin_path = admin_path_file.read_text("utf-8", errors="ignore").strip() or "/bt"
    base_ip = ""
    for ip in api.get("limit_addr") or []:
        ip = str(ip).strip()
        if not ip:
            continue
        if ip.startswith("127.") or ip == "::1":
            continue
        if ip.startswith("10.") or ip.startswith("192.168."):
            continue
        if ip.startswith("172.") and re.match(r"^172\.(1[6-9]|2[0-9]|3[0-1])\.", ip):
            continue
        base_ip = ip
        break
    base_url = f"https://{base_ip}:22460" if base_ip else "https://127.0.0.1:22460"
    return {"name": "本机面板", "base_url": base_url, "admin_path": admin_path, "api_token": token_crypt, "verify_ssl": 0}


def deploy_local(site_name, cert_path, key_path):
    if not site_name:
        return True, "未配置本机站点，跳过部署"
    local_panel = get_local_panel_config()
    if local_panel:
        return deploy_remote(local_panel, site_name, cert_path, key_path)
    cert_source = Path(cert_path)
    key_source = Path(key_path)
    if not cert_source.exists() or not key_source.exists():
        return False, "证书文件不存在"
    target_dir = Path(f"/www/server/panel/vhost/cert/{site_name}")
    target_dir.mkdir(parents=True, exist_ok=True)
    (target_dir / "fullchain.pem").write_bytes(cert_source.read_bytes())
    (target_dir / "privkey.pem").write_bytes(key_source.read_bytes())
    ok, output = run_command(["nginx", "-s", "reload"])
    if not ok:
        ok, output = run_command(["systemctl", "reload", "nginx"])
    return ok, output


def deploy_remote(panel, site_name, cert_path, key_path):
    if not site_name:
        return False, "远程站点名称为空"
    cert_source = Path(cert_path)
    key_source = Path(key_path)
    if not cert_source.exists() or not key_source.exists():
        return False, "证书文件不存在"
    csr = cert_source.read_text()
    key = key_source.read_text()
    ok, status, resp, _attempted, _meta = panel_api_request(
        panel,
        "/site",
        {"action": "SetSSL", "siteName": site_name, "key": key, "csr": csr},
    )
    return ok, resp or f"HTTP {status}"


def auto_loop():
    time.sleep(120)
    while True:
        certs = get_certs()
        for cert in certs:
            expiry = parse_expiry(cert["cert_path"])
            if not expiry:
                continue
            days_left = (expiry - datetime.utcnow()).days
            if days_left <= 30:
                ok, result = renew_cert(cert)
                if not ok:
                    record_error(cert["id"], result)
                    continue
                cert_path, key_path = result
                record_renew(cert["id"], cert_path, key_path)
                deploy_local(cert["site_name"], cert_path, key_path)
        time.sleep(24 * 3600)


def start_batch_issue_renew(certs=None, scope="all", mode="auto"):
    global BATCH_RUNNING, BATCH_STATE
    with BATCH_LOCK:
        if BATCH_RUNNING:
            return False, "批量任务已在运行"
        BATCH_RUNNING = True
        BATCH_STATE = {
            "done": False,
            "started_at": datetime.utcnow().isoformat(),
            "finished_at": "",
            "scope": scope,
            "mode": mode,
            "total": 0,
            "processed": 0,
            "issued": 0,
            "renewed": 0,
            "skipped": 0,
            "failed": 0,
            "current": "",
            "last": "",
            "lines": [],
            "updated_at": datetime.utcnow().isoformat(),
        }

    def runner():
        global BATCH_RUNNING, BATCH_STATE
        started = datetime.utcnow().isoformat()
        log_action("batch", "issue_renew", "ok", f"started {started}")
        batch_append_line(f"[{started}] started")
        certs_list = list(certs) if certs is not None else list(get_certs() or [])
        with BATCH_LOCK:
            BATCH_STATE["total"] = len(certs_list)
            BATCH_STATE["updated_at"] = datetime.utcnow().isoformat()
        total = len(certs_list)
        issued_n = 0
        renewed_n = 0
        skipped_n = 0
        failed_n = 0
        processed = 0
        try:
            for cert in certs_list:
                try:
                    processed += 1
                    current = (
                        str(row_value(cert, "domains", "") or "")
                        or str(row_value(cert, "name", "") or "")
                        or str(row_value(cert, "id", "") or "")
                    ).strip()
                    if not current:
                        current = f"id={row_value(cert, 'id', '')}"
                    with BATCH_LOCK:
                        BATCH_STATE["processed"] = processed
                        BATCH_STATE["current"] = current
                        BATCH_STATE["updated_at"] = datetime.utcnow().isoformat()
                    batch_append_line(f"[{datetime.utcnow().isoformat()}] {current} start")
                    expiry = parse_expiry(cert["cert_path"])
                    now = datetime.utcnow()
                    if mode == "issue" and expiry and expiry > now:
                        skipped_n += 1
                        batch_append_line(f"[{datetime.utcnow().isoformat()}] {current} skip_valid")
                        with BATCH_LOCK:
                            BATCH_STATE["skipped"] = skipped_n
                            BATCH_STATE["last"] = f"{current}: 跳过"
                            BATCH_STATE["updated_at"] = datetime.utcnow().isoformat()
                        continue
                    if mode in {"issue", "auto"} and ((not expiry) or (expiry <= now) or mode == "issue"):
                        ok, result = issue_cert(cert)
                        if not ok:
                            failed_n += 1
                            record_error(cert["id"], result)
                            batch_append_line(f"[{datetime.utcnow().isoformat()}] {current} issue_fail: {result}")
                            with BATCH_LOCK:
                                BATCH_STATE["failed"] = failed_n
                                BATCH_STATE["last"] = f"{current}: 申请失败: {result}"
                                BATCH_STATE["updated_at"] = datetime.utcnow().isoformat()
                            continue
                        cert_path, key_path = result
                        record_issue(cert["id"], cert_path, key_path)
                        deploy_local(cert["site_name"], cert_path, key_path)
                        issued_n += 1
                        batch_append_line(f"[{datetime.utcnow().isoformat()}] {current} issued")
                        with BATCH_LOCK:
                            BATCH_STATE["issued"] = issued_n
                            BATCH_STATE["last"] = f"{current}: 已申请"
                            BATCH_STATE["updated_at"] = datetime.utcnow().isoformat()
                        continue
                    if mode == "renew" or (mode == "auto" and (expiry - now).days <= 30):
                        ok, result = renew_cert(cert, force=(mode == "renew"))
                        if not ok:
                            failed_n += 1
                            record_error(cert["id"], result)
                            batch_append_line(f"[{datetime.utcnow().isoformat()}] {current} renew_fail: {result}")
                            with BATCH_LOCK:
                                BATCH_STATE["failed"] = failed_n
                                BATCH_STATE["last"] = f"{current}: 续签失败: {result}"
                                BATCH_STATE["updated_at"] = datetime.utcnow().isoformat()
                            continue
                        cert_path, key_path = result
                        if mode == "renew" and ((not expiry) or (expiry <= now)):
                            record_issue(cert["id"], cert_path, key_path)
                        else:
                            record_renew(cert["id"], cert_path, key_path)
                        deploy_local(cert["site_name"], cert_path, key_path)
                        renewed_n += 1
                        batch_append_line(f"[{datetime.utcnow().isoformat()}] {current} renewed")
                        with BATCH_LOCK:
                            BATCH_STATE["renewed"] = renewed_n
                            BATCH_STATE["last"] = f"{current}: 已续签"
                            BATCH_STATE["updated_at"] = datetime.utcnow().isoformat()
                        continue
                    skipped_n += 1
                    batch_append_line(f"[{datetime.utcnow().isoformat()}] {current} skipped")
                    with BATCH_LOCK:
                        BATCH_STATE["skipped"] = skipped_n
                        BATCH_STATE["last"] = f"{current}: 跳过"
                        BATCH_STATE["updated_at"] = datetime.utcnow().isoformat()
                except Exception as e:
                    failed_n += 1
                    try:
                        record_error(row_value(cert, "id", 0), str(e))
                    except Exception:
                        pass
                    batch_append_line(f"[{datetime.utcnow().isoformat()}] {current} exception: {e}")
                    with BATCH_LOCK:
                        BATCH_STATE["failed"] = failed_n
                        BATCH_STATE["last"] = f"{current}: 异常: {e}"
                        BATCH_STATE["updated_at"] = datetime.utcnow().isoformat()
        finally:
            finished = datetime.utcnow().isoformat()
            log_action(
                "batch",
                "issue_renew",
                "ok",
                f"finished {finished}; total={total} issued={issued_n} renewed={renewed_n} skipped={skipped_n} failed={failed_n}",
            )
            batch_append_line(
                f"[{finished}] finished total={total} issued={issued_n} renewed={renewed_n} skipped={skipped_n} failed={failed_n}"
            )
            with BATCH_LOCK:
                BATCH_STATE["done"] = True
                BATCH_STATE["finished_at"] = finished
                BATCH_STATE["total"] = total
                BATCH_STATE["processed"] = processed
                BATCH_STATE["issued"] = issued_n
                BATCH_STATE["renewed"] = renewed_n
                BATCH_STATE["skipped"] = skipped_n
                BATCH_STATE["failed"] = failed_n
                BATCH_STATE["updated_at"] = datetime.utcnow().isoformat()
                BATCH_RUNNING = False

    threading.Thread(target=runner, daemon=True).start()
    return True, "批量任务已启动（后台执行）"


def read_body(handler):
    length = int(handler.headers.get("Content-Length", "0"))
    if length <= 0:
        return ""
    return handler.rfile.read(length).decode("utf-8")


def parse_form(handler):
    data = read_body(handler)
    return parse_qs(data)


def json_response(handler, payload, status=HTTPStatus.OK):
    data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(data)))
    handler.end_headers()
    handler.wfile.write(data)


def wants_json_request(handler):
    accept = (handler.headers.get("Accept") or "").lower()
    xrw = (handler.headers.get("X-Requested-With") or "").lower()
    if "application/json" in accept:
        return True
    if xrw == "fetch" or xrw == "xmlhttprequest":
        return True
    return False


def get_batch_state():
    with BATCH_LOCK:
        running = bool(BATCH_RUNNING)
        st = dict(BATCH_STATE or {})
    st["running"] = running
    return st


def render_page(content, message=""):
    show_error_modal = is_error_message(message)
    return f"""
<!doctype html>
<html lang="zh">
  <head>
    <meta charset="utf-8">
    <title>SSL 管理面板</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link rel="stylesheet" href="/static/style.css">
  </head>
  <body>
    <div class="container">
      <header class="app-header">
        <div class="app-brand">
          <div class="app-title">SSL 管理面板</div>
          <div class="app-subtitle">证书统一管理 · 自动续签 · 一键部署</div>
        </div>
      </header>
      {"" if show_error_modal or not message else f'<div class="flash">{html.escape(message)}</div>'}
      {f'''
      <div class="modal-mask" id="modal-mask" aria-hidden="true">
        <div class="modal" role="dialog" aria-modal="true" aria-labelledby="modal-title">
          <div class="modal-header">
            <div class="modal-title" id="modal-title">操作失败</div>
            <button class="modal-close" type="button" onclick="window.__closeModal && window.__closeModal()">×</button>
          </div>
          <div class="modal-body"><pre class="modal-pre">{html.escape(message)}</pre></div>
          <div class="modal-footer">
            <button class="button primary" type="button" onclick="window.__closeModal && window.__closeModal()">我知道了</button>
          </div>
        </div>
      </div>
      <script>
        (function () {{
          function closeModal() {{
            var m = document.getElementById('modal-mask');
            if (m) {{
              m.classList.remove('show');
              m.setAttribute('aria-hidden', 'true');
            }}
          }}
          window.__closeModal = closeModal;
          var mask = document.getElementById('modal-mask');
          if (mask) {{
            mask.addEventListener('click', function (e) {{
              if (e.target === mask) closeModal();
            }});
            document.addEventListener('keydown', function (e) {{
              if (e.key === 'Escape') closeModal();
            }});
          }}
          {('var m = document.getElementById("modal-mask"); if (m) { m.classList.add("show"); m.setAttribute("aria-hidden", "false"); }' if show_error_modal else '')}
        }})();
      </script>
      ''' if show_error_modal else ""}
      {content}
    </div>
  </body>
</html>
"""


def render_login(message=""):
    hint = "默认账号：admin  默认密码：admin（首次登录后请立即修改密码）"
    content = f"""
    <div class="flash">{html.escape(hint)}</div>
    <form method="post">
      <div class="form-row"><label>用户名</label><input type="text" name="username" required></div>
      <div class="form-row"><label>密码</label><input type="password" name="password" required></div>
      <div class="actions"><button type="submit">登录</button></div>
    </form>
    """
    return render_page(content, message)


def render_password(message=""):
    content = f"""
    <form method="post">
      <div class="form-row"><label>旧密码</label><input type="password" name="old_password" required></div>
      <div class="form-row"><label>新密码</label><input type="password" name="new_password" required></div>
      <div class="form-row"><label>确认新密码</label><input type="password" name="confirm_password" required></div>
      <div class="actions"><button type="submit">修改密码</button></div>
    </form>
    """
    return render_page(content, message)


def render_index(message=""):
    rows = []
    certs = list(get_certs() or [])
    for idx, cert in enumerate(certs, start=1):
        expiry = parse_expiry(cert["cert_path"])
        days_left = (expiry - datetime.utcnow()).days if expiry else None
        panel_name = "本机"
        status_badge = '<span class="badge success">自动续签中</span>' if expiry else '<span class="badge warning">未签发</span>'
        needs_issue = not bool(expiry)
        rows.append(
            f"""
            <tr>
              <td style="width:42px"><input class="cert-select" type="checkbox" value="{cert["id"]}"></td>
              <td class="cell-number" style="width:56px">{idx}</td>
              <td>{html.escape(cert["name"])}</td>
              <td>
                <div class="domain-wrapper">
                  <div class="domain-text">{html.escape(cert["domains"])}</div>
                  {status_badge}
                </div>
              </td>
              <td class="cell-mono">{html.escape(cert["webroot"])}</td>
              <td>{html.escape(panel_name)}</td>
              <td>{html.escape(cert["site_name"] or "-")}</td>
              <td>{expiry or "未签发"}</td>
              <td class="cell-number">{days_left if days_left is not None else "-"}</td>
              <td>
                <div class="btn-group">
                  {f'<button type="button" class="button primary small single-issue" data-id="{cert["id"]}">申请</button>' if needs_issue else ''}
                  <a class="button ghost small" href="/cert?id={cert['id']}">查看/下载</a>
                  {'' if needs_issue else f'<button type="button" class="button ghost small single-renew" data-id="{cert["id"]}">续签</button>'}
                  <form method="post" action="/delete?id={cert['id']}"><button class="button danger small" type="submit">删除</button></form>
                </div>
              </td>
            </tr>
            """
        )
    content = f"""
    <div class="page-toolbar">
      <div class="toolbar-left">
        <a class="button primary" href="/new">申请免费证书</a>
        <a class="button ghost" href="/import/local">导入本机站点</a>
        <button id="batch-issue-renew-selected-btn" type="button" class="button ghost">申请/续签（所选）</button>
        <button id="batch-delete-selected-btn" type="button" class="button danger">删除（所选）</button>
        <label style="display:flex; align-items:center; gap:6px; font-size:13px">
          <input id="batch-purge-files" type="checkbox">
          同时清理证书文件
        </label>
        <button id="batch-issue-renew-btn" type="button" class="button ghost">全部申请/续签</button>
      </div>
      <div class="toolbar-right">
        <a class="button ghost" href="/bt">本机宝塔设置</a>
        <a class="button ghost" href="/logs">操作日志</a>
        <a class="button danger" href="/logout">退出登录</a>
      </div>
    </div>
    <div id="batch-mask" class="modal-mask" aria-hidden="true">
      <div class="modal">
        <div class="modal-header">
          <div class="modal-title">批量申请/续签</div>
          <button id="batch-close" class="modal-close" type="button">×</button>
        </div>
        <div class="modal-body">
          <pre id="batch-pre" class="modal-pre">准备中…</pre>
        </div>
        <div class="modal-footer">
          <button id="batch-copy" type="button" class="button ghost">复制</button>
          <button id="batch-hide" type="button" class="button ghost">隐藏</button>
        </div>
      </div>
    </div>
    <script>
      (function () {{
        var btn = document.getElementById('batch-issue-renew-btn');
        var btnSelected = document.getElementById('batch-issue-renew-selected-btn');
        var btnDeleteSelected = document.getElementById('batch-delete-selected-btn');
        var purgeToggle = document.getElementById('batch-purge-files');
        var mask = document.getElementById('batch-mask');
        var pre = document.getElementById('batch-pre');
        var closeBtn = document.getElementById('batch-close');
        var hideBtn = document.getElementById('batch-hide');
        var copyBtn = document.getElementById('batch-copy');

        var pollTimer = null;
        var finished = false;

        function show() {{
          if (!mask) return;
          mask.classList.add('show');
          mask.setAttribute('aria-hidden', 'false');
        }}

        function hide() {{
          if (!mask) return;
          mask.classList.remove('show');
          mask.setAttribute('aria-hidden', 'true');
        }}

        function setText(s) {{
          if (!pre) return;
          pre.textContent = s;
        }}

        function fmtState(st) {{
          if (!st) return '未获取到状态';
          var total = Number(st.total || 0);
          var processed = Number(st.processed || 0);
          var issued = Number(st.issued || 0);
          var renewed = Number(st.renewed || 0);
          var skipped = Number(st.skipped || 0);
          var failed = Number(st.failed || 0);
          var running = !!st.running;
          var done = !!st.done;
          var pct = total > 0 ? Math.floor((processed * 100) / total) : 0;
          var lines = [];
          lines.push('状态：' + (done ? '已完成' : (running ? '运行中' : '未运行')));
          if (total > 0) lines.push('进度：' + processed + '/' + total + '（' + pct + '%）');
          lines.push('申请：' + issued + '  续签：' + renewed + '  跳过：' + skipped + '  失败：' + failed);
          if (st.current) lines.push('当前：' + st.current);
          if (st.last) lines.push('最近：' + st.last);
          if (st.updated_at) lines.push('更新时间：' + st.updated_at);
          if (st.finished_at) lines.push('完成时间：' + st.finished_at);
          var out = lines.join('\\n');
          if (st.lines && st.lines.length) {{
            out += '\\n\\n' + st.lines.join('\\n');
          }}
          return out;
        }}

        function poll() {{
          fetch('/batch/status', {{ headers: {{ 'Accept': 'application/json', 'X-Requested-With': 'fetch' }} }})
            .then(function (r) {{ return r.json(); }})
            .then(function (st) {{
              setText(fmtState(st));
              if (!finished && st && st.done) {{
                finished = true;
                if (pollTimer) clearInterval(pollTimer);
                setTimeout(function () {{ window.location.reload(); }}, 900);
              }}
            }})
            .catch(function () {{
              setText('获取进度失败，稍后会自动重试…');
            }});
        }}

        function startPolling() {{
          if (pollTimer) return;
          poll();
          pollTimer = setInterval(poll, 1000);
        }}

        function selectedIds() {{
          var boxes = document.querySelectorAll('input.cert-select');
          var ids = [];
          for (var i = 0; i < boxes.length; i++) {{
            if (boxes[i].checked) ids.push(boxes[i].value);
          }}
          return ids;
        }}

        function setAllChecked(checked) {{
          var boxes = document.querySelectorAll('input.cert-select');
          for (var i = 0; i < boxes.length; i++) boxes[i].checked = !!checked;
        }}

        function syncCheckAll() {{
          var checkAll = document.getElementById('cert-check-all');
          if (!checkAll) return;
          var boxes = document.querySelectorAll('input.cert-select');
          var any = false;
          var all = true;
          for (var i = 0; i < boxes.length; i++) {{
            any = true;
            if (!boxes[i].checked) all = false;
          }}
          checkAll.checked = any && all;
        }}

        function startBatch() {{
          show();
          setText('正在启动任务…');
          startPolling();
          fetch('/batch/issue-renew', {{
            method: 'POST',
            headers: {{ 'Accept': 'application/json', 'X-Requested-With': 'fetch' }}
          }}).then(function () {{
            poll();
          }}).catch(function () {{
            poll();
          }});
        }}

        function startBatchSelected() {{
          var ids = selectedIds();
          if (!ids.length) {{
            alert('请先勾选至少一个域名');
            return;
          }}
          show();
          setText('正在启动任务…');
          startPolling();
          var body = new URLSearchParams();
          for (var i = 0; i < ids.length; i++) body.append('ids', ids[i]);
          fetch('/batch/issue-renew-selected', {{
            method: 'POST',
            headers: {{ 'Accept': 'application/json', 'X-Requested-With': 'fetch', 'Content-Type': 'application/x-www-form-urlencoded' }},
            body: body.toString()
          }}).then(function () {{
            poll();
          }}).catch(function () {{
            poll();
          }});
        }}

        function runSingle(mode, id) {{
          if (!id) return;
          show();
          setText('正在启动任务…');
          startPolling();
          var body = new URLSearchParams();
          body.append('ids', String(id));
          var url = mode === 'renew' ? '/batch/renew-selected' : '/batch/issue-selected';
          fetch(url, {{
            method: 'POST',
            headers: {{ 'Accept': 'application/json', 'X-Requested-With': 'fetch', 'Content-Type': 'application/x-www-form-urlencoded' }},
            body: body.toString()
          }}).then(function () {{
            poll();
          }}).catch(function () {{
            poll();
          }});
        }}

        function deleteSelected() {{
          var ids = selectedIds();
          if (!ids.length) {{
            alert('请先勾选至少一个域名');
            return;
          }}
          var purge = !!(purgeToggle && purgeToggle.checked);
          if (!confirm(purge ? '确认删除所选证书配置，并清理旧证书文件？' : '确认删除所选证书配置？')) return;
          var body = new URLSearchParams();
          for (var i = 0; i < ids.length; i++) body.append('ids', ids[i]);
          if (purge) body.append('purge_files', '1');
          fetch('/batch/delete-selected', {{
            method: 'POST',
            headers: {{ 'Accept': 'application/json', 'X-Requested-With': 'fetch', 'Content-Type': 'application/x-www-form-urlencoded' }},
            body: body.toString()
          }}).then(function (r) {{ return r.json(); }}).then(function () {{
            window.location.reload();
          }}).catch(function () {{
            window.location.reload();
          }});
        }}

        if (btn) btn.addEventListener('click', startBatch);
        if (btnSelected) btnSelected.addEventListener('click', startBatchSelected);
        if (btnDeleteSelected) btnDeleteSelected.addEventListener('click', deleteSelected);
        if (hideBtn) hideBtn.addEventListener('click', hide);
        if (closeBtn) closeBtn.addEventListener('click', hide);
        if (copyBtn) copyBtn.addEventListener('click', function () {{
          try {{
            var txt = pre ? pre.textContent : '';
            if (navigator.clipboard && navigator.clipboard.writeText) {{
              navigator.clipboard.writeText(txt || '');
            }} else {{
              var ta = document.createElement('textarea');
              ta.value = txt || '';
              document.body.appendChild(ta);
              ta.select();
              document.execCommand('copy');
              document.body.removeChild(ta);
            }}
          }} catch (e) {{}}
        }});
        if (mask) mask.addEventListener('click', function (e) {{ if (e.target === mask) hide(); }});
        document.addEventListener('keydown', function (e) {{ if (e.key === 'Escape') hide(); }});

        document.addEventListener('change', function (e) {{
          if (!e || !e.target) return;
          if (e.target.id === 'cert-check-all') {{
            setAllChecked(!!e.target.checked);
            return;
          }}
          if (e.target.classList && e.target.classList.contains('cert-select')) {{
            syncCheckAll();
          }}
        }});

        document.addEventListener('click', function (e) {{
          var t = e && e.target;
          if (!t) return;
          if (t.classList && t.classList.contains('single-issue')) {{
            runSingle('issue', t.getAttribute('data-id'));
            return;
          }}
          if (t.classList && t.classList.contains('single-renew')) {{
            runSingle('renew', t.getAttribute('data-id'));
            return;
          }}
        }});

        fetch('/batch/status', {{ headers: {{ 'Accept': 'application/json', 'X-Requested-With': 'fetch' }} }})
          .then(function (r) {{ return r.json(); }})
          .then(function (st) {{
            if (st && st.running) {{
              show();
              startPolling();
            }}
          }})
          .catch(function () {{}});
      }})();
    </script>
    <div class="card">
    <div class="table-responsive">
    <table class="cert-table">
      <thead>
        <tr>
          <th style="width:42px"><input id="cert-check-all" type="checkbox"></th>
          <th style="width:56px">序号</th>
          <th>名称</th>
          <th>域名</th>
          <th>Webroot</th>
          <th>面板</th>
          <th>站点</th>
          <th>到期时间</th>
          <th>剩余天数</th>
          <th>操作</th>
        </tr>
      </thead>
      <tbody>
        {''.join(rows)}
      </tbody>
    </table>
    </div>
    </div>
    """
    return render_page(content, message)


def render_new(message=""):
    content = f"""
    <form method="post">
      <h2>申请免费证书</h2>
      <div class="form-row"><label>域名（逗号分隔）</label><input type="text" name="domains" placeholder="example.com, www.example.com" required></div>
      <div class="flash">请确保域名已解析到本服务器，并且 80 端口可访问到本服务。</div>
      <div class="actions"><button type="submit" class="button primary">立即申请</button><a class="button ghost" href="/">返回</a></div>
    </form>
    """
    return render_page(content, message)


def render_cert_detail(cert, message=""):
    cert_id = cert["id"]
    domains = cert["domains"] or ""
    expiry = parse_expiry(cert["cert_path"]) if cert["cert_path"] else None
    cert_path = cert["cert_path"] or ""
    key_path = cert["key_path"] or ""
    cert_text = ""
    key_text = ""
    if cert_path and Path(cert_path).exists():
        try:
            cert_text = Path(cert_path).read_text("utf-8", errors="ignore")
        except Exception:
            cert_text = ""
    if key_path and Path(key_path).exists():
        try:
            key_text = Path(key_path).read_text("utf-8", errors="ignore")
        except Exception:
            key_text = ""
    content = f"""
    <div class="page-toolbar">
      <div class="toolbar-left">
        <a class="button ghost" href="/">返回</a>
      </div>
      <div class="toolbar-right">
        <a class="button ghost" href="/download?type=zip&id={cert_id}">下载证书包</a>
      </div>
    </div>
    <div class="card">
      <h2>证书详情</h2>
      <table>
        <tbody>
          <tr><th style="width:160px">域名</th><td>{html.escape(domains)}</td></tr>
          <tr><th>到期时间</th><td>{html.escape(str(expiry) if expiry else "未签发")}</td></tr>
          <tr><th>证书文件</th><td class="cell-mono">{html.escape(cert_path or "-")}</td></tr>
          <tr><th>私钥文件</th><td class="cell-mono">{html.escape(key_path or "-")}</td></tr>
        </tbody>
      </table>
    </div>
    <div class="card" style="margin-top:12px">
      <div class="page-toolbar">
        <div class="toolbar-left"><h2 style="margin:0">证书内容（fullchain）</h2></div>
        <div class="toolbar-right">
          <button type="button" class="button ghost" onclick="window.__copyText('cert-text')">复制</button>
          <a class="button ghost" href="/download?type=cert&id={cert_id}">下载</a>
        </div>
      </div>
      <textarea class="code-text" id="cert-text" readonly>{html.escape(cert_text)}</textarea>
    </div>
    <div class="card" style="margin-top:12px">
      <div class="page-toolbar">
        <div class="toolbar-left"><h2 style="margin:0">私钥内容（key）</h2></div>
        <div class="toolbar-right">
          <button type="button" class="button ghost" onclick="window.__copyText('key-text')">复制</button>
          <a class="button ghost" href="/download?type=key&id={cert_id}">下载</a>
        </div>
      </div>
      <textarea class="code-text" id="key-text" readonly>{html.escape(key_text)}</textarea>
    </div>
    <script>
      window.__copyText = function (id) {{
        var el = document.getElementById(id);
        if (!el) return;
        el.focus();
        el.select();
        try {{ document.execCommand('copy'); }} catch (e) {{}}
      }};
    </script>
    """
    return render_page(content, message)


def render_panels(message=""):
    rows = []
    for p in get_panels():
        verify = "开启" if bool(int(row_value(p, "verify_ssl", 0) or 0)) else "关闭"
        rows.append(
            f"""
            <tr>
              <td>{html.escape(p['name'])}</td>
              <td>{html.escape(p['base_url'])}</td>
              <td>{html.escape(p['admin_path'])}</td>
              <td>{verify}</td>
              <td>
                <div class="btn-group">
                  <form method="post" action="/panels/test?id={p['id']}"><button type="submit" class="button ghost small">测试连接</button></form>
                  <a class="button ghost small" href="/panels/edit?id={p['id']}">编辑</a>
                  <form method="post" action="/panels/delete?id={p['id']}"><button class="button danger small" type="submit">删除</button></form>
                  <a class="button primary small" href="/panels/import?id={p['id']}">导入站点</a>
                </div>
              </td>
            </tr>
            """
        )
    content = f"""
    <div class="page-toolbar">
      <div class="toolbar-left">
        <a class="button primary" href="/panels/new">新增面板</a>
        <a class="button ghost" href="/">返回</a>
      </div>
    </div>
    <div class="card">
      <div class="table-responsive">
        <table class="cert-table">
          <thead>
            <tr><th>名称</th><th>地址</th><th>Admin Path</th><th>HTTPS 证书校验</th><th>操作</th></tr>
          </thead>
          <tbody>{''.join(rows)}</tbody>
        </table>
      </div>
    </div>
    """
    return render_page(content, message)


def render_panel_form(panel=None, message=""):
    panel = panel or {"name": "", "base_url": "", "admin_path": "/bt", "api_token": "", "verify_ssl": 0}
    checked = "checked" if bool(int(row_value(panel, "verify_ssl", 0) or 0)) else ""
    content = f"""
    <form method="post">
      <div class="form-row"><label>名称</label><input type="text" name="name" value="{html.escape(panel['name'])}" required></div>
      <div class="form-row"><label>面板地址</label><input type="text" name="base_url" value="{html.escape(panel['base_url'])}" placeholder="http://IP:8888" required></div>
      <div class="form-row"><label>Admin Path</label><input type="text" name="admin_path" value="{html.escape(panel['admin_path'])}" placeholder="/bt"></div>
      <div class="form-row"><label>API Token</label><input type="text" name="api_token" value="{html.escape(panel['api_token'])}" required></div>
      <div class="form-row"><label><input type="checkbox" name="verify_ssl" value="1" {checked}> 验证 HTTPS 证书（自签/缺链请关闭）</label></div>
      <div class="actions"><button type="submit">保存</button><a class="button ghost" href="/panels">返回</a></div>
    </form>
    """
    return render_page(content, message)


def render_import(message="", sites=None, panel=None):
    rows = []
    for s in sites or []:
        rows.append(
            f"<tr><td>{html.escape(s)}</td><td><form method='post' action='/import/add?panel_id={panel['id']}&site={html.escape(s)}'><button type='submit'>加入证书配置</button></form></td></tr>"
        )
    content = f"""
    <div class="actions"><a class="button ghost" href="/panels">返回</a></div>
    <h2>导入宝塔站点 - {html.escape(panel['name'])}</h2>
    <div class="actions"><form method="post" action="/import/scan?panel_id={panel['id']}"><button type="submit">扫描站点</button></form></div>
    <table><thead><tr><th>站点/域名</th><th>操作</th></tr></thead><tbody>{''.join(rows)}</tbody></table>
    """
    return render_page(content, message)


def render_bt_settings(message=""):
    stored = get_local_bt_settings()
    effective = get_local_panel_config() or {}
    base_url = stored.get("base_url") or effective.get("base_url") or "https://127.0.0.1:22460"
    admin_path = stored.get("admin_path") or effective.get("admin_path") or "/bt"
    api_token = stored.get("api_token") or effective.get("api_token") or ""
    checked = "checked" if bool(int(stored.get("verify_ssl") or 0)) else ""
    hint = "已自动读取本机宝塔配置，可在此覆盖保存" if (not stored.get("api_token") and effective.get("api_token")) else ""
    nginx_status = ""
    try:
        txt = NGINX_DEFAULT_CONF.read_text("utf-8", errors="ignore") if NGINX_DEFAULT_CONF.exists() else ""
        nginx_status = "已配置" if nginx_default_has_acme_proxy(txt) else "未配置"
    except Exception:
        nginx_status = "未知"
    content = f"""
    <form method="post">
      <h2>本机宝塔面板设置</h2>
      <div class="form-row"><label>面板地址</label><input type="text" name="base_url" value="{html.escape(base_url)}" placeholder="https://127.0.0.1:22460"></div>
      <div class="form-row"><label>Admin Path（安全入口）</label><input type="text" name="admin_path" value="{html.escape(admin_path)}" placeholder="/24315b07"></div>
      <div class="form-row"><label>API Token（接口密钥）</label><input type="text" name="api_token" value="{html.escape(api_token)}" placeholder="宝塔面板-设置-API接口"></div>
      <div class="form-row"><label><input type="checkbox" name="verify_ssl" value="1" {checked}> 验证 HTTPS 证书（一般本机可关闭）</label></div>
      {f'<div class="flash">{html.escape(hint)}</div>' if hint else ''}
      <div class="actions">
        <button type="submit" class="button primary">保存</button>
        <a class="button ghost" href="/">返回</a>
      </div>
    </form>
    <div class="card" style="margin-top:12px">
      <h2>Nginx 默认站点</h2>
      <div class="flash">用于让任意解析到本机的域名都能通过 HTTP-01 校验。当前状态：{html.escape(nginx_status)}</div>
      <div class="actions">
        <form method="post" action="/nginx/default/apply">
          <button type="submit" class="button primary">一键配置 ACME 转发</button>
        </form>
      </div>
      <div class="text-muted" style="margin-top:8px; font-size:12px">{html.escape(str(NGINX_DEFAULT_CONF))}</div>
      <div class="text-muted" style="margin-top:6px; font-size:12px">转发目标：http://127.0.0.1:{html.escape(str(ACME_PROXY_PORT))}</div>
    </div>
    """
    return render_page(content, message)


def render_logs():
    with get_db() as conn:
        items = conn.execute(
            "SELECT id, action, target, status, message, created_at FROM logs ORDER BY id DESC LIMIT 200"
        ).fetchall()
    rows = []
    for it in items:
        rows.append(
            f"<tr><td>{it['id']}</td><td>{html.escape(it['action'])}</td><td>{html.escape(it['target'] or '')}</td><td>{it['status']}</td><td>{html.escape(it['message'] or '')}</td><td>{it['created_at']}</td></tr>"
        )
    content = f"""
    <div class="actions"><a class="button ghost" href="/">返回</a></div>
    <table><thead><tr><th>ID</th><th>动作</th><th>目标</th><th>状态</th><th>消息</th><th>时间</th></tr></thead><tbody>{''.join(rows)}</tbody></table>
    """
    return render_page(content)


def get_panel_by_id(panel_id):
    with get_db() as conn:
        return conn.execute("SELECT * FROM panels WHERE id = ?", (panel_id,)).fetchone()


def import_sites_from_local():
    db_path = "/www/server/panel/data/default.db"
    names = []
    if os.path.exists(db_path):
        try:
            conn = sqlite3.connect(db_path)
            conn.row_factory = sqlite3.Row
            rows = conn.execute("SELECT name FROM sites").fetchall()
            conn.close()
            names.extend([r["name"] for r in rows if (r["name"] or "").strip()])
        except Exception:
            pass
    root = "/www/server/panel/vhost/nginx"
    if os.path.isdir(root):
        for fn in os.listdir(root):
            if not fn.endswith(".conf"):
                continue
            try:
                text = Path(os.path.join(root, fn)).read_text("utf-8", errors="ignore")
                for m in re.finditer(r"server_name\\s+([^;]+);", text):
                    names.extend(split_domain_field(m.group(1)))
            except Exception:
                pass
    return sorted(set([n for n in names if n]))


def split_domain_field(value):
    raw = (value or "").strip()
    if not raw:
        return []
    parts = re.split(r"[,|\s]+", raw)
    return [p.strip() for p in parts if p and p.strip()]


def extract_webroot_from_nginx_conf_text(text):
    if not text:
        return None
    m = re.search(r"(?m)^\s*root\s+([^;]+);", text)
    if not m:
        return None
    path = (m.group(1) or "").strip().strip('"').strip("'")
    return path or None


def get_local_bt_site_webroot(site_name_or_domain):
    target = (site_name_or_domain or "").strip()
    if not target:
        return None

    db_path = "/www/server/panel/data/default.db"
    if os.path.exists(db_path):
        try:
            conn = sqlite3.connect(db_path)
            conn.row_factory = sqlite3.Row
            cols = [r["name"] for r in conn.execute("PRAGMA table_info(sites)").fetchall()]
            path_col = None
            for c in ["path", "site_path", "sitePath", "root"]:
                if c in cols:
                    path_col = c
                    break
            if path_col:
                row = conn.execute(
                    f"SELECT {path_col} AS p FROM sites WHERE name = ? LIMIT 1", (target,)
                ).fetchone()
                if row:
                    p = (row["p"] or "").strip()
                    if p:
                        return p
        except Exception:
            pass
        finally:
            try:
                conn.close()
            except Exception:
                pass

    root = "/www/server/panel/vhost/nginx"
    if not os.path.isdir(root):
        return None

    direct = os.path.join(root, f"{target}.conf")
    if os.path.exists(direct):
        try:
            text = Path(direct).read_text("utf-8", errors="ignore")
            p = extract_webroot_from_nginx_conf_text(text)
            if p:
                return p
        except Exception:
            pass

    for fn in os.listdir(root):
        if not fn.endswith(".conf"):
            continue
        try:
            text = Path(os.path.join(root, fn)).read_text("utf-8", errors="ignore")
            matched = False
            for m in re.finditer(r"server_name\s+([^;]+);", text):
                names = split_domain_field(m.group(1))
                for nm in names:
                    if nm == target:
                        matched = True
                        break
                    if nm.startswith("*.") and target.endswith(nm[1:]):
                        matched = True
                        break
                if matched:
                    break
            if not matched:
                continue
            p = extract_webroot_from_nginx_conf_text(text)
            if p:
                return p
        except Exception:
            pass
    return None


def get_panel_site_webroot(panel, domain):
    if not panel or not domain:
        return None
    ok, _status, body, _attempted, _meta = panel_api_request(
        panel,
        "/data",
        {"action": "getData", "table": "sites", "limit": 200, "p": 1},
    )
    if not ok:
        return None
    try:
        data = json.loads(body)
    except Exception:
        return None
    if not isinstance(data, dict) or data.get("status") is False:
        return None
    items = []
    payload = data.get("data")
    if isinstance(payload, dict):
        items = payload.get("data") or payload.get("list") or []
    elif isinstance(payload, list):
        items = payload
    elif "list" in data:
        items = data.get("list") or []
    for item in items:
        if not isinstance(item, dict):
            continue
        name = (item.get("name") or item.get("domain") or item.get("site_name") or "").strip()
        if not name:
            continue
        matched = False
        for nm in split_domain_field(name):
            if nm == domain:
                matched = True
                break
            if nm.startswith("*.") and domain.endswith(nm[1:]):
                matched = True
                break
        if not matched and domain != name:
            continue
        p = (item.get("path") or item.get("sitePath") or item.get("site_path") or "").strip()
        if p:
            return p
    return None


def guess_webroot_for_domain(domain, site_name=None):
    d = (domain or "").strip()
    if not d:
        return None
    candidates = [d]
    parts = d.split(".")
    if len(parts) > 2:
        for i in range(1, len(parts) - 1):
            alt = ".".join(parts[i:])
            if alt.count(".") >= 1 and alt not in candidates:
                candidates.append(alt)

    for cand in candidates:
        if site_name:
            p = get_local_bt_site_webroot(site_name)
            if p:
                return p
        p = get_local_bt_site_webroot(cand)
        if p:
            return p
        panel = get_local_panel_config()
        if panel:
            p = get_panel_site_webroot(panel, cand)
            if p:
                return p
    return None


def parse_sites_payload(data):
    if not isinstance(data, dict):
        return []
    if data.get("status") is False:
        return []
    items = []
    payload = data.get("data")
    if isinstance(payload, dict):
        items = payload.get("data") or payload.get("list") or []
    elif isinstance(payload, list):
        items = payload
    elif "list" in data:
        items = data.get("list") or []
    names = []
    for item in items:
        if isinstance(item, dict):
            name = item.get("name") or item.get("domain") or item.get("site_name")
            for nm in split_domain_field(name):
                if nm:
                    names.append(nm)
    return sorted(set(names))


def import_sites_from_panel(panel):
    ok, status, body, _attempted, _meta = panel_api_request(panel, "/data", {"action": "getData", "table": "sites", "limit": 200, "p": 1})
    if status == 404:
        log_action("import_scan", panel["name"], "fail", "HTTP 404")
        return []
    try:
        data = json.loads(body)
    except Exception:
        log_action("import_scan", panel["name"], "fail", "bad json")
        return []
    names = parse_sites_payload(data)
    ok, status, body, _attempted, _meta = panel_api_request(panel, "/data", {"action": "getData", "table": "domain", "limit": 200, "p": 1})
    if status == 404:
        log_action("import_scan", panel["name"], "fail", "HTTP 404")
        return []
    try:
        data = json.loads(body)
    except Exception:
        log_action("import_scan", panel["name"], "fail", "bad json")
        return []
    names.extend(parse_sites_payload(data))
    return sorted(set([n for n in names if n]))


def import_sites_from_local_panel_api():
    panel = get_local_panel_config()
    if not panel:
        return []
    return import_sites_from_panel(panel)

def get_importable_local_sites():
    sites = import_sites_from_local() or []
    sites_api = import_sites_from_local_panel_api() or []
    merged = sorted(set([s for s in sites + sites_api if s]))
    return merged


def check_api_token(handler):
    token = None
    auth = handler.headers.get("X-API-Token", "")
    if auth:
        token = auth.strip()
    if not token:
        parsed = urlparse(handler.path)
        params = parse_qs(parsed.query)
        token = params.get("token", [""])[0]
    return token == get_setting("api_token")


class Handler(BaseHTTPRequestHandler):
    def respond_html(self, body, status=HTTPStatus.OK, cookies=None):
        data = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        if cookies:
            for ck in cookies:
                self.send_header("Set-Cookie", ck)
        self.end_headers()
        self.wfile.write(data)

    def respond_bytes(self, content, content_type="application/octet-stream", filename=None, status=HTTPStatus.OK):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(content)))
        if filename:
            safe = filename.replace('"', "")
            self.send_header("Content-Disposition", f'attachment; filename="{safe}"')
        self.end_headers()
        self.wfile.write(content)

    def redirect(self, path, message="", cookies=None):
        if message:
            parsed = urlparse(path)
            query = parse_qs(parsed.query)
            query["msg"] = [message]
            path = urlunparse(
                (
                    parsed.scheme,
                    parsed.netloc,
                    parsed.path,
                    parsed.params,
                    urlencode(query, doseq=True),
                    parsed.fragment,
                )
            )
        self.send_response(HTTPStatus.SEE_OTHER)
        if cookies:
            for ck in cookies:
                self.send_header("Set-Cookie", ck)
        self.send_header("Location", path)
        self.end_headers()

    def require_auth(self):
        user = get_current_user(self)
        if not user:
            self.redirect("/login")
            return None
        return user

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path.startswith("/.well-known/acme-challenge/"):
            rel = parsed.path.lstrip("/")
            file_path = ACME_CHALLENGE_ROOT / rel
            if file_path.exists() and file_path.is_file():
                try:
                    content = file_path.read_bytes()
                    self.send_response(HTTPStatus.OK)
                    self.send_header("Content-Type", "text/plain; charset=utf-8")
                    self.send_header("Content-Length", str(len(content)))
                    self.end_headers()
                    self.wfile.write(content)
                    return
                except Exception:
                    pass
            self.send_response(HTTPStatus.NOT_FOUND)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.end_headers()
            self.wfile.write(b"Not Found")
            return

        if parsed.path.startswith("/static/"):
            file_path = BASE_DIR / parsed.path.lstrip("/")
            if file_path.exists() and file_path.is_file():
                try:
                    content = file_path.read_bytes()
                    self.send_response(HTTPStatus.OK)
                    if parsed.path.endswith(".css"):
                        self.send_header("Content-Type", "text/css; charset=utf-8")
                    elif parsed.path.endswith(".js"):
                         self.send_header("Content-Type", "application/javascript; charset=utf-8")
                    else:
                        self.send_header("Content-Type", "application/octet-stream")
                    self.send_header("Content-Length", str(len(content)))
                    self.end_headers()
                    self.wfile.write(content)
                    return
                except Exception:
                    pass
            return self.respond_html("Not Found", status=HTTPStatus.NOT_FOUND)

        params = parse_qs(parsed.query)
        message = params.get("msg", [""])[0]
        if parsed.path == "/login":
            return self.respond_html(render_login(message))
        if parsed.path == "/logout":
            return self.redirect("/login", "已退出", cookies=["session=; Path=/; Max-Age=0"])
        user = self.require_auth()
        if not user:
            return
        if parsed.path == "/batch/status":
            return json_response(self, get_batch_state())
        if user["must_change"] and parsed.path != "/password":
            return self.redirect("/password", "请先修改密码")
        if parsed.path == "/password":
            return self.respond_html(render_password(message))
        if parsed.path == "/":
            return self.respond_html(render_index(message))
        if parsed.path == "/apply":
            return self.redirect("/new")
        if parsed.path == "/new":
            return self.respond_html(render_new(message))
        if parsed.path == "/cert":
            cert_id = params.get("id", [""])[0]
            if not cert_id.isdigit():
                return self.redirect("/", "证书 ID 无效")
            with get_db() as conn:
                cert = conn.execute("SELECT * FROM certs WHERE id = ?", (cert_id,)).fetchone()
            if not cert:
                return self.redirect("/", "证书配置不存在")
            return self.respond_html(render_cert_detail(cert, message))
        if parsed.path == "/download":
            cert_id = params.get("id", [""])[0]
            dtype = (params.get("type", [""])[0] or "").strip()
            if not cert_id.isdigit():
                return self.redirect("/", "证书 ID 无效")
            if dtype not in {"cert", "key", "zip"}:
                return self.redirect(f"/cert?id={cert_id}", "下载类型无效")
            with get_db() as conn:
                cert = conn.execute("SELECT * FROM certs WHERE id = ?", (cert_id,)).fetchone()
            if not cert:
                return self.redirect("/", "证书配置不存在")
            cert_path = (cert["cert_path"] or "").strip()
            key_path = (cert["key_path"] or "").strip()
            domain = primary_domain(cert["domains"] or f"cert-{cert_id}")
            if dtype == "cert":
                if not cert_path or not Path(cert_path).exists():
                    return self.redirect(f"/cert?id={cert_id}", "证书文件不存在")
                return self.respond_bytes(Path(cert_path).read_bytes(), "application/x-pem-file", f"{domain}.fullchain.pem")
            if dtype == "key":
                if not key_path or not Path(key_path).exists():
                    return self.redirect(f"/cert?id={cert_id}", "私钥文件不存在")
                return self.respond_bytes(Path(key_path).read_bytes(), "application/x-pem-file", f"{domain}.key")
            if not cert_path or not Path(cert_path).exists() or not key_path or not Path(key_path).exists():
                return self.redirect(f"/cert?id={cert_id}", "证书或私钥文件不存在")
            buf = io.BytesIO()
            with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
                zf.writestr(f"{domain}.fullchain.pem", Path(cert_path).read_bytes())
                zf.writestr(f"{domain}.key", Path(key_path).read_bytes())
            return self.respond_bytes(buf.getvalue(), "application/zip", f"{domain}.zip")
        if parsed.path.startswith("/panels"):
            return self.redirect("/", "单机部署模式不支持添加/管理其他服务器宝塔面板")
        if parsed.path == "/import/local":
            sites = get_importable_local_sites()
            rows = []
            for s in sites:
                rows.append(
                    f"""
                    <tr>
                      <td style="width:40px"><input type="checkbox" name="sites" value="{html.escape(s)}"></td>
                      <td>{html.escape(s)}</td>
                      <td style="width:180px"><button type="submit" class="button ghost small" formaction="/import/local/add?site={html.escape(s)}">加入证书配置</button></td>
                    </tr>
                    """
                )
            empty_tip = ""
            if not sites:
                empty_tip = "未获取到本机站点/域名。请检查：1）已在“本机宝塔设置”保存正确的面板地址/Admin Path/API Token；2）宝塔面板已开启 API 接口；3）容器运行在宝塔服务器本机。"
            content = f"""
            <div class="actions"><a class="button ghost" href="/">返回</a></div>
            {f'<div class="flash">{html.escape(empty_tip)}</div>' if empty_tip else ''}
            <form method="post">
              <div class="actions" style="margin: 10px 0">
                <label style="display:flex; align-items:center; gap:8px"><input id="site-check-all" type="checkbox"> 全选</label>
                <button type="submit" class="button primary" formaction="/import/local/add_selected">导入所选</button>
                <button type="submit" class="button ghost" formaction="/import/local/add_all">一键全部导入</button>
              </div>
              <table>
                <thead><tr><th style="width:40px"></th><th>站点/域名</th><th style="width:180px">操作</th></tr></thead>
                <tbody>{''.join(rows)}</tbody>
              </table>
            </form>
            <script>
              (function () {{
                var all = document.getElementById('site-check-all');
                if (!all) return;
                all.addEventListener('change', function () {{
                  var boxes = document.querySelectorAll('input[name=\"sites\"]');
                  for (var i = 0; i < boxes.length; i++) boxes[i].checked = all.checked;
                }});
              }})();
            </script>
            """
            return self.respond_html(render_page(content, message))
        if parsed.path == "/bt":
            return self.respond_html(render_bt_settings(message))
        if parsed.path == "/logs":
            return self.respond_html(render_logs())
        return self.respond_html("Not Found", status=HTTPStatus.NOT_FOUND)

    def do_POST(self):
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)
        if parsed.path == "/login":
            form = parse_form(self)
            username = (form.get("username", [""])[0]).strip()
            password = (form.get("password", [""])[0]).strip()
            with get_db() as conn:
                user = conn.execute("SELECT id, username, password_hash, must_change FROM users WHERE username = ?", (username,)).fetchone()
            if not user or not verify_password(password, user["password_hash"]):
                log_action("login", username, "fail", "bad credentials")
                return self.respond_html(render_login("账号或密码错误"))
            token = sign_session(user["id"], user["must_change"])
            log_action("login", username, "ok", "")
            return self.redirect("/", cookies=[f"session={token}; Path=/; HttpOnly"])
        user = self.require_auth()
        if not user:
            return
        if user["must_change"] and parsed.path != "/password":
            return self.redirect("/password", "请先修改密码")
        if parsed.path == "/password":
            form = parse_form(self)
            old_password = (form.get("old_password", [""])[0]).strip()
            new_password = (form.get("new_password", [""])[0]).strip()
            confirm_password = (form.get("confirm_password", [""])[0]).strip()
            if not new_password or new_password != confirm_password:
                return self.respond_html(render_password("新密码不一致"))
            with get_db() as conn:
                row = conn.execute("SELECT password_hash FROM users WHERE id = ?", (user["id"],)).fetchone()
                if not row or not verify_password(old_password, row["password_hash"]):
                    return self.respond_html(render_password("旧密码错误"))
                conn.execute(
                    "UPDATE users SET password_hash = ?, must_change = 0, updated_at = ? WHERE id = ?",
                    (create_password_hash(new_password), datetime.utcnow().isoformat(), user["id"]),
                )
            token = sign_session(user["id"], 0)
            log_action("password_change", user["username"], "ok", "")
            return self.redirect("/", "密码已更新", cookies=[f"session={token}; Path=/; HttpOnly"])
        if parsed.path == "/bt":
            form = parse_form(self)
            base_url = (form.get("base_url", [""])[0]).strip()
            admin_path = (form.get("admin_path", [""])[0]).strip()
            api_token = (form.get("api_token", [""])[0]).strip()
            verify_ssl = 1 if (form.get("verify_ssl", [""])[0]).strip() else 0
            if api_token and not base_url:
                base_url = "https://127.0.0.1:22460"
            if admin_path and not admin_path.startswith("/"):
                admin_path = "/" + admin_path
            save_local_bt_settings(base_url, admin_path, api_token, verify_ssl)
            panel = get_local_panel_config()
            if not panel:
                log_action("bt_settings", base_url or "auto", "ok", "saved only")
                return self.redirect("/bt", "已保存，但未检测到可用的宝塔配置")
            ok, msg = test_panel(panel)
            log_action("bt_settings", base_url or "auto", "ok" if ok else "fail", msg)
            return self.redirect("/bt", f"已保存，{msg}" if ok else f"已保存，但连接失败：{msg}")
        if parsed.path == "/nginx/default/apply":
            ok, msg = apply_nginx_default_acme_proxy()
            log_action("nginx_default", "apply", "ok" if ok else "fail", msg)
            return self.redirect("/bt", msg if ok else f"配置失败：{msg}")
        if parsed.path == "/batch/issue-renew":
            ok, msg = start_batch_issue_renew()
            if wants_json_request(self):
                return json_response(self, {"ok": bool(ok), "message": msg, "state": get_batch_state()})
            return self.redirect("/", msg if ok else f"执行失败：{msg}")
        if parsed.path == "/batch/issue-renew-selected":
            form = parse_form(self)
            ids = form.get("ids") or []
            certs = get_certs_by_ids(ids)
            if not certs:
                if wants_json_request(self):
                    return json_response(self, {"ok": False, "message": "未选择任何域名", "state": get_batch_state()}, status=HTTPStatus.BAD_REQUEST)
                return self.redirect("/", "未选择任何域名")
            ok, msg = start_batch_issue_renew(certs=certs, scope="selected")
            if wants_json_request(self):
                return json_response(self, {"ok": bool(ok), "message": msg, "state": get_batch_state()})
            return self.redirect("/", msg if ok else f"执行失败：{msg}")
        if parsed.path == "/batch/issue-selected":
            form = parse_form(self)
            ids = form.get("ids") or []
            certs = get_certs_by_ids(ids)
            if not certs:
                if wants_json_request(self):
                    return json_response(self, {"ok": False, "message": "未选择任何域名", "state": get_batch_state()}, status=HTTPStatus.BAD_REQUEST)
                return self.redirect("/", "未选择任何域名")
            ok, msg = start_batch_issue_renew(certs=certs, scope="selected", mode="issue")
            if wants_json_request(self):
                return json_response(self, {"ok": bool(ok), "message": msg, "state": get_batch_state()})
            return self.redirect("/", msg if ok else f"执行失败：{msg}")
        if parsed.path == "/batch/renew-selected":
            form = parse_form(self)
            ids = form.get("ids") or []
            certs = get_certs_by_ids(ids)
            if not certs:
                if wants_json_request(self):
                    return json_response(self, {"ok": False, "message": "未选择任何域名", "state": get_batch_state()}, status=HTTPStatus.BAD_REQUEST)
                return self.redirect("/", "未选择任何域名")
            ok, msg = start_batch_issue_renew(certs=certs, scope="selected", mode="renew")
            if wants_json_request(self):
                return json_response(self, {"ok": bool(ok), "message": msg, "state": get_batch_state()})
            return self.redirect("/", msg if ok else f"执行失败：{msg}")
        if parsed.path == "/batch/delete-selected":
            form = parse_form(self)
            ids = [x for x in (form.get("ids") or []) if str(x).strip().isdigit()]
            purge = bool((form.get("purge_files") or [""])[0])
            if not ids:
                if wants_json_request(self):
                    return json_response(self, {"ok": False, "message": "未选择任何域名"}, status=HTTPStatus.BAD_REQUEST)
                return self.redirect("/", "未选择任何域名")
            id_ints = [int(x) for x in ids]
            certs = get_certs_by_ids(id_ints) if purge else []
            with get_db() as conn:
                placeholders = ",".join(["?"] * len(id_ints))
                conn.execute(f"DELETE FROM certs WHERE id IN ({placeholders})", tuple(id_ints))
            log_action("cert_delete_batch", ",".join([str(i) for i in id_ints]), "ok", "")
            purged = 0
            if purge:
                for c in certs:
                    purged += purge_cert_files(c)
                log_action("cert_purge_batch", ",".join([str(i) for i in id_ints]), "ok", str(purged))
            if wants_json_request(self):
                return json_response(self, {"ok": True, "deleted": len(id_ints), "purged": purged})
            return self.redirect("/", f"已删除 {len(id_ints)} 个")
        if parsed.path == "/new":
            form = parse_form(self)
            domains = (form.get("domains", [""])[0]).strip()
            valid, result = validate_domains(domains)
            if not valid:
                return self.respond_html(render_new(result))
            if any(d.startswith("*.") for d in result):
                return self.respond_html(render_new("当前模式不支持通配符域名（*.example.com），请使用 DNS 验证"))
            normalized_domains = ", ".join(result)
            existing_id = get_existing_cert_id_for_domains(normalized_domains)
            if existing_id:
                return self.redirect(f"/cert?id={existing_id}", "域名已存在证书记录")

            name = primary_domain(normalized_domains)
            (ACME_CHALLENGE_ROOT / ".well-known" / "acme-challenge").mkdir(parents=True, exist_ok=True)
            webroot = str(ACME_CHALLENGE_ROOT)
            email = f"admin@{primary_domain(normalized_domains)}"
            now = datetime.utcnow().isoformat()
            with get_db() as conn:
                conn.execute(
                    """
                    INSERT INTO certs (name, domains, webroot, email, panel_id, site_name, acme_home, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (name, normalized_domains, webroot, email, None, None, str(DEFAULT_ACME_HOME), now, now),
                )
                cert_id = conn.execute("SELECT last_insert_rowid() AS id").fetchone()["id"]
                cert = conn.execute("SELECT * FROM certs WHERE id = ?", (cert_id,)).fetchone()
            log_action("cert_add", domains, "ok", name)
            try:
                ok, issued = issue_cert(cert)
            except Exception as e:
                record_error(cert_id, str(e))
                return self.redirect(f"/cert?id={cert_id}", f"申请失败: {e}")
            if not ok:
                record_error(cert_id, issued)
                return self.redirect(f"/cert?id={cert_id}", f"申请失败: {issued}")
            cert_path, key_path = issued
            record_issue(cert_id, cert_path, key_path)
            return self.redirect(f"/cert?id={cert_id}", "申请成功")
        if parsed.path == "/issue" or parsed.path == "/renew":
            cert_id = params.get("id", [""])[0]
            if not cert_id.isdigit():
                return self.redirect("/", "证书 ID 无效")
            with get_db() as conn:
                cert = conn.execute("SELECT * FROM certs WHERE id = ?", (cert_id,)).fetchone()
            if not cert:
                return self.redirect("/", "证书配置不存在")
            if parsed.path == "/issue":
                existing_expiry = parse_expiry(cert["cert_path"])
                if existing_expiry and existing_expiry > datetime.utcnow():
                    return self.redirect("/", "证书已存在，请使用续签")
                try:
                    ok, result = issue_cert(cert)
                except Exception as e:
                    log_action("issue", row_value(cert, "domains", "") or str(cert_id), "fail", str(e))
                    record_error(cert_id, str(e))
                    return self.redirect("/", f"申请失败: {e}")
                if not ok:
                    record_error(cert_id, result)
                    return self.redirect("/", result)
                cert_path, key_path = result
                record_issue(cert_id, cert_path, key_path)
            else:
                try:
                    ok, result = renew_cert(cert, force=True)
                except Exception as e:
                    log_action("renew", row_value(cert, "domains", "") or str(cert_id), "fail", str(e))
                    record_error(cert_id, str(e))
                    return self.redirect("/", f"续签失败: {e}")
                if not ok:
                    record_error(cert_id, result)
                    return self.redirect("/", result)
                cert_path, key_path = result
                record_renew(cert_id, cert_path, key_path)
            deploy_local(cert["site_name"], cert_path, key_path)
            return self.redirect("/", "已完成")
        if parsed.path == "/delete":
            cert_id = params.get("id", [""])[0]
            if not cert_id.isdigit():
                return self.redirect("/", "证书 ID 无效")
            with get_db() as conn:
                conn.execute("DELETE FROM certs WHERE id = ?", (cert_id,))
            log_action("cert_delete", cert_id, "ok", "")
            return self.redirect("/", "已删除")
        if parsed.path.startswith("/panels") or parsed.path == "/import/scan":
            return self.redirect("/", "单机部署模式不支持添加/管理其他服务器宝塔面板")
        if parsed.path == "/import/add":
            return self.redirect("/", "单机部署模式不支持远程面板导入")
        if parsed.path == "/import/local/add":
            site = params.get("site", [""])[0]
            if not site:
                return self.redirect("/import/local", "参数错误")
            name = site
            domains = site
            if has_cert_config_for_domains(domains):
                return self.redirect("/", "域名已存在证书配置，禁止重复添加")
            (ACME_CHALLENGE_ROOT / ".well-known" / "acme-challenge").mkdir(parents=True, exist_ok=True)
            webroot = str(ACME_CHALLENGE_ROOT)
            email = f"admin@{primary_domain(site)}" if "." in site else "admin@example.com"
            now = datetime.utcnow().isoformat()
            with get_db() as conn:
                conn.execute(
                    """
                    INSERT INTO certs (name, domains, webroot, email, panel_id, site_name, acme_home, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (name, domains, webroot, email, None, site, str(DEFAULT_ACME_HOME), now, now),
                )
            log_action("import_local_add", site, "ok", "")
            return self.redirect("/", "已加入配置")
        if parsed.path == "/import/local/add_selected":
            form = parse_form(self)
            sites = [s.strip() for s in (form.get("sites") or []) if s and s.strip()]
            if not sites:
                return self.redirect("/import/local", "未选择任何域名")
            added = 0
            skipped = 0
            for site in sites:
                if has_cert_config_for_domains(site):
                    skipped += 1
                    continue
                (ACME_CHALLENGE_ROOT / ".well-known" / "acme-challenge").mkdir(parents=True, exist_ok=True)
                webroot = str(ACME_CHALLENGE_ROOT)
                email = f"admin@{primary_domain(site)}" if "." in site else "admin@example.com"
                now = datetime.utcnow().isoformat()
                with get_db() as conn:
                    conn.execute(
                        """
                        INSERT INTO certs (name, domains, webroot, email, panel_id, site_name, acme_home, created_at, updated_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (site, site, webroot, email, None, site, str(DEFAULT_ACME_HOME), now, now),
                    )
                log_action("import_local_add", site, "ok", "")
                added += 1
            return self.redirect("/", f"已导入 {added} 个，跳过 {skipped} 个")
        if parsed.path == "/import/local/add_all":
            sites = get_importable_local_sites()
            if not sites:
                return self.redirect("/import/local", "未获取到可导入域名")
            added = 0
            skipped = 0
            for site in sites:
                if has_cert_config_for_domains(site):
                    skipped += 1
                    continue
                (ACME_CHALLENGE_ROOT / ".well-known" / "acme-challenge").mkdir(parents=True, exist_ok=True)
                webroot = str(ACME_CHALLENGE_ROOT)
                email = f"admin@{primary_domain(site)}" if "." in site else "admin@example.com"
                now = datetime.utcnow().isoformat()
                with get_db() as conn:
                    conn.execute(
                        """
                        INSERT INTO certs (name, domains, webroot, email, panel_id, site_name, acme_home, created_at, updated_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (site, site, webroot, email, None, site, str(DEFAULT_ACME_HOME), now, now),
                    )
                log_action("import_local_add", site, "ok", "")
                added += 1
            return self.redirect("/", f"已全部导入 {added} 个，跳过 {skipped} 个")
        return self.respond_html("Not Found", status=HTTPStatus.NOT_FOUND)


def start_server():
    server = ThreadingHTTPServer(("0.0.0.0", int(os.environ.get("PORT", "8080"))), Handler)
    server.serve_forever()


if __name__ == "__main__":
    init_db()
    if os.environ.get("AUTO_RENEW", "1") == "1":
        threading.Thread(target=auto_loop, daemon=True).start()
    start_server()
