import os
import time
import secrets
from functools import wraps

from flask import Flask, render_template, request, redirect, session, abort
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# ============================================================
# [修复] 使用环境变量或随机生成强密钥，替代硬编码弱密钥
# ============================================================
app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)

# ============================================================
# [修复] Session Cookie 安全配置
# ============================================================
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=False,          # 生产环境应设为 True (HTTPS)
)

# ============================================================
# [修复] 密码使用哈希存储，替代明文
# ============================================================
USERS = {
    "admin": {
        "username": "admin",
        "password": generate_password_hash("admin123"),
        "role": "admin",
        "email": "admin@example.com",
        "phone": "13800138000",
        "balance": 99999,
    },
    "alice": {
        "username": "alice",
        "password": generate_password_hash("alice2025"),
        "role": "user",
        "email": "alice@example.com",
        "phone": "13900139001",
        "balance": 100,
    },
}


# ============================================================
# [新增] 登录频率限制（内存中按 IP 追踪）
# ============================================================
LOGIN_RATE_LIMIT = 5          # 最多尝试次数
LOGIN_RATE_WINDOW = 60        # 时间窗口（秒）
_login_attempts = {}           # {ip: [timestamp, ...]}


def _check_login_rate_limit(ip: str) -> bool:
    """返回 True 表示已被限制"""
    now = time.time()
    window_start = now - LOGIN_RATE_WINDOW
    # 清理过期记录
    if ip in _login_attempts:
        _login_attempts[ip] = [t for t in _login_attempts[ip] if t > window_start]
        if len(_login_attempts[ip]) >= LOGIN_RATE_LIMIT:
            return True
    return False


def _record_login_attempt(ip: str):
    if ip not in _login_attempts:
        _login_attempts[ip] = []
    _login_attempts[ip].append(time.time())


# ============================================================
# [新增] CSRF 保护
# ============================================================
def _generate_csrf_token() -> str:
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(16)
    return session["csrf_token"]


def _validate_csrf_token(token: str | None) -> bool:
    if not token:
        return False
    stored = session.get("csrf_token")
    if not stored:
        return False
    return secrets.compare_digest(stored, token)


def csrf_required(f):
    """视图装饰器：校验 POST 请求中的 CSRF token"""
    @wraps(f)
    def decorated(*args, **kwargs):
        if request.method == "POST":
            token = request.form.get("csrf_token")
            if not _validate_csrf_token(token):
                abort(403, description="CSRF token 无效或已过期，请刷新页面重试")
        return f(*args, **kwargs)
    return decorated


# ============================================================
# [修复] 辅助函数：移除密码后再传递到模板，避免密码泄露
# ============================================================
def _safe_user_info(username: str) -> dict | None:
    """从 USERS 中取出用户信息，但移除密码字段"""
    raw = USERS.get(username)
    if raw is None:
        return None
    return {k: v for k, v in raw.items() if k != "password"}


# ============================================================
# 路由：首页
# ============================================================
@app.route("/")
def index():
    username = session.get("username")
    user_info = _safe_user_info(username) if username else None
    return render_template("index.html", user=user_info)


# ============================================================
# 路由：登录
# ============================================================
@app.route("/login", methods=["GET", "POST"])
@csrf_required
def login():
    if request.method == "POST":
        client_ip = request.remote_addr or "unknown"

        # [新增] 登录频率限制
        if _check_login_rate_limit(client_ip):
            return render_template(
                "login.html",
                error="登录尝试过于频繁，请稍后再试",
                csrf_token=_generate_csrf_token(),
            )

        # [修复] 输入清洗与校验
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""

        if not username or not password:
            return render_template(
                "login.html",
                error="请输入用户名和密码",
                csrf_token=_generate_csrf_token(),
            )

        # [修复] 使用安全哈希比对，替代 == 明文比对
        if username in USERS and check_password_hash(USERS[username]["password"], password):
            # 登录成功 → 重置该 IP 的失败计数
            _login_attempts.pop(client_ip, None)
            # 重新生成 CSRF token（防止会话固定）
            session.clear()
            session["username"] = username
            session["csrf_token"] = secrets.token_hex(16)
            user_info = _safe_user_info(username)
            return render_template("index.html", user=user_info)

        # [新增] 记录失败尝试
        _record_login_attempt(client_ip)

        # [修复] 统一错误信息，不提示是"用户名"还是"密码"的错误
        return render_template(
            "login.html",
            error="用户名或密码不正确",
            csrf_token=_generate_csrf_token(),
        )

    # GET 请求：生成 CSRF token 传入模板
    return render_template("login.html", csrf_token=_generate_csrf_token())


# ============================================================
# 路由：登出
# ============================================================
@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


# ============================================================
# 启动
# ============================================================
if __name__ == "__main__":
    # [修复] debug 模式由环境变量控制，生产环境默认关闭
    debug_mode = os.environ.get("FLASK_DEBUG", "0") == "1"
    app.run(host="0.0.0.0", port=5000, debug=debug_mode)
