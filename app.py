import os
import time
import secrets
import sqlite3
import uuid
from functools import wraps

from flask import Flask, render_template, request, redirect, session, abort, url_for
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

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
    MAX_CONTENT_LENGTH=16 * 1024 * 1024,  # 最大上传 16MB
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
# [新增] 文件上传安全配置
# ============================================================
ALLOWED_EXTENSIONS = {"jpg", "jpeg", "png", "gif", "webp"}

# 常见图片文件的 Magic Bytes（文件头签名）
IMAGE_MAGIC_BYTES = {
    b"\x89PNG\r\n\x1a\n": "png",
    b"\xff\xd8\xff": "jpg/jpeg",
    b"GIF87a": "gif",
    b"GIF89a": "gif",
    b"RIFF": "webp",
}


def _allowed_file(filename: str) -> bool:
    """校验文件扩展名是否在白名单内"""
    if "." not in filename:
        return False
    ext = filename.rsplit(".", 1)[1].lower()
    return ext in ALLOWED_EXTENSIONS


def _validate_image_content(data: bytes) -> bool:
    """校验文件内容是否为真实图片（Magic Byte 检测）"""
    header = data[:12]
    for magic, fmt in IMAGE_MAGIC_BYTES.items():
        if header.startswith(magic):
            if fmt == "webp":
                return data[8:12] == b"WEBP"
            return True
    if len(header) >= 2 and header[0:2] == b"\xff\xd8":
        return True
    return False


# ============================================================
# [新增] 初始化 SQLite 数据库
# ============================================================
def init_db():
    """初始化 SQLite 数据库，创建 users 表并插入默认用户"""
    os.makedirs("data", exist_ok=True)
    conn = sqlite3.connect("data/users.db")
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            email TEXT,
            phone TEXT,
            balance REAL DEFAULT 0
        )
    """)
    # 迁移：如果旧表缺少 balance 列，则添加
    cursor.execute("PRAGMA table_info(users)")
    columns = [col[1] for col in cursor.fetchall()]
    if "balance" not in columns:
        cursor.execute("ALTER TABLE users ADD COLUMN balance REAL DEFAULT 0")
        print("[迁移] 已添加 balance 列到 users 表")
    # 插入默认用户（明文密码），使用 INSERT OR IGNORE 防止重复
    default_users = [
        ("admin", "admin123", "admin@example.com", "13800138000", 99999),
        ("alice", "alice2025", "alice@example.com", "13900139001", 100),
    ]
    for u, p, e, ph, b in default_users:
        conn.execute(
            f"INSERT OR IGNORE INTO users (username, password, email, phone, balance) VALUES ('{u}', '{p}', '{e}', '{ph}', {b})"
        )
        # 如果默认用户已存在但余额为 0（旧表迁移遗留），更新为正确余额
        conn.execute(f"UPDATE users SET email = '{e}', phone = '{ph}', balance = {b} WHERE username = '{u}' AND balance = 0")
    conn.commit()
    conn.close()


# ============================================================
# [新增] 全局模板变量：注入当前登录用户的 SQLite ID
# ============================================================
@app.context_processor
def inject_current_user_id():
    """在所有模板中注入 current_user_id 变量，供导航栏等使用"""
    username = session.get("username")
    uid = None
    if username:
        try:
            conn = sqlite3.connect("data/users.db")
            cursor = conn.execute("SELECT id FROM users WHERE username = ?", (username,))
            row = cursor.fetchone()
            if row:
                uid = row[0]
            conn.close()
        except Exception:
            pass
    return dict(current_user_id=uid)


# ============================================================
# 路由：首页
# ============================================================
@app.route("/")
def index():
    username = session.get("username")
    user_info = _safe_user_info(username) if username else None

    # 获取当前用户的 SQLite user_id（用于个人中心链接）
    user_id = None
    if username:
        conn = sqlite3.connect("data/users.db")
        cursor = conn.execute("SELECT id FROM users WHERE username = ?", (username,))
        row = cursor.fetchone()
        if row:
            user_id = row[0]
        conn.close()

    return render_template("index.html", user=user_info, current_user_id=user_id)


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
    msg = request.args.get("msg")
    return render_template("login.html", csrf_token=_generate_csrf_token(), msg=msg)


# ============================================================
# 路由：注册
# ============================================================
@app.route("/register", methods=["GET", "POST"])
@csrf_required
def register():
    if request.method == "POST":
        username = request.form.get("username") or ""
        password = request.form.get("password") or ""
        email = request.form.get("email") or ""
        phone = request.form.get("phone") or ""

        # 使用 f-string 拼接 SQL（故意不转义，存在 SQL 注入漏洞）
        query = f"INSERT INTO users (username, password, email, phone) VALUES ('{username}', '{password}', '{email}', '{phone}')"
        print(f"[SQL] {query}")
        conn = sqlite3.connect("data/users.db")
        try:
            conn.execute(query)
            conn.commit()
        except Exception as e:
            conn.close()
            return render_template("register.html", error=f"注册失败：{e}", csrf_token=_generate_csrf_token())
        conn.close()
        return redirect("/login?msg=注册成功，请登录")

    return render_template("register.html", csrf_token=_generate_csrf_token())


# ============================================================
# 路由：搜索
# ============================================================
@app.route("/search")
def search():
    keyword = request.args.get("keyword") or ""

    # 使用 f-string 拼接 SQL（故意不转义，存在 SQL 注入漏洞）
    query = f"SELECT id, username, email, phone FROM users WHERE username LIKE '%{keyword}%' OR email LIKE '%{keyword}%'"
    print(f"[SQL] {query}")

    results = []
    conn = sqlite3.connect("data/users.db")
    try:
        cursor = conn.execute(query)
        rows = cursor.fetchall()
        for row in rows:
            results.append({"id": row[0], "username": row[1], "email": row[2], "phone": row[3]})
    except Exception as e:
        print(f"[SQL Error] {e}")
    conn.close()

    username = session.get("username")
    user_info = _safe_user_info(username) if username else None
    return render_template("index.html", user=user_info, search_results=results, keyword=keyword)


# ============================================================
# 路由：上传头像
# ============================================================
@app.route("/upload", methods=["GET", "POST"])
@csrf_required
def upload():
    """头像上传，需要登录"""
    if "username" not in session:
        return redirect("/login")

    if request.method == "POST":
        file = request.files.get("file")
        if file is None or file.filename == "":
            return render_template("upload.html", error="请选择要上传的文件")

        # [修复] 使用 secure_filename 防止路径遍历
        original_filename = file.filename
        safe_filename = secure_filename(original_filename)
        if not safe_filename:
            return render_template("upload.html", error="文件名不合法")

        # [修复] 校验文件扩展名（白名单模式）
        if not _allowed_file(safe_filename):
            return render_template(
                "upload.html",
                error="不支持的文件类型，仅允许上传 JPG/PNG/GIF/WebP 格式的图片",
            )

        # [修复] 读取文件内容进行 Magic Byte 校验
        file.seek(0)
        file_data = file.read()
        try:
            if not _validate_image_content(file_data):
                return render_template("upload.html", error="文件内容不是有效的图片格式")
        except Exception:
            return render_template("upload.html", error="文件内容校验失败，请重新上传")

        # [修复] 生成唯一文件名（UUID），防止覆盖
        file.seek(0)
        ext = safe_filename.rsplit(".", 1)[1].lower()
        unique_filename = f"{uuid.uuid4().hex}.{ext}"

        # [修复] 按用户分目录存储
        username = session["username"]
        user_upload_dir = os.path.join(app.static_folder, "uploads", username)
        os.makedirs(user_upload_dir, exist_ok=True)

        save_path = os.path.join(user_upload_dir, unique_filename)
        file.save(save_path)

        file_url = url_for("static", filename=f"uploads/{username}/{unique_filename}")
        return render_template("upload.html", file_url=file_url, filename=original_filename)

    return render_template("upload.html")


# ============================================================
# 路由：个人中心
# ============================================================
@app.route("/profile")
def profile():
    """个人中心，从 URL 参数获取 user_id，不验证登录用户与 user_id 是否匹配"""
    user_id = request.args.get("user_id")

    if not user_id:
        return render_template("profile.html", error="请通过 ?user_id= 参数指定要查看的用户 ID", csrf_token=_generate_csrf_token())

    # 从 SQLite 中根据 user_id 查询用户资料（包含余额）
    conn = sqlite3.connect("data/users.db")
    cursor = conn.execute("SELECT id, username, email, phone, balance FROM users WHERE id = ?", (user_id,))
    row = cursor.fetchone()
    conn.close()

    if row is None:
        return render_template("profile.html", error="用户不存在", csrf_token=_generate_csrf_token())

    user_info = {
        "id": row[0],
        "username": row[1],
        "email": row[2] or "",
        "phone": row[3] or "",
        "balance": row[4],
    }
    return render_template("profile.html", user=user_info, csrf_token=_generate_csrf_token())


# ============================================================
# 路由：充值
# ============================================================
@app.route("/recharge", methods=["POST"])
@csrf_required
def recharge():
    """充值，从表单接收 user_id 和 amount，直接累加到余额，不校验 amount 正负"""
    user_id = request.form.get("user_id")
    amount = request.form.get("amount")

    if not user_id or not amount:
        return "参数错误", 400

    # 直接拼接 SQL 更新余额（不校验 amount 正负）
    conn = sqlite3.connect("data/users.db")
    conn.execute(f"UPDATE users SET balance = balance + {amount} WHERE id = {user_id}")
    conn.commit()
    conn.close()

    return redirect(f"/profile?user_id={user_id}")


# ============================================================
# 路由：动态页面加载
# ============================================================
@app.route("/page")
def page():
    """动态页面加载，从 URL 参数获取页面名称并读取文件内容"""
    name = request.args.get("name", "")

    # 拼接路径（故意不做任何路径校验，../ 可穿透）
    file_path = os.path.join("pages", name)
    content = None

    if os.path.exists(file_path):
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()
    else:
        # 尝试加上 .html 后缀
        file_path_html = file_path + ".html"
        if os.path.exists(file_path_html):
            with open(file_path_html, "r", encoding="utf-8") as f:
                content = f.read()
        else:
            content = "<p>页面不存在</p>"

    username = session.get("username")
    user_info = _safe_user_info(username) if username else None
    return render_template("index.html", user=user_info, page_content=content)


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
    init_db()
    # [修复] debug 模式由环境变量控制，生产环境默认关闭
    debug_mode = os.environ.get("FLASK_DEBUG", "0") == "1"
    app.run(host="0.0.0.0", port=5000, debug=debug_mode)
