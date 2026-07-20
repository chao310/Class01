# SQL 注入漏洞分析与修复方案

> **项目：** 用户信息管理平台  
> **日期：** 2026-07-20  
> **涉及文件：** `app.py`、`templates/register.html`、`templates/index.html`

---

## 一、漏洞概述

本项目在三个位置存在 SQL 注入漏洞，所有 SQL 查询均使用 **f-string 字符串拼接** 方式构建，未对用户输入做任何过滤或转义，攻击者可通过构造特殊输入操纵 SQL 语句，导致数据泄露、数据篡改甚至数据库被破坏。

| # | 漏洞位置 | 方法 | 行号 | 危害等级 |
|---|---------|------|------|---------|
| 1 | `register()` — 用户注册 | `INSERT` f-string 拼接 | app.py:223 | 🔴 严重 |
| 2 | `search()` — 用户搜索 | `SELECT` f-string 拼接 | app.py:246 | 🔴 严重 |
| 3 | `init_db()` — 初始化默认用户 | `INSERT` f-string 拼接 | app.py:139-141 | 🟢 低危（数据可控） |

---

## 二、漏洞原理解析

### 2.1 注册功能注入（INSERT 语句）

**漏洞代码（app.py:222-223）：**
```python
query = f"INSERT INTO users (username, password, email, phone) VALUES ('{username}', '{password}', '{email}', '{phone}')"
conn.execute(query)
```

**正常输入时生成：**
```sql
INSERT INTO users (username, password, email, phone)
VALUES ('bob', 'bob123', 'bob@test.com', '13900001111')
```

**恶意输入时生成：**
```
用户名:  hacker', 'evilpass', 'h@x.com', '999')--
密码:    x
邮箱:    x
手机:    x
```

```sql
INSERT INTO users (username, password, email, phone)
VALUES ('hacker', 'evilpass', 'h@x.com', '999')--', 'x', 'x', 'x')
```

`--` 将后面的 SQL 注释掉，攻击者成功插入了一个任意密码的 `hacker` 用户。

### 2.2 搜索功能注入（SELECT 语句）

**漏洞代码（app.py:245-246）：**
```python
query = f"SELECT id, username, email, phone FROM users WHERE username LIKE '%{keyword}%' OR email LIKE '%{keyword}%'"
conn.execute(query)
```

**正常输入时生成：**
```sql
SELECT id, username, email, phone FROM users
WHERE username LIKE '%admin%' OR email LIKE '%admin%'
```

**攻击 ① — OR 永真注入，返回全部用户：**
```
keyword: ' OR '1'='1
```

```sql
SELECT id, username, email, phone FROM users
WHERE username LIKE '%' OR '1'='1%' OR email LIKE '%' OR '1'='1%'
--                   ^^^^^^^^^^^^^^^^
--                   永真条件，所有行都会返回
```

**攻击 ② — UNION 注入，返回任意数据：**
```
keyword: ' UNION SELECT 1,'inj','inj@x.com','138'--
```

```sql
SELECT id, username, email, phone FROM users
WHERE username LIKE '%' UNION SELECT 1,'inj','inj@x.com','138'--%' OR email LIKE '%...
--                   ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
--                   UNION 将第二个查询的结果合并到结果集中
```

`UNION SELECT` 的列数必须与原查询一致（4 列：id, username, email, phone），否则 SQLite 会报错。

---

## 三、POC 攻击验证

### POC 1：注册注入 — 创建任意用户

```bash
# 先获取 CSRF token
CSRF=$(curl -s http://127.0.0.1:5000/register | grep -oP 'value="\K[a-f0-9]+(?=")')

# 注入：用户名中闭合 VALUES 并注释掉后面的内容
curl -X POST http://127.0.0.1:5000/register \
  -d "csrf_token=$CSRF" \
  -d "username=hacker', 'hacker123', 'hacker@x.com', '666')--" \
  -d "password=x" \
  -d "email=x" \
  -d "phone=x"

# 验证：用新创建的用户登录
CSRF=$(curl -s -c /tmp/cookies.txt http://127.0.0.1:5000/login | grep -oP 'value="\K[a-f0-9]+(?=")')
curl -X POST http://127.0.0.1:5000/login -b /tmp/cookies.txt \
  -d "csrf_token=$CSRF" \
  -d "username=hacker" \
  -d "password=hacker123" \
  | grep "欢迎"
```

### POC 2：搜索注入 — 获取全部用户

```bash
# 登录获取 session
CSRF=$(curl -s -c /tmp/cookies.txt http://127.0.0.1:5000/login | grep -oP 'value="\K[a-f0-9]+(?=")')
curl -X POST http://127.0.0.1:5000/login -b /tmp/cookies.txt \
  -d "csrf_token=$CSRF" \
  -d "username=admin" \
  -d "password=admin123"

# OR 注入 — 返回所有用户
curl -s "http://127.0.0.1:5000/search?keyword=%27%20OR%20%271%27%3D%271" \
  -b /tmp/cookies.txt | grep -oP '<td>\K[^<]+'

# UNION 注入 — 插入自定义数据
curl -s "http://127.0.0.1:5000/search?keyword=%27%20UNION%20SELECT%201,%27inj%27,%27inj@x.com%27,%27138%27--" \
  -b /tmp/cookies.txt | grep "inj"
```

---

## 四、修复方案

### 方案一：使用参数化查询（推荐 ✅）

#### 修复 register() — app.py

```python
@app.route("/register", methods=["GET", "POST"])
@csrf_required
def register():
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        email = (request.form.get("email") or "").strip()
        phone = (request.form.get("phone") or "").strip()

        # [修复] 使用参数化查询替代 f-string 拼接
        query = "INSERT INTO users (username, password, email, phone) VALUES (?, ?, ?, ?)"
        print(f"[SQL] {query} 参数: {username!r}, {password!r}, {email!r}, {phone!r}")

        conn = sqlite3.connect("data/users.db")
        try:
            conn.execute(query, (username, password, email, phone))
            conn.commit()
        except sqlite3.IntegrityError:
            conn.close()
            return render_template("register.html", error="用户名已存在", csrf_token=_generate_csrf_token())
        except Exception as e:
            conn.close()
            return render_template("register.html", error=f"注册失败", csrf_token=_generate_csrf_token())
        conn.close()
        return redirect("/login?msg=注册成功，请登录")

    return render_template("register.html", csrf_token=_generate_csrf_token())
```

#### 修复 search() — app.py

```python
@app.route("/search")
def search():
    keyword = request.args.get("keyword") or ""

    # [修复] 使用参数化查询替代 f-string 拼接
    query = "SELECT id, username, email, phone FROM users WHERE username LIKE ? OR email LIKE ?"
    like_pattern = f"%{keyword}%"
    print(f"[SQL] {query} 参数: {like_pattern!r}")

    results = []
    conn = sqlite3.connect("data/users.db")
    try:
        cursor = conn.execute(query, (like_pattern, like_pattern))
        rows = cursor.fetchall()
        for row in rows:
            results.append({"id": row[0], "username": row[1], "email": row[2], "phone": row[3]})
    except Exception as e:
        print(f"[SQL Error] {e}")
    conn.close()

    username = session.get("username")
    user_info = _safe_user_info(username) if username else None
    return render_template("index.html", user=user_info, search_results=results, keyword=keyword)
```

#### 修复 init_db() — app.py

```python
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
            phone TEXT
        )
    """)
    # [修复] 使用参数化查询
    default_users = [
        ("admin", "admin123", "admin@example.com", "13800138000"),
        ("alice", "alice2025", "alice@example.com", "13900139001"),
    ]
    conn.executemany(
        "INSERT OR IGNORE INTO users (username, password, email, phone) VALUES (?, ?, ?, ?)",
        default_users
    )
    conn.commit()
    conn.close()
```

### 方案二：使用 ORM 框架（更完善的方案）

如果使用 **Flask-SQLAlchemy**，ORM 层自动处理参数转义，从根本上杜绝 SQL 注入：

```python
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    email = db.Column(db.String(120))
    phone = db.Column(db.String(20))

# 注册 — ORM 方式
new_user = User(username=username, password=password, email=email, phone=phone)
db.session.add(new_user)
db.session.commit()

# 搜索 — ORM 方式
results = User.query.filter(
    db.or_(User.username.like(f"%{keyword}%"), User.email.like(f"%{keyword}%"))
).all()
```

---

## 五、修复前后对比

### 5.1 注册功能

| 对比项 | 修复前（有漏洞） | 修复后（安全） |
|--------|----------------|--------------|
| SQL 构建 | `f"VALUES ('{username}', ...)"` | `VALUES (?, ?, ?, ?)` |
| 参数传递 | 直接拼入字符串 | 通过元组 `(username, ...)` 传入 |
| 单引号处理 | 不处理，可闭合 SQL | 自动转义，作为纯文本 |
| 能否注入 | ✅ 可以 | ❌ 不可以 |

### 5.2 搜索功能

| 对比项 | 修复前（有漏洞） | 修复后（安全） |
|--------|----------------|--------------|
| SQL 构建 | `f"LIKE '%{keyword}%'"` | `LIKE ?` |
| 参数传递 | 直接拼入字符串 | 传入 `(like_pattern,)` |
| LIKE 通配符 | 支持（`%` `_`） | 仍支持（作为数据传入） |
| 能否注入 | ✅ 可以 | ❌ 不可以 |

### 5.3 验证测试

修复后运行以下注入测试，全部失败（返回 0 结果或报错）：

```bash
# 修复后 — UNION 注入应失败
curl "http://127.0.0.1:5000/search?keyword=%27%20UNION%20SELECT%201,2,3,4--"
# 结果：无搜索结果（' UNION... 被当作普通文本搜索）

# 修复后 — OR 注入应只返回匹配的用户
curl "http://127.0.0.1:5000/search?keyword=%27%20OR%20%271%27%3D%271"
# 结果：无搜索结果（' OR '1'='1 被当作普通文本搜索）
```

---

## 六、防御 SQL 注入的最佳实践

| # | 最佳实践 | 说明 |
|---|---------|------|
| 1 | **参数化查询（首选）** | 使用 `?` 占位符，数据库驱动自动转义 |
| 2 | **ORM 框架** | SQLAlchemy 等 ORM 层自动处理参数化 |
| 3 | **最小权限原则** | 数据库连接只用必要权限（如禁止 DROP） |
| 4 | **输入验证** | 对输入做类型、长度、格式校验（作为纵深防御，不替代参数化） |
| 5 | **错误信息不泄露** | 不将原始数据库异常返回给用户 |
| 6 | **WAF 规则** | 生产环境部署 Web 应用防火墙作为补充 |
| 7 | **代码审查** | 上线前审查所有 SQL 操作，杜绝字符串拼接 |

### 核心原则

```
⚠️  永远不要将用户输入直接拼接到 SQL 字符串中
✅  始终使用参数化查询（? 占位符）传递用户数据
```

参数化查询的工作原理：数据库驱动将 **SQL 结构**（语句模板）和 **数据**（参数值）分开传输，无论用户输入中包含什么特殊字符，都会被当作纯数据值处理，不会改变 SQL 语句的结构。

---

## 七、完整修复后的 app.py 关键代码段

将注册和搜索路由替换为以下代码，即可彻底修复 SQL 注入漏洞：

```python
# ============================================================
# 路由：注册 — 安全版本
# ============================================================
@app.route("/register", methods=["GET", "POST"])
@csrf_required
def register():
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        email = (request.form.get("email") or "").strip()
        phone = (request.form.get("phone") or "").strip()

        if not username or not password:
            return render_template("register.html", error="用户名和密码不能为空", csrf_token=_generate_csrf_token())

        # 安全：参数化查询
        query = "INSERT INTO users (username, password, email, phone) VALUES (?, ?, ?, ?)"

        conn = sqlite3.connect("data/users.db")
        try:
            conn.execute(query, (username, password, email, phone))
            conn.commit()
        except sqlite3.IntegrityError:
            conn.close()
            return render_template("register.html", error="用户名已存在", csrf_token=_generate_csrf_token())
        except Exception as e:
            conn.close()
            return render_template("register.html", error="注册失败，请稍后重试", csrf_token=_generate_csrf_token())
        conn.close()
        return redirect("/login?msg=注册成功，请登录")

    return render_template("register.html", csrf_token=_generate_csrf_token())


# ============================================================
# 路由：搜索 — 安全版本
# ============================================================
@app.route("/search")
def search():
    keyword = request.args.get("keyword") or ""

    # 安全：参数化查询（LIKE 参数同样可以使用 ? 占位符）
    query = "SELECT id, username, email, phone FROM users WHERE username LIKE ? OR email LIKE ?"
    like_pattern = f"%{keyword}%"

    results = []
    conn = sqlite3.connect("data/users.db")
    try:
        cursor = conn.execute(query, (like_pattern, like_pattern))
        for row in cursor.fetchall():
            results.append({"id": row[0], "username": row[1], "email": row[2], "phone": row[3]})
    except Exception as e:
        print(f"[SQL Error] {e}")
    conn.close()

    username = session.get("username")
    user_info = _safe_user_info(username) if username else None
    return render_template("index.html", user=user_info, search_results=results, keyword=keyword)
```

---

## 八、总结

| 漏洞位置 | 漏洞类型 | 严重程度 | 修复方法 |
|---------|---------|---------|---------|
| 注册 `register()` | SQL 注入（INSERT） | 🔴 严重 | 参数化查询 `VALUES (?, ?, ?, ?)` |
| 搜索 `search()` | SQL 注入（SELECT） | 🔴 严重 | 参数化查询 `LIKE ?` |
| 初始化 `init_db()` | SQL 注入（INSERT） | 🟢 低危 | `executemany()` + 参数化 |

**一句话总结：** 永远不要用 `f"'{user_input}'"` 拼接 SQL，改用 `?` 占位符 + 参数元组传递数据。

---

*文档版本：v1.0 | 编写日期：2026-07-20*
