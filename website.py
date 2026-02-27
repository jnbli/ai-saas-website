import os
import sqlite3
from contextlib import asynccontextmanager
from datetime import datetime  # ← Added this import

import requests
from argon2 import PasswordHasher, exceptions
from fastapi import Depends, FastAPI, Form, HTTPException, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.security import OAuth2PasswordRequestForm

app = FastAPI()

# ────────────────────────────────────────────────
# Password hashing
# ────────────────────────────────────────────────
ph = PasswordHasher(
    memory_cost=65536, time_cost=3, parallelism=4, hash_len=32, salt_len=16
)


def get_password_hash(password: str) -> str:
    return ph.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    try:
        ph.verify(hashed_password, plain_password)
        return True
    except (exceptions.VerifyMismatchError, exceptions.InvalidHashError):
        return False


# ────────────────────────────────────────────────
# Bifrost config & helpers
# ────────────────────────────────────────────────
BIFROST_BASE = os.getenv("BIFROST_BASE", "http://localhost:8080")
BIFROST_AUTH = (
    os.getenv("BIFROST_ADMIN_USERNAME", "root"),
    os.getenv("BIFROST_ADMIN_PASSWORD", "root"),
)


def list_customers():
    try:
        r = requests.get(
            f"{BIFROST_BASE}/api/governance/customers", auth=BIFROST_AUTH, timeout=10
        )
        r.raise_for_status()
        data = r.json()
        if "governance" in data and "customers" in data["governance"]:
            return data["governance"]["customers"]
        if "customers" in data:
            return data["customers"]
        if isinstance(data, list):
            return data
        return []
    except Exception as e:
        raise HTTPException(500, f"Cannot connect to Bifrost: {str(e)}")


def find_customer_by_name(name: str):
    for c in list_customers():
        if c.get("name") == name:
            return c
    return None


def create_customer(name: str):
    payload = {"name": name, "budget": {"max_limit": 2000.0, "reset_duration": "1M"}}
    r = requests.post(
        f"{BIFROST_BASE}/api/governance/customers",
        json=payload,
        auth=BIFROST_AUTH,
        timeout=10,
    )
    r.raise_for_status()
    data = r.json()
    return data.get("customer", data)


def list_virtual_keys():
    try:
        r = requests.get(
            f"{BIFROST_BASE}/api/governance/virtual-keys", auth=BIFROST_AUTH, timeout=10
        )
        r.raise_for_status()
        data = r.json()
        if "governance" in data and "virtual_keys" in data["governance"]:
            return data["governance"]["virtual_keys"]
        if "virtual_keys" in data:
            return data["virtual_keys"]
        if isinstance(data, list):
            return data
        return []
    except Exception:
        return []


def get_virtual_key_by_id(vk_id: str):
    try:
        r = requests.get(
            f"{BIFROST_BASE}/api/governance/virtual-keys/{vk_id}",
            auth=BIFROST_AUTH,
            timeout=10,
        )
        r.raise_for_status()
        data = r.json()
        if (
            "virtual_keys" in data
            and isinstance(data["virtual_keys"], list)
            and data["virtual_keys"]
        ):
            return data["virtual_keys"][0]
        return data
    except requests.HTTPError as e:
        if e.response and e.response.status_code == 404:
            return None
        raise


def create_virtual_key(customer_id: str, username: str):
    # Timestamp makes name unique enough to avoid most conflicts
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    name = f"{username}_saas_key_{timestamp}"
    payload = {
        "name": name,
        "description": f"AI SaaS key for user {username}",
        "provider_configs": [
            {"provider": "openai", "weight": 1.0, "allowed_models": ["gpt-4o"]}
        ],
        "customer_id": customer_id,
        "budget": {"max_limit": 100.0, "reset_duration": "1M"},
        "is_active": True,
    }
    r = requests.post(
        f"{BIFROST_BASE}/api/governance/virtual-keys",
        json=payload,
        auth=BIFROST_AUTH,
        timeout=10,
    )
    r.raise_for_status()
    data = r.json()
    return data.get("virtual_key", data)


def reactivate_virtual_key(vk_id: str):
    requests.put(
        f"{BIFROST_BASE}/api/governance/virtual-keys/{vk_id}",
        json={"is_active": True},
        auth=BIFROST_AUTH,
        timeout=10,
    ).raise_for_status()


def deactivate_virtual_key(vk_id: str):
    requests.put(
        f"{BIFROST_BASE}/api/governance/virtual-keys/{vk_id}",
        json={"is_active": False},
        auth=BIFROST_AUTH,
        timeout=10,
    ).raise_for_status()


def ensure_bifrost_access(username: str, db: sqlite3.Connection) -> str:
    """
    Ensures a valid, active virtual key for the user.

    - Uses stored vk_id if it exists and is reachable
    - Reactivates the key (PUT is_active=true) even if already active
      → idempotent and prevents desync
    - Only creates new key if stored vk_id is 404 (gone)
    - Raises meaningful errors on unexpected API behavior
    """
    cur = db.cursor()
    cur.execute(
        """
        SELECT bifrost_vk_id, bifrost_vk_value
        FROM users WHERE username = ?
        """,
        (username,),
    )
    row = cur.fetchone()
    stored_vk_id, stored_vk_value = row if row else (None, None)

    # Debug (remove or comment out in production)
    print(f"[DEBUG] {username} - Stored vk_id: {stored_vk_id}")
    print(f"[DEBUG] {username} - Stored vk_value exists: {bool(stored_vk_value)}")

    # Ensure customer exists
    customer = find_customer_by_name(username)
    if not customer:
        print(f"[DEBUG] Creating customer for {username}")
        customer = create_customer(username)
    customer_id = customer["id"]

    vk_value = stored_vk_value  # optimistic fast path

    if stored_vk_id:
        try:
            # Check if key still exists
            print(f"[DEBUG] GET key {stored_vk_id}")
            r = requests.get(
                f"{BIFROST_BASE}/api/governance/virtual-keys/{stored_vk_id}",
                auth=BIFROST_AUTH,
                timeout=10,
            )
            print(f"[DEBUG] GET status: {r.status_code}")

            if r.status_code == 200:
                data = r.json()

                # Bifrost always wraps in "virtual_key"
                if "virtual_key" not in data:
                    raise RuntimeError(
                        f"Bifrost response missing 'virtual_key' key: {data}"
                    )

                vk = data["virtual_key"]
                current_active = vk.get("is_active")

                if current_active is None:
                    print("[WARNING] 'is_active' missing → assuming False")
                    current_active = False

                print(f"[DEBUG] Current is_active in Bifrost: {current_active}")

                # Always force active on subscribe (safe & idempotent)
                print(f"[DEBUG] Ensuring is_active=true via PUT")
                put_r = requests.put(
                    f"{BIFROST_BASE}/api/governance/virtual-keys/{stored_vk_id}",
                    json={"is_active": True},
                    auth=BIFROST_AUTH,
                    timeout=10,
                )
                print(f"[DEBUG] PUT status: {put_r.status_code}")
                put_r.raise_for_status()

                # Refresh to confirm
                r = requests.get(
                    f"{BIFROST_BASE}/api/governance/virtual-keys/{stored_vk_id}",
                    auth=BIFROST_AUTH,
                    timeout=10,
                )
                r.raise_for_status()
                data = r.json()
                vk = data["virtual_key"]
                vk_value = vk["value"]
                print(f"[DEBUG] Key active after PUT - value: {vk_value[:10]}...")

            elif r.status_code == 404:
                print(f"[DEBUG] Key {stored_vk_id} not found (404) → creating new")
                cur.execute(
                    "UPDATE users SET bifrost_vk_id = NULL, bifrost_vk_value = NULL WHERE username = ?",
                    (username,),
                )
                db.commit()
                vk_value = None
            else:
                r.raise_for_status()  # other errors → fail

        except requests.HTTPError as e:
            print(f"[DEBUG] Key check/PUT failed: {e}")
            if not (e.response and e.response.status_code == 404):
                raise RuntimeError(f"Failed to validate/reactivate key: {e}")

    # Create new only if we have no usable key
    if not vk_value:
        print(f"[DEBUG] Creating new virtual key for {username}")
        payload = {
            "name": f"{username}_saas_key",
            "description": f"AI SaaS desktop key for {username}",
            "provider_configs": [
                {"provider": "openai", "weight": 1.0, "allowed_models": ["gpt-4o"]}
            ],
            "customer_id": customer_id,
            "budget": {"max_limit": 100.0, "reset_duration": "1M"},
            "is_active": True,
        }

        r = requests.post(
            f"{BIFROST_BASE}/api/governance/virtual-keys",
            json=payload,
            auth=BIFROST_AUTH,
            timeout=10,
        )
        print(f"[DEBUG] POST status: {r.status_code}")
        if r.status_code >= 400:
            print(f"[DEBUG] POST failed: {r.text}")
        r.raise_for_status()

        data = r.json()
        if "virtual_key" not in data:
            raise RuntimeError(f"Unexpected POST response: {data}")

        vk = data["virtual_key"]
        vk_id = vk["id"]
        vk_value = vk["value"]

        # Save new key
        cur.execute(
            """
            UPDATE users
            SET bifrost_customer_name = ?,
                bifrost_customer_id = ?,
                bifrost_vk_id = ?,
                bifrost_vk_value = ?
            WHERE username = ?
            """,
            (username, customer_id, vk_id, vk_value, username),
        )
        db.commit()

    if not vk_value:
        raise ValueError("Failed to obtain virtual key value")

    print(f"[DEBUG] Returning vk_value: {vk_value[:10]}...")
    return vk_value


# ────────────────────────────────────────────────
# SQLite setup + migration
# ────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    conn = sqlite3.connect("users.db", check_same_thread=False)
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password_hash TEXT NOT NULL,
            paid INTEGER NOT NULL DEFAULT 0,
            bifrost_customer_name TEXT,
            bifrost_customer_id TEXT,
            bifrost_vk_id TEXT,
            bifrost_vk_value TEXT
        )
    """)
    # Migrate columns if missing
    cur.execute("PRAGMA table_info(users)")
    cols = {row[1] for row in cur.fetchall()}
    for col in [
        "bifrost_customer_name",
        "bifrost_customer_id",
        "bifrost_vk_id",
        "bifrost_vk_value",
    ]:
        if col not in cols:
            cur.execute(f"ALTER TABLE users ADD COLUMN {col} TEXT")
    conn.commit()
    app.state.db = conn
    yield
    conn.close()


app.router.lifespan_context = lifespan


def get_db(request: Request):
    return request.app.state.db


# ────────────────────────────────────────────────
# HTML templates
# ────────────────────────────────────────────────
home_page = """
<!DOCTYPE html>
<html>
<body style="font-family:sans-serif; margin:40px;">
  <h1>ai-saas-website</h1>
  <p><a href="/register">Register</a> | <a href="/login">Login</a></p>
</body>
</html>
"""

register_form = """
<!DOCTYPE html>
<html>
<body style="font-family:sans-serif; margin:40px;">
  <h2>Register</h2>
  <form method="post">
    Username: <input name="username" required pattern="[a-zA-Z0-9_-]{3,20}"><br><br>
    Password: <input name="password" type="password" required minlength="1"><br><br>
    <button type="submit">Create account</button>
  </form>
  <p><a href="/">← back</a></p>
</body>
</html>
"""

login_form = """
<!DOCTYPE html>
<html>
<body style="font-family:sans-serif; margin:40px;">
  <h2>Login</h2>
  <form method="post">
    Username: <input name="username" required><br><br>
    Password: <input name="password" type="password" required><br><br>
    <button type="submit">Log in</button>
  </form>
  <p><a href="/">← back</a></p>
</body>
</html>
"""

dashboard = """
<!DOCTYPE html>
<html>
<body style="font-family:sans-serif; margin:40px;">
  <h2>Welcome, {username}</h2>
  <p>Subscription status: <b>{status}</b></p>
  {button}
  <hr>
  <p><a href="/logout">Log out</a></p>
</body>
</html>
"""


# ────────────────────────────────────────────────
# Routes
# ────────────────────────────────────────────────
@app.get("/", response_class=HTMLResponse)
async def root():
    return home_page


@app.get("/register", response_class=HTMLResponse)
async def register_page():
    return register_form


@app.post("/register")
async def register(
    request: Request, username: str = Form(...), password: str = Form(...)
):
    db = get_db(request)
    cur = db.cursor()
    cur.execute("SELECT 1 FROM users WHERE username = ?", (username,))
    if cur.fetchone():
        raise HTTPException(400, "Username already taken")
    hashed = get_password_hash(password)
    cur.execute(
        """INSERT INTO users
           (username, password_hash, paid, bifrost_customer_name, bifrost_customer_id, bifrost_vk_id, bifrost_vk_value)
           VALUES (?, ?, 0, NULL, NULL, NULL, NULL)""",
        (username, hashed),
    )
    db.commit()
    return RedirectResponse("/login", status_code=303)


@app.get("/login", response_class=HTMLResponse)
async def login_page():
    return login_form


@app.post("/login")
async def do_login(
    request: Request, username: str = Form(...), password: str = Form(...)
):
    db = get_db(request)
    cur = db.cursor()
    cur.execute("SELECT password_hash, paid FROM users WHERE username = ?", (username,))
    row = cur.fetchone()
    if not row or not verify_password(password, row[0]):
        raise HTTPException(401, "Wrong username or password")
    response = RedirectResponse("/dashboard", status_code=303)
    response.set_cookie(
        key="username", value=username, httponly=True, max_age=3600 * 24 * 14
    )
    return response


@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard_page(request: Request):
    username = request.cookies.get("username")
    if not username:
        return RedirectResponse("/login", status_code=303)
    db = get_db(request)
    cur = db.cursor()
    cur.execute("SELECT paid FROM users WHERE username = ?", (username,))
    row = cur.fetchone()
    if not row:
        return RedirectResponse("/logout", status_code=303)
    paid = bool(row[0])
    status = "Active ✓" if paid else "Not subscribed"
    button = (
        """
        <form method="post" action="/subscribe">
            <button type="submit" style="font-size:1.3em; padding:12px 30px;">Subscribe now</button>
        </form>
        """
        if not paid
        else """
        <form method="post" action="/cancel">
            <button type="submit" style="font-size:1.3em; padding:12px 30px; background:#c00; color:white;">Cancel subscription</button>
        </form>
        """
    )
    return dashboard.format(username=username, status=status, button=button)


@app.post("/subscribe")
async def subscribe(request: Request):
    username = request.cookies.get("username")
    if not username:
        raise HTTPException(401)
    db = get_db(request)
    try:
        ensure_bifrost_access(username, db)
    except Exception as e:
        raise HTTPException(500, f"Bifrost error: {str(e)}")
    db.execute("UPDATE users SET paid = 1 WHERE username = ?", (username,))
    db.commit()
    return RedirectResponse("/dashboard", status_code=303)


@app.post("/cancel")
async def cancel(request: Request):
    username = request.cookies.get("username")
    if not username:
        raise HTTPException(401)
    db = get_db(request)
    cur = db.cursor()
    cur.execute("SELECT bifrost_vk_id FROM users WHERE username = ?", (username,))
    row = cur.fetchone()
    if row and row[0]:
        try:
            deactivate_virtual_key(row[0])
        except Exception:
            pass  # best effort
    db.execute("UPDATE users SET paid = 0 WHERE username = ?", (username,))
    db.commit()
    return RedirectResponse("/dashboard", status_code=303)


@app.get("/logout")
async def logout():
    response = RedirectResponse("/", status_code=303)
    response.delete_cookie("username")
    return response


@app.post("/token")
async def login_for_access_token(
    form_data: OAuth2PasswordRequestForm = Depends(), request: Request = None
):
    if not request:
        raise HTTPException(500, "Request required")
    db = get_db(request)
    cur = db.cursor()
    cur.execute(
        "SELECT password_hash, paid, bifrost_vk_value FROM users WHERE username = ?",
        (form_data.username,),
    )
    row = cur.fetchone()
    if not row or not verify_password(form_data.password, row[0]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if not row[1]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Active subscription required to obtain API token",
        )
    vk_value = row[2]
    if not vk_value:
        vk_value = ensure_bifrost_access(form_data.username, db)
    return {
        "access_token": vk_value,
        "token_type": "bearer",
        "expires_in": 31536000,  # long-lived
    }
