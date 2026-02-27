# mvp
import sqlite3
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone

import jwt
from argon2 import PasswordHasher, exceptions
from fastapi import Depends, FastAPI, Form, HTTPException, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.security import OAuth2PasswordRequestForm

from config import settings

app = FastAPI()

# ────────────────────────────────────────────────
# Password hashing with Argon2 (argon2-cffi)
# ────────────────────────────────────────────────
ph = PasswordHasher(
    memory_cost=65536,  # 64 MiB
    time_cost=3,  # iterations
    parallelism=4,  # lanes/threads
    hash_len=32,
    salt_len=16,
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
# JWT settings
# ────────────────────────────────────────────────
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_HOURS = 24


def create_access_token(data: dict) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(hours=ACCESS_TOKEN_EXPIRE_HOURS)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, settings.secret_key, algorithm=ALGORITHM)
    return encoded_jwt


# ────────────────────────────────────────────────
# SQLite setup
# ────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    conn = sqlite3.connect("users.db", check_same_thread=False)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password_hash TEXT NOT NULL,
            paid INTEGER NOT NULL DEFAULT 0
        )
    """)
    conn.commit()
    app.state.db = conn
    yield
    conn.close()


app.router.lifespan_context = lifespan


def get_db(request: Request):
    return request.app.state.db


# ────────────────────────────────────────────────
# HTML snippets
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
        "INSERT INTO users (username, password_hash, paid) VALUES (?, ?, 0)",
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
    db.execute("UPDATE users SET paid = 1 WHERE username = ?", (username,))
    db.commit()
    return RedirectResponse("/dashboard", status_code=303)


@app.post("/cancel")
async def cancel(request: Request):
    username = request.cookies.get("username")
    if not username:
        raise HTTPException(401)
    db = get_db(request)
    db.execute("UPDATE users SET paid = 0 WHERE username = ?", (username,))
    db.commit()
    return RedirectResponse("/dashboard", status_code=303)


@app.get("/logout")
async def logout():
    response = RedirectResponse("/", status_code=303)
    response.delete_cookie("username")
    return response


# ────────────────────────────────────────────────
# JWT Token endpoint (only for subscribed users)
# ────────────────────────────────────────────────


@app.post("/token")
async def login_for_access_token(
    form_data: OAuth2PasswordRequestForm = Depends(), request: Request = None
):
    db = get_db(request)
    cur = db.cursor()

    cur.execute(
        "SELECT password_hash, paid FROM users WHERE username = ?",
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

    access_token = create_access_token(data={"sub": form_data.username})
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "expires_in": ACCESS_TOKEN_EXPIRE_HOURS * 3600,
    }
