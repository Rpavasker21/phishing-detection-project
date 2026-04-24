from fastapi import FastAPI, Request, Form, Response, Cookie
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from pathlib import Path
import sqlite3
import pickle
import hashlib
import os
import jwt
from datetime import datetime, timedelta, timezone
import re
from urllib.parse import urlparse
import matplotlib
import matplotlib.pyplot as plt
import io
import base64

matplotlib.use('Agg')

SECRET_KEY = "phishing_shield_secret_key"
ALGORITHM = "HS256"
BASE_DIR = Path(__file__).resolve().parent.parent
MODEL_PATH = BASE_DIR / "model.pkl"
VECTORIZER_PATH = BASE_DIR / "vectorizer.pkl"
DB_PATH = BASE_DIR / "phishing_app.db"

app = FastAPI(title="Phishing Detection Website")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allow browser extension environments
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class ScanRequest(BaseModel):
    content: str

templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")


def get_db_connection():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS predictions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            input_text TEXT NOT NULL,
            prediction TEXT NOT NULL,
            confidence REAL NOT NULL
        )
    """)

def hash_password(password: str):
    salt = os.urandom(16)
    pwd_hash = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100000)
    return salt.hex() + ":" + pwd_hash.hex()

def verify_password(password: str, stored_hash: str):
    try:
        salt_hex, hash_hex = stored_hash.split(":")
        salt = bytes.fromhex(salt_hex)
        pwd_hash = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100000)
        return pwd_hash.hex() == hash_hex
    except ValueError:
        # Fallback for old plaintext passwords
        return password == stored_hash

def create_jwt_token(data: dict):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(minutes=60)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def decode_jwt_token(token: str):
    if not token:
        return None
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload.get("sub")
    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
        return None

    conn.commit()
    conn.close()


def load_model():
    if not MODEL_PATH.exists():
        raise FileNotFoundError(f"model.pkl not found at: {MODEL_PATH}")

    if not VECTORIZER_PATH.exists():
        raise FileNotFoundError(f"vectorizer.pkl not found at: {VECTORIZER_PATH}")

    with open(MODEL_PATH, "rb") as f:
        model = pickle.load(f)

    with open(VECTORIZER_PATH, "rb") as f:
        vectorizer = pickle.load(f)

    return model, vectorizer


init_db()
model, vectorizer = load_model()


@app.get("/", response_class=HTMLResponse)
def home(request: Request, error: str = "", message: str = ""):
    return templates.TemplateResponse(
        "login.html",
        {
            "request": request,
            "error": error,
            "message": message
        }
    )


@app.get("/signup", response_class=HTMLResponse)
def signup_page(request: Request, message: str = ""):
    return templates.TemplateResponse(
        "signup.html",
        {
            "request": request,
            "message": message
        }
    )


@app.post("/signup", response_class=HTMLResponse)
def signup(request: Request, username: str = Form(...), password: str = Form(...)):
    username = username.strip()
    password = password.strip()

    if not username or not password:
        return templates.TemplateResponse(
            "signup.html",
            {
                "request": request,
                "message": "Username and password are required."
            }
        )

    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()

        hashed_pw = hash_password(password)

        cur.execute(
            "INSERT INTO users (username, password) VALUES (?, ?)",
            (username, hashed_pw)
        )
        conn.commit()

        return templates.TemplateResponse(
            "login.html",
            {
                "request": request,
                "message": "Signup successful. Please login.",
                "error": ""
            }
        )

    except sqlite3.IntegrityError:
        return templates.TemplateResponse(
            "signup.html",
            {
                "request": request,
                "message": "Username already exists. Try another one."
            }
        )

    except Exception as e:
        return HTMLResponse(
            content=f"Signup failed: {str(e)}",
            status_code=500
        )

    finally:
        if conn:
            conn.close()


@app.post("/login")
def login(username: str = Form(...), password: str = Form(...)):
    username = username.strip()
    password = password.strip()

    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute(
        "SELECT * FROM users WHERE username = ?",
        (username,)
    )
    user = cur.fetchone()
    conn.close()

    if user and verify_password(password, user["password"]):
        token = create_jwt_token({"sub": username})
        response = RedirectResponse(url="/dashboard", status_code=303)
        response.set_cookie(key="session_token", value=token, httponly=True)
        return response

    return RedirectResponse(url="/?error=Invalid username or password", status_code=303)


@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(
    request: Request,
    result: str = "",
    confidence: str = "",
    text: str = "",
    urls_data: str = "" # Pass JSON of urls if any, or just handle in memory if not redirecting
):
    token = request.cookies.get("session_token")
    username = decode_jwt_token(token) if token else None

    if not username:
        return RedirectResponse(url="/?error=Please log in again", status_code=303)

    # Analytics
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT prediction FROM predictions WHERE username = ?", (username,))
    rows = cur.fetchall()
    conn.close()
    
    phish_count = sum(1 for r in rows if "PHISHING" in r["prediction"])
    legit_count = sum(1 for r in rows if "LEGIT" in r["prediction"])
    
    chart_data = ""
    if phish_count > 0 or legit_count > 0:
        fig, ax = plt.subplots(figsize=(4, 3))
        ax.bar(['Phishing', 'Legit'], [phish_count, legit_count], color=['#ff4d4d', '#4CAF50'])
        ax.set_title("Your Search History Analytics", fontsize=10)
        plt.tight_layout()
        buf = io.BytesIO()
        plt.savefig(buf, format='png')
        buf.seek(0)
        chart_data = base64.b64encode(buf.read()).decode('utf-8')
        plt.close(fig)

    import json
    urls = []
    if urls_data:
        try:
            urls = json.loads(urls_data)
        except Exception:
            pass

    return templates.TemplateResponse(
        "dashboard.html",
        {
            "request": request,
            "username": username,
            "result": result,
            "confidence": confidence,
            "text": text,
            "chart_data": chart_data,
            "urls": urls
        }
    )


@app.post("/predict-ui", response_class=HTMLResponse)
def predict_ui(
    request: Request,
    text: str = Form(...)
):
    token = request.cookies.get("session_token")
    username = decode_jwt_token(token) if token else None

    if not username:
        return RedirectResponse(url="/?error=Please log in again", status_code=303)

    cleaned_text = text.strip()

    if len(cleaned_text) < 5:
        return dashboard(request=request, result="Please enter a longer message or URL.", text=cleaned_text)

    transformed = vectorizer.transform([cleaned_text])
    pred = int(model.predict(transformed)[0])

    if hasattr(model, "predict_proba"):
        probs = model.predict_proba(transformed)[0]
        confidence_value = float(max(probs)) * 100
    else:
        confidence_value = 0.0

    result = "PHISHING ⚠️" if pred == 1 else "LEGIT ✅"

    # URL Extraction
    url_pattern = r'https?://[^\s]+'
    found_urls = re.findall(url_pattern, cleaned_text)
    extracted_urls = []
    for u in found_urls:
        domain = urlparse(u).netloc
        extracted_urls.append({"url": u, "domain": domain})

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO predictions (username, input_text, prediction, confidence) VALUES (?, ?, ?, ?)",
        (username, cleaned_text, result, confidence_value)
    )
    conn.commit()
    conn.close()

    import json
    urls_data = json.dumps(extracted_urls)

    return dashboard(
        request=request, 
        result=result, 
        confidence=f"{confidence_value:.2f}%", 
        text=cleaned_text,
        urls_data=urls_data
    )


@app.get("/history", response_class=HTMLResponse)
def history(request: Request, username: str = ""):
    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute(
        "SELECT * FROM predictions WHERE username = ? ORDER BY id DESC",
        (username,)
    )
    rows = cur.fetchall()
    conn.close()

    return templates.TemplateResponse(
        "history.html",
        {
            "request": request,
            "username": username,
            "rows": rows
        }
    )


@app.get("/health")
def health():
    return {"status": "running"}

@app.post("/api/v1/scan")
def api_scan(payload: ScanRequest):
    cleaned_text = payload.content.strip()
    if len(cleaned_text) < 5:
        return {"prediction": "UNKNOWN", "confidence": "0.00%"}

    transformed = vectorizer.transform([cleaned_text])
    pred = int(model.predict(transformed)[0])

    if hasattr(model, "predict_proba"):
        probs = model.predict_proba(transformed)[0]
        confidence_value = float(max(probs)) * 100
    else:
        confidence_value = 0.0

    result = "PHISHING ⚠️" if pred == 1 else "LEGIT ✅"

    return {"prediction": result, "confidence": f"{confidence_value:.2f}%"}