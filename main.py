"""
Backend di Xeno: chat IA (Gemini) + account + bot Discord sempre online.
Variabili (Environment su Render): GEMINI_API_KEY, ENCRYPTION_KEY, GEMINI_MODEL (opz.),
DB_PATH (opz., con disco: /data/bots.db), GITHUB_CLIENT_ID/SECRET, GOOGLE_CLIENT_ID/SECRET (opz.)
Comando di avvio consigliato su Render (UNA sola copia, altrimenti i bot Discord si duplicano):
  gunicorn main:app --workers 1 --threads 8 --timeout 120
Test dell'IA: apri  https://IL-TUO-SITO.onrender.com/api/ai-test
"""
import os, asyncio, threading, time, sqlite3, base64, hashlib, re, secrets, traceback
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FTimeout
from contextlib import contextmanager
from urllib.parse import urlencode, quote
import requests
from flask import Flask, request, jsonify, send_from_directory, redirect
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix
from itsdangerous import URLSafeTimedSerializer
from cryptography.fernet import Fernet
import discord
from google import genai
from google.genai import types

MODEL = (os.environ.get("GEMINI_MODEL") or "gemini-3.8-flash").strip()
FALLBACKS = ["gemini-2.5-flash", "gemini-2.0-flash"]   # provati solo se il modello principale non esiste
MIN_AGE, SESSION_DAYS = 14, 30
OAUTH = {
    "github": {"id": os.environ.get("GITHUB_CLIENT_ID", ""), "secret": os.environ.get("GITHUB_CLIENT_SECRET", "")},
    "google": {"id": os.environ.get("GOOGLE_CLIENT_ID", ""), "secret": os.environ.get("GOOGLE_CLIENT_SECRET", "")},
}
SYSTEM = "Ti chiami Xeno. Sei un assistente IA gentile e chiaro. Rispondi nella lingua dell'utente."
SYSTEM_CODE = SYSTEM + " Quando l'utente chiede del codice, rispondi con il codice completo in un blocco ``` e una breve spiegazione."
ALLOWED_MIME = {"image/jpeg", "image/png", "image/webp", "image/gif", "application/pdf"}

# ---------- Gemini ----------
client = genai.Client(api_key=os.environ["GEMINI_API_KEY"].strip(),
                      http_options=types.HttpOptions(timeout=40000))   # 40 s per tentativo
pool = ThreadPoolExecutor(max_workers=8)

def _call(model, contents, system):
    cfg = {"system_instruction": system}
    if model.startswith("gemini-3"):
        cfg["thinking_config"] = types.ThinkingConfig(thinking_level="low")
    res = client.models.generate_content(model=model, contents=contents,
                                         config=types.GenerateContentConfig(**cfg))
    text = (res.text or "").strip()
    if not text:
        raise ValueError("EMPTY")
    return text

def _try_models(contents, system):
    last = None
    for mdl in dict.fromkeys([MODEL] + FALLBACKS):
        try:
            return _call(mdl, contents, system)
        except Exception as e:
            last = e
            if not any(k in str(e) for k in ("404", "NOT_FOUND", "INVALID_ARGUMENT")):
                break          # errore diverso (quota, chiave, timeout): inutile cambiare modello
    raise last

def generate(contents, system):
    """Risposta di Gemini, con limite massimo di 55 secondi (mai appeso all'infinito)."""
    fut = pool.submit(_try_models, contents, system)
    try:
        return fut.result(timeout=55)
    except FTimeout:
        raise TimeoutError("timed out")

def friendly(e):
    m, low = str(e), str(e).lower()
    if m == "EMPTY":
        return "L'IA non ha dato nessuna risposta (forse bloccata dai filtri). Riprova con un'altra frase."
    if "429" in m or "RESOURCE_EXHAUSTED" in m:
        return "Troppe richieste o quota di Gemini esaurita. Riprova tra un minuto."
    if "api key" in low or "API_KEY" in m or "PERMISSION_DENIED" in m or "UNAUTHENTICATED" in m:
        return "La chiave Gemini non è valida: controlla GEMINI_API_KEY su Render."
    if "404" in m or "NOT_FOUND" in m:
        return "Il modello Gemini non esiste: cambia GEMINI_MODEL su Render."
    if "timeout" in low or "timed out" in low or "deadline" in low:
        return "L'IA ci ha messo troppo, riprova."
    return "Errore dell'IA: " + m[:200]

def ask_gemini(text):
    try:
        c = [types.Content(role="user", parts=[types.Part.from_text(text=text)])]
        return generate(c, SYSTEM)[:1900]
    except Exception as e:
        traceback.print_exc()
        return friendly(e)

def build_contents(messages, files):
    turns = []
    for m in (messages or [])[-30:]:
        role = "user" if m.get("role") == "user" else "model"
        text = str(m.get("content") or "").strip()
        if not text:
            continue
        if turns and turns[-1]["role"] == role:
            turns[-1]["text"] += "\n" + text
        else:
            turns.append({"role": role, "text": text})
    while turns and turns[0]["role"] != "user":
        turns.pop(0)
    if not turns or turns[-1]["role"] != "user":
        return None, "Scrivi un messaggio."
    extra = []
    for f in (files or [])[:4]:
        mime = (f or {}).get("mime")
        if mime not in ALLOWED_MIME:
            continue
        try:
            extra.append(types.Part.from_bytes(data=base64.b64decode(f.get("data", ""), validate=True), mime_type=mime))
        except Exception:
            return None, "Allegato non valido."
    contents = []
    for i, t in enumerate(turns):
        parts = [types.Part.from_text(text=t["text"])]
        if i == len(turns) - 1:
            parts += extra
        contents.append(types.Content(role=t["role"], parts=parts))
    return contents, None

KEY = os.environ["ENCRYPTION_KEY"].strip().encode()
fernet = Fernet(KEY)
signer = URLSafeTimedSerializer(hashlib.sha256(b"xeno-sessions:" + KEY).hexdigest())

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 25 * 1024 * 1024
CORS(app)
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

def body():
    return request.get_json(force=True, silent=True) or {}

# ---------- database ----------
def _db_path(path):
    d = os.path.dirname(path)
    if d:
        try:
            os.makedirs(d, exist_ok=True)
        except OSError:
            pass
        if not (os.path.isdir(d) and os.access(d, os.W_OK)):
            print("ATTENZIONE: cartella %s non disponibile, uso bots.db locale (dati persi ai riavvii)." % d)
            return "bots.db"
    return path

DB_PATH = _db_path(os.environ.get("DB_PATH", "bots.db"))
db_lock = threading.Lock()

@contextmanager
def db():
    c = sqlite3.connect(DB_PATH, timeout=15)
    c.row_factory = sqlite3.Row
    try:
        yield c
        c.commit()
    except Exception:
        c.rollback()
        raise
    finally:
        c.close()

with db() as c:
    c.execute("""CREATE TABLE IF NOT EXISTS bots(
        user_id TEXT PRIMARY KEY, platform TEXT, token_enc BLOB,
        prefix TEXT, active INTEGER DEFAULT 1, last_error TEXT)""")
    c.execute("""CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT UNIQUE,
        username TEXT UNIQUE COLLATE NOCASE, age INTEGER, pw_hash TEXT,
        provider TEXT, provider_id TEXT, created INTEGER)""")
    c.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_social ON users(provider, provider_id)")

def save_bot(user_id, token, prefix):
    with db_lock, db() as c:
        c.execute("REPLACE INTO bots VALUES(?,?,?,?,1,NULL)",
                  (user_id, "discord", fernet.encrypt(token.encode()), prefix))

def set_state(user_id, active, error=None):
    with db_lock, db() as c:
        c.execute("UPDATE bots SET active=?, last_error=? WHERE user_id=?", (active, error, user_id))

def get_bot(user_id):
    with db_lock, db() as c:
        return c.execute("SELECT * FROM bots WHERE user_id=?", (user_id,)).fetchone()

def delete_bot(user_id):
    with db_lock, db() as c:
        c.execute("DELETE FROM bots WHERE user_id=?", (user_id,))

# ---------- sessione ----------
def current_user():
    h = request.headers.get("Authorization", "")
    if not h.startswith("Bearer "):
        return None
    try:
        data = signer.loads(h[7:], salt="session", max_age=SESSION_DAYS * 86400)
    except Exception:
        return None
    with db_lock, db() as c:
        ok = c.execute("SELECT 1 FROM users WHERE id=?", (data["u"],)).fetchone()
    return str(data["u"]) if ok else None

def need_login():
    return jsonify(error="Accedi per continuare."), 401

# ---------- chat ----------
@app.post("/api/chat")
def chat():
    if not current_user():
        return need_login()
    d = body()
    contents, err = build_contents(d.get("messages"), d.get("files"))
    if err:
        return jsonify(error=err), 400
    sysm = SYSTEM_CODE if d.get("mode") == "code" else SYSTEM
    topics = {"developing": "sviluppo e programmazione", "studio": "studio e compiti",
              "personale": "uso personale", "lavoro": "lavoro"}
    chosen = [topics[i] for i in (d.get("interests") or []) if i in topics]
    if chosen:
        sysm += " L'utente vuole usarti soprattutto per: " + ", ".join(chosen) + "."
    try:
        return jsonify(reply=generate(contents, sysm))
    except Exception as e:
        traceback.print_exc()
        return jsonify(error=friendly(e)), 500

@app.get("/api/ai-test")
def ai_test():
    """Apri questo indirizzo nel browser per vedere se Gemini funziona e con quale modello."""
    t0 = time.time()
    try:
        r = generate([types.Content(role="user", parts=[types.Part.from_text(text="Rispondi solo: ok")])], SYSTEM)
        return jsonify(ok=True, model=MODEL, secondi=round(time.time() - t0, 1), risposta=r[:80])
    except Exception as e:
        return jsonify(ok=False, model=MODEL, secondi=round(time.time() - t0, 1),
                       errore=friendly(e), dettaglio=str(e)[:300]), 500

# ---------- bot Discord ----------
running = {}

def stop_running(user_id):
    b = running.pop(user_id, None)
    if b:
        asyncio.run_coroutine_threadsafe(b["client"].close(), b["loop"])

def _launch(user_id, token, prefix, wait=20):
    stop_running(user_id)
    intents = discord.Intents.default()
    intents.message_content = True
    dclient = discord.Client(intents=intents)
    loop = asyncio.new_event_loop()
    ready, result = threading.Event(), {}

    @dclient.event
    async def on_ready():
        result["id"] = dclient.user.id
        ready.set()

    @dclient.event
    async def on_message(m):
        if m.author.bot or not m.content.startswith(prefix):
            return
        q = m.content[len(prefix):].strip()
        if not q:
            return
        async with m.channel.typing():
            answer = await asyncio.to_thread(ask_gemini, q)
        await m.reply(answer)

    def run():
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(dclient.start(token))
        except discord.LoginFailure:
            result["error"], result["fatal"] = "Token non valido.", True
        except discord.PrivilegedIntentsRequired:
            result["error"], result["fatal"] = "Attiva Message Content Intent nel Developer Portal.", True
        except Exception as e:
            result["error"] = str(e)[:200]
        ready.set()

    threading.Thread(target=run, daemon=True).start()
    ready.wait(wait)
    if "id" not in result:
        return None, result.get("error", "Il bot non è partito in tempo."), result.get("fatal", False)
    running[user_id] = {"client": dclient, "loop": loop}
    return "https://discord.com/oauth2/authorize?client_id=%s&scope=bot&permissions=68608" % result["id"], None, False

launch_lock = threading.Lock()

def launch(user_id, token, prefix, wait=20):
    with launch_lock:
        return _launch(user_id, token, prefix, wait)

def revive(row):
    with launch_lock:
        row = get_bot(row["user_id"])
        if not row or not row["active"]:
            return
        r = running.get(row["user_id"])
        if r and not r["client"].is_closed():
            return
        _, err, fatal = _launch(row["user_id"], fernet.decrypt(row["token_enc"]).decode(), row["prefix"], wait=30)
        if err and fatal:
            set_state(row["user_id"], 0, err)

def watchdog():
    while True:
        try:
            with db_lock, db() as c:
                rows = c.execute("SELECT * FROM bots WHERE active=1").fetchall()
            for row in rows:
                r = running.get(row["user_id"])
                if not r or r["client"].is_closed():
                    try:
                        revive(row)
                    except Exception as e:
                        print("watchdog bot", row["user_id"], e)
        except Exception as e:
            print("watchdog:", e)
        time.sleep(30)

@app.post("/api/go-online")
def go_online():
    user_id = current_user()
    if not user_id:
        return need_login()
    d = body()
    token = (d.get("token") or "").strip()
    prefix = (d.get("prefix") or "!").strip()[:3] or "!"
    if d.get("platform") != "discord":
        return jsonify(error="Per ora è disponibile solo Discord."), 400
    if not token:
        return jsonify(error="Manca il token del bot."), 400
    invite, err, _ = launch(user_id, token, prefix)
    if err:
        return jsonify(error=err), 400
    save_bot(user_id, token, prefix)
    return jsonify(message="Il bot è online e resterà acceso anche dopo i riavvii. Scrivi %sciao in un canale." % prefix,
                   invite=invite)

@app.post("/api/stop-bot")
def stop_bot():
    user_id = current_user()
    if not user_id:
        return need_login()
    stop_running(user_id)
    delete_bot(user_id)
    return jsonify(message="Bot spento e token cancellato.")

@app.get("/api/bot-status")
def bot_status():
    user_id = current_user()
    if not user_id:
        return need_login()
    row = get_bot(user_id)
    if not row:
        return jsonify(state="nessun bot")
    r = running.get(row["user_id"])
    return jsonify(state="online" if r and not r["client"].is_closed() else "spento", error=row["last_error"])

# ---------- account ----------
USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,20}$")

def check_profile(username, age):
    if not USERNAME_RE.match(username or ""):
        return "Il nome utente deve avere 3-20 caratteri: lettere, numeri, _ . -"
    try:
        age = int(age)
    except (TypeError, ValueError):
        return "Inserisci un'età valida."
    if age < MIN_AGE:
        return "Devi avere almeno %d anni per creare un account." % MIN_AGE
    if age > 120:
        return "Inserisci un'età valida."
    return None

def create_user(email, username, age, pw_hash, provider, pid):
    with db_lock, db() as c:
        if c.execute("SELECT 1 FROM users WHERE username=?", (username,)).fetchone():
            return None, "Questo nome utente è già preso."
        if email and c.execute("SELECT 1 FROM users WHERE email=?", (email,)).fetchone():
            return None, "Questa email è già registrata."
        try:
            cur = c.execute("INSERT INTO users(email,username,age,pw_hash,provider,provider_id,created) VALUES(?,?,?,?,?,?,?)",
                            (email, username, int(age), pw_hash, provider, pid, int(time.time())))
        except sqlite3.IntegrityError:
            return None, "Account già esistente."
        return cur.lastrowid, None

def session_for(uid):
    with db_lock, db() as c:
        row = c.execute("SELECT id, username FROM users WHERE id=?", (uid,)).fetchone()
    return {"token": signer.dumps({"u": row["id"]}, salt="session"),
            "user": {"id": row["id"], "username": row["username"]}}

@app.get("/api/auth/providers")
def providers():
    return jsonify(google=bool(OAUTH["google"]["id"]), github=bool(OAUTH["github"]["id"]))

@app.get("/api/auth/me")
def me():
    uid = current_user()
    if not uid:
        return need_login()
    with db_lock, db() as c:
        row = c.execute("SELECT id, username FROM users WHERE id=?", (uid,)).fetchone()
    return jsonify(user={"id": row["id"], "username": row["username"]})

@app.post("/api/auth/email")
def auth_email():
    d = body()
    email = (d.get("email") or "").strip().lower()
    password = d.get("password") or ""
    if "@" not in email or len(password) < 6:
        return jsonify(error="Inserisci un'email valida e una password di almeno 6 caratteri."), 400
    with db_lock, db() as c:
        row = c.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
    if not row:
        return jsonify(need_profile=True)
    if not row["pw_hash"]:
        return jsonify(error="Questo account usa l'accesso con %s." % (row["provider"] or "un altro servizio").capitalize()), 400
    if not check_password_hash(row["pw_hash"], password):
        return jsonify(error="Password sbagliata."), 400
    return jsonify(session_for(row["id"]))

@app.post("/api/auth/register")
def auth_register():
    d = body()
    email = (d.get("email") or "").strip().lower()
    password = d.get("password") or ""
    username = (d.get("username") or "").strip()
    if "@" not in email or len(password) < 6:
        return jsonify(error="Email o password non valide."), 400
    err = check_profile(username, d.get("age"))
    if err:
        return jsonify(error=err), 400
    uid, err = create_user(email, username, d.get("age"), generate_password_hash(password), None, None)
    if err:
        return jsonify(error=err), 400
    return jsonify(session_for(uid))

@app.post("/api/auth/complete")
def auth_complete():
    d = body()
    try:
        p = signer.loads(d.get("pending", ""), salt="pending", max_age=900)
    except Exception:
        return jsonify(error="Sessione scaduta, riprova ad accedere."), 400
    username = (d.get("username") or "").strip()
    err = check_profile(username, d.get("age"))
    if err:
        return jsonify(error=err), 400
    uid, err = create_user(p.get("email"), username, d.get("age"), None, p["p"], p["pid"])
    if err:
        return jsonify(error=err), 400
    return jsonify(session_for(uid))

def back(**kw):
    return redirect("/#" + urlencode(kw, quote_via=quote))

@app.get("/api/auth/<p>/start")
def oauth_start(p):
    cfg = OAUTH.get(p)
    if not cfg or not cfg["id"]:
        return back(autherr="Questo accesso non è ancora attivo.")
    cb = request.url_root.rstrip("/") + "/api/auth/%s/callback" % p
    state = signer.dumps({"p": p, "n": secrets.token_hex(8)}, salt="state")
    if p == "github":
        url = "https://github.com/login/oauth/authorize?" + urlencode(
            {"client_id": cfg["id"], "redirect_uri": cb, "scope": "read:user user:email", "state": state})
    else:
        url = "https://accounts.google.com/o/oauth2/v2/auth?" + urlencode(
            {"client_id": cfg["id"], "redirect_uri": cb, "response_type": "code",
             "scope": "openid email profile", "state": state, "prompt": "select_account"})
    return redirect(url)

@app.get("/api/auth/<p>/callback")
def oauth_callback(p):
    cfg = OAUTH.get(p)
    if not cfg or not cfg["id"]:
        return back(autherr="Questo accesso non è ancora attivo.")
    try:
        st = signer.loads(request.args.get("state", ""), salt="state", max_age=600)
        assert st["p"] == p
    except Exception:
        return back(autherr="Sessione scaduta, riprova.")
    code = request.args.get("code")
    if not code:
        return back(autherr="Accesso annullato.")
    cb = request.url_root.rstrip("/") + "/api/auth/%s/callback" % p
    try:
        if p == "github":
            t = requests.post("https://github.com/login/oauth/access_token",
                data={"client_id": cfg["id"], "client_secret": cfg["secret"], "code": code, "redirect_uri": cb},
                headers={"Accept": "application/json"}, timeout=10).json()
            h = {"Authorization": "Bearer " + t["access_token"], "Accept": "application/vnd.github+json"}
            u = requests.get("https://api.github.com/user", headers=h, timeout=10).json()
            mails = requests.get("https://api.github.com/user/emails", headers=h, timeout=10).json()
            mails = mails if isinstance(mails, list) else []
            email = next((e["email"] for e in mails if e.get("primary") and e.get("verified")), None)
            pid, name = str(u["id"]), u.get("login") or ""
        else:
            t = requests.post("https://oauth2.googleapis.com/token",
                data={"code": code, "client_id": cfg["id"], "client_secret": cfg["secret"],
                      "redirect_uri": cb, "grant_type": "authorization_code"}, timeout=10).json()
            u = requests.get("https://openidconnect.googleapis.com/v1/userinfo",
                headers={"Authorization": "Bearer " + t["access_token"]}, timeout=10).json()
            pid = u["sub"]
            email = u.get("email") if u.get("email_verified") else None
            name = u.get("name") or ""
    except Exception:
        traceback.print_exc()
        return back(autherr="Non sono riuscito a completare l'accesso, riprova.")
    email = email.lower() if email else None
    with db_lock, db() as c:
        row = c.execute("SELECT id FROM users WHERE provider=? AND provider_id=?", (p, pid)).fetchone()
        if not row and email:
            row = c.execute("SELECT id FROM users WHERE email=?", (email,)).fetchone()
    if row:
        return back(token=session_for(row["id"])["token"])
    pending = signer.dumps({"p": p, "pid": pid, "email": email}, salt="pending")
    return back(signup=pending, name=re.sub(r"[^A-Za-z0-9_.-]", "", name)[:20])

# ---------- pagina ----------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

@app.get("/")
def home():
    if os.path.exists(os.path.join(BASE_DIR, "index.html")):
        resp = send_from_directory(BASE_DIR, "index.html")
        resp.headers["Cache-Control"] = "no-cache"
        return resp
    return "Xeno backend attivo"

@app.get("/healthz")
def healthz():
    return "ok"

@app.get("/favicon.ico")
def favicon():
    return "", 204

threading.Thread(target=watchdog, daemon=True).start()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))
