"""
Backend di Xeno: ti dà token + prefisso, il bot resta online da solo.
- Token salvati CIFRATI in un database (SQLite)
- All'avvio riaccende tutti i bot salvati
- Ogni 30 secondi controlla i bot e riavvia quelli caduti
- Account veri: email+password oppure Google / GitHub, con nome utente ed età

Variabili d'ambiente (Environment su Render):
  GEMINI_API_KEY   la tua chiave Gemini
  ENCRYPTION_KEY   chiave per cifrare i token (vedi sotto come crearla)
  DB_PATH          percorso del database (con disco Render: /data/bots.db)
  GITHUB_CLIENT_ID / GITHUB_CLIENT_SECRET   (opzionali) per "Continua con GitHub"
  GOOGLE_CLIENT_ID / GOOGLE_CLIENT_SECRET   (opzionali) per "Continua con Google"

Crea ENCRYPTION_KEY una volta sola, da terminale:
  python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
NON perderla e NON cambiarla: senza di lei i token salvati non si leggono più.
"""
import os, asyncio, threading, time, sqlite3, base64, hashlib, re, secrets
from urllib.parse import urlencode, quote
import requests
from flask import Flask, request, jsonify, send_from_directory, redirect
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix
from itsdangerous import URLSafeTimedSerializer
from flask_cors import CORS
from cryptography.fernet import Fernet
import discord
import google.generativeai as genai

MODEL = "gemini-2.0-flash"   # metti lo stesso modello che usi già nella tua app
DB_PATH = os.environ.get("DB_PATH", "bots.db")
MIN_AGE = 14
SESSION_DAYS = 30
OAUTH = {
    "github": {"id": os.environ.get("GITHUB_CLIENT_ID", ""), "secret": os.environ.get("GITHUB_CLIENT_SECRET", "")},
    "google": {"id": os.environ.get("GOOGLE_CLIENT_ID", ""), "secret": os.environ.get("GOOGLE_CLIENT_SECRET", "")},
}

genai.configure(api_key=os.environ["GEMINI_API_KEY"])
model = genai.GenerativeModel(
    MODEL,
    system_instruction="Ti chiami Xeno. Sei un assistente IA gentile e chiaro. "
                       "Rispondi nella lingua dell'utente.")
fernet = Fernet(os.environ["ENCRYPTION_KEY"].encode())
# firma delle sessioni: derivata da ENCRYPTION_KEY, non serve un'altra variabile
signer = URLSafeTimedSerializer(
    hashlib.sha256(b"xeno-sessions:" + os.environ["ENCRYPTION_KEY"].encode()).hexdigest())

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 25 * 1024 * 1024   # allegati: max 25 MB a richiesta
CORS(app)
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)   # Render: link https corretti

# ---------- database ----------
db_lock = threading.Lock()
def db():
    c = sqlite3.connect(DB_PATH)
    c.row_factory = sqlite3.Row
    return c

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
        c.execute("UPDATE bots SET active=?, last_error=? WHERE user_id=?",
                  (active, error, user_id))

def get_bot(user_id):
    with db_lock, db() as c:
        return c.execute("SELECT * FROM bots WHERE user_id=?", (user_id,)).fetchone()

def delete_bot(user_id):
    with db_lock, db() as c:
        c.execute("DELETE FROM bots WHERE user_id=?", (user_id,))

# ---------- chi sta chiamando? ----------
def current_user():
    """Ritorna l'id dell'utente (testo) se la sessione è valida, altrimenti None."""
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

# ---------- IA ----------
def ask_gemini(text):
    try:
        return model.generate_content(text).text[:1900]
    except Exception as e:
        return "Errore dell'IA: " + str(e)[:200]

ALLOWED_MIME = {"image/jpeg", "image/png", "image/webp", "image/gif", "application/pdf"}

@app.post("/api/chat")
def chat():
    uid = current_user()
    if not uid:
        return need_login()
    d = request.get_json(force=True)
    history = "\n".join(f"{m['role']}: {m['content']}" for m in d.get("messages", []))
    if d.get("mode") == "code":
        history = "Rispondi con codice completo in un blocco ``` e una breve spiegazione.\n" + history
    parts = [history]
    for f in (d.get("files") or [])[:4]:          # max 4 allegati
        mime = f.get("mime")
        if mime not in ALLOWED_MIME:
            continue
        try:
            parts.append({"mime_type": mime, "data": base64.b64decode(f.get("data", ""))})
        except Exception:
            return jsonify(error="Allegato non valido."), 400
    try:
        return jsonify(reply=model.generate_content(parts).text)
    except Exception as e:
        return jsonify(error=str(e)[:200]), 500

# ---------- bot Discord ----------
running = {}   # user_id -> {"client", "loop"}

def stop_running(user_id):
    b = running.pop(user_id, None)
    if b:
        asyncio.run_coroutine_threadsafe(b["client"].close(), b["loop"])

def _launch(user_id, token, prefix, wait=20):
    """Avvia il bot. Ritorna (invite, errore, fatale). fatale=True se il token è sbagliato."""
    stop_running(user_id)
    intents = discord.Intents.default()
    intents.message_content = True
    client = discord.Client(intents=intents)
    loop = asyncio.new_event_loop()
    ready, result = threading.Event(), {}

    @client.event
    async def on_ready():
        result["id"] = client.user.id
        ready.set()

    @client.event
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
            loop.run_until_complete(client.start(token))
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
    running[user_id] = {"client": client, "loop": loop}
    invite = "https://discord.com/oauth2/authorize?client_id=%s&scope=bot&permissions=68608" % result["id"]
    return invite, None, False

launch_lock = threading.Lock()   # un solo avvio alla volta: niente bot doppi

def launch(user_id, token, prefix, wait=20):
    with launch_lock:
        return _launch(user_id, token, prefix, wait)

def revive(row):
    with launch_lock:
        row = get_bot(row["user_id"])          # dati aggiornati
        if not row or not row["active"]:
            return
        r = running.get(row["user_id"])
        if r and not r["client"].is_closed():  # nel frattempo è già ripartito
            return
        token = fernet.decrypt(row["token_enc"]).decode()
        _, err, fatal = _launch(row["user_id"], token, row["prefix"], wait=30)
        if err and fatal:
            set_state(row["user_id"], 0, err)  # token da correggere: non riprovo all'infinito

def watchdog():
    """Riaccende all'avvio e poi ogni 30 secondi i bot che devono essere attivi."""
    while True:
        try:
            with db_lock, db() as c:
                rows = c.execute("SELECT * FROM bots WHERE active=1").fetchall()
            for row in rows:
                r = running.get(row["user_id"])
                if not r or r["client"].is_closed():
                    revive(row)
        except Exception as e:
            print("watchdog:", e)
        time.sleep(30)

# ---------- API ----------
@app.post("/api/go-online")
def go_online():
    user_id = current_user()
    if not user_id:
        return need_login()
    d = request.get_json(force=True)
    token = (d.get("token") or "").strip()
    prefix = (d.get("prefix") or "!").strip()[:3]
    if d.get("platform") != "discord":
        return jsonify(error="Per ora è disponibile solo Discord."), 400
    if not token:
        return jsonify(error="Manca il token del bot."), 400
    invite, err, _ = launch(user_id, token, prefix)
    if err:
        return jsonify(error=err), 400
    save_bot(user_id, token, prefix)   # salvato solo se il token funziona
    return jsonify(message="Il bot è online e resterà acceso anche dopo i riavvii. "
                           "Scrivi %sciao in un canale." % prefix, invite=invite)

@app.post("/api/stop-bot")
def stop_bot():
    user_id = current_user()
    if not user_id:
        return need_login()
    stop_running(user_id)
    delete_bot(user_id)   # cancella anche il token salvato
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
    online = bool(r) and not r["client"].is_closed()
    return jsonify(state="online" if online else "spento", error=row["last_error"])

# ---------- ACCOUNT ----------
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
            cur = c.execute(
                "INSERT INTO users(email,username,age,pw_hash,provider,provider_id,created) "
                "VALUES(?,?,?,?,?,?,?)",
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
    """Email già registrata -> accede. Email nuova -> chiede nome utente ed età."""
    d = request.get_json(force=True)
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
    d = request.get_json(force=True)
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
    """Secondo passo dopo Google/GitHub per chi non è ancora registrato."""
    d = request.get_json(force=True)
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
        return back(autherr="Non sono riuscito a completare l'accesso, riprova.")
    email = email.lower() if email else None
    with db_lock, db() as c:
        row = c.execute("SELECT id FROM users WHERE provider=? AND provider_id=?", (p, pid)).fetchone()
        if not row and email:   # già registrato con la stessa email verificata
            row = c.execute("SELECT id FROM users WHERE email=?", (email,)).fetchone()
    if row:
        return back(token=session_for(row["id"])["token"])
    pending = signer.dumps({"p": p, "pid": pid, "email": email}, salt="pending")
    return back(signup=pending, name=re.sub(r"[^A-Za-z0-9_.-]", "", name)[:20])

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

@app.get("/")
def home():
    # se index.html è nella stessa cartella di main.py, il link del servizio mostra l'app
    if os.path.exists(os.path.join(BASE_DIR, "index.html")):
        return send_from_directory(BASE_DIR, "index.html")
    return "Xeno backend attivo"

threading.Thread(target=watchdog, daemon=True).start()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))
