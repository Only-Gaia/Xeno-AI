"""
Backend di Xeno: chat IA (Gemini) + account + bot Discord sempre online.
- Account veri: email+password oppure GitHub, con nome utente ed età
- Token dei bot Discord salvati CIFRATI in un database (SQLite)
- All'avvio riaccende tutti i bot salvati; ogni 30 secondi riavvia quelli caduti

Variabili d'ambiente (Environment su Render):
  GEMINI_API_KEY   la tua chiave Gemini (comincia con AIza...)
  ENCRYPTION_KEY   chiave per cifrare i token (vedi sotto come crearla)
  GEMINI_MODEL     (opzionale) modello Gemini, default gemini-3.8-flash
  DB_PATH          percorso del database (con disco Render: /data/bots.db)
  GITHUB_CLIENT_ID / GITHUB_CLIENT_SECRET   (opzionali) per "Continua con GitHub"
  GOOGLE_CLIENT_ID / GOOGLE_CLIENT_SECRET   (opzionali, non usati dal sito ora)

Crea ENCRYPTION_KEY una volta sola, da terminale:
  python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
NON perderla e NON cambiarla: senza di lei i token salvati non si leggono più.
"""
import os, asyncio, threading, time, sqlite3, base64, hashlib, re, secrets, traceback
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
MIN_AGE = 14
SESSION_DAYS = 30
OAUTH = {
    "github": {"id": os.environ.get("GITHUB_CLIENT_ID", ""), "secret": os.environ.get("GITHUB_CLIENT_SECRET", "")},
    "google": {"id": os.environ.get("GOOGLE_CLIENT_ID", ""), "secret": os.environ.get("GOOGLE_CLIENT_SECRET", "")},
}
SYSTEM = ("Ti chiami Xeno. Sei un assistente IA gentile e chiaro. "
          "Rispondi nella lingua dell'utente.")
SYSTEM_CODE = SYSTEM + (" Quando l'utente chiede del codice, rispondi con il codice completo "
                        "in un blocco ``` e una breve spiegazione.")
ALLOWED_MIME = {"image/jpeg", "image/png", "image/webp", "image/gif", "application/pdf"}

# ---------- Gemini (SDK ufficiale google-genai) ----------
client = genai.Client(
    api_key=os.environ["GEMINI_API_KEY"].strip(),
    http_options=types.HttpOptions(timeout=90000))   # 90 secondi, poi errore (non resta appeso)

def generate(contents, system):
    """Chiede una risposta a Gemini. Ritorna il testo oppure solleva un errore."""
    cfg = {"system_instruction": system}
    if MODEL.startswith("gemini-3"):
        # i modelli 3.x di default "ragionano" a lungo; "low" li rende veloci per la chat
        cfg["thinking_config"] = types.ThinkingConfig(thinking_level="low")
    res = client.models.generate_content(
        model=MODEL, contents=contents, config=types.GenerateContentConfig(**cfg))
    text = (res.text or "").strip()
    if not text:
        raise ValueError("EMPTY")
    return text

def friendly(e):
    """Trasforma gli errori di Gemini in frasi chiare in italiano."""
    m = str(e)
    low = m.lower()
    if m == "EMPTY":
        return "L'IA non ha dato nessuna risposta (forse bloccata dai filtri). Riprova con un'altra frase."
    if "429" in m or "RESOURCE_EXHAUSTED" in m:
        return "Troppe richieste o quota di Gemini esaurita. Riprova tra un minuto."
    if "api key" in low or "API_KEY" in m or "401" in m or "403" in m or "PERMISSION_DENIED" in m:
        return "La chiave Gemini non è valida: controlla GEMINI_API_KEY su Render."
    if "404" in m or "NOT_FOUND" in m:
        return "Il modello Gemini non esiste più: cambia GEMINI_MODEL su Render."
    if "timeout" in low or "timed out" in low or "deadline" in low:
        return "L'IA ci ha messo troppo, riprova."
    return "Errore dell'IA: " + m[:200]

def ask_gemini(text):
    """Per il bot Discord: una domanda, una risposta (max 1900 caratteri)."""
    try:
        c = [types.Content(role="user", parts=[types.Part.from_text(text=text)])]
        return generate(c, SYSTEM)[:1900]
    except Exception as e:
        traceback.print_exc()
        return friendly(e)

def build_contents(messages, files):
    """Messaggi della chat -> formato Gemini. Ritorna (contents, errore)."""
    turns = []
    for m in (messages or [])[-30:]:                 # ultimi 30 messaggi
        role = "user" if m.get("role") == "user" else "model"
        text = str(m.get("content") or "").strip()
        if not text:
            continue
        if turns and turns[-1]["role"] == role:      # niente due turni di fila dello stesso tipo
            turns[-1]["text"] += "\n" + text
        else:
            turns.append({"role": role, "text": text})
    while turns and turns[0]["role"] != "user":
        turns.pop(0)
    if not turns or turns[-1]["role"] != "user":
        return None, "Scrivi un messaggio."
    extra = []
    for f in (files or [])[:4]:                      # max 4 allegati
        mime = (f or {}).get("mime")
        if mime not in ALLOWED_MIME:
            continue
        try:
            extra.append(types.Part.from_bytes(
                data=base64.b64decode(f.get("data", ""), validate=True), mime_type=mime))
        except Exception:
            return None, "Allegato non valido."
    contents = []
    for i, t in enumerate(turns):
        parts = [types.Part.from_text(text=t["text"])]
        if i == len(turns) - 1:
            parts += extra                           # gli allegati vanno con l'ultimo messaggio
        contents.append(types.Content(role=t["role"], parts=parts))
    return contents, None

fernet = Fernet(os.environ["ENCRYPTION_KEY"].strip().encode())
# firma delle sessioni: derivata da ENCRYPTION_KEY, non serve un'altra variabile
signer = URLSafeTimedSerializer(
    hashlib.sha256(b"xeno-sessions:" + os.environ["ENCRYPTION_KEY"].strip().encode()).hexdigest())

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 25 * 1024 * 1024   # allegati: max 25 MB a richiesta
CORS(app)
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)   # Render: link https corretti

def body():
    """Il JSON della richiesta, senza errori se è vuoto o rotto."""
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
            print("ATTENZIONE: la cartella %s non esiste (manca il disco su Render?). "
                  "Uso bots.db locale: i dati si perdono ad ogni riavvio." % d)
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

# ---------- chat ----------
@app.post("/api/chat")
def chat():
    if not current_user():
        return need_login()
    d = body()
    contents, err = build_contents(d.get("messages"), d.get("files"))
    if err:
        return jsonify(error=err), 400
    try:
        reply = generate(contents, SYSTEM_CODE if d.get("mode") == "code" else SYSTEM)
        return jsonify(reply=reply)
    except Exception as e:
        traceback.print_exc()          # il motivo preciso compare nei Logs di Render
        return jsonify(error=friendly(e)), 500

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
                    try:
                        revive(row)
                    except Exception as e:      # un bot rotto non ferma gli altri
                        print("watchdog bot", row["user_id"], e)
        except Exception as e:
            print("watchdog:", e)
        time.sleep(30)

# ---------- API bot ----------
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
    """Secondo passo dopo GitHub per chi non è ancora registrato."""
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
        if not row and email:   # già registrato con la stessa email verificata
            row = c.execute("SELECT id FROM users WHERE email=?", (email,)).fetchone()
    if row:
        return back(token=session_for(row["id"])["token"])
    pending = signer.dumps({"p": p, "pid": pid, "email": email}, salt="pending")
    return back(signup=pending, name=re.sub(r"[^A-Za-z0-9_.-]", "", name)[:20])

# ---------- pagina del sito ----------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

@app.get("/")
def home():
    # se index.html è nella stessa cartella di main.py, il link del servizio mostra l'app
    if os.path.exists(os.path.join(BASE_DIR, "index.html")):
        resp = send_from_directory(BASE_DIR, "index.html")
        resp.headers["Cache-Control"] = "no-cache"      # dopo un aggiornamento vedi subito la versione nuova
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
