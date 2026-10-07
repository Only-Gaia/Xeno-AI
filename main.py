"""
Backend di Xeno: ti dà token + prefisso, il bot resta online da solo.
- Token salvati CIFRATI in un database (SQLite)
- All'avvio riaccende tutti i bot salvati
- Ogni 30 secondi controlla i bot e riavvia quelli caduti
- Accesso protetto da un codice segreto (ACCESS_CODE), niente Firebase

Variabili d'ambiente (Environment su Render):
  GEMINI_API_KEY   la tua chiave Gemini
  ENCRYPTION_KEY   chiave per cifrare i token (vedi sotto come crearla)
  ACCESS_CODE      codice segreto di accesso (una frase lunga scelta da te)
  DB_PATH          (opzionale) percorso del database, es. /data/bots.db

Crea ENCRYPTION_KEY una volta sola, da terminale:
  python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
NON perderla e NON cambiarla: senza di lei i token salvati non si leggono più.
"""
import os, asyncio, threading, time, sqlite3, hmac, base64
from flask import Flask, request, jsonify
from flask_cors import CORS
from cryptography.fernet import Fernet
import discord
import google.generativeai as genai

MODEL = "gemini-2.0-flash"   # metti lo stesso modello che usi già nella tua app
DB_PATH = os.environ.get("DB_PATH", "bots.db")
ACCESS_CODE = os.environ.get("ACCESS_CODE", "")

genai.configure(api_key=os.environ["GEMINI_API_KEY"])
model = genai.GenerativeModel(
    MODEL,
    system_instruction="Ti chiami Xeno. Sei un assistente IA gentile e chiaro. "
                       "Rispondi nella lingua dell'utente.")
fernet = Fernet(os.environ["ENCRYPTION_KEY"].encode())

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 25 * 1024 * 1024   # allegati: max 25 MB a richiesta
CORS(app)

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
    """Ritorna "owner" se il codice di accesso è corretto, altrimenti None."""
    h = request.headers.get("Authorization", "")
    if ACCESS_CODE and h.startswith("Bearer ") and hmac.compare_digest(h[7:], ACCESS_CODE):
        return "owner"
    return None

def need_login():
    return jsonify(error="Codice di accesso mancante o sbagliato."), 401

# ---------- IA ----------
def ask_gemini(text):
    try:
        return model.generate_content(text).text[:1900]
    except Exception as e:
        return "Errore dell'IA: " + str(e)[:200]

ALLOWED_MIME = {"image/jpeg", "image/png", "image/webp", "image/gif", "application/pdf"}

@app.post("/api/chat")
def chat():
    if not current_user():
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

@app.get("/")
def home():
    return "Xeno backend attivo"

threading.Thread(target=watchdog, daemon=True).start()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))
