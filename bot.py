import os
import logging
import time
import json
import requests
import asyncio
import base64
from base64 import b64decode, b64encode
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad, pad
from telegram import Update
from telegram.ext import Application, CommandHandler, MessageHandler, filters, ContextTypes

# ---------------- LOGGING ----------------
logging.basicConfig(
    format="%(asctime)s - %(levelname)s - %(message)s",
    level=logging.INFO
)
logger = logging.getLogger(__name__)

# ---------------- CONFIG ----------------
API_URL = "https://application.utkarshapp.com/index.php/data_model"
COMMON_KEY = b"%!^F&^$)&^$&*$^&"
COMMON_IV = b"#*v$JvywJvyJDyvJ"

key_chars = "%!F*&^$)_*%3f&B+"
iv_chars = "#*$DJvyw2w%!_-$@"

BASE_HEADERS = {
    "Authorization": "Bearer 152#svf346t45ybrer34yredk76t",
    "Content-Type": "text/plain; charset=UTF-8",
    "devicetype": "1",
    "host": "application.utkarshapp.com",
    "lang": "1",
    "user-agent": "okhttp/4.9.0",
    "userid": "0",
    "version": "152"
}

base_url = "https://online.utkarsh.com/"
login_url = "https://online.utkarsh.com/web/Auth/login"
tiles_data_url = "https://online.utkarsh.com/web/Course/tiles_data"
layer_two_data_url = "https://online.utkarsh.com/web/Course/get_layer_two_data"
meta_source_url = "/meta_distributer/on_request_meta_source"

# ---------------- HELPERS ----------------
def encrypt(data, use_common_key, key=None, iv=None):
    cipher_key, cipher_iv = (COMMON_KEY, COMMON_IV) if use_common_key else (key, iv)
    cipher = AES.new(cipher_key, AES.MODE_CBC, cipher_iv)
    padded = pad(json.dumps(data, separators=(",", ":")).encode(), AES.block_size)
    return b64encode(cipher.encrypt(padded)).decode() + ":"

def decrypt(data, use_common_key, key=None, iv=None):
    try:
        cipher_key, cipher_iv = (COMMON_KEY, COMMON_IV) if use_common_key else (key, iv)
        cipher = AES.new(cipher_key, AES.MODE_CBC, cipher_iv)
        enc = b64decode(data.split(":")[0])
        dec = unpad(cipher.decrypt(enc), AES.block_size)
        return dec.decode()
    except Exception as e:
        logger.error(f"Decrypt error: {e}")
        return None

def post_request(path, data=None, use_common_key=False, key=None, iv=None, headers=None):
    enc = encrypt(data, use_common_key, key, iv) if data else None
    r = requests.post(API_URL + path, headers=headers, data=enc)
    if r.status_code != 200:
        return {}
    dec = decrypt(r.text, use_common_key, key, iv)
    try:
        return json.loads(dec) if dec else {}
    except:
        return {}

def decrypt_and_load_json(enc):
    try:
        enc = b64decode(enc)
        key = b"%!$!%_$&!%F)&^!^"
        iv = b"#*y*#2yJ*#$wJv*v"
        cipher = AES.new(key, AES.MODE_CBC, iv)
        dec = cipher.decrypt(enc)
        try:
            text = unpad(dec, AES.block_size).decode()
        except:
            text = dec.decode(errors="ignore")
        return json.loads(text)
    except Exception as e:
        logger.error(f"Stream decrypt error: {e}")
        return {}

def encrypt_stream(txt):
    key = b"%!$!%_$&!%F)&^!^"
    iv = b"#*y*#2yJ*#$wJv*v"
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return b64encode(cipher.encrypt(pad(txt.encode(), AES.block_size))).decode()

# ---------------- CORE ----------------
async def extract_courses(mobile, password, batch_id):
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, _sync_extract, mobile, password, batch_id)

def _sync_extract(mobile, password, batch_id):
    session = requests.Session()

    r = session.get(base_url)
    csrf = r.cookies.get("csrf_name")
    if not csrf:
        return [], "CSRF error"

    login_data = {
        "csrf_name": csrf,
        "mobile": mobile,
        "password": password,
        "url": "0",
        "submit": "LogIn"
    }

    resp = session.post(login_url, data=login_data)
    try:
        j = resp.json()
    except:
        return [], "Login response invalid"

    data = decrypt_and_load_json(j.get("response"))
    jwt = data.get("data", {}).get("jwt")
    if not jwt:
        return [], "Login failed"

    headers = BASE_HEADERS.copy()
    headers["jwt"] = jwt

    profile = post_request("/users/get_my_profile", use_common_key=True, headers=headers)
    uid = profile.get("data", {}).get("id")
    if not uid:
        return [], "User ID error"

    headers["userid"] = uid
    key = "".join(key_chars[int(i)] for i in (uid + "1524567456436545")[:16]).encode()
    iv = "".join(iv_chars[int(i)] for i in (uid + "1524567456436545")[:16]).encode()

    files = []
    tile_payload = encrypt_stream(json.dumps({
        "course_id": batch_id,
        "layer": 1,
        "type": "course_combo"
    }))

    res = session.post(
        tiles_data_url,
        data={"tile_input": tile_payload, "csrf_name": csrf}
    ).json()

    tiles = decrypt_and_load_json(res.get("response")).get("data", [])

    for t in tiles:
        fn = f"{t.get('id')}_{int(time.time())}.txt"
        with open(fn, "w", encoding="utf-8") as f:
            f.write(t.get("title", "No Title") + "\n")
        files.append(fn)

    return files, None

# ---------------- TELEGRAM ----------------
user_sessions = {}

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "Send like:\nmobile*password\nThen send Batch ID"
    )

async def handle_text(update: Update, context: ContextTypes.DEFAULT_TYPE):
    uid = update.effective_user.id
    txt = update.message.text.strip()

    if "*" in txt:
        m, p = txt.split("*", 1)
        user_sessions[uid] = {"mobile": m, "password": p}
        await update.message.reply_text("✅ Login saved. Batch ID bhejo.")
        return

    if uid not in user_sessions:
        await update.message.reply_text("❌ Pehle mobile*password bhejo.")
        return

    await update.message.reply_text("⏳ Processing...")
    files, err = await extract_courses(
        user_sessions[uid]["mobile"],
        user_sessions[uid]["password"],
        txt
    )

    if err:
        await update.message.reply_text("❌ " + err)
        return

    for f in files:
        with open(f, "rb") as d:
            await update.message.reply_document(d)
        os.remove(f)

    await update.message.reply_text("✅ Done!")

# ---------------- MAIN ----------------
def main():
    TOKEN = "7954227358:AAHQ6EdccjB77PtaesIIYjUTaqzpRltoHaw"

    app = Application.builder().token(TOKEN).build()
    app.add_handler(CommandHandler("start", start))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_text))

    logger.info("🤖 Bot started...")
    app.run_polling(drop_pending_updates=True)

if __name__ == "__main__":
    main()
