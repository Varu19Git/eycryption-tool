from fastapi import FastAPI, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os, base64

app = FastAPI()

# ✅ CORS FIX
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def derive_key(password: str, salt: bytes):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    return kdf.derive(password.encode())

# 🔐 TEXT ENCRYPT
@app.post("/encrypt-text")
async def encrypt_text(text: str = Form(...), password: str = Form(...)):
    try:
        salt = os.urandom(16)
        iv = os.urandom(12)

        key = derive_key(password, salt)
        aes = AESGCM(key)

        encrypted = aes.encrypt(iv, text.encode(), None)

        result = base64.b64encode(salt + iv + encrypted).decode()
        return {"encrypted": result}
    except Exception as e:
        return {"error": str(e)}

# 🔓 TEXT DECRYPT
@app.post("/decrypt-text")
async def decrypt_text(cipher: str = Form(...), password: str = Form(...)):
    try:
        data = base64.b64decode(cipher)

        salt = data[:16]
        iv = data[16:28]
        ct = data[28:]

        key = derive_key(password, salt)
        aes = AESGCM(key)

        decrypted = aes.decrypt(iv, ct, None)

        return {"decrypted": decrypted.decode()}
    except Exception:
        return {"error": "Wrong key or corrupted data"}

# 📁 FILE ENCRYPT
@app.post("/encrypt-file")
async def encrypt_file(file: UploadFile = File(...), password: str = Form(...)):
    content = await file.read()

    salt = os.urandom(16)
    iv = os.urandom(12)

    key = derive_key(password, salt)
    aes = AESGCM(key)

    encrypted = aes.encrypt(iv, content, None)

    final = salt + iv + encrypted

    return StreamingResponse(
        iter([final]),
        media_type="application/octet-stream",
        headers={"Content-Disposition": f"attachment; filename={file.filename}.enc"}
    )

# 📁 FILE DECRYPT
@app.post("/decrypt-file")
async def decrypt_file(file: UploadFile = File(...), password: str = Form(...)):
    data = await file.read()

    salt = data[:16]
    iv = data[16:28]
    ct = data[28:]

    key = derive_key(password, salt)
    aes = AESGCM(key)

    decrypted = aes.decrypt(iv, ct, None)

    return StreamingResponse(
        iter([decrypted]),
        media_type="application/octet-stream",
        headers={"Content-Disposition": "attachment; filename=decrypted_file"}
    )