from flask import Flask, request, jsonify
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import requests
import traceback
from datetime import datetime
import time
import base64
import json
import my_pb2
from key_iv import AES_KEY, AES_IV

app = Flask(__name__)
session = requests.Session()

# ✅ BD (Blueshark) API
DATA_API = "https://clientbp.ggblueshark.com/UpdateSocialBasicInfo"

HEADERS_TEMPLATE = {
    "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
    "Connection": "Keep-Alive",
    "Accept-Encoding": "gzip",
    "Content-Type": "application/octet-stream",
    "Expect": "100-continue",
    "X-Unity-Version": "2018.4.11f1",
    "X-GA": "v1 1",
    "ReleaseVersion": "OB50",
}

def encrypt_message(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(pad(plaintext, AES.block_size))

def build_signature(uid: int, region: str, bio: str) -> my_pb2.Signature:
    msg = my_pb2.Signature()
    msg.field2 = 9
    msg.field5 = int(uid)

    region_map = {
        "ind": 101,
        "br": 102,
        "sg": 103,
        "us": 104,
        "bd": 105,
    }
    msg.field6 = region_map.get(region.lower(), 104)

    msg.field8 = bio
    msg.field9 = 1
    msg.field11 = int(time.time())
    msg.field12 = int(datetime.now().strftime("%Y%m%d%H%M%S"))
    return msg

def decode_jwt_payload(token: str) -> dict:
    try:
        parts = token.split(".")
        if len(parts) < 2:
            return {}
        payload_b64 = parts[1]
        padding = "=" * (-len(payload_b64) % 4)
        decoded = base64.urlsafe_b64decode(payload_b64 + padding)
        return json.loads(decoded.decode("utf-8"))
    except Exception as e:
        print("JWT decode error:", e)
        return {}

@app.route("/bio", methods=["GET"])
def send_bio():
    try:
        token = request.args.get("token")
        bio = request.args.get("bio")

        if not token or not bio:
            return jsonify({"status": "error", "message": "Missing 'token' or 'bio'"}), 400
        if len(bio) > 80:
            return jsonify({"status": "error", "message": "bio too long (max 80 chars)"}), 400

        # JWT থেকে uid আর region বের করা
        payload = decode_jwt_payload(token)
        uid = payload.get("account_id", 0)
        region = payload.get("country_code", "us")

        # Build protobuf
        msg = build_signature(uid, region, bio)
        serialized = msg.SerializeToString()
        encrypted = encrypt_message(AES_KEY, AES_IV, serialized)

        headers = HEADERS_TEMPLATE.copy()
        headers["Authorization"] = token if token.lower().startswith("bearer ") else f"Bearer {token}"

        resp = session.post(DATA_API, data=encrypted, headers=headers, verify=False, timeout=20)

        try:
            server_text = resp.content.decode("utf-8")
        except UnicodeDecodeError:
            server_text = resp.content.decode("latin1", errors="ignore")

        lower_text = server_text.lower().strip()
        is_ok = (200 <= resp.status_code < 300) and ("invalid" not in lower_text)

        debug = {
            "uid_used": uid,
            "region_used": region,
            "encrypted_len": len(encrypted),
            "encrypted_prefix_hex": encrypted[:16].hex(),
            "raw_response_hex": resp.content.hex()[:80]
        }

        now = datetime.now().strftime("%H:%M:%S %d/%m/%Y")
        return jsonify({
            "status": "success" if is_ok else "error",
            "http_status": resp.status_code,
            "time": now,
            "response": server_text,
            "debug": debug
        }), (200 if is_ok else 502)

    except Exception as e:
        traceback.print_exc()
        return jsonify({"status": "error", "message": str(e)}), 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
    
