from flask import Flask, request, jsonify
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import requests
import traceback
from datetime import datetime
import time
import my_pb2
from key_iv import AES_KEY, AES_IV

app = Flask(__name__)
session = requests.Session()

DATA_API = "https://client.ind.freefiremobile.com/UpdateSocialBasicInfo"

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

def build_signature(uid: str, region: str, bio: str) -> my_pb2.Signature:
    msg = my_pb2.Signature()
    msg.field2 = 9

    # UID as int (agar number hai)
    msg.field5 = int(uid)

    # Region ko ab string treat karo
    # Agar pb2 ka type int64 hai to safe rakhne ke liye
    # ek mapping use karna hoga
    region_map = {
        "ind": 101,
        "br": 102,
        "sg": 103,
        "us": 104,
    }
    msg.field6 = region_map.get(region.lower(), 0)

    msg.field8 = bio
    msg.field9 = 1
    msg.field11 = int(time.time())
    msg.field12 = int(datetime.now().strftime("%Y%m%d%H%M%S"))
    return msg

@app.route("/update_bio", methods=["GET"])
def send_bio():
    try:
        token = request.args.get("token")
        bio = request.args.get("bio")
        uid = request.args.get("uid")
        region = request.args.get("region")

        # Basic validation
        if not token or not bio:
            return jsonify({"status": "error", "message": "Missing 'token' or 'bio' parameter"}), 400
        if not uid or not region:
            return jsonify({"status": "error", "message": "Missing 'uid' or 'region' parameter"}), 400

        # Optional: Bio length guard (adjust if server requires stricter)
        if len(bio) > 80:
            return jsonify({"status": "error", "message": "bio too long (max 80 chars recommended)"}), 400

        # Build protobuf
        msg = build_signature(int(uid), int(region), bio)
        serialized = msg.SerializeToString()

        # Encrypt
        encrypted = encrypt_message(AES_KEY, AES_IV, serialized)

        # Headers
        headers = HEADERS_TEMPLATE.copy()
        # Ensure "Bearer " not duplicated
        headers["Authorization"] = token if token.strip().lower().startswith("bearer ") else f"Bearer {token}"

        # Send
        resp = session.post(
            DATA_API,
            data=encrypted,
            headers=headers,
            verify=False,
            timeout=20,
        )

        # Try decode; keep raw on failure
        try:
            server_text = resp.content.decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            server_text = resp.content.decode("latin1", errors="ignore")

        # Smarter status mapping
        lower_text = server_text.lower().strip()
        is_ok = (200 <= resp.status_code < 300) and ("invalid" not in lower_text)

        # Debug snapshot (helps you compare with real client)
        debug = {
            "encrypted_len": len(encrypted),
            "encrypted_prefix_hex": encrypted[:16].hex(),  # first block
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
    # NOTE: never expose in prod
    app.run(host="0.0.0.0", port=5000)