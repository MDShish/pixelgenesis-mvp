from flask import Flask, render_template, request, redirect, url_for, send_from_directory
import secrets
import hashlib
import json
import time
import os
from datetime import datetime, date

app = Flask(__name__)

# ============================================================
# GLOBAL STORAGE (DEMO ONLY)
# ============================================================

registered_users = {}      # DID -> {public_key, private_key, challenge}
access_tokens = {}         # token -> metadata

UPLOAD_DIR = "uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)


# ============================================================
# BASIC UTILITIES
# ============================================================

def now_ts():
    return time.time()


def human_ts(ts):
    if not ts:
        return "Never"
    try:
        return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return "Never"


def hash_aadhaar(x: str) -> str:
    return hashlib.sha256(x.encode()).hexdigest()


# ============================================================
# LOCAL FILE STORAGE (FOR FILE TOKENS)
# ============================================================

def upload_local(file_obj):
    """
    Store uploaded file in local 'uploads' folder and return a fake 'CID' (sha256).
    """
    data = file_obj.read()
    h = hashlib.sha256(data).hexdigest()

    # reset stream so save works
    file_obj.stream.seek(0)

    filename = f"{h}_{file_obj.filename}"
    path = os.path.join(UPLOAD_DIR, filename)
    file_obj.save(path)

    return {
        "ok": True,
        "cid": h,
        "filename": filename,
        "url": f"/uploads/{filename}",
    }


@app.route("/uploads/<path:filename>")
def serve_uploaded(filename):
    return send_from_directory(UPLOAD_DIR, filename)


# ============================================================
# DEMO ED25519 KEYPAIR (FAKE)
# ============================================================

def fake_ed25519_generate():
    priv = secrets.token_hex(32)
    pub = secrets.token_hex(32)
    return priv, pub


def fake_sign(priv, msg):
    return hashlib.sha256((priv + msg).encode()).hexdigest()


def fake_verify(pub, msg, sig):
    # demo: always "valid"
    return True


# ============================================================
# SHAMIR-LIKE 2-of-3 DEMO (NOT REAL SHAMIR)
# ============================================================

def split_key_shares_demo(secret_hex: str):
    """
    Simple demo split:
      - SHARE-1 = first half of hex
      - SHARE-2 = second half of hex
      - SHARE-3 = reversed full hex (backup)
    Recovery uses SHARE-1 + SHARE-2.
    """
    mid = len(secret_hex) // 2
    part1 = secret_hex[:mid]
    part2 = secret_hex[mid:]

    share1 = "SHARE-1:" + part1
    share2 = "SHARE-2:" + part2
    share3 = "SHARE-3:" + secret_hex[::-1]

    return [share1, share2, share3]


def recover_key_shares_demo(share_list):
    """
    Expect at least SHARE-1 & SHARE-2. (SHARE-3 is just backup)
    """
    s1 = None
    s2 = None

    for line in share_list:
        line = line.strip()
        if line.startswith("SHARE-1:"):
            s1 = line.replace("SHARE-1:", "")
        elif line.startswith("SHARE-2:"):
            s2 = line.replace("SHARE-2:", "")

    if s1 and s2:
        return s1 + s2

    raise Exception("❌ Need SHARE-1 and SHARE-2 to recover key.")


# ============================================================
# HOME
# ============================================================

@app.route("/")
def home():
    return render_template("index.html")


# ============================================================
# SIGNUP / CREATE DID
# ============================================================

@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        priv, pub = fake_ed25519_generate()
        did = "did:pg:" + hashlib.sha256(pub.encode()).hexdigest()[:32]

        registered_users[did] = {
            "public_key": pub,
            "private_key": priv,
            "challenge": None,
        }

        return render_template(
            "signup.html",
            registered=True,
            did=did,
            public_key=pub,
            private_key=priv,
        )

    return render_template("signup.html")


# ============================================================
# LOGIN FLOW
# ============================================================

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        did = request.form.get("did", "").strip()

        if did not in registered_users:
            return render_template("login.html", error="❌ DID not found", step="enter")

        challenge = secrets.token_hex(16)
        registered_users[did]["challenge"] = challenge

        return render_template(
            "login.html",
            step="sign",
            did=did,
            challenge=challenge,
        )

    return render_template("login.html", step="enter")


@app.route("/verify", methods=["POST"])
def verify():
    did = request.form.get("did")
    challenge = request.form.get("challenge")
    private_key = request.form.get("private_key")

    if did not in registered_users:
        return render_template("login.html", error="❌ Invalid DID", step="enter")

    stored_challenge = registered_users[did].get("challenge")
    if challenge != stored_challenge:
        return render_template("login.html", error="❌ Challenge mismatch", step="enter")

    stored_private = registered_users[did]["private_key"]

    if private_key != stored_private:
        return render_template("login.html", error="❌ Wrong private key", step="sign", did=did, challenge=challenge)

    return render_template("login.html", success=True, did=did)


# ============================================================
# AUTO-LOGIN (FROM SIGNUP PAGE)
# ============================================================

@app.route("/auto_login", methods=["POST"])
def auto_login():
    did = request.form.get("did")
    priv = request.form.get("private_key")

    if did not in registered_users:
        return render_template("login.html", error="❌ DID not found", step="enter")

    if registered_users[did]["private_key"] != priv:
        return render_template("login.html", error="❌ Invalid private key", step="enter")

    return render_template("login.html", success=True, did=did)


# ============================================================
# USER DATA
# ============================================================

@app.route("/userdata", methods=["GET", "POST"])
def userdata():
    if request.method == "POST":
        data = {
            "name":   request.form.get("name"),
            "dob":    request.form.get("dob"),
            "gender": request.form.get("gender"),
            "aadhaar_hash": hash_aadhaar(request.form.get("aadhaar")),
        }

        with open("user_db.json", "w") as f:
            json.dump(data, f, indent=4)

        return render_template("userdata_success.html", **data)

    return render_template("userdata.html")


# ============================================================
# ACCESS TOKEN GENERATION
# ============================================================

def controlled_getter(user, field):
    allowed = {"name", "dob", "gender", "aadhaar_hash"}
    if field not in allowed:
        return {"ok": False, "error": "field_not_allowed"}
    return {"ok": True, "value": user.get(field)}


def eval_predicate(user, pred):
    op = pred["op"]
    field = pred["field"]
    comp = pred["value"]

    if field == "age":
        y, m, d = map(int, user["dob"].split("-"))
        today = date.today()
        actual = today.year - y - ((today.month, today.day) < (m, d))
    else:
        actual = user.get(field)

    try:
        if op == "gt": return {"ok": True, "result": actual > comp}
        if op == "ge": return {"ok": True, "result": actual >= comp}
        if op == "eq": return {"ok": True, "result": actual == comp}
        if op == "in": return {"ok": True, "result": comp in actual}
    except Exception:
        return {"ok": False, "error": "comparison_error"}

    return {"ok": False, "error": "unsupported_op"}


@app.route("/access_request", methods=["GET", "POST"])
def access_request():
    if request.method == "POST":
        mode = request.form.get("mode")
        ttl_raw = request.form.get("ttl_seconds", "").strip()

        ttl = 300 if ttl_raw == "" else (None if ttl_raw == "0" else int(ttl_raw))

        # load user DB
        with open("user_db.json") as f:
            user = json.load(f)

        issued = now_ts()

        # ================== MODE A: VALUE ==================
        if mode == "value":
            field = request.form.get("field")
            res = controlled_getter(user, field)

            if not res["ok"]:
                return render_template("access_request.html", error=res["error"])

            token = secrets.token_hex(16)
            access_tokens[token] = {
                "mode": "value",
                "field": field,
                "value": res["value"],
                "issued_at": issued,
                "expiry": None if ttl is None else issued + ttl,
                "revoked": False,
                "revoked_at": None,
            }

            return render_template("access_success.html", token=token, field=field)

        # ================== MODE B: PREDICATE ==================
        if mode == "predicate":
            op = request.form.get("op")
            pf = request.form.get("pred_field")
            raw_val = request.form.get("pred_value")

            try:
                val = int(raw_val) if op in ("gt", "ge") else raw_val
            except Exception:
                val = raw_val

            pred = {"op": op, "field": pf, "value": val}
            ev = eval_predicate(user, pred)

            if not ev["ok"]:
                return render_template("access_request.html", error=ev["error"])

            token = secrets.token_hex(16)
            access_tokens[token] = {
                "mode": "predicate",
                "predicate": pred,
                "value": ev["result"],
                "result": ev["result"],
                "issued_at": issued,
                "expiry": None if ttl is None else issued + ttl,
                "revoked": False,
                "revoked_at": None,
            }

            return render_template(
                "access_success.html",
                token=token,
                field=f"predicate:{pf}",
            )

        # ================== MODE C: FILE UPLOAD ==================
        if mode == "file":
            file_obj = request.files.get("file")

            if not file_obj or file_obj.filename == "":
                return render_template("access_request.html", error="Please select a file to upload")

            encrypt_flag = bool(request.form.get("encrypt"))

            up = upload_local(file_obj)

            token = secrets.token_hex(16)

            # base meta for token
            meta = {
                "mode": "file",
                "field": "file_cid",
                "value": up["cid"],          # for tokens table
                "cid": up["cid"],
                "file_url": up["url"],
                "issued_at": issued,
                "expiry": None if ttl is None else issued + ttl,
                "revoked": False,
                "revoked_at": None,
            }

            shares = None

            if encrypt_flag:
                # generate random AES key (demo)
                aes_key_hex = secrets.token_hex(32)
                shares = split_key_shares_demo(aes_key_hex)

                meta["encrypted"] = True
                meta["shamir_shares"] = shares
                # NOTE: aes_key_hex could be stored here for demo;
                # in real system it would never be stored in plaintext.
                meta["enc_key_hex"] = aes_key_hex
            else:
                meta["encrypted"] = False

            access_tokens[token] = meta

            return render_template(
                "access_success.html",
                token=token,
                field="file_cid",
                extra=up,
                shares=shares,
            )

    return render_template("access_request.html")


# ============================================================
# VERIFY ACCESS TOKEN
# ============================================================

@app.route("/verify_access", methods=["GET", "POST"])
def verify_access():
    if request.method == "POST":
        token = request.form.get("token", "").strip()
        info = access_tokens.get(token)

        if not info:
            return render_template("verify_access.html", error="Invalid Token")

        if info["revoked"]:
            return render_template("verify_access.html", error="Token Revoked")

        if info["expiry"] and time.time() > info["expiry"]:
            return render_template("verify_access.html", error="Token Expired")

        # Pass structured token + any file url/value
        return render_template(
            "verify_access.html",
            success=True,
            structured=info,
            value=info.get("value"),
            file_url=info.get("file_url"),
        )

    return render_template("verify_access.html")


# ============================================================
# TOKEN LIST & REVOCATION
# ============================================================

@app.route("/tokens")
def tokens():
    display = []

    for t, meta in access_tokens.items():
        if meta.get("expiry") is None:
            remaining = "Never"
        else:
            rem = int(meta["expiry"] - now_ts())
            remaining = f"{rem}s" if rem > 0 else "Expired"

        display.append({
            "token": t,
            "mode": meta.get("mode"),
            "field": meta.get("field"),
            "value": meta.get("value"),
            "issued": human_ts(meta.get("issued_at")),
            "expiry": human_ts(meta.get("expiry")) if meta.get("expiry") else "Never",
            "remaining": remaining,
            "revoked": meta.get("revoked", False),
            "revoked_at": human_ts(meta.get("revoked_at")) if meta.get("revoked_at") else "—",
        })

    return render_template("tokens.html", tokens=display, message=request.args.get("message"))


@app.route("/revoke_token", methods=["POST"])
def revoke_token():
    token = request.form.get("token")

    if not token or token not in access_tokens:
        return redirect(url_for("tokens", message="not_found"))

    access_tokens[token]["revoked"] = True
    access_tokens[token]["revoked_at"] = now_ts()

    return redirect(url_for("tokens", message="revoked"))


# ============================================================
# SHAMIR SECRET RECOVERY (UI)
# ============================================================

@app.route("/shamir/recover", methods=["GET", "POST"])
def shamir_recover():
    if request.method == "POST":
        raw = request.form.get("shares", "").strip()

        if raw == "":
            return render_template("shamir_recover.html", error="❌ No shares provided")

        shares = [line.strip() for line in raw.splitlines() if line.strip()]

        if len(shares) < 2:
            return render_template("shamir_recover.html", error="❌ Enter at least SHARE-1 and SHARE-2")

        try:
            secret_hex = recover_key_shares_demo(shares)
            return render_template("shamir_recover.html", recovered=True, secret_hex=secret_hex)
        except Exception as e:
            return render_template("shamir_recover.html", error=str(e))

    return render_template("shamir_recover.html")


# ============================================================
# VC SIGNING
# ============================================================

@app.route("/vc/sign", methods=["GET", "POST"])
def sign_vc():
    if request.method == "POST":
        did = request.form.get("did")
        vc = request.form.get("vc")

        if did not in registered_users:
            return render_template("vc_sign.html", error="DID not found")

        priv = registered_users[did]["private_key"]
        sig = fake_sign(priv, vc)

        return render_template(
            "vc_sign.html",
            signed=True,
            signature=sig,
            public_key=registered_users[did]["public_key"],
            vc=vc,
        )

    return render_template("vc_sign.html")


# ============================================================
# RUN SERVER
# ============================================================

if __name__ == "__main__":
    app.run(debug=True)
