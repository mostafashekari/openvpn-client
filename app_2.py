from flask import Flask, send_file, render_template, redirect, url_for, abort, request, Response
import subprocess
import os
import time
import re
import shutil
import pathlib
import hashlib
import traceback
import glob
from functools import wraps

app = Flask(__name__)

# ========== تنظیمات احراز هویت ==========
USERNAME = "mo"         # ← این‌جا نام‌کاربری خودت را بگذار
PASSWORD = "mo"        # ← این‌جا رمز عبور دلخواهت را بگذار

def check_auth(u, p):
    return u == USERNAME and p == PASSWORD

def authenticate():
    return Response(
        'دسترسی نیاز به احراز هویت دارد.', 401,
        {'WWW-Authenticate': 'Basic realm="Login Required"'}
    )

def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth or not check_auth(auth.username, auth.password):
            return authenticate()
        return f(*args, **kwargs)
    return decorated


# ========== ثابت‌ها ==========
BASE_DIR     = "/root"
EASY_RSA_DIR = "/etc/openvpn/easy-rsa"
PKI_DIR      = os.path.join(EASY_RSA_DIR, "pki")
STATUS_LOG   = "/etc/openvpn/openvpn-status.log"
PKI_INDEX    = os.path.join(PKI_DIR, "index.txt")

LOG_PATH     = "/tmp/ovpn_delete.log"
CRL_SRC      = os.path.join(PKI_DIR, "crl.pem")
CRL_DEST     = "/etc/openvpn/crl.pem"

VALID_NAME = re.compile(r"^[a-zA-Z0-9_-]+$")


# ========== ابزار کمکی ====================================================
def _sha256(path, n=16):
    h = hashlib.sha256()
    with open(path, "rb") as fp:
        for blk in iter(lambda: fp.read(8192), b""):
            h.update(blk)
    return h.hexdigest()[:n]

def easyrsa_cmd(*cmd):
    env = os.environ.copy()
    env["EASYRSA_BATCH"] = "1"
    env["EASYRSA_PKI"]   = PKI_DIR
    subprocess.run([os.path.join(EASY_RSA_DIR, "easyrsa"), *cmd],
                   cwd=EASY_RSA_DIR, env=env, check=True)

def check_and_init_pki():
    if not os.path.exists(PKI_DIR):
        easyrsa_cmd("init-pki")

def secure_name(name: str) -> str:
    if not VALID_NAME.fullmatch(name):
        abort(404)
    return name

def get_connected_clients() -> set[str]:
    if not os.path.exists(STATUS_LOG):
        return set()
    clients, cap = set(), False
    with open(STATUS_LOG) as f:
        for line in f:
            if line.startswith("CLIENT_LIST"):
                cap = True; continue
            if line.startswith("ROUTING_TABLE"):
                break
            if cap:
                clients.add(line.split(",")[0])
    return clients

def get_creation_time(path: str) -> float:
    return os.path.getctime(path)

def _extract_numbers(names: set[str]) -> list[int]:
    return [int(n[7:]) for n in names if n.startswith("client_") and n[7:].isdigit()]

def _clients_from_index() -> set[str]:
    names = set()
    if os.path.exists(PKI_INDEX):
        with open(PKI_INDEX) as f:
            for line in f:
                parts = line.strip().split("\t")
                if len(parts) < 6:
                    continue
                cn = parts[5]
                if cn.startswith("/CN="): cn = cn[4:]
                elif cn.startswith("CN="): cn = cn[3:]
                names.add(cn.lstrip("/"))
    return names

def get_next_client_number() -> int:
    used = {f[:-5] for f in os.listdir(BASE_DIR)
            if f.startswith("client_") and f.endswith(".ovpn")}
    used |= _clients_from_index()
    nums = set(_extract_numbers(used))
    n = 1
    while n in nums:
        n += 1
    return n


# ========== عملیات کلاینت‌ها ================================================
def create_client(name: str):
    script = f"""#!/bin/bash
cd {BASE_DIR}
./openvpn-install.sh <<EOF
1
{name}
1
EOF
"""
    path = os.path.join(BASE_DIR, "auto_create.sh")
    with open(path, "w") as f:
        f.write(script)
    os.chmod(path, 0o700)
    subprocess.run(["bash", path], check=True)

def delete_client(name: str):
    try:
        with open(LOG_PATH, "w") as log:
            # 1) استخراج سریال
            crt = os.path.join(PKI_DIR, "issued", f"{name}.crt")
            if not os.path.exists(crt):
                raise FileNotFoundError(f"CRT پیدا نشد: {crt}")
            serial = subprocess.check_output(
                ["openssl","x509","-in",crt,"-noout","-serial"], text=True
            ).strip().split("=",1)[1]
            log.write(f"serial={serial}\n")

            # 2) revoke + gen-crl
            easyrsa_cmd("revoke", name)
            easyrsa_cmd("gen-crl")

            # 3) کپی CRL
            os.makedirs(os.path.dirname(CRL_DEST), exist_ok=True)
            shutil.copy2(CRL_SRC, CRL_DEST)
            os.chmod(CRL_DEST, 0o644)
            log.write(f"CRL sha={_sha256(CRL_SRC)}\n")

            # 4) ری‌استارت OpenVPN
            subprocess.run(["systemctl","restart","openvpn@server"], check=True)

            # 5) حذف فایل‌ها
            for p in (os.path.join(BASE_DIR,f"{name}.ovpn"), crt,
                      os.path.join(PKI_DIR,"private",f"{name}.key")):
                if os.path.exists(p):
                    os.remove(p)

    except Exception:
        with open(LOG_PATH, "a") as log:
            log.write(traceback.format_exc())


# ========== روت‌های محافظت‌شده ============================================
@app.route("/")
@requires_auth
def index():
    connected = get_connected_clients()
    clients = []
    for f in os.listdir(BASE_DIR):
        if f.startswith("client_") and f.endswith(".ovpn"):
            name = f[:-5]
            ts   = get_creation_time(os.path.join(BASE_DIR, f))
            clients.append({
                "name": name,
                "created_ts": ts,
                "created": time.strftime("%Y-%m-%d %H:%M", time.localtime(ts)),
            })
    clients.sort(key=lambda c: c["created_ts"], reverse=True)
    return render_template("index.html", clients=clients)

@app.route("/new-client")
@requires_auth
def new_client():
    try:
        check_and_init_pki()
        name = f"client_{get_next_client_number()}"
        create_client(name)
        return redirect(url_for("index"))
    except Exception as e:
        return f"خطا در ساخت کلاینت: {e}", 500

@app.route("/download/<name>")
@requires_auth
def download_client(name):
    name = secure_name(name)
    path = os.path.join(BASE_DIR, f"{name}.ovpn")
    if os.path.exists(path):
        return send_file(path, as_attachment=True)
    return "فایل وجود ندارد", 404

@app.route("/delete-client/<name>")
@requires_auth
def delete_client_route(name):
    name = secure_name(name)
    delete_client(name)
    return redirect(url_for("index"))

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
