from flask import Flask, send_file, render_template, redirect, url_for, abort
import subprocess
import os
import time
import re
import shutil
import pathlib
import hashlib
import traceback
import glob

app = Flask(__name__)

# ========== ثابت‌ها ==========
BASE_DIR     = "/root"                                  # محل نگه‌داری فایل‌های .ovpn
EASY_RSA_DIR = "/etc/openvpn/easy-rsa"                  # محل نصب Easy‑RSA
PKI_DIR      = os.path.join(EASY_RSA_DIR, "pki")
STATUS_LOG   = "/etc/openvpn/openvpn-status.log"        # لاگ وضعیت سرور OpenVPN
PKI_INDEX    = os.path.join(PKI_DIR, "index.txt")

LOG_PATH     = "/tmp/ovpn_delete.log"
CRL_SRC      = os.path.join(PKI_DIR, "crl.pem")
CRL_DEST     = "/etc/openvpn/crl.pem"                   # مسیر ثابت که server.conf از آن استفاده می‌کند

VALID_NAME = re.compile(r"^[a-zA-Z0-9_-]+$")

# ========== ابزار کمکی -------------------------------------------------

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
    clients, capture = set(), False
    with open(STATUS_LOG) as f:
        for line in f:
            if line.startswith("CLIENT_LIST"):
                capture = True; continue
            if line.startswith("ROUTING_TABLE"):
                break
            if capture:
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
    used = set(
        f[:-5] for f in os.listdir(BASE_DIR)
        if f.startswith("client_") and f.endswith(".ovpn")
    )
    used |= _clients_from_index()
    nums = set(_extract_numbers(used))
    n = 1
    while n in nums:
        n += 1
    return n

# ========== عملیات کلاینت‌ها =============================================

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
        print(f"\n=== 🔴 حذف کلاینت «{name}» ===")

        # آماده‌سازی لاگ
        with open(LOG_PATH, "w") as log:

            # 1) استخراج سریال از crt پیش از revoke
            crt_path = os.path.join(PKI_DIR, "issued", f"{name}.crt")
            log.write(f">> چک CRT: {crt_path}\n")
            if not os.path.exists(crt_path):
                raise FileNotFoundError(f"CRT پیدا نشد: {crt_path}")
            serial = subprocess.check_output(
                ["openssl", "x509", "-in", crt_path, "-noout", "-serial"],
                text=True
            ).strip().split("=",1)[1]
            log.write(f"<< سریال استخراج شد: {serial}\n")
            print(f"📌 سریال: {serial}")

            # 2) revoke
            log.write(">> easyrsa revoke\n")
            easyrsa_cmd("revoke", name)
            log.write("<< revoke OK\n")
            print("✅ revoke ثبت شد")

            # 3) gen-crl
            log.write(">> easyrsa gen-crl\n")
            easyrsa_cmd("gen-crl")
            if not os.path.exists(CRL_SRC):
                raise RuntimeError("CRL تولید نشد!")
            sha = _sha256(CRL_SRC)
            log.write(f"<< gen-crl OK sha={sha}\n")
            print(f"📄 CRL جدید sha={sha}")

            # 4) کپی CRL فقط به مسیرِ /etc/openvpn/crl.pem
            log.write(f">> کپی CRL به {CRL_DEST}\n")
            pathlib.Path(CRL_DEST).parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(CRL_SRC, CRL_DEST)
            os.chmod(CRL_DEST, 0o644)
            dest_sha = _sha256(CRL_DEST)
            log.write(f"<< copied sha={dest_sha}\n")
            print(f"   ↪ {CRL_DEST} | sha={dest_sha}")

            # 5) ری‌استارت سرویس openvpn@server
            log.write(">> systemctl restart openvpn@server\n")
            subprocess.run(["systemctl","restart","openvpn@server"], check=True)
            log.write("<< restart OK\n")
            print("🔄 سرویس openvpn@server ری‌استارت شد")

            # 6) چک سریال در CRL
            with open(CRL_SRC) as f:
                crl_text = f.read()
            ok = serial.lower() in crl_text.lower()
            log.write(f"<< serial {'FOUND' if ok else 'NOT found'}\n")
            print(f"🔒 سریال در CRL {'هست' if ok else 'نیست!'}")

            # 7) حذف فایل‌های محلی
            for p in (
                os.path.join(BASE_DIR, f"{name}.ovpn"),
                crt_path,
                os.path.join(PKI_DIR, "private", f"{name}.key")
            ):
                if os.path.exists(p):
                    os.remove(p)
                    log.write(f"<< removed {p}\n")
                    print(f"🗑 حذف شد: {p}")

            log.write("=== پایان عملیات ===\n")

        print(f"🟢 کلاینت «{name}» حذف شد؛ گزارش در {LOG_PATH}")

    except Exception:
        print("❌ خطا:\n", traceback.format_exc())
        raise

# ========== روت‌ها ========================================================

@app.route("/")
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
                "status": "متصل" if name in connected else "غیرفعال"
            })
    clients.sort(key=lambda c: c["created_ts"], reverse=True)
    return render_template("index.html", clients=clients)

@app.route("/new-client")
def new_client():
    try:
        check_and_init_pki()
        name = f"client_{get_next_client_number()}"
        create_client(name)
        return redirect(url_for("index"))
    except Exception as e:
        return f"خطا در ساخت کلاینت: {e}", 500

@app.route("/download/<name>")
def download_client(name):
    name = secure_name(name)
    path = os.path.join(BASE_DIR, f"{name}.ovpn")
    if os.path.exists(path):
        return send_file(path, as_attachment=True)
    return "فایل وجود ندارد", 404

@app.route("/delete-client/<name>")
def delete_client_route(name):
    name = secure_name(name)
    try:
        delete_client(name)
        return redirect(url_for("index"))
    except Exception as e:
        return f"خطا در حذف کلاینت: {e}", 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
