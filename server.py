#!/usr/bin/env python3
# ============================================================================
#  Micro Meta Pro - License Server (Supabase edition) v2.0
#  ----------------------------------------------------------------------------
#  * Pure Python stdlib - NO pip install needed (uses urllib for Supabase REST)
#  * Data stored in Supabase (free cloud Postgres) - PERMANENT, never wiped,
#    even if the host (Render/Koyeb/etc) restarts.
#  * Admin panel at  /admin  (token protected).
#  * One key = one device: on first activation the key locks to that PC;
#    the SAME key on ANY OTHER PC returns BLOCKED.
#
#  Required environment variables (set them on Render):
#    SUPABASE_URL   e.g. https://abcd1234.supabase.co
#    SUPABASE_KEY   the service_role key (Settings -> API)
#    ADMIN_TOKEN    any long secret password you choose (for the admin panel)
#    PORT           auto-provided by Render (defaults to 8777 locally)
# ============================================================================
import json
import os
import re
import secrets
import smtplib
from email.mime.text import MIMEText
from datetime import date, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib import request as _rq, parse as _up, error as _er

SB_URL      = os.environ.get("SUPABASE_URL", "").rstrip("/")
SB_KEY      = os.environ.get("SUPABASE_KEY", "")
ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN", "") or secrets.token_urlsafe(24)
HOST        = os.environ.get("HOST", "0.0.0.0")
PORT        = int(os.environ.get("PORT", "8777"))


def _sb(method, table, query="", body=None, prefer=None):
    """Minimal Supabase REST (PostgREST) client over stdlib urllib."""
    url = SB_URL + "/rest/v1/" + table
    if query:
        url += "?" + query
    headers = {
        "apikey": SB_KEY,
        "Authorization": "Bearer " + SB_KEY,
        "Content-Type": "application/json",
    }
    if prefer:
        headers["Prefer"] = prefer
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = _rq.Request(url, data=data, headers=headers, method=method)
    try:
        with _rq.urlopen(req, timeout=12) as r:
            raw = r.read()
            return json.loads(raw) if raw else []
    except _er.HTTPError as e:
        try:
            return {"_error": e.code, "_body": e.read().decode("utf-8", "ignore")}
        except Exception:
            return {"_error": e.code}
    except Exception as e:
        return {"_error": 0, "_body": str(e)}


def _q(v):
    return _up.quote(str(v), safe="")


def get_license(key):
    rows = _sb("GET", "licenses", "key=eq." + _q(key) + "&select=*")
    if isinstance(rows, list) and rows:
        return rows[0]
    return None


def log_req(ip, action, key, device, result):
    try:
        _sb("POST", "logs", body={
            "ts": datetime.now().isoformat(timespec="seconds"),
            "ip": ip, "action": action, "key": key,
            "device": (device or "")[:20], "result": result,
        }, prefer="return=minimal")
    except Exception:
        pass


ALPHA = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"  # no confusing 0/O/1/I/L


def gen_key():
    for _ in range(20):
        k = "MMP-" + "-".join(
            "".join(secrets.choice(ALPHA) for _ in range(5)) for _ in range(3))
        if get_license(k) is None:
            return k
    return "MMP-" + "-".join(
        "".join(secrets.choice(ALPHA) for _ in range(5)) for _ in range(3))


def is_expired(rec):
    if (rec.get("type") or "").upper() != "MONTH":
        return False
    exp = (rec.get("expiry") or "").strip()
    if not exp:
        return False
    try:
        return date.fromisoformat(exp) < date.today()
    except Exception:
        return False


# -- Client API (called by the PC app) --------------------------------------

def api_info(key, ip):
    rec = get_license(key)
    if rec is None:
        log_req(ip, "info", key, "", "NOT_FOUND")
        return {"status": "NOT_FOUND"}
    st = (rec.get("status") or "").upper()
    if st == "ACTIVE" and is_expired(rec):
        st = "EXPIRED"
    log_req(ip, "info", key, "", st)
    return {"status": st, "type": rec.get("type"), "expiry": rec.get("expiry") or ""}


def api_bind(key, device, ip):
    rec = get_license(key)
    if rec is None:
        r = {"status": "INVALID"}
    elif (rec.get("status") or "").upper() in ("BLOCK", "DEACTIVE", "DISABLED"):
        r = {"status": "DEACTIVE"}
    elif is_expired(rec):
        r = {"status": "EXPIRED"}
    elif rec.get("device") and rec.get("device") != device:
        r = {"status": "BLOCKED"}          # <-- same key on another PC = BLOCKED
    else:
        _sb("PATCH", "licenses", "key=eq." + _q(key),
            body={"device": device, "activated": date.today().isoformat()},
            prefer="return=minimal")
        r = {"status": "BOUND"}
    log_req(ip, "bind", key, device, r["status"])
    return r


def api_check(key, device, ip):
    rec = get_license(key)
    if rec is None:
        log_req(ip, "check", key, device, "NOT_FOUND")
        return {"status": "NOT_FOUND"}
    st = (rec.get("status") or "").upper()
    if st == "ACTIVE" and is_expired(rec):
        st = "EXPIRED"
    # device mismatch guard (belt-and-suspenders with the app side)
    if st == "ACTIVE" and device and rec.get("device") and rec.get("device") != device:
        st = "BLOCK"
    log_req(ip, "check", key, device, st)
    return {"status": st, "expiry": rec.get("expiry") or "",
            "device": rec.get("device") or ""}


def get_notice():
    rows = _sb("GET", "notice", "select=message&id=eq.1")
    if isinstance(rows, list) and rows:
        return str(rows[0].get("message") or "")
    return ""


def api_notice():
    return {"status": "OK", "message": get_notice()}


def get_version():
    rows = _sb("GET", "appver", "select=version,url,notes,sha256,mandatory&id=eq.1")
    if isinstance(rows, list) and rows:
        r = rows[0]
        return {
            "version": str(r.get("version") or ""),
            "url": str(r.get("url") or ""),
            "notes": str(r.get("notes") or ""),
            "sha256": str(r.get("sha256") or ""),
            "mandatory": bool(r.get("mandatory")),
        }
    return {"version": "", "url": "", "notes": "", "sha256": "", "mandatory": False}


def api_version():
    v = get_version()
    return {"status": "OK", "version": v["version"], "url": v["url"],
            "notes": v["notes"], "sha256": v["sha256"], "mandatory": v["mandatory"]}


def api_trial(email, device, ip):
    if not device:
        return {"status": "INVALID"}
    rows = _sb("GET", "trials", "device=eq." + _q(device) + "&select=*")
    if isinstance(rows, list) and rows:
        rec = rows[0] if isinstance(rows[0], dict) else {}
        r = {"status": "ALREADY_REGISTERED",
             "email": rec.get("email") or "",
             "start": rec.get("start") or ""}
    else:
        _sb("POST", "trials", body={"device": device, "email": email,
            "start": date.today().isoformat()}, prefer="return=minimal")
        r = {"status": "OK"}
    log_req(ip, "trial", "", device, r["status"])
    return r



# -- Gmail verification + trial daily limit ----------------------------------

GMAIL_USER = os.environ.get("GMAIL_USER", "").strip().strip('"').strip("'")
# App passwords are shown by Google with spaces ("abcd efgh ijkl mnop") — remove them
GMAIL_PASS = os.environ.get("GMAIL_APP_PASSWORD", "").strip().strip('"').strip("'").replace(" ", "")
# HTTPS email webhook (Google Apps Script) — needed on Render FREE tier,
# where ALL outbound SMTP ports (25/465/587) are blocked ([Errno 101]).
EMAIL_WEBHOOK_URL = os.environ.get("EMAIL_WEBHOOK_URL", "").strip().strip('"').strip("'")
EMAIL_WEBHOOK_SECRET = os.environ.get("EMAIL_WEBHOOK_SECRET", "mmp-mail-4321").strip()
TRIAL_DAILY_LIMIT = int(os.environ.get("TRIAL_DAILY_LIMIT", "50"))
CODE_TTL_MIN = 15


def _send_via_webhook(to_email, code):
    """Send the code via Google Apps Script over HTTPS (port 443 — never blocked)."""
    body = json.dumps({
        "secret": EMAIL_WEBHOOK_SECRET,
        "to": to_email,
        "subject": "Micro Meta Pro - Verification Code: " + code,
        "body": ("Your Micro Meta Pro verification code is: " + code +
                 "\n\nThis code expires in " + str(CODE_TTL_MIN) + " minutes."
                 "\n\nIf you did not request this, you can ignore this email."),
    }).encode("utf-8")
    req = _rq.Request(EMAIL_WEBHOOK_URL, data=body,
                      headers={"Content-Type": "application/json"}, method="POST")
    with _rq.urlopen(req, timeout=30) as r:
        resp = r.read().decode("utf-8", "ignore").strip()
    if "OK" not in resp:
        raise RuntimeError("Webhook error: " + resp[:80])


def _send_gmail(to_email, code):
    if EMAIL_WEBHOOK_URL:
        _send_via_webhook(to_email, code)
        return
    msg = MIMEText(
        "Your Micro Meta Pro verification code is: " + code +
        "\n\nThis code expires in " + str(CODE_TTL_MIN) + " minutes."
        "\n\nIf you did not request this, you can ignore this email.")
    msg["Subject"] = "Micro Meta Pro - Verification Code: " + code
    msg["From"] = GMAIL_USER
    msg["To"] = to_email
    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465, timeout=20) as s:
            s.login(GMAIL_USER, GMAIL_PASS)
            s.sendmail(GMAIL_USER, [to_email], msg.as_string())
    except smtplib.SMTPAuthenticationError:
        raise  # wrong user/app password — no point retrying
    except Exception:
        # port 465 blocked/slow — retry with STARTTLS on 587
        with smtplib.SMTP("smtp.gmail.com", 587, timeout=20) as s:
            s.ehlo()
            s.starttls()
            s.login(GMAIL_USER, GMAIL_PASS)
            s.sendmail(GMAIL_USER, [to_email], msg.as_string())


def api_send_code(email, device, ip):
    email = (email or "").strip().lower()
    if not device:
        return {"status": "INVALID"}
    if not re.match(r"^[a-z0-9][a-z0-9._%+-]*@gmail\.com$", email):
        return {"status": "INVALID_EMAIL"}
    if not EMAIL_WEBHOOK_URL and (not GMAIL_USER or not GMAIL_PASS):
        return {"status": "EMAIL_NOT_CONFIGURED"}
    rows = _sb("GET", "trials", "device=eq." + _q(device) + "&select=*")
    if isinstance(rows, list) and rows:
        log_req(ip, "send_code", "", device, "ALREADY_REGISTERED")
        rec = rows[0] if isinstance(rows[0], dict) else {}
        return {"status": "ALREADY_REGISTERED",
                "email": rec.get("email") or "",
                "start": rec.get("start") or ""}
    code = "".join(secrets.choice("0123456789") for _ in range(6))
    _sb("DELETE", "email_codes", "device=eq." + _q(device), prefer="return=minimal")
    _sb("POST", "email_codes", body={
        "device": device, "email": email, "code": code,
        "created": datetime.now().isoformat(timespec="seconds"),
    }, prefer="return=minimal")
    try:
        _send_gmail(email, code)
    except Exception as e:
        log_req(ip, "send_code", str(e)[:60], device, "EMAIL_FAIL")
        return {"status": "EMAIL_FAIL", "message": str(e)[:180]}
    log_req(ip, "send_code", "", device, "CODE_SENT")
    return {"status": "CODE_SENT"}


def api_verify_code(email, device, code, ip):
    email = (email or "").strip().lower()
    code = (code or "").strip()
    if not device or not code:
        return {"status": "INVALID"}
    rows = _sb("GET", "email_codes", "device=eq." + _q(device) + "&select=*")
    if not (isinstance(rows, list) and rows):
        return {"status": "NO_CODE"}
    rec = rows[0]
    try:
        created = datetime.fromisoformat(rec.get("created") or "")
        expired = (datetime.now() - created) > timedelta(minutes=CODE_TTL_MIN)
    except Exception:
        expired = True
    if expired:
        _sb("DELETE", "email_codes", "device=eq." + _q(device), prefer="return=minimal")
        log_req(ip, "verify_code", "", device, "EXPIRED_CODE")
        return {"status": "EXPIRED_CODE"}
    if (rec.get("email") or "").lower() != email or (rec.get("code") or "") != code:
        log_req(ip, "verify_code", "", device, "BAD_CODE")
        return {"status": "BAD_CODE"}
    _sb("DELETE", "email_codes", "device=eq." + _q(device), prefer="return=minimal")
    return api_trial(email, device, ip)


def api_trial_use(device, ip):
    if not device:
        return {"status": "INVALID"}
    rows = _sb("GET", "trials", "device=eq." + _q(device) + "&select=*")
    if not (isinstance(rows, list) and rows):
        return {"status": "NOT_FOUND"}
    rec = rows[0]
    today = date.today().isoformat()
    used = 0
    if (rec.get("used_date") or "") == today:
        try:
            used = int(rec.get("used_count") or 0)
        except (TypeError, ValueError):
            used = 0
    used += 1
    _sb("PATCH", "trials", "device=eq." + _q(device),
        body={"used_date": today, "used_count": used}, prefer="return=minimal")
    if used > TRIAL_DAILY_LIMIT:
        if used == TRIAL_DAILY_LIMIT + 1:
            log_req(ip, "trial_use", "", device, "LIMIT")
        return {"status": "LIMIT", "used": used, "limit": TRIAL_DAILY_LIMIT}
    return {"status": "OK", "used": used, "limit": TRIAL_DAILY_LIMIT}


def handle_api(data, ip):
    action = str(data.get("action", "")).strip().lower()
    key    = str(data.get("key", "")).strip().upper()
    device = str(data.get("device", "")).strip()
    if action == "info":
        return api_info(key, ip)
    if action == "check":
        return api_check(key, device, ip)
    if action == "register_trial":
        return api_trial(str(data.get("email", "")).strip(), device, ip)
    if action == "send_code":
        return api_send_code(str(data.get("email", "")).strip(), device, ip)
    if action == "verify_code":
        return api_verify_code(str(data.get("email", "")).strip(), device,
                               str(data.get("code", "")).strip(), ip)
    if action == "trial_use":
        return api_trial_use(device, ip)
    if action == "notice":
        return api_notice()
    if action == "version":
        return api_version()
    if key and device:
        return api_bind(key, device, ip)
    return {"status": "INVALID"}


# -- Admin API --------------------------------------------------------------

def handle_admin(data):
    op = str(data.get("op", "")).strip().lower()

    if op == "add":
        key = str(data.get("key") or gen_key()).strip().upper()
        typ = "MONTH" if str(data.get("type", "LIFE")).upper() == "MONTH" else "LIFE"
        try:
            days = int(data.get("days") or 30)
        except (TypeError, ValueError):
            days = 30
        expiry = (date.today() + timedelta(days=days)).isoformat() if typ == "MONTH" else ""
        if get_license(key) is not None:
            return {"ok": False, "error": "Key already exists"}
        res = _sb("POST", "licenses", body={
            "key": key, "type": typ, "status": "ACTIVE", "expiry": expiry,
            "device": "", "customer": str(data.get("customer", "")),
            "phone": str(data.get("phone", "")), "email": str(data.get("email", "")),
            "payment": str(data.get("payment", "")), "note": str(data.get("note", "")),
            "created": date.today().isoformat(), "activated": "",
        }, prefer="return=minimal")
        if isinstance(res, dict) and res.get("_error"):
            return {"ok": False, "error": "DB error: " + str(res.get("_body", res["_error"]))[:180]}
        return {"ok": True, "key": key, "type": typ, "expiry": expiry}

    if op in ("block", "unblock", "delete", "reset_device", "set_expiry", "renew"):
        key = str(data.get("key", "")).strip().upper()
        rec = get_license(key)
        if rec is None:
            return {"ok": False, "error": "Key not found"}
        if op == "block":
            _sb("PATCH", "licenses", "key=eq." + _q(key), body={"status": "BLOCK"}, prefer="return=minimal")
        elif op == "unblock":
            _sb("PATCH", "licenses", "key=eq." + _q(key), body={"status": "ACTIVE"}, prefer="return=minimal")
        elif op == "delete":
            _sb("DELETE", "licenses", "key=eq." + _q(key), prefer="return=minimal")
        elif op == "reset_device":
            _sb("PATCH", "licenses", "key=eq." + _q(key), body={"device": ""}, prefer="return=minimal")
        elif op in ("set_expiry", "renew"):
            if op == "renew":
                base_s = (rec.get("expiry") or "").strip()
                try:
                    base_d = max(date.fromisoformat(base_s), date.today())
                except Exception:
                    base_d = date.today()
                try:
                    days = int(data.get("days") or 30)
                except (TypeError, ValueError):
                    days = 30
                new_exp = (base_d + timedelta(days=days)).isoformat()
            else:
                new_exp = str(data.get("expiry", "")).strip()
            _sb("PATCH", "licenses", "key=eq." + _q(key),
                body={"expiry": new_exp, "status": "ACTIVE"}, prefer="return=minimal")
        return {"ok": True}

    if op == "set_notice":
        msg = str(data.get("message", "")).strip()
        _sb("PATCH", "notice", "id=eq.1", body={"message": msg,
            "updated": date.today().isoformat()}, prefer="return=minimal")
        return {"ok": True}

    if op == "get_notice":
        return {"ok": True, "message": get_notice()}

    if op == "set_version":
        _sb("PATCH", "appver", "id=eq.1", body={
            "version": str(data.get("version", "")).strip(),
            "url": str(data.get("url", "")).strip(),
            "notes": str(data.get("notes", "")).strip(),
            "sha256": str(data.get("sha256", "")).strip().lower(),
            "mandatory": bool(data.get("mandatory", False))}, prefer="return=minimal")
        return {"ok": True}

    if op == "get_version":
        v = get_version()
        return {"ok": True, "version": v["version"], "url": v["url"],
                "notes": v["notes"], "sha256": v["sha256"], "mandatory": v["mandatory"]}

    if op == "list":
        rows = _sb("GET", "licenses", "select=*&order=created.desc,key.asc")
        return {"ok": True, "licenses": rows if isinstance(rows, list) else []}

    if op == "trials":
        rows = _sb("GET", "trials", "select=*&order=start.desc&limit=500")
        return {"ok": True, "trials": rows if isinstance(rows, list) else []}

    if op == "logs":
        rows = _sb("GET", "logs", "select=*&order=id.desc&limit=200")
        return {"ok": True, "logs": rows if isinstance(rows, list) else []}

    if op == "stats":
        rows = _sb("GET", "licenses", "select=status,device")
        rows = rows if isinstance(rows, list) else []
        lic = len(rows)
        act = sum(1 for x in rows if (x.get("status") or "").upper() == "ACTIVE")
        dev = sum(1 for x in rows if x.get("device"))
        tr = _sb("GET", "trials", "select=device")
        tri = len(tr) if isinstance(tr, list) else 0
        return {"ok": True, "licenses": lic, "active": act,
                "activated_devices": dev, "trials": tri}

    return {"ok": False, "error": "Unknown op"}


# -- Admin panel HTML -------------------------------------------------------

ADMIN_HTML = """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Micro Meta Pro — License Admin</title>
<style>
:root{--bg:#0b0d10;--card:#14171c;--card2:#1b1f26;--border:#262b33;
--green:#22c55e;--red:#ef4444;--orange:#f59e0b;--blue:#3b82f6;--mut:#8b939e}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:#e5e7eb;font:14px/1.5 system-ui,Segoe UI,sans-serif;padding:24px}
h1{font-size:20px;margin-bottom:4px}
.sub{color:var(--mut);font-size:12px;margin-bottom:20px}
.card{background:var(--card);border:1px solid var(--border);border-radius:10px;padding:16px;margin-bottom:16px}
.card h2{font-size:14px;margin-bottom:12px;color:#fff}
input,select{background:var(--card2);border:1px solid var(--border);color:#e5e7eb;
border-radius:6px;padding:8px 10px;font-size:13px;outline:none}
input:focus{border-color:var(--green)}
button{background:var(--green);color:#04110a;border:0;border-radius:6px;
padding:8px 14px;font-size:13px;font-weight:600;cursor:pointer}
button.mini{padding:3px 8px;font-size:11px;margin-left:4px}
button.red{background:var(--red);color:#fff}button.blue{background:var(--blue);color:#fff}
button.gray{background:var(--card2);color:#e5e7eb;border:1px solid var(--border)}
.row{display:flex;gap:8px;flex-wrap:wrap;align-items:center}
table{width:100%;border-collapse:collapse;font-size:12px}
th,td{padding:7px 8px;border-bottom:1px solid var(--border);text-align:left;white-space:nowrap}
th{color:var(--mut);font-weight:600}
.badge{padding:2px 8px;border-radius:20px;font-size:11px;font-weight:700}
.b-ACTIVE{background:#0c2a18;color:var(--green)}.b-BLOCK{background:#2a0c0c;color:var(--red)}
.b-EXPIRED{background:#2a1f0c;color:var(--orange)}
.stat{display:inline-block;background:var(--card2);border:1px solid var(--border);
border-radius:8px;padding:10px 18px;margin-right:10px;text-align:center}
.stat b{display:block;font-size:20px;color:var(--green)}
.key{font-family:Consolas,monospace;color:#7dd3fc}
#msg{margin:8px 0;font-size:13px;min-height:18px}
.ok{color:var(--green)}.err{color:var(--red)}
.tablewrap{overflow-x:auto}
</style></head><body>
<h1>🔐 Micro Meta Pro — License Admin</h1>
<div class="sub">Self-hosted license server • bKash/Nagad manual sales • Supabase cloud DB (permanent &amp; private)</div>
<div class="card"><h2>Admin Token</h2>
<div class="row"><input id="token" type="password" placeholder="Admin token (config.json)" size="40">
<button onclick="saveToken()">Connect</button></div></div>
<div id="panel" style="display:none">
<div class="card" id="stats"></div>
<div class="card"><h2>➕ Add License (after bKash/Nagad payment)</h2>
<div class="row">
<input id="a_customer" placeholder="Customer name">
<input id="a_phone" placeholder="Phone / bKash no">
<input id="a_payment" placeholder="TrxID (bKash/Nagad)">
<select id="a_type"><option value="LIFE">Lifetime</option><option value="MONTH">Monthly</option></select>
<input id="a_days" type="number" value="30" style="width:70px" title="days (monthly)">
<button onclick="addLic()">Generate Key</button></div>
<div id="msg"></div></div>
<div class="card"><h2>📢 Notice to All Users</h2>
<div class="row"><input id="n_msg" placeholder="Message shown as popup in every user's app…" size="60">
<button onclick="setNotice()">Send Notice</button>
<button class="red" onclick="clearNotice()">Clear</button></div>
<div id="n_cur" class="sub" style="margin-top:8px"></div></div>
<div class="card"><h2>🚀 App Update (Auto-Update)</h2>
<div class="row"><input id="v_ver" placeholder="Latest version e.g. 4.7.2" size="16">
<input id="v_url" placeholder="Setup.exe direct download URL…" size="50"></div>
<div class="row" style="margin-top:8px"><input id="v_sha" placeholder="SHA256 checksum (optional)" size="64"></div>
<div class="row" style="margin-top:8px"><label style="display:flex;align-items:center;gap:6px;color:#e5e7eb;font-size:13px"><input type="checkbox" id="v_mand" style="width:auto;margin:0"> ⚠️ Mandatory update (users cannot skip)</label></div>
<textarea id="v_notes" placeholder="Release notes / what's new (optional)…" style="width:100%;min-height:70px;margin-top:8px;background:var(--card2);border:1px solid var(--border);color:#e5e7eb;border-radius:6px;padding:8px 10px;font-size:13px;outline:none;font-family:inherit"></textarea>
<div class="row" style="margin-top:8px"><button onclick="setVer()">Save</button></div>
<div id="v_cur" class="sub" style="margin-top:8px"></div></div>
<div class="card"><h2>📜 Licenses <button class="mini gray" onclick="refresh()">↻ Refresh</button></h2>
<div class="row" style="margin-bottom:8px"><input id="search" placeholder="Search…" oninput="render()" size="30"></div>
<div class="tablewrap"><table id="tbl"></table></div></div>
<div class="card"><h2>⏳ Trials</h2><div class="tablewrap"><table id="trials"></table></div></div>
<div class="card"><h2>📄 Recent Activity</h2><div class="tablewrap"><table id="logs"></table></div></div>
</div>
<script>
let LICS=[];
const tok=()=>localStorage.getItem("mmp_token")||"";
const val=i=>document.getElementById(i).value;
function saveToken(){localStorage.setItem("mmp_token",document.getElementById("token").value.trim());refresh();}
async function api(body){body.token=tok();
const r=await fetch("/admin/api",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(body)});
return r.json();}
function esc(s){return String(s??"").replace(/[&<>"]/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));}
async function refresh(){
const st=await api({op:"stats"});
if(!st.ok){document.getElementById("panel").style.display="none";alert(st.error||"Invalid token");return;}
document.getElementById("panel").style.display="";
document.getElementById("stats").innerHTML=
`<span class="stat"><b>${st.licenses}</b>Total Keys</span>`+
`<span class="stat"><b>${st.active}</b>Active</span>`+
`<span class="stat"><b>${st.activated_devices}</b>Devices</span>`+
`<span class="stat"><b>${st.trials}</b>Trials</span>`;
const l=await api({op:"list"});LICS=l.licenses||[];render();
const t=await api({op:"trials"});
document.getElementById("trials").innerHTML="<tr><th>Device</th><th>Email</th><th>Start</th></tr>"+
(t.trials||[]).map(x=>`<tr><td class="key">${esc(x.device.slice(0,18))}…</td><td>${esc(x.email)}</td><td>${esc(x.start)}</td></tr>`).join("");
const g=await api({op:"logs"});
document.getElementById("logs").innerHTML="<tr><th>Time</th><th>IP</th><th>Action</th><th>Key</th><th>Result</th></tr>"+
(g.logs||[]).map(x=>`<tr><td>${esc(x.ts)}</td><td>${esc(x.ip)}</td><td>${esc(x.action)}</td><td class="key">${esc(x.key)}</td><td>${esc(x.result)}</td></tr>`).join("");
loadNotice();
loadVer();
}
async function loadNotice(){const r=await api({op:"get_notice"});
document.getElementById("n_msg").value=r.message||"";
document.getElementById("n_cur").textContent=r.message?("📢 Active notice: "+r.message):"No active notice";}
async function setNotice(){const r=await api({op:"set_notice",message:val("n_msg")});
if(r.ok){alert("Notice sent to all users ✅");loadNotice();}else alert(r.error||"failed");}
async function clearNotice(){const r=await api({op:"set_notice",message:""});
if(r.ok){alert("Notice cleared");loadNotice();}else alert(r.error||"failed");}
async function loadVer(){const r=await api({op:"get_version"});
document.getElementById("v_ver").value=r.version||"";
document.getElementById("v_url").value=r.url||"";
document.getElementById("v_sha").value=r.sha256||"";
document.getElementById("v_notes").value=r.notes||"";
document.getElementById("v_mand").checked=!!r.mandatory;
document.getElementById("v_cur").textContent=r.version?("🚀 Users are told latest version is: "+r.version+(r.mandatory?" ⚠️ (mandatory)":"")):"No version set — auto-update off";}
async function setVer(){const r=await api({op:"set_version",version:val("v_ver"),url:val("v_url"),sha256:val("v_sha"),notes:val("v_notes"),mandatory:document.getElementById("v_mand").checked});
if(r.ok){alert("Version info saved ✅ Users will get the update popup.");loadVer();}else alert(r.error||"failed");}
function render(){
const q=(document.getElementById("search").value||"").toLowerCase();
const rows=LICS.filter(x=>JSON.stringify(x).toLowerCase().includes(q));
document.getElementById("tbl").innerHTML=
"<tr><th>Key</th><th>Customer</th><th>Phone</th><th>TrxID</th><th>Type</th><th>Status</th><th>Expiry</th><th>Device</th><th>Actions</th></tr>"+
rows.map(x=>`<tr><td class="key">${esc(x.key)}</td><td>${esc(x.customer)}</td><td>${esc(x.phone)}</td>
<td>${esc(x.payment)}</td><td>${esc(x.type)}</td>
<td><span class="badge b-${esc(x.status)}">${esc(x.status)}</span></td>
<td>${esc(x.expiry)||"—"}</td><td>${x.device?esc(x.device.slice(0,10))+"…":"—"}</td>
<td>${x.status==="ACTIVE"
?`<button class="mini red" onclick="op('block','${x.key}')">Block</button>`
:`<button class="mini" onclick="op('unblock','${x.key}')">Unblock</button>`}
<button class="mini blue" onclick="op('reset_device','${x.key}')">Reset Device</button>
${x.type==="MONTH"?`<button class="mini gray" onclick="op('renew','${x.key}')">+30d</button>`:""}
<button class="mini gray" onclick="if(confirm('Delete '+'${x.key}'+'?'))op('delete','${x.key}')">✕</button>
</td></tr>`).join("");
}
async function op(o,k){const r=await api({op:o,key:k});if(!r.ok)alert(r.error||"failed");refresh();}
async function addLic(){
const r=await api({op:"add",customer:val("a_customer"),phone:val("a_phone"),
payment:val("a_payment"),type:val("a_type"),days:val("a_days")});
const m=document.getElementById("msg");
if(r.ok){m.className="ok";m.innerHTML=`✅ Key created: <span class="key">${r.key}</span>`+
`${r.expiry?" (expires "+r.expiry+")":" (lifetime)"} — copy & send to customer`;
["a_customer","a_phone","a_payment"].forEach(i=>document.getElementById(i).value="");refresh();}
else{m.className="err";m.textContent="❌ "+(r.error||"failed");}}
if(tok()){document.getElementById("token").value=tok();refresh();}
</script></body></html>"""


# -- HTTP server ------------------------------------------------------------

class Handler(BaseHTTPRequestHandler):
    server_version = "MMPLicense/2.0"

    def log_message(self, *args):
        pass

    def _send(self, code, body, ctype="application/json"):
        if isinstance(body, (dict, list)):
            out = json.dumps(body).encode("utf-8")
        elif isinstance(body, str):
            out = body.encode("utf-8")
        else:
            out = body
        self.send_response(code)
        self.send_header("Content-Type", ctype + "; charset=utf-8")
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        try:
            self.wfile.write(out)
        except Exception:
            pass

    def do_GET(self):
        path = self.path.split("?")[0].rstrip("/") or "/"
        if path in ("/", "/admin"):
            self._send(200, ADMIN_HTML, "text/html")
        elif path in ("/api", "/healthz"):
            self._send(200, {"status": "OK", "server": "MMP License Server v2"})
        else:
            self._send(404, {"status": "NOT_FOUND"})

    def do_POST(self):
        try:
            length = int(self.headers.get("Content-Length") or 0)
            data = json.loads(self.rfile.read(length) or b"{}")
            if not isinstance(data, dict):
                data = {}
        except Exception:
            data = {}
        ip = self.headers.get("X-Forwarded-For", self.client_address[0]).split(",")[0].strip()
        path = self.path.split("?")[0].rstrip("/") or "/"
        if path in ("/", "/api", "/exec"):
            self._send(200, handle_api(data, ip))
        elif path == "/admin/api":
            if not secrets.compare_digest(str(data.get("token", "")), str(ADMIN_TOKEN)):
                self._send(403, {"ok": False, "error": "Invalid admin token"})
                return
            self._send(200, handle_admin(data))
        else:
            self._send(404, {"status": "NOT_FOUND"})


def main():
    print("=" * 62)
    print("  Micro Meta Pro - License Server v2.0 (Supabase)")
    print("  Listening   : http://%s:%s" % (HOST, PORT))
    print("  Admin UI    : /admin")
    print("  Supabase    : %s" % (SB_URL or "(SUPABASE_URL not set!)"))
    print("  Admin token : %s" % ADMIN_TOKEN)
    if not SB_URL or not SB_KEY:
        print("  WARNING: set SUPABASE_URL and SUPABASE_KEY env vars!")
    print("=" * 62)
    ThreadingHTTPServer((HOST, PORT), Handler).serve_forever()


if __name__ == "__main__":
    main()
