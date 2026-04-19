import re
import time
import functools
import logging

from flask import Flask, render_template, jsonify, request, Response
from log_analyzer import get_all_honeypot_data
import pandas as pd
import yaml

app = Flask(__name__)
logger = logging.getLogger("MAIN")

try:
    with open("config.yaml", "r") as f:
        _config = yaml.safe_load(f)
except FileNotFoundError:
    _config = {}

_DASHBOARD_USER = _config.get("dashboard", {}).get("username", "admin")
_DASHBOARD_PASS = _config.get("dashboard", {}).get("password", "changeme")

_cache: dict = {"data": None, "ts": 0}
CACHE_TTL = 30


def get_cached_data():
    now = time.time()
    if _cache["data"] is None or (now - _cache["ts"]) > CACHE_TTL:
        _cache["data"] = get_all_honeypot_data()
        _cache["ts"] = now
    return _cache["data"]


def check_auth(username: str, password: str) -> bool:
    return username == _DASHBOARD_USER and password == _DASHBOARD_PASS


def require_auth(f):
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth or not check_auth(auth.username, auth.password):
            return Response(
                "Unauthorized. Please provide valid credentials.",
                401,
                {"WWW-Authenticate": 'Basic realm="Honeypot Dashboard"'},
            )
        return f(*args, **kwargs)

    return decorated


_IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def is_valid_ip(ip: str) -> bool:
    if not _IP_RE.match(ip):
        return False
    return all(0 <= int(p) <= 255 for p in ip.split("."))


@app.route("/")
@require_auth
def dashboard():
    return render_template("dashboard.html")


@app.route("/api/data")
@require_auth
def api_data():
    df = get_cached_data()

    if df.empty:
        return jsonify({
            "total_events": 0,
            "ioc_count": 0,
            "traffic_by_service": {},
            "top_mitre": {},
            "top_ips": {},
            "attack_timeline": {},
            "last_attack": None,
        })

    total_events = len(df)
    ioc_count = int(df["is_ioc"].sum())

    traffic_by_service = df.groupby("service")["event"].count().to_dict()

    top_ips = df["ip_address"].value_counts().head(10).to_dict()

    mitre_list = [tech for sublist in df["mitre"] if sublist for tech in sublist]
    top_mitre = pd.Series(mitre_list).value_counts().head(5).to_dict()

    df["timestamp"] = pd.to_datetime(
        df["timestamp"], format="%Y-%m-%d %H:%M:%S,%f", errors="coerce"
    )

    full_hours = {f"{h:02d}:00": 0 for h in range(24)}
    attack_counts = (
        df[df["is_ioc"]]
        .set_index("timestamp")
        .resample("1H")
        .size()
        .to_dict()
    )
    for k, v in attack_counts.items():
        full_hours[k.strftime("%H:00")] = v

    last_attack_data = None
    ioc_df = df[df["is_ioc"]].sort_values(by="timestamp", ascending=False)
    if not ioc_df.empty:
        last_ioc = ioc_df.iloc[0]
        last_attack_data = {
            "timestamp": last_ioc["timestamp"].strftime("%Y-%m-%d %H:%M:%S"),
            "service": last_ioc["service"],
            "event": last_ioc["full_message"].split(" - Detected MITRE")[0].strip(),
            "mitre": last_ioc["mitre"],
        }

    return jsonify({
        "total_events": total_events,
        "ioc_count": ioc_count,
        "traffic_by_service": traffic_by_service,
        "top_mitre": top_mitre,
        "top_ips": top_ips,
        "attack_timeline": full_hours,
        "last_attack": last_attack_data,
    })


@app.route("/api/logs/<ip_address>")
@require_auth
def api_logs_by_ip(ip_address: str):
    if not ip_address or ip_address == "N/A":
        return jsonify({"logs": [], "error": "IP not provided"}), 400

    if not is_valid_ip(ip_address):
        logger.warning(f"[DASHBOARD] Invalid IP requested: {ip_address!r}")
        return jsonify({"logs": [], "error": "Invalid IP format"}), 400

    df = get_cached_data()

    if df.empty:
        return jsonify({"logs": []})

    filtered_df = df[df["ip_address"] == ip_address]

    logs = (
        filtered_df[["timestamp", "service", "level", "logger", "full_message"]]
        .sort_values(by="timestamp", ascending=False)
        .to_dict("records")
    )

    for log in logs:
        if isinstance(log["timestamp"], pd.Timestamp):
            log["timestamp"] = log["timestamp"].strftime("%Y-%m-%d %H:%M:%S")
        else:
            try:
                ts = pd.to_datetime(log["timestamp"], format="%Y-%m-%d %H:%M:%S,%f")
                log["timestamp"] = ts.strftime("%Y-%m-%d %H:%M:%S")
            except Exception:
                pass

    return jsonify({"logs": logs, "ip_requested": ip_address})


if __name__ == "__main__":
    app.run(debug=False, host="127.0.0.1", port=5000)
