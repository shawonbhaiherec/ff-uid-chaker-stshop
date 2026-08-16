"""
Free Fire Player Name Checker API
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
• GET /name?uid=<UID>&region=<REGION>  → returns player name
• Tokens are 100 % automatic: auto-refresh on expiry AND on any
  auth failure.  Game updates (new OB version) are handled by
  auto-detecting the current version from the server response —
  no manual token updates ever needed.
"""

import asyncio, base64, json, logging, os, sys, time
from datetime import datetime, timezone
from threading import Lock
from typing import Dict, Tuple

import httpx
from Crypto.Cipher import AES
from flask import Flask, jsonify, request
from flask_cors import CORS
from google.protobuf import json_format

sys.path.insert(0, os.path.dirname(__file__))
from proto import AccountPersonalShow_pb2, FreeFire_pb2, main_pb2

# ─────────────────────────────────────────────────────────────────────────────
#  Logging
# ─────────────────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("FFName")

# ─────────────────────────────────────────────────────────────────────────────
#  Constants
# ─────────────────────────────────────────────────────────────────────────────
MAIN_KEY       = base64.b64decode("WWcmdGMlREV1aDYlWmNeOA==")
MAIN_IV        = base64.b64decode("Nm95WkRyMjJFM3ljaGpNJQ==")
USER_AGENT     = "ART/2.2.0 (Linux; U; Android 14; SAMSUNG_S25 Build/UP1A.240905.001)"
CLIENT_SECRET  = "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3"
CLIENT_ID      = "100067"
OAUTH_URL      = "https://ffmconnect.live.gop.garenanow.com/oauth/guest/token/grant"
LOGIN_URL      = "https://loginbp.ggblueshark.com/MajorLogin"
TOKEN_TTL      = 25200   # 7 hours
API_VERSION    = "1.0.0"

# Known OB versions — tried newest first; list grows automatically when the
# server echoes a newer version back in the login response.
_KNOWN_VERSIONS = ["OB54", "OB53", "OB52", "OB55", "OB56"]

SUPPORTED_REGIONS = {
    "IND", "BR", "US", "SAC", "NA", "SG", "RU",
    "ID", "TW", "VN", "TH", "ME", "PK", "CIS", "BD", "EUROPE",
}

REGION_CREDENTIALS: Dict[str, str] = {
    "BD":  "uid=5828697960&password=DDE35BE5432054D6EED9A643A72484C93060530E8784BB09B065FA1416A35E74",
    "IND": "uid=3197059560&password=3EC146CD4EEF7A640F2967B06D7F4413BD4FB37382E0ED260E214E8BACD96734",
    "BR":  "uid=3939493997&password=D08775EC0CCCEA77B2426EBC4CF04C097E0D58822804756C02738BF37578EE17",
    "US":  "uid=3939493997&password=D08775EC0CCCEA77B2426EBC4CF04C097E0D58822804756C02738BF37578EE17",
    "SAC": "uid=3939493997&password=D08775EC0CCCEA77B2426EBC4CF04C097E0D58822804756C02738BF37578EE17",
    "NA":  "uid=3939493997&password=D08775EC0CCCEA77B2426EBC4CF04C097E0D58822804756C02738BF37578EE17",
}
DEFAULT_CREDENTIAL = "uid=3937206629&password=E4D17A3799816184A9BA20C68D8DE55C69180F8C793CA1C6B164C6D14848D8DF"

# ─────────────────────────────────────────────────────────────────────────────
#  Crypto helpers
# ─────────────────────────────────────────────────────────────────────────────
def _pad(data: bytes) -> bytes:
    n = AES.block_size - (len(data) % AES.block_size)
    return data + bytes([n] * n)

def aes_encrypt(data: bytes) -> bytes:
    return AES.new(MAIN_KEY, AES.MODE_CBC, MAIN_IV).encrypt(_pad(data))

def parse_proto(raw: bytes, proto_type):
    msg = proto_type()
    msg.ParseFromString(raw)
    return msg

async def serialize_proto(obj: dict, proto_msg) -> bytes:
    json_format.ParseDict(obj, proto_msg)
    return proto_msg.SerializeToString()

# ─────────────────────────────────────────────────────────────────────────────
#  Auto-version detection
# ─────────────────────────────────────────────────────────────────────────────
_active_version: str = _KNOWN_VERSIONS[0]   # start with newest known
_version_lock   = Lock()

def get_active_version() -> str:
    with _version_lock:
        return _active_version

def set_active_version(v: str) -> None:
    global _active_version
    with _version_lock:
        if v and v != _active_version:
            logger.info(f"[Version] Updated active version → {v}")
            _active_version = v
            if v not in _KNOWN_VERSIONS:
                _KNOWN_VERSIONS.insert(0, v)

# ─────────────────────────────────────────────────────────────────────────────
#  Token management  (fully automatic, never needs manual update)
# ─────────────────────────────────────────────────────────────────────────────
_token_cache: Dict[str, dict] = {}
_token_lock   = Lock()

def _get_creds(region: str) -> str:
    return REGION_CREDENTIALS.get(region.upper(), DEFAULT_CREDENTIAL)

async def _fetch_oauth(creds: str) -> Tuple[str, str]:
    payload = (f"{creds}&response_type=token&client_type=2"
               f"&client_secret={CLIENT_SECRET}&client_id={CLIENT_ID}")
    async with httpx.AsyncClient(timeout=15) as c:
        r = await c.post(OAUTH_URL, data=payload, headers={
            "User-Agent": USER_AGENT,
            "Content-Type": "application/x-www-form-urlencoded",
            "Connection": "Keep-Alive", "Accept-Encoding": "gzip",
        })
        r.raise_for_status()
    d = r.json()
    return d["access_token"], d["open_id"]

async def _game_login_with_version(access_token: str, open_id: str,
                                   release_ver: str) -> Tuple[str, str, str]:
    """
    Attempt a game login with the given release version string.
    Returns (bearer, server_url, detected_version).
    Raises RuntimeError if the token is missing in the response.
    """
    proto_bytes = await serialize_proto({
        "open_id": open_id, "open_id_type": "4",
        "login_token": access_token, "orign_platform_type": "4",
    }, FreeFire_pb2.LoginReq())
    enc = aes_encrypt(proto_bytes)
    async with httpx.AsyncClient(timeout=15) as c:
        r = await c.post(LOGIN_URL, data=enc, headers={
            "User-Agent": USER_AGENT,
            "Content-Type": "application/octet-stream",
            "Connection": "Keep-Alive", "Accept-Encoding": "gzip",
            "Expect": "100-continue",
            "X-Unity-Version": "2018.4.11f1",
            "X-GA": "v1 1",
            "ReleaseVersion": release_ver,
        })
        r.raise_for_status()
    res = json.loads(json_format.MessageToJson(
        parse_proto(r.content, FreeFire_pb2.LoginRes)
    ))
    token      = res.get("token", "")
    server_url = res.get("serverUrl", "")
    if not token:
        raise RuntimeError(f"No token in response: {res}")
    return f"Bearer {token}", server_url, release_ver

async def _create_token(region: str) -> None:
    """
    Obtain a fresh token for `region`, automatically trying all known
    release versions if the current one fails.
    """
    region = region.upper()
    creds  = _get_creds(region)
    access_token, open_id = await _fetch_oauth(creds)

    # Try versions newest-first; stop at first success.
    errors = []
    versions_to_try = [get_active_version()] + [
        v for v in _KNOWN_VERSIONS if v != get_active_version()
    ]
    for ver in versions_to_try:
        try:
            bearer, server_url, working_ver = await _game_login_with_version(
                access_token, open_id, ver
            )
            set_active_version(working_ver)
            with _token_lock:
                _token_cache[region] = {
                    "token":      bearer,
                    "server_url": server_url,
                    "expires_at": time.time() + TOKEN_TTL,
                    "refreshed":  datetime.now(timezone.utc).isoformat(),
                    "version":    working_ver,
                }
            logger.info(f"[Token] {region} OK  ver={working_ver}  srv={server_url}")
            return
        except Exception as e:
            errors.append(f"{ver}: {e}")
            logger.warning(f"[Token] {region} failed with {ver}: {e}")

    raise RuntimeError(f"All versions failed for {region}: {errors}")

async def get_token(region: str, force: bool = False) -> Tuple[str, str]:
    region = region.upper()
    with _token_lock:
        info = _token_cache.get(region)
    if not force and info and time.time() < info["expires_at"] - 300:
        return info["token"], info["server_url"]
    await _create_token(region)
    with _token_lock:
        info = _token_cache[region]
    return info["token"], info["server_url"]

# ─────────────────────────────────────────────────────────────────────────────
#  Player name fetch  (auto-retry on auth failure)
# ─────────────────────────────────────────────────────────────────────────────
async def fetch_player_name(uid: int, region: str) -> str | None:
    """
    Returns the player's nickname, or None if the UID doesn't exist.
    On a 401/auth error: forces a token refresh and retries once.
    """
    for attempt in range(2):
        bearer, server_url = await get_token(region, force=(attempt > 0))
        payload = await serialize_proto(
            {"a": uid, "b": 7}, main_pb2.GetPlayerPersonalShow()
        )
        enc = aes_encrypt(payload)
        try:
            async with httpx.AsyncClient(timeout=15) as c:
                r = await c.post(server_url + "/GetPlayerPersonalShow",
                                 data=enc, headers={
                    "User-Agent": USER_AGENT,
                    "Content-Type": "application/octet-stream",
                    "Connection": "Keep-Alive", "Accept-Encoding": "gzip",
                    "Expect": "100-continue",
                    "Authorization": bearer,
                    "X-Unity-Version": "2018.4.11f1",
                    "X-GA": "v1 1",
                    "ReleaseVersion": get_active_version(),
                })
                if r.status_code == 401 and attempt == 0:
                    logger.warning(f"[Auth] 401 on uid={uid} region={region} — refreshing token")
                    continue   # retry with forced refresh
                r.raise_for_status()
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 401 and attempt == 0:
                continue
            raise

        raw = json.loads(json_format.MessageToJson(
            parse_proto(r.content, AccountPersonalShow_pb2.AccountPersonalShowInfo)
        ))
        name = raw.get("basicInfo", {}).get("nickname")
        return name or None

    return None   # should not reach here

# ─────────────────────────────────────────────────────────────────────────────
#  Flask app
# ─────────────────────────────────────────────────────────────────────────────
app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}}, supports_credentials=True)

CREDITS = {
    "author":  "FFxAPI",
    "channel": "https://t.me/FFxAPI",
}

def _ok(data, cached=False):
    return jsonify({
        "status":      "success",
        "api_version": API_VERSION,
        "timestamp":   datetime.now(timezone.utc).isoformat(),
        "cached":      cached,
        "credits":     CREDITS,
        "data":        data,
    }), 200

def _err(code: str, msg: str, status: int, extra: dict = None):
    body = {
        "status":      "error",
        "api_version": API_VERSION,
        "timestamp":   datetime.now(timezone.utc).isoformat(),
        "error":       {"code": code, "message": msg},
    }
    if extra:
        body["error"].update(extra)
    return jsonify(body), status

# ─────────────────────────────────────────────────────────────────────────────
#  Routes
# ─────────────────────────────────────────────────────────────────────────────
@app.route("/")
def index():
    return jsonify({
        "name":        "FF Name Checker API",
        "version":     API_VERSION,
        "endpoints": {
            "/name":    "GET ?uid=&region=  — fetch player name",
            "/health":  "GET               — API health check",
            "/regions": "GET               — list supported regions",
        },
        "example": "/name?uid=2769409057&region=BD",
        "credits": CREDITS,
    })


@app.route("/name")
def get_name():
    uid    = request.args.get("uid", "").strip()
    region = request.args.get("region", "BD").strip().upper()

    if not uid:
        return _err("MISSING_UID", "Query param 'uid' is required.", 400)
    if not uid.isdigit():
        return _err("INVALID_UID", "UID must be numeric.", 400)
    if not (5 <= len(uid) <= 12):
        return _err("INVALID_UID", "UID must be 5–12 digits.", 400)
    if region not in SUPPORTED_REGIONS:
        return _err("INVALID_REGION", f"Region '{region}' not supported.", 400,
                    {"supported_regions": sorted(SUPPORTED_REGIONS)})

    try:
        logger.info(f"[Name] uid={uid} region={region}")
        name = asyncio.run(fetch_player_name(int(uid), region))
        if not name:
            return _err("NOT_FOUND", f"Player UID {uid} not found in {region}.", 404)
        return _ok({
            "uid":    uid,
            "name":   name,
            "region": region,
        })
    except httpx.TimeoutException:
        return _err("TIMEOUT", "Upstream timed out. Please retry.", 504)
    except httpx.HTTPStatusError as e:
        return _err("UPSTREAM_ERROR", f"Upstream HTTP {e.response.status_code}.", 502)
    except Exception as e:
        logger.exception(f"[Error] uid={uid} region={region}: {e}")
        return _err("INTERNAL_ERROR", "Unexpected error. Try again.", 500)


@app.route("/health")
def health():
    active = sum(1 for r in SUPPORTED_REGIONS if _token_cache.get(r))
    return jsonify({
        "status":       "healthy",
        "version":      API_VERSION,
        "game_version": get_active_version(),
        "timestamp":    datetime.now(timezone.utc).isoformat(),
        "tokens":       {"active": active, "total": len(SUPPORTED_REGIONS)},
    })


@app.route("/regions")
def list_regions():
    return jsonify({
        "total":   len(SUPPORTED_REGIONS),
        "regions": sorted(SUPPORTED_REGIONS),
        "default": "BD",
    })


@app.errorhandler(404)
def not_found(_):
    return _err("NOT_FOUND", "Endpoint not found.", 404)

@app.errorhandler(405)
def method_not_allowed(_):
    return _err("METHOD_NOT_ALLOWED", "Method not allowed.", 405)


# ─────────────────────────────────────────────────────────────────────────────
#  App factory
# ─────────────────────────────────────────────────────────────────────────────
def create_app() -> Flask:
    return app


if __name__ == "__main__":
    port  = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("FLASK_DEBUG", "false").lower() == "true"
    logger.info(f"[Server] FF Name Checker API v{API_VERSION} → port {port}")
    create_app().run(host="0.0.0.0", port=port, debug=debug)
