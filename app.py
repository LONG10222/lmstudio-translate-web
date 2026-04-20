from __future__ import annotations

import hashlib
import ipaddress
import io
import json
import secrets
import socket
import ssl
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from socketserver import ThreadingMixIn
from urllib.parse import urlparse
from wsgiref.simple_server import WSGIRequestHandler, WSGIServer, make_server

import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from flask import (
    Flask,
    jsonify,
    make_response,
    redirect,
    render_template,
    request,
    send_file,
    url_for,
)
from requests import exceptions as request_exceptions


BASE_DIR = Path(__file__).resolve().parent
CONFIG_PATH = BASE_DIR / "config.json"
SECURITY_PATH = BASE_DIR / "security.json"
RUNTIME_DIR = BASE_DIR / ".runtime"
TLS_DIR = RUNTIME_DIR / "tls"
CA_CERT_PATH = TLS_DIR / "lan-root-ca.crt"
CA_KEY_PATH = TLS_DIR / "lan-root-ca.key"
SERVER_CERT_PATH = TLS_DIR / "lan-server.crt"
SERVER_KEY_PATH = TLS_DIR / "lan-server.key"

COOKIE_NAME = "lmstudio_translate_session"
APP_HOST = "0.0.0.0"
APP_PORT = 7870
PIN_TTL_MINUTES = 10
TRUST_DEVICE_DAYS = 30
TEMP_SESSION_HOURS = 12

LM_STUDIO_BASE_URL_CANDIDATES = [
    "http://127.0.0.1:1234/v1",
    "http://localhost:1234/v1",
    "http://[::1]:1234/v1",
]

DEFAULT_CONFIG = {
    "base_url": "",
    "api_key": "lm-studio",
    "model_name": "",
    "temperature": 0.2,
    "max_tokens": 1024,
    "source_lang": "en",
    "target_lang": "zh",
    "request_timeout": 180,
}

LANGUAGE_OPTIONS = [
    ("auto", "自动识别"),
    ("zh", "中文"),
    ("en", "英文"),
    ("ja", "日文"),
    ("ko", "韩文"),
    ("fr", "法文"),
    ("de", "德文"),
    ("es", "西班牙文"),
    ("ru", "俄文"),
]

LANGUAGE_LABELS = dict(LANGUAGE_OPTIONS)
MODEL_PREFERENCES = [
    "translategemma-12b-it",
    "translategemma-27b-it-i1",
    "qwen3.5-27b",
    "qwen2.5-14b-instruct-1m",
]

app = Flask(__name__, template_folder="templates", static_folder="static")


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def datetime_to_storage(value: datetime | None) -> str | None:
    return value.isoformat() if value else None


def datetime_from_storage(value: str | None) -> datetime | None:
    if not value:
        return None
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def format_display_time(value: datetime | None) -> str:
    if value is None:
        return ""
    return value.astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")


def load_config() -> dict:
    config = DEFAULT_CONFIG.copy()
    if CONFIG_PATH.exists():
        with open(CONFIG_PATH, "r", encoding="utf-8") as file:
            persisted = json.load(file)
        config.update(persisted)
    return config


def save_config(config: dict) -> None:
    with open(CONFIG_PATH, "w", encoding="utf-8") as file:
        json.dump(config, file, ensure_ascii=False, indent=2)


def load_security_config() -> dict:
    security = {
        "pairing_pin": None,
        "pairing_pin_expires_at": None,
        "device_sessions": [],
    }
    if SECURITY_PATH.exists():
        with open(SECURITY_PATH, "r", encoding="utf-8") as file:
            persisted = json.load(file)
        security.update(persisted)

    security["device_sessions"] = [
        session
        for session in security.get("device_sessions", [])
        if datetime_from_storage(session.get("expires_at")) and datetime_from_storage(session.get("expires_at")) > utc_now()
    ]

    pin_expires_at = datetime_from_storage(security.get("pairing_pin_expires_at"))
    if pin_expires_at is None or pin_expires_at <= utc_now():
        security["pairing_pin"] = None
        security["pairing_pin_expires_at"] = None

    return security


def save_security_config(security: dict) -> None:
    with open(SECURITY_PATH, "w", encoding="utf-8") as file:
        json.dump(security, file, ensure_ascii=False, indent=2)


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def issue_pairing_pin(security: dict) -> tuple[str, datetime]:
    pin = f"{secrets.randbelow(1_000_000):06d}"
    expires_at = utc_now() + timedelta(minutes=PIN_TTL_MINUTES)
    security["pairing_pin"] = pin
    security["pairing_pin_expires_at"] = datetime_to_storage(expires_at)
    save_security_config(security)
    return pin, expires_at


def ensure_active_pairing_pin(security: dict) -> tuple[str, datetime]:
    pin = security.get("pairing_pin")
    expires_at = datetime_from_storage(security.get("pairing_pin_expires_at"))
    if not pin or expires_at is None or expires_at <= utc_now():
        return issue_pairing_pin(security)
    return pin, expires_at


def verify_pairing_pin(security: dict, pin: str) -> bool:
    stored_pin = security.get("pairing_pin")
    expires_at = datetime_from_storage(security.get("pairing_pin_expires_at"))
    if not stored_pin or expires_at is None or expires_at <= utc_now():
        return False
    return secrets.compare_digest(stored_pin, pin)


def create_device_session(security: dict, remember_device: bool) -> tuple[str, datetime]:
    raw_token = secrets.token_urlsafe(32)
    expires_at = utc_now() + (
        timedelta(days=TRUST_DEVICE_DAYS)
        if remember_device
        else timedelta(hours=TEMP_SESSION_HOURS)
    )
    security.setdefault("device_sessions", []).append(
        {
            "token_hash": hash_token(raw_token),
            "expires_at": datetime_to_storage(expires_at),
        }
    )
    save_security_config(security)
    return raw_token, expires_at


def remove_device_session(security: dict, raw_token: str | None) -> None:
    if not raw_token:
        return
    token_hash = hash_token(raw_token)
    security["device_sessions"] = [
        session
        for session in security.get("device_sessions", [])
        if session.get("token_hash") != token_hash
    ]
    save_security_config(security)


def normalize_base_url(base_url: str) -> str:
    return (base_url or "").strip().rstrip("/")


def ensure_local_base_url(base_url: str) -> str:
    normalized = normalize_base_url(base_url)
    if not normalized:
        raise ValueError("未找到可用的本机 LM Studio 地址。")

    parsed = urlparse(normalized)
    if parsed.scheme not in {"http", "https"}:
        raise ValueError("接口地址只允许 http 或 https。")
    if not parsed.hostname:
        raise ValueError("接口地址缺少主机名。")

    host = parsed.hostname
    if host == "localhost":
        return normalized

    try:
        ip = ipaddress.ip_address(host)
    except ValueError as exc:
        raise ValueError("为了防止翻译内容发到外网，只允许连接本机 LM Studio。") from exc

    if not ip.is_loopback:
        raise ValueError("为了防止翻译内容发到外网，只允许连接本机 LM Studio。")

    return normalized


def make_session() -> requests.Session:
    session = requests.Session()
    session.trust_env = False
    return session


def probe_models(base_url: str, api_key: str, timeout: int = 10) -> list[str]:
    with make_session() as session:
        response = session.get(
            f"{base_url}/models",
            headers={"Authorization": f"Bearer {api_key}"},
            timeout=timeout,
        )
    response.raise_for_status()
    payload = response.json()
    return [item["id"] for item in payload.get("data", []) if item.get("id")]


def resolve_lmstudio_base_url(config: dict) -> tuple[str | None, list[str], str | None]:
    configured_base_url = normalize_base_url(config.get("base_url", ""))
    candidates: list[str] = []

    if configured_base_url:
        try:
            candidates.append(ensure_local_base_url(configured_base_url))
        except Exception as exc:
            return None, [], format_request_error(exc, "读取模型列表")
    else:
        candidates.extend(LM_STUDIO_BASE_URL_CANDIDATES)

    last_exc: Exception | None = None
    for candidate in candidates:
        try:
            safe_base_url = ensure_local_base_url(candidate)
            models = probe_models(safe_base_url, config["api_key"], timeout=4)
            return safe_base_url, models, None
        except Exception as exc:
            last_exc = exc

    if last_exc is None:
        last_exc = ValueError("未找到可用的本机 LM Studio 地址。")
    return None, [], format_request_error(last_exc, "读取模型列表")


def pick_default_model(models: list[str]) -> str:
    for candidate in MODEL_PREFERENCES:
        if candidate in models:
            return candidate
    return models[0] if models else ""


def language_label(code: str) -> str:
    return LANGUAGE_LABELS.get(code, code)


def format_request_error(exc: Exception, action: str) -> str:
    if isinstance(exc, ValueError):
        return f"{action}失败：{exc}"
    if isinstance(exc, request_exceptions.ConnectionError):
        return (
            f"{action}失败：无法连接到本机 LM Studio 接口。"
            "系统已自动搜索常见回环地址，但都没有连通。"
            "请确认 LM Studio 已启动，并且本地服务正在监听 1234 端口。"
        )
    if isinstance(exc, request_exceptions.Timeout):
        return f"{action}失败：LM Studio 响应超时。"
    if isinstance(exc, request_exceptions.HTTPError) and exc.response is not None:
        try:
            detail = exc.response.json()
        except ValueError:
            detail = exc.response.text.strip()
        return f"{action}失败：LM Studio 返回 {exc.response.status_code}，{detail}"
    return f"{action}失败：{exc}"


def build_messages(text: str, source_lang: str, target_lang: str) -> list[dict]:
    source_text = "自动识别输入语言" if source_lang == "auto" else language_label(source_lang)
    target_text = language_label(target_lang)
    user_prompt = (
        "You are a professional translator.\n"
        "Translate the text faithfully and naturally.\n"
        "Do not explain. Do not summarize. Output translation only.\n\n"
        f"Source language: {source_text}\n"
        f"Target language: {target_text}\n"
        "Text:\n"
        f"{text}"
    )
    return [{"role": "user", "content": user_prompt}]


def translate_text(config: dict, base_url: str, text: str) -> str:
    with make_session() as session:
        response = session.post(
            f"{base_url}/chat/completions",
            headers={
                "Authorization": f"Bearer {config['api_key']}",
                "Content-Type": "application/json",
            },
            json={
                "model": config["model_name"],
                "messages": build_messages(
                    text, config["source_lang"], config["target_lang"]
                ),
                "temperature": config["temperature"],
                "max_tokens": config["max_tokens"],
            },
            timeout=int(config["request_timeout"]),
        )
    response.raise_for_status()
    payload = response.json()
    return payload["choices"][0]["message"]["content"].strip()


def sanitize_config(payload: dict) -> dict:
    config = load_config()
    config["base_url"] = normalize_base_url(payload.get("base_url", config["base_url"]))
    config["api_key"] = str(payload.get("api_key", config["api_key"])).strip() or "lm-studio"
    config["model_name"] = str(payload.get("model_name", config["model_name"])).strip()
    config["source_lang"] = str(payload.get("source_lang", config["source_lang"]))
    config["target_lang"] = str(payload.get("target_lang", config["target_lang"]))

    try:
        config["temperature"] = float(payload.get("temperature", config["temperature"]))
    except (TypeError, ValueError):
        config["temperature"] = DEFAULT_CONFIG["temperature"]

    try:
        config["max_tokens"] = int(payload.get("max_tokens", config["max_tokens"]))
    except (TypeError, ValueError):
        config["max_tokens"] = DEFAULT_CONFIG["max_tokens"]

    return config


def get_remote_ip() -> ipaddress._BaseAddress | None:
    if not request.remote_addr:
        return None
    try:
        return ipaddress.ip_address(request.remote_addr)
    except ValueError:
        return None


def is_private_client(ip: ipaddress._BaseAddress | None) -> bool:
    if ip is None:
        return False
    return ip.is_loopback or ip.is_private


def is_local_admin_request() -> bool:
    remote_ip = get_remote_ip()
    return bool(remote_ip and remote_ip.is_loopback)


def is_authorized_client(security: dict) -> bool:
    if is_local_admin_request():
        return True

    raw_token = request.cookies.get(COOKIE_NAME)
    if not raw_token:
        return False

    token_hash = hash_token(raw_token)
    for session in security.get("device_sessions", []):
        expires_at = datetime_from_storage(session.get("expires_at"))
        if expires_at and expires_at > utc_now() and secrets.compare_digest(session.get("token_hash", ""), token_hash):
            return True
    return False


def get_private_ipv4_addresses() -> list[ipaddress.IPv4Address]:
    addresses: set[ipaddress.IPv4Address] = set()
    hostnames = {socket.gethostname(), socket.getfqdn(), "localhost"}
    for hostname in hostnames:
        try:
            for result in socket.getaddrinfo(hostname, None, family=socket.AF_INET):
                address = ipaddress.ip_address(result[4][0])
                if isinstance(address, ipaddress.IPv4Address) and address.is_private and not address.is_loopback:
                    addresses.add(address)
        except OSError:
            continue
    return sorted(addresses)


def get_lan_urls() -> list[str]:
    return [f"https://{address}:{APP_PORT}/" for address in get_private_ipv4_addresses()]


def ensure_ca_certificate() -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
    TLS_DIR.mkdir(parents=True, exist_ok=True)

    if CA_CERT_PATH.exists() and CA_KEY_PATH.exists():
        ca_cert = x509.load_pem_x509_certificate(CA_CERT_PATH.read_bytes())
        ca_key = serialization.load_pem_private_key(CA_KEY_PATH.read_bytes(), password=None)
        return ca_key, ca_cert

    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "CN"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "LM Studio Translate Web"),
            x509.NameAttribute(NameOID.COMMON_NAME, "LM Studio Translate Local Root CA"),
        ]
    )
    now = utc_now()
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=False,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256())
    )

    CA_CERT_PATH.write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
    CA_KEY_PATH.write_bytes(
        ca_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    return ca_key, ca_cert


def build_server_sans() -> list[x509.GeneralName]:
    sans: list[x509.GeneralName] = [
        x509.DNSName("localhost"),
        x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
        x509.IPAddress(ipaddress.ip_address("::1")),
    ]

    dns_seen = {"localhost"}
    for hostname in (socket.gethostname(), socket.getfqdn()):
        if hostname and hostname not in dns_seen:
            dns_seen.add(hostname)
            sans.append(x509.DNSName(hostname))

    for address in get_private_ipv4_addresses():
        sans.append(x509.IPAddress(address))

    return sans


def ensure_server_certificate(ca_key: rsa.RSAPrivateKey, ca_cert: x509.Certificate) -> None:
    server_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = utc_now()
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "LM Studio Translate Web"),
            x509.NameAttribute(NameOID.COMMON_NAME, "LM Studio Translate HTTPS Server"),
        ]
    )
    server_cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(server_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=365))
        .add_extension(x509.SubjectAlternativeName(build_server_sans()), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256())
    )

    SERVER_CERT_PATH.write_bytes(server_cert.public_bytes(serialization.Encoding.PEM))
    SERVER_KEY_PATH.write_bytes(
        server_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )


def certificate_thumbprint(certificate: x509.Certificate) -> str:
    return certificate.fingerprint(hashes.SHA256()).hex().upper()


def format_thumbprint(hex_value: str) -> str:
    return ":".join(hex_value[i : i + 2] for i in range(0, len(hex_value), 2))


def build_windows_onboarding_bundle(runtime: dict) -> bytes:
    cert_bytes = CA_CERT_PATH.read_bytes()
    lan_urls = runtime.get("lan_urls", [])
    lan_url = lan_urls[0] if lan_urls else runtime["local_url"]
    bundle_readme = f"""LM Studio Translate Web 局域网接入包

1. 先双击 Install-RootCA.ps1
2. 按提示把根证书导入当前 Windows 用户的受信任根证书颁发机构
3. 导入完成后，在这台电脑打开：
   {lan_url}
4. 首次登录时输入主机页面显示的 6 位 PIN

根证书 SHA-256 指纹：
{runtime["ca_thumbprint_display"]}
"""
    install_script = f"""$ErrorActionPreference = "Stop"

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$certPath = Join-Path $scriptDir "lmstudio-translate-root-ca.crt"

if (-not (Test-Path $certPath)) {{
    throw "Certificate file not found: $certPath"
}}

Import-Certificate -FilePath $certPath -CertStoreLocation Cert:\\CurrentUser\\Root | Out-Null

Write-Host ""
Write-Host "根证书已导入当前用户信任区。" -ForegroundColor Green
Write-Host "下一步：" -ForegroundColor Cyan
Write-Host "1. 打开 {lan_url}"
Write-Host "2. 输入主机页面显示的 6 位 PIN"
Write-Host ""
Pause
"""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("lmstudio-translate-root-ca.crt", cert_bytes)
        archive.writestr("Install-RootCA.ps1", install_script.encode("utf-8"))
        archive.writestr("README.txt", bundle_readme.encode("utf-8"))
    return buffer.getvalue()


def prepare_runtime() -> dict:
    security = load_security_config()
    pin, pin_expires_at = ensure_active_pairing_pin(security)
    ca_key, ca_cert = ensure_ca_certificate()
    ensure_server_certificate(ca_key, ca_cert)
    thumbprint = certificate_thumbprint(ca_cert)

    return {
        "local_url": f"https://127.0.0.1:{APP_PORT}/",
        "lan_urls": get_lan_urls(),
        "pairing_pin": pin,
        "pairing_pin_expires_at_display": format_display_time(pin_expires_at),
        "ca_cert_path": str(CA_CERT_PATH),
        "ca_thumbprint": thumbprint,
        "ca_thumbprint_display": format_thumbprint(thumbprint),
        "server_cert_path": str(SERVER_CERT_PATH),
        "server_key_path": str(SERVER_KEY_PATH),
    }


class ThreadedWSGIServer(ThreadingMixIn, WSGIServer):
    daemon_threads = True
    allow_reuse_address = True


class QuietWSGIRequestHandler(WSGIRequestHandler):
    def log_message(self, format: str, *args) -> None:
        return


def run_https_server(runtime: dict) -> None:
    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ssl_context.load_cert_chain(
        certfile=runtime["server_cert_path"],
        keyfile=runtime["server_key_path"],
    )
    with make_server(
        APP_HOST,
        APP_PORT,
        app,
        server_class=ThreadedWSGIServer,
        handler_class=QuietWSGIRequestHandler,
    ) as server:
        server.socket = ssl_context.wrap_socket(server.socket, server_side=True)
        server.serve_forever()


@app.before_request
def restrict_client_network():
    remote_ip = get_remote_ip()
    if not is_private_client(remote_ip):
        return make_response("只允许本机或局域网私有地址访问。", 403)

    security = load_security_config()
    protected_endpoints = {"api_models", "api_translate"}
    if request.endpoint in protected_endpoints and not is_authorized_client(security):
        return jsonify({"ok": False, "error": "未授权。请先输入 6 位 PIN。"}), 403


@app.after_request
def apply_security_headers(response):
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "base-uri 'self'; "
        "frame-ancestors 'none'; "
        "form-action 'self'"
    )
    return response


@app.get("/")
def index():
    security = load_security_config()
    runtime = prepare_runtime()
    if not is_authorized_client(security):
        return render_template("login.html", error_message="")

    config = load_config()
    base_url, models, model_error = resolve_lmstudio_base_url(config)
    if base_url:
        config["base_url"] = base_url
    if models and (not config["model_name"] or config["model_name"] not in models):
        config["model_name"] = pick_default_model(models)
    save_config(config)

    return render_template(
        "index.html",
        config=config,
        models=models,
        language_options=LANGUAGE_OPTIONS,
        initial_error=model_error or "",
        lan_urls=runtime["lan_urls"] if is_local_admin_request() else [],
        pairing_pin=runtime["pairing_pin"] if is_local_admin_request() else "",
        pairing_pin_expires_at_display=runtime["pairing_pin_expires_at_display"] if is_local_admin_request() else "",
        ca_thumbprint_display=runtime["ca_thumbprint_display"] if is_local_admin_request() else "",
    )


@app.post("/login")
def login():
    security = load_security_config()
    pin = request.form.get("pairing_pin", "").strip()
    remember_device = request.form.get("remember_device") == "1"
    if not verify_pairing_pin(security, pin):
        return render_template("login.html", error_message="PIN 错误或已过期。"), 403

    device_token, expires_at = create_device_session(security, remember_device)
    response = make_response(redirect(url_for("index")))
    response.set_cookie(
        COOKIE_NAME,
        device_token,
        max_age=int((expires_at - utc_now()).total_seconds()),
        httponly=True,
        samesite="Strict",
        secure=True,
    )
    return response


@app.post("/logout")
def logout():
    security = load_security_config()
    remove_device_session(security, request.cookies.get(COOKIE_NAME))
    response = make_response(redirect(url_for("index")))
    response.delete_cookie(COOKIE_NAME)
    return response


@app.post("/admin/pin/regenerate")
def regenerate_pin():
    if not is_local_admin_request():
        return jsonify({"ok": False, "error": "只有本机管理员可以重新生成 PIN。"}), 403

    security = load_security_config()
    pin, expires_at = issue_pairing_pin(security)
    return jsonify(
        {
            "ok": True,
            "pairing_pin": pin,
            "pairing_pin_expires_at_display": format_display_time(expires_at),
            "message": "已生成新的 6 位 PIN。",
        }
    )


@app.get("/admin/ca-cert")
def download_ca_cert():
    if not is_local_admin_request():
        return make_response("只允许在本机下载根证书。", 403)
    prepare_runtime()
    return send_file(
        CA_CERT_PATH,
        as_attachment=True,
        download_name="lmstudio-translate-root-ca.crt",
        mimetype="application/x-x509-ca-cert",
    )


@app.get("/admin/windows-bundle")
def download_windows_bundle():
    if not is_local_admin_request():
        return make_response("只允许在本机下载接入包。", 403)

    runtime = prepare_runtime()
    bundle = build_windows_onboarding_bundle(runtime)
    response = make_response(bundle)
    response.headers["Content-Type"] = "application/zip"
    response.headers["Content-Disposition"] = 'attachment; filename="lmstudio-lan-windows-bundle.zip"'
    return response


@app.post("/api/models")
def api_models():
    payload = request.get_json(silent=True) or {}
    config = sanitize_config(payload)

    base_url, models, error_message = resolve_lmstudio_base_url(config)
    if error_message:
        return jsonify({"ok": False, "error": error_message}), 400

    config["base_url"] = base_url or config["base_url"]
    if models and (not config["model_name"] or config["model_name"] not in models):
        config["model_name"] = pick_default_model(models)
    save_config(config)

    return jsonify(
        {
            "ok": True,
            "models": models,
            "base_url": config["base_url"],
            "model_name": config["model_name"],
            "message": f"已自动探测并刷新模型列表，共 {len(models)} 个模型。",
        }
    )


@app.post("/api/translate")
def api_translate():
    payload = request.get_json(silent=True) or {}
    config = sanitize_config(payload)
    source_text = str(payload.get("source_text", "")).strip()

    if not source_text:
        return jsonify({"ok": False, "error": "请输入要翻译的文本。"}), 400

    base_url, models, error_message = resolve_lmstudio_base_url(config)
    if error_message:
        return jsonify({"ok": False, "error": error_message}), 400

    config["base_url"] = base_url or config["base_url"]
    if models and (not config["model_name"] or config["model_name"] not in models):
        config["model_name"] = pick_default_model(models)

    if not config["model_name"]:
        return jsonify({"ok": False, "error": "请先选择或手动填写模型名。"}), 400

    save_config(config)

    try:
        translated_text = translate_text(config, config["base_url"], source_text)
    except Exception as exc:
        return jsonify({"ok": False, "error": format_request_error(exc, "翻译")}), 400

    return jsonify(
        {
            "ok": True,
            "translated_text": translated_text,
            "base_url": config["base_url"],
            "message": "翻译完成。",
            "model_name": config["model_name"],
        }
    )


if __name__ == "__main__":
    runtime = prepare_runtime()
    run_https_server(runtime)
