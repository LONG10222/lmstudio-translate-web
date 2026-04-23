from __future__ import annotations

import ctypes
import hashlib
import ipaddress
import io
import json
import math
import os
import secrets
import re
import socket
import ssl
import subprocess
import threading
import time
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from socketserver import ThreadingMixIn
from urllib.parse import urlparse
from wsgiref.simple_server import WSGIRequestHandler, WSGIServer, make_server

import qrcode
import qrcode.image.svg
import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from flask import (
    Flask,
    Response,
    jsonify,
    make_response,
    redirect,
    render_template,
    request,
    send_file,
    stream_with_context,
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
DEVICE_ID_COOKIE_NAME = "lmstudio_translate_device"
APP_HOST = "0.0.0.0"
APP_PORT = 7870
BOOTSTRAP_PORT = 7871
PIN_TTL_MINUTES = 10
TRUST_DEVICE_DAYS = 30
TEMP_SESSION_HOURS = 12
DEVICE_COOKIE_MAX_AGE = 60 * 60 * 24 * 365 * 5
MIN_TRANSLATION_MAX_TOKENS = 256
MAX_TRANSLATION_MAX_TOKENS = 4096
MIN_CHUNK_CHARS = 700
MAX_CHUNK_CHARS = 3200
GPU_SNAPSHOT_TTL_SECONDS = 2.0
SYSTEM_SNAPSHOT_TTL_SECONDS = 2.0

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
GPU_SNAPSHOT_LOCK = threading.Lock()
GPU_SNAPSHOT_CACHE = {"captured_at": 0.0, "snapshot": None}
SYSTEM_SNAPSHOT_LOCK = threading.Lock()
SYSTEM_SNAPSHOT_CACHE = {"captured_at": 0.0, "snapshot": None}


class TranslationQueue:
    def __init__(self) -> None:
        self._condition = threading.Condition()
        self._next_ticket = 0
        self._serving_ticket = 0
        self._active = False

    def acquire(self) -> dict:
        with self._condition:
            ticket = self._next_ticket
            self._next_ticket += 1
            queued_ahead = max(0, ticket - self._serving_ticket)
            wait_started_at = time.perf_counter()

            while ticket != self._serving_ticket or self._active:
                self._condition.wait()

            wait_ms = round((time.perf_counter() - wait_started_at) * 1000, 1)
            self._active = True
            return {
                "ticket": ticket,
                "queued_ahead": queued_ahead,
                "wait_ms": wait_ms,
            }

    def release(self) -> None:
        with self._condition:
            self._active = False
            self._serving_ticket += 1
            self._condition.notify_all()


TRANSLATION_QUEUE = TranslationQueue()


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
        "pending_devices": [],
        "approved_devices": [],
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

    security["pending_devices"] = [
        device
        for device in security.get("pending_devices", [])
        if str(device.get("device_id_hash", "")).strip()
    ]
    security["approved_devices"] = [
        device
        for device in security.get("approved_devices", [])
        if str(device.get("device_id_hash", "")).strip()
    ]

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


def hash_device_id(device_id: str) -> str:
    return hash_token(f"device::{device_id}")


def normalize_device_label(label: str | None, fallback: str) -> str:
    collapsed = re.sub(r"\s+", " ", str(label or "")).strip()
    return (collapsed or fallback)[:80]


def normalize_user_agent(user_agent: str | None) -> str:
    return re.sub(r"\s+", " ", str(user_agent or "")).strip()[:240]


def current_device_platform() -> str:
    return detect_client_platform(request.headers.get("User-Agent"))


def current_device_ip() -> str:
    remote_ip = get_remote_ip()
    return str(remote_ip) if remote_ip else (request.remote_addr or "")


def default_device_label(platform: str, remote_ip: str) -> str:
    label = platform_label(platform)
    return f"{label} · {remote_ip}" if remote_ip else label


def ensure_device_id() -> tuple[str, bool]:
    raw_device_id = str(request.cookies.get(DEVICE_ID_COOKIE_NAME, "")).strip()
    if raw_device_id:
        return raw_device_id, False
    return secrets.token_urlsafe(32), True


def attach_device_cookie(response, raw_device_id: str) -> None:
    response.set_cookie(
        DEVICE_ID_COOKIE_NAME,
        raw_device_id,
        max_age=DEVICE_COOKIE_MAX_AGE,
        httponly=True,
        samesite="Strict",
        secure=True,
    )


def find_device_record(records: list[dict], device_id_hash: str) -> dict | None:
    for record in records:
        if secrets.compare_digest(str(record.get("device_id_hash", "")), device_id_hash):
            return record
    return None


def device_record_payload(record: dict) -> dict:
    return {
        "device_id_hash": record.get("device_id_hash", ""),
        "device_fingerprint": str(record.get("device_id_hash", ""))[:12],
        "device_label": record.get("device_label", ""),
        "platform": record.get("platform", "unknown"),
        "platform_label": platform_label(record.get("platform", "unknown")),
        "user_agent": record.get("user_agent", ""),
        "first_seen_ip": record.get("first_seen_ip", ""),
        "last_seen_ip": record.get("last_seen_ip", ""),
        "request_count": int(record.get("request_count", 0) or 0),
        "first_requested_at_display": format_display_time(datetime_from_storage(record.get("first_requested_at"))),
        "last_requested_at_display": format_display_time(datetime_from_storage(record.get("last_requested_at"))),
        "approved_at_display": format_display_time(datetime_from_storage(record.get("approved_at"))),
        "last_seen_at_display": format_display_time(datetime_from_storage(record.get("last_seen_at"))),
    }


def current_device_status(security: dict, raw_device_id: str) -> tuple[str, dict | None]:
    device_id_hash = hash_device_id(raw_device_id)
    approved = find_device_record(security.get("approved_devices", []), device_id_hash)
    if approved:
        return "approved", approved
    pending = find_device_record(security.get("pending_devices", []), device_id_hash)
    if pending:
        return "pending", pending
    return "none", None


def queue_device_access_request(security: dict, raw_device_id: str, device_label: str | None = None) -> dict:
    now = utc_now()
    device_id_hash = hash_device_id(raw_device_id)
    remote_ip = current_device_ip()
    platform = current_device_platform()
    label = normalize_device_label(device_label, default_device_label(platform, remote_ip))
    user_agent = normalize_user_agent(request.headers.get("User-Agent"))

    approved = find_device_record(security.get("approved_devices", []), device_id_hash)
    if approved:
        approved["device_label"] = label or approved.get("device_label", "")
        approved["last_seen_ip"] = remote_ip
        approved["last_seen_at"] = datetime_to_storage(now)
        if user_agent:
            approved["user_agent"] = user_agent
        save_security_config(security)
        return approved

    pending = find_device_record(security.get("pending_devices", []), device_id_hash)
    if pending is None:
        pending = {
            "device_id_hash": device_id_hash,
            "device_label": label,
            "platform": platform,
            "user_agent": user_agent,
            "first_seen_ip": remote_ip,
            "last_seen_ip": remote_ip,
            "first_requested_at": datetime_to_storage(now),
            "last_requested_at": datetime_to_storage(now),
            "request_count": 1,
        }
        security.setdefault("pending_devices", []).append(pending)
    else:
        pending["device_label"] = label
        pending["platform"] = platform
        pending["user_agent"] = user_agent
        pending["last_seen_ip"] = remote_ip
        pending["last_requested_at"] = datetime_to_storage(now)
        pending["request_count"] = int(pending.get("request_count", 0) or 0) + 1
    save_security_config(security)
    return pending


def approve_device_request(security: dict, device_id_hash: str) -> dict:
    pending_devices = security.get("pending_devices", [])
    pending = find_device_record(pending_devices, device_id_hash)
    if pending is None:
        raise ValueError("未找到待审批设备。")

    now = utc_now()
    approved = find_device_record(security.get("approved_devices", []), device_id_hash)
    if approved is None:
        approved = {
            "device_id_hash": device_id_hash,
            "device_label": pending.get("device_label", ""),
            "platform": pending.get("platform", "unknown"),
            "user_agent": pending.get("user_agent", ""),
            "first_seen_ip": pending.get("first_seen_ip", ""),
            "last_seen_ip": pending.get("last_seen_ip", ""),
            "approved_at": datetime_to_storage(now),
            "last_seen_at": datetime_to_storage(now),
            "request_count": pending.get("request_count", 1),
        }
        security.setdefault("approved_devices", []).append(approved)
    else:
        approved["device_label"] = pending.get("device_label", approved.get("device_label", ""))
        approved["platform"] = pending.get("platform", approved.get("platform", "unknown"))
        approved["user_agent"] = pending.get("user_agent", approved.get("user_agent", ""))
        approved["last_seen_ip"] = pending.get("last_seen_ip", approved.get("last_seen_ip", ""))
        approved["last_seen_at"] = datetime_to_storage(now)
        approved.setdefault("approved_at", datetime_to_storage(now))
        approved["request_count"] = pending.get("request_count", approved.get("request_count", 1))

    security["pending_devices"] = [
        device
        for device in pending_devices
        if not secrets.compare_digest(str(device.get("device_id_hash", "")), device_id_hash)
    ]
    save_security_config(security)
    return approved


def reject_device_request(security: dict, device_id_hash: str) -> bool:
    pending_before = len(security.get("pending_devices", []))
    security["pending_devices"] = [
        device
        for device in security.get("pending_devices", [])
        if not secrets.compare_digest(str(device.get("device_id_hash", "")), device_id_hash)
    ]
    changed = len(security["pending_devices"]) != pending_before
    if changed:
        save_security_config(security)
    return changed


def revoke_approved_device(security: dict, device_id_hash: str) -> bool:
    approved_before = len(security.get("approved_devices", []))
    security["approved_devices"] = [
        device
        for device in security.get("approved_devices", [])
        if not secrets.compare_digest(str(device.get("device_id_hash", "")), device_id_hash)
    ]
    changed = len(security["approved_devices"]) != approved_before
    if changed:
        save_security_config(security)
    return changed


def touch_approved_device(security: dict, raw_device_id: str) -> None:
    approved = find_device_record(security.get("approved_devices", []), hash_device_id(raw_device_id))
    if approved is None:
        return
    now = utc_now()
    approved["last_seen_at"] = datetime_to_storage(now)
    approved["last_seen_ip"] = current_device_ip()
    user_agent = normalize_user_agent(request.headers.get("User-Agent"))
    if user_agent:
        approved["user_agent"] = user_agent
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

    for candidate in LM_STUDIO_BASE_URL_CANDIDATES:
        if candidate not in candidates:
            candidates.append(candidate)

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
        "Preserve paragraph structure where practical.\n"
        "Do not explain. Do not summarize. Output translation only.\n\n"
        f"Source language: {source_text}\n"
        f"Target language: {target_text}\n"
        "Text:\n"
        f"{text}"
    )
    return [{"role": "user", "content": user_prompt}]


def clamp_int(value: int, lower: int, upper: int) -> int:
    return max(lower, min(upper, value))


class MEMORYSTATUSEX(ctypes.Structure):
    _fields_ = [
        ("dwLength", ctypes.c_ulong),
        ("dwMemoryLoad", ctypes.c_ulong),
        ("ullTotalPhys", ctypes.c_ulonglong),
        ("ullAvailPhys", ctypes.c_ulonglong),
        ("ullTotalPageFile", ctypes.c_ulonglong),
        ("ullAvailPageFile", ctypes.c_ulonglong),
        ("ullTotalVirtual", ctypes.c_ulonglong),
        ("ullAvailVirtual", ctypes.c_ulonglong),
        ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
    ]


def read_gpu_memory_snapshot(force: bool = False) -> dict:
    now = time.monotonic()
    with GPU_SNAPSHOT_LOCK:
        cached = GPU_SNAPSHOT_CACHE.get("snapshot")
        if (
            not force
            and cached is not None
            and now - float(GPU_SNAPSHOT_CACHE.get("captured_at", 0.0)) < GPU_SNAPSHOT_TTL_SECONDS
        ):
            return cached

    snapshot = {
        "available": False,
        "name": "",
        "free_mb": None,
        "total_mb": None,
        "free_ratio": None,
        "gpu_count": 0,
        "reason": "unavailable",
    }

    try:
        result = subprocess.run(
            [
                "nvidia-smi",
                "--query-gpu=name,memory.free,memory.total",
                "--format=csv,noheader,nounits",
            ],
            capture_output=True,
            text=True,
            timeout=2,
            check=True,
        )
        gpus: list[dict] = []
        for raw_line in result.stdout.splitlines():
            line = raw_line.strip()
            if not line:
                continue
            parts = [part.strip() for part in line.split(",")]
            if len(parts) != 3:
                continue
            try:
                free_mb = int(parts[1])
                total_mb = int(parts[2])
            except ValueError:
                continue
            gpus.append(
                {
                    "name": parts[0],
                    "free_mb": free_mb,
                    "total_mb": total_mb,
                    "free_ratio": (free_mb / total_mb) if total_mb else 0.0,
                }
            )

        if gpus:
            best_gpu = max(gpus, key=lambda item: (item["free_mb"], item["total_mb"]))
            snapshot = {
                "available": True,
                "name": best_gpu["name"],
                "free_mb": best_gpu["free_mb"],
                "total_mb": best_gpu["total_mb"],
                "free_ratio": best_gpu["free_ratio"],
                "gpu_count": len(gpus),
                "reason": "",
            }
        else:
            snapshot["reason"] = "no-gpu-data"
    except FileNotFoundError:
        snapshot["reason"] = "nvidia-smi-not-found"
    except subprocess.TimeoutExpired:
        snapshot["reason"] = "nvidia-smi-timeout"
    except subprocess.CalledProcessError:
        snapshot["reason"] = "nvidia-smi-error"

    with GPU_SNAPSHOT_LOCK:
        GPU_SNAPSHOT_CACHE["captured_at"] = now
        GPU_SNAPSHOT_CACHE["snapshot"] = snapshot
    return snapshot


def read_system_memory_snapshot(force: bool = False) -> dict:
    now = time.monotonic()
    with SYSTEM_SNAPSHOT_LOCK:
        cached = SYSTEM_SNAPSHOT_CACHE.get("snapshot")
        if (
            not force
            and cached is not None
            and now - float(SYSTEM_SNAPSHOT_CACHE.get("captured_at", 0.0)) < SYSTEM_SNAPSHOT_TTL_SECONDS
        ):
            return cached

    snapshot = {
        "available": False,
        "total_mb": None,
        "free_mb": None,
        "free_ratio": None,
        "logical_cores": max(1, os.cpu_count() or 1),
        "reason": "unavailable",
    }

    try:
        if os.name == "nt":
            memory_status = MEMORYSTATUSEX()
            memory_status.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
            if not ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(memory_status)):
                raise OSError("GlobalMemoryStatusEx failed")
            total_bytes = int(memory_status.ullTotalPhys)
            free_bytes = int(memory_status.ullAvailPhys)
        else:
            page_size = int(os.sysconf("SC_PAGE_SIZE"))
            total_pages = int(os.sysconf("SC_PHYS_PAGES"))
            free_pages = int(os.sysconf("SC_AVPHYS_PAGES"))
            total_bytes = page_size * total_pages
            free_bytes = page_size * free_pages

        total_mb = max(1, total_bytes // (1024 * 1024))
        free_mb = max(0, free_bytes // (1024 * 1024))
        snapshot = {
            "available": True,
            "total_mb": total_mb,
            "free_mb": free_mb,
            "free_ratio": (free_mb / total_mb) if total_mb else 0.0,
            "logical_cores": max(1, os.cpu_count() or 1),
            "reason": "",
        }
    except (AttributeError, OSError, ValueError):
        snapshot["reason"] = "memory-query-failed"

    with SYSTEM_SNAPSHOT_LOCK:
        SYSTEM_SNAPSHOT_CACHE["captured_at"] = now
        SYSTEM_SNAPSHOT_CACHE["snapshot"] = snapshot
    return snapshot


def estimate_gpu_token_ceiling(snapshot: dict) -> int | None:
    if not snapshot.get("available"):
        return None

    free_mb = int(snapshot["free_mb"])
    free_ratio = float(snapshot["free_ratio"])

    if free_mb >= 16_384:
        ceiling = 4096
    elif free_mb >= 12_288:
        ceiling = 3072
    elif free_mb >= 8_192:
        ceiling = 2048
    elif free_mb >= 6_144:
        ceiling = 1536
    elif free_mb >= 4_096:
        ceiling = 1024
    elif free_mb >= 3_072:
        ceiling = 768
    elif free_mb >= 2_048:
        ceiling = 512
    else:
        ceiling = 256

    if free_ratio < 0.12:
        ceiling = min(ceiling, 512)
    elif free_ratio < 0.2:
        ceiling = min(ceiling, 768)

    return clamp_int(ceiling, MIN_TRANSLATION_MAX_TOKENS, MAX_TRANSLATION_MAX_TOKENS)


def estimate_memory_token_ceiling(snapshot: dict) -> int:
    if not snapshot.get("available"):
        return 1024

    free_mb = int(snapshot["free_mb"])
    free_ratio = float(snapshot["free_ratio"])

    if free_mb >= 24_576:
        ceiling = 4096
    elif free_mb >= 16_384:
        ceiling = 3072
    elif free_mb >= 12_288:
        ceiling = 2048
    elif free_mb >= 8_192:
        ceiling = 1536
    elif free_mb >= 6_144:
        ceiling = 1024
    elif free_mb >= 4_096:
        ceiling = 768
    else:
        ceiling = 512

    if free_ratio < 0.12:
        ceiling = min(ceiling, 512)
    elif free_ratio < 0.18:
        ceiling = min(ceiling, 768)

    return clamp_int(ceiling, MIN_TRANSLATION_MAX_TOKENS, MAX_TRANSLATION_MAX_TOKENS)


def estimate_cpu_token_ceiling(snapshot: dict) -> int:
    logical_cores = int(snapshot.get("logical_cores") or 1)
    if logical_cores >= 24:
        ceiling = 3072
    elif logical_cores >= 16:
        ceiling = 2048
    elif logical_cores >= 12:
        ceiling = 1536
    elif logical_cores >= 8:
        ceiling = 1024
    elif logical_cores >= 4:
        ceiling = 768
    else:
        ceiling = 512
    return clamp_int(ceiling, MIN_TRANSLATION_MAX_TOKENS, MAX_TRANSLATION_MAX_TOKENS)


def classify_hardware_tier(
    gpu_snapshot: dict,
    memory_snapshot: dict,
    cpu_token_ceiling: int,
    memory_token_ceiling: int,
) -> str:
    gpu_ceiling = estimate_gpu_token_ceiling(gpu_snapshot) if gpu_snapshot.get("available") else None
    if gpu_ceiling is not None and gpu_ceiling >= 2048 and memory_token_ceiling >= 2048 and cpu_token_ceiling >= 1536:
        return "high"
    if gpu_ceiling is not None and gpu_ceiling >= 1024 and memory_token_ceiling >= 1024 and cpu_token_ceiling >= 1024:
        return "balanced"
    if memory_token_ceiling >= 1536 and cpu_token_ceiling >= 1024:
        return "balanced"
    return "constrained"


def build_translation_plan(config: dict, source_text: str) -> dict:
    configured_tokens = clamp_int(
        int(config.get("max_tokens", DEFAULT_CONFIG["max_tokens"])),
        64,
        8192,
    )
    gpu_snapshot = read_gpu_memory_snapshot()
    memory_snapshot = read_system_memory_snapshot()
    gpu_token_ceiling = estimate_gpu_token_ceiling(gpu_snapshot)
    memory_token_ceiling = estimate_memory_token_ceiling(memory_snapshot)
    cpu_token_ceiling = estimate_cpu_token_ceiling(memory_snapshot)
    hardware_tier = classify_hardware_tier(
        gpu_snapshot,
        memory_snapshot,
        cpu_token_ceiling,
        memory_token_ceiling,
    )

    effective_max_tokens = configured_tokens
    token_ceilings = [memory_token_ceiling, cpu_token_ceiling]
    if gpu_token_ceiling is not None:
        token_ceilings.append(gpu_token_ceiling)
    auto_tokens_enabled = True
    effective_max_tokens = min([configured_tokens, *token_ceilings])

    text_length = len(source_text.strip())
    if hardware_tier == "constrained" and text_length > 12_000:
        effective_max_tokens = min(effective_max_tokens, 768)
    elif hardware_tier == "balanced" and text_length > 18_000:
        effective_max_tokens = min(effective_max_tokens, 1536)
    elif text_length < 800 and hardware_tier == "high":
        effective_max_tokens = min(configured_tokens, max(768, effective_max_tokens))

    effective_max_tokens = clamp_int(
        effective_max_tokens,
        MIN_TRANSLATION_MAX_TOKENS,
        MAX_TRANSLATION_MAX_TOKENS,
    )
    base_chunk_limit = effective_max_tokens * 4
    if hardware_tier == "high":
        chunk_upper = MAX_CHUNK_CHARS
    elif hardware_tier == "balanced":
        chunk_upper = 2600
    else:
        chunk_upper = 1800
    chunk_char_limit = max(MIN_CHUNK_CHARS, min(chunk_upper, base_chunk_limit))
    estimated_chunk_count = max(1, math.ceil(max(1, text_length) / chunk_char_limit))
    effective_timeout = clamp_int(
        max(
            int(config.get("request_timeout", DEFAULT_CONFIG["request_timeout"])),
            45 + estimated_chunk_count * (10 if hardware_tier == "constrained" else 6),
        ),
        45,
        300,
    )
    tuning_summary = build_tuning_summary(
        gpu_snapshot,
        memory_snapshot,
        hardware_tier,
        effective_max_tokens,
        chunk_char_limit,
    )

    return {
        "configured_max_tokens": configured_tokens,
        "effective_max_tokens": effective_max_tokens,
        "chunk_char_limit": chunk_char_limit,
        "auto_tokens_enabled": auto_tokens_enabled,
        "effective_timeout": effective_timeout,
        "gpu_snapshot": gpu_snapshot,
        "memory_snapshot": memory_snapshot,
        "gpu_token_ceiling": gpu_token_ceiling,
        "memory_token_ceiling": memory_token_ceiling,
        "cpu_token_ceiling": cpu_token_ceiling,
        "hardware_tier": hardware_tier,
        "estimated_chunk_count": estimated_chunk_count,
        "tuning_summary": tuning_summary,
    }


def estimate_chunk_char_limit(plan: dict) -> int:
    return int(plan["chunk_char_limit"])


def build_tuning_summary(
    gpu_snapshot: dict,
    memory_snapshot: dict,
    hardware_tier: str,
    effective_max_tokens: int,
    chunk_char_limit: int,
) -> str:
    tier_label = {
        "high": "高性能",
        "balanced": "均衡",
        "constrained": "保守",
    }.get(hardware_tier, "均衡")

    parts = [tier_label]
    if gpu_snapshot.get("available"):
        parts.append(
            f"GPU {gpu_snapshot['free_mb'] / 1024:.1f}/{gpu_snapshot['total_mb'] / 1024:.1f} GiB"
        )
    if memory_snapshot.get("available"):
        parts.append(
            f"RAM {memory_snapshot['free_mb'] / 1024:.1f}/{memory_snapshot['total_mb'] / 1024:.1f} GiB"
        )
    parts.append(f"CPU {int(memory_snapshot.get('logical_cores') or 1)} 线程")
    parts.append(f"Tokens {effective_max_tokens}")
    parts.append(f"分段 {chunk_char_limit} 字")
    return " · ".join(parts)


def estimate_completion_tokens(plan: dict, text: str) -> int:
    estimated_tokens = math.ceil(len(text) / 3)
    return clamp_int(
        min(int(plan["effective_max_tokens"]), max(MIN_TRANSLATION_MAX_TOKENS, estimated_tokens)),
        MIN_TRANSLATION_MAX_TOKENS,
        MAX_TRANSLATION_MAX_TOKENS,
    )


def gpu_snapshot_response(snapshot: dict) -> dict:
    if not snapshot.get("available"):
        return {
            "available": False,
            "name": "",
            "free_mb": None,
            "total_mb": None,
            "free_gib": "",
            "total_gib": "",
            "summary": "未读取到可用显存，沿用手动 Tokens。",
        }

    free_mb = int(snapshot["free_mb"])
    total_mb = int(snapshot["total_mb"])
    return {
        "available": True,
        "name": snapshot["name"],
        "free_mb": free_mb,
        "total_mb": total_mb,
        "free_gib": f"{free_mb / 1024:.1f} GiB",
        "total_gib": f"{total_mb / 1024:.1f} GiB",
        "summary": f"{snapshot['name']} · 剩余 {free_mb / 1024:.1f} / {total_mb / 1024:.1f} GiB",
    }


def system_snapshot_response(snapshot: dict) -> dict:
    if not snapshot.get("available"):
        return {
            "available": False,
            "free_mb": None,
            "total_mb": None,
            "free_gib": "",
            "total_gib": "",
            "logical_cores": int(snapshot.get("logical_cores") or 1),
            "summary": "未读取到系统内存，按保守策略执行。",
        }

    free_mb = int(snapshot["free_mb"])
    total_mb = int(snapshot["total_mb"])
    logical_cores = int(snapshot.get("logical_cores") or 1)
    return {
        "available": True,
        "free_mb": free_mb,
        "total_mb": total_mb,
        "free_gib": f"{free_mb / 1024:.1f} GiB",
        "total_gib": f"{total_mb / 1024:.1f} GiB",
        "logical_cores": logical_cores,
        "summary": f"RAM 剩余 {free_mb / 1024:.1f} / {total_mb / 1024:.1f} GiB · CPU {logical_cores} 线程",
    }


def split_text_for_translation(text: str, max_chars: int) -> list[str]:
    normalized = text.replace("\r\n", "\n").strip()
    if not normalized:
        return []

    chunks: list[str] = []
    start = 0
    boundary_markers = ["\n\n", "\n", "。", "！", "？", "!", "?", "；", ";", "，", ",", " "]

    while start < len(normalized):
        remaining = len(normalized) - start
        if remaining <= max_chars:
            tail = normalized[start:].strip()
            if tail:
                chunks.append(tail)
            break

        window = normalized[start : start + max_chars + 1]
        split_at = -1
        search_from = max_chars // 2
        for marker in boundary_markers:
            index = window.rfind(marker, search_from)
            if index != -1:
                split_at = max(split_at, index + len(marker))

        if split_at <= 0:
            split_at = max_chars

        chunk = window[:split_at].strip()
        if not chunk:
            chunk = window[:max_chars].strip()
            split_at = max_chars

        chunks.append(chunk)
        start += split_at
        while start < len(normalized) and normalized[start].isspace():
            start += 1

    return chunks


def split_text_for_translation_v2(text: str, max_chars: int) -> list[str]:
    def find_split_at(segment: str, preferred: int, hard_limit: int) -> int:
        lower_bound = max(1, int(preferred * 0.45))
        window = segment[:hard_limit]
        primary_markers = ["\n\n", "\n", "。", "！", "？", "…", ".", "!", "?"]
        secondary_markers = ["；", ";", "：", ":", "，", ",", "、", "）", ")", "]", "”", "\"", "'", " "]

        best = -1
        for marker in primary_markers:
            index = window.rfind(marker, lower_bound)
            if index != -1:
                best = max(best, index + len(marker))
        if best > 0:
            return best

        for marker in secondary_markers:
            index = window.rfind(marker, lower_bound)
            if index != -1:
                best = max(best, index + len(marker))
        if best > 0:
            return best

        next_window = segment[: min(len(segment), hard_limit + max(24, preferred // 8))]
        next_space = next_window.find(" ", preferred)
        if next_space != -1:
            return next_space + 1
        return hard_limit

    def split_oversized_segment(segment: str) -> list[str]:
        pieces: list[str] = []
        remaining = segment.strip()
        while len(remaining) > max_chars:
            hard_limit = min(len(remaining), max_chars + max(24, max_chars // 8))
            split_at = find_split_at(remaining, max_chars, hard_limit)
            piece = remaining[:split_at].strip()
            if not piece:
                split_at = min(len(remaining), hard_limit)
                piece = remaining[:split_at].strip()
            pieces.append(piece)
            remaining = remaining[split_at:].lstrip()
        if remaining:
            pieces.append(remaining)
        return pieces

    normalized = text.replace("\r\n", "\n").strip()
    if not normalized:
        return []

    paragraph_groups = [part.strip() for part in re.split(r"\n{2,}", normalized) if part.strip()]
    if not paragraph_groups:
        return []

    sentence_pattern = re.compile(r".+?(?:[。！？!?…]+|[.;；:：](?=\s)|\n|$)", re.S)
    chunks: list[str] = []
    current = ""

    def flush_current() -> None:
        nonlocal current
        if current.strip():
            chunks.append(current.strip())
        current = ""

    for paragraph in paragraph_groups:
        if len(paragraph) <= max_chars:
            candidate = f"{current}\n\n{paragraph}".strip() if current else paragraph
            if len(candidate) <= max_chars:
                current = candidate
                continue
            flush_current()
            current = paragraph
            continue

        sentences = [match.group(0).strip() for match in sentence_pattern.finditer(paragraph) if match.group(0).strip()]
        if not sentences:
            sentences = [paragraph]

        for sentence in sentences:
            fragments = [sentence] if len(sentence) <= max_chars else split_oversized_segment(sentence)
            for fragment in fragments:
                separator = "\n\n" if current else ""
                candidate = f"{current}{separator}{fragment}" if current else fragment
                if len(candidate) <= max_chars:
                    current = candidate.strip()
                    continue
                flush_current()
                if len(fragment) <= max_chars:
                    current = fragment.strip()
                    continue
                for forced in split_oversized_segment(fragment):
                    if len(forced) <= max_chars:
                        if current:
                            flush_current()
                        current = forced.strip()
                    else:
                        chunks.append(forced[:max_chars].strip())
        flush_current()

    flush_current()
    return [chunk for chunk in chunks if chunk]


def split_text_for_translation_v3(text: str, max_chars: int) -> list[str]:
    normalized = text.replace("\r\n", "\n").strip()
    if not normalized:
        return []

    overflow = max(24, max_chars // 8)
    lower_bound = max(1, int(max_chars * 0.55))
    boundary_groups = [
        ["\n\n", "\n"],
        ["。", "！", "？", "……", "…", ".", "!", "?"],
        ["；", ";", "：", ":", "，", ",", "、", ")", "]", "}", "”", "\"", "'"],
        [" "],
    ]

    def find_first(markers: list[str], segment: str, start: int, end: int) -> int:
        best: int | None = None
        for marker in markers:
            index = segment.find(marker, start, end)
            if index != -1:
                candidate = index + len(marker)
                if best is None or candidate < best:
                    best = candidate
        return best or -1

    def find_last(markers: list[str], segment: str, start: int, end: int) -> int:
        best = -1
        for marker in markers:
            index = segment.rfind(marker, start, end)
            if index != -1:
                best = max(best, index + len(marker))
        return best

    def choose_split_point(segment: str) -> int:
        if len(segment) <= max_chars:
            return len(segment)

        hard_limit = min(len(segment), max_chars + overflow)
        preferred = max_chars
        tiny_tail_threshold = max(12, max_chars // 4)

        if len(segment) <= hard_limit:
            for markers in boundary_groups:
                split_at = find_first(markers, segment, preferred, len(segment))
                if split_at != -1:
                    return split_at
            return len(segment)

        for markers in boundary_groups:
            backward = find_last(markers, segment, lower_bound, preferred + 1)
            if backward != -1:
                remainder = len(segment) - backward
                if remainder < tiny_tail_threshold:
                    forward = find_first(markers, segment, preferred, hard_limit + 1)
                    if forward != -1:
                        return forward
                return backward

        for markers in boundary_groups:
            forward = find_first(markers, segment, preferred, hard_limit + 1)
            if forward != -1:
                return forward

        return hard_limit

    chunks: list[str] = []
    remaining = normalized

    while remaining:
        if len(remaining) <= max_chars:
            chunks.append(remaining.strip())
            break

        split_at = choose_split_point(remaining)
        piece = remaining[:split_at].strip()
        if not piece:
            split_at = min(len(remaining), max_chars)
            piece = remaining[:split_at].strip()

        chunks.append(piece)
        remaining = remaining[split_at:].lstrip()

    return [chunk for chunk in chunks if chunk]


def extract_stream_delta(payload: dict) -> str:
    choices = payload.get("choices") or []
    if not choices:
        return ""
    choice = choices[0] or {}
    delta = choice.get("delta") or {}
    if isinstance(delta, dict) and delta.get("content"):
        return str(delta.get("content"))
    if choice.get("text"):
        return str(choice.get("text"))
    message = choice.get("message") or {}
    if isinstance(message, dict) and message.get("content"):
        return str(message.get("content"))
    return ""


def request_translation_stream(config: dict, plan: dict, base_url: str, text: str):
    max_tokens = estimate_completion_tokens(plan, text)
    translated = ""
    with make_session() as session:
        with session.post(
            f"{base_url}/chat/completions",
            headers={
                "Authorization": f"Bearer {config['api_key']}",
                "Content-Type": "application/json",
            },
            json={
                "model": config["model_name"],
                "messages": build_messages(text, config["source_lang"], config["target_lang"]),
                "temperature": config["temperature"],
                "max_tokens": max_tokens,
                "stream": True,
            },
            timeout=int(plan["effective_timeout"]),
            stream=True,
        ) as response:
            response.raise_for_status()
            response.encoding = "utf-8"
            for raw_line in response.iter_lines(decode_unicode=True):
                if not raw_line:
                    continue
                line = raw_line.strip()
                if not line.startswith("data:"):
                    continue
                payload = line[5:].strip()
                if not payload or payload == "[DONE]":
                    continue
                event = json.loads(payload)
                delta = extract_stream_delta(event)
                if not delta:
                    continue
                translated += delta
                yield translated

    translated = translated.strip()
    if not translated:
        raise ValueError("LM Studio 返回了空结果。请尝试更换模型，或调大最大输出 Tokens。")


def join_translated_chunks(translated_chunks: list[str]) -> str:
    return ("\n\n".join(chunk for chunk in translated_chunks if chunk)).strip()


def request_translation(config: dict, plan: dict, base_url: str, text: str) -> str:
    max_tokens = estimate_completion_tokens(plan, text)
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
                "max_tokens": max_tokens,
            },
            timeout=int(plan["effective_timeout"]),
        )
    response.raise_for_status()
    payload = response.json()
    translated = payload["choices"][0]["message"]["content"].strip()
    if not translated:
        raise ValueError("LM Studio 返回了空结果。请尝试更换模型，或调大最大输出 Tokens。")
    return translated


def translate_text(config: dict, plan: dict, base_url: str, text: str) -> tuple[str, int]:
    chunks = split_text_for_translation_v3(text, estimate_chunk_char_limit(plan))
    if not chunks:
        return "", 0

    translated_chunks = [request_translation(config, plan, base_url, chunk) for chunk in chunks]
    joiner = "\n\n" if len(translated_chunks) > 1 else ""
    return joiner.join(translated_chunks), len(translated_chunks)


def stream_translate_text(config: dict, plan: dict, base_url: str, text: str):
    chunks = split_text_for_translation_v3(text, estimate_chunk_char_limit(plan))
    if not chunks:
        return

    translated_chunks = [""] * len(chunks)
    for chunk_index, chunk in enumerate(chunks, start=1):
        last_value = ""
        for partial in request_translation_stream(config, plan, base_url, chunk):
            last_value = partial
            translated_chunks[chunk_index - 1] = partial.strip()
            yield {
                "event": "progress",
                "chunk_index": chunk_index,
                "chunk_count": len(chunks),
                "translated_chunk": partial.strip(),
                "translated_text": join_translated_chunks(translated_chunks),
            }

        translated_chunks[chunk_index - 1] = last_value.strip()
        yield {
            "event": "chunk_done",
            "chunk_index": chunk_index,
            "chunk_count": len(chunks),
            "translated_chunk": translated_chunks[chunk_index - 1],
            "translated_text": join_translated_chunks(translated_chunks),
        }


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

    raw_device_id = request.cookies.get(DEVICE_ID_COOKIE_NAME)
    if raw_device_id and find_device_record(security.get("approved_devices", []), hash_device_id(raw_device_id)):
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


def get_lan_hostnames() -> list[str]:
    hostnames: list[str] = []
    seen: set[str] = set()
    for hostname in (socket.gethostname(), socket.getfqdn()):
        normalized = (hostname or "").strip().strip(".")
        if not normalized or normalized.lower() == "localhost":
            continue
        if normalized.lower() not in seen:
            seen.add(normalized.lower())
            hostnames.append(normalized)
    return hostnames


def get_lan_urls() -> list[str]:
    return [f"https://{address}:{APP_PORT}/" for address in get_private_ipv4_addresses()]


def get_hostname_urls() -> list[str]:
    return [f"https://{hostname}:{APP_PORT}/" for hostname in get_lan_hostnames()]


def get_bootstrap_urls() -> list[str]:
    return [f"http://{address}:{BOOTSTRAP_PORT}/bootstrap" for address in get_private_ipv4_addresses()]


def get_hostname_bootstrap_urls() -> list[str]:
    return [f"http://{hostname}:{BOOTSTRAP_PORT}/bootstrap" for hostname in get_lan_hostnames()]


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


def current_server_san_values() -> tuple[set[str], set[str]]:
    dns_values: set[str] = set()
    ip_values: set[str] = set()
    for san in build_server_sans():
        if isinstance(san, x509.DNSName):
            dns_values.add(san.value.lower())
        elif isinstance(san, x509.IPAddress):
            ip_values.add(str(san.value))
    return dns_values, ip_values


def server_certificate_matches_current_network() -> bool:
    if not SERVER_CERT_PATH.exists() or not SERVER_KEY_PATH.exists():
        return False

    try:
        server_cert = x509.load_pem_x509_certificate(SERVER_CERT_PATH.read_bytes())
        san_extension = server_cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    except (ValueError, x509.ExtensionNotFound):
        return False

    existing_dns = {value.lower() for value in san_extension.value.get_values_for_type(x509.DNSName)}
    existing_ips = {str(value) for value in san_extension.value.get_values_for_type(x509.IPAddress)}
    expected_dns, expected_ips = current_server_san_values()
    return expected_dns == existing_dns and expected_ips == existing_ips


def ensure_server_certificate(ca_key: rsa.RSAPrivateKey, ca_cert: x509.Certificate) -> None:
    if server_certificate_matches_current_network():
        return

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


def make_zip_info(filename: str, executable: bool = False) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(filename)
    info.compress_type = zipfile.ZIP_DEFLATED
    if executable:
        info.external_attr = 0o755 << 16
    return info


def preferred_lan_url(runtime: dict) -> str:
    lan_urls = runtime.get("lan_urls", [])
    return lan_urls[0] if lan_urls else runtime["local_url"]


def build_bundle_readme(platform_label: str, runtime: dict, install_file: str) -> str:
    lan_url = preferred_lan_url(runtime)
    return f"""LM Studio Translate Web 局域网接入包

适用系统：
{platform_label}

1. 运行同目录下的 {install_file}
2. 按提示把根证书导入当前系统信任区
3. 导入完成后，在这台电脑打开：
   {lan_url}
4. 首次登录时输入主机页面显示的 6 位 PIN

根证书 SHA-256 指纹：
{runtime["ca_thumbprint_display"]}
"""


def build_windows_onboarding_bundle(runtime: dict) -> bytes:
    cert_bytes = CA_CERT_PATH.read_bytes()
    lan_url = preferred_lan_url(runtime)
    bundle_readme = build_bundle_readme("Windows", runtime, "Install-RootCA.ps1")
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
        archive.writestr(make_zip_info("lmstudio-translate-root-ca.crt"), cert_bytes)
        archive.writestr(make_zip_info("Install-RootCA.ps1"), install_script.encode("utf-8"))
        archive.writestr(make_zip_info("README.txt"), bundle_readme.encode("utf-8"))
    return buffer.getvalue()


def build_macos_onboarding_bundle(runtime: dict) -> bytes:
    cert_bytes = CA_CERT_PATH.read_bytes()
    lan_url = preferred_lan_url(runtime)
    bundle_readme = build_bundle_readme("macOS", runtime, "Install-RootCA.command")
    install_script = f"""#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CERT_PATH="$SCRIPT_DIR/lmstudio-translate-root-ca.crt"

if [ ! -f "$CERT_PATH" ]; then
  echo "Certificate file not found: $CERT_PATH"
  exit 1
fi

sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain "$CERT_PATH"

echo ""
echo "根证书已导入系统钥匙串。"
echo "下一步："
echo "1. 打开 {lan_url}"
echo "2. 输入主机页面显示的 6 位 PIN"
echo ""
read -r -p "按回车键继续..."
"""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(make_zip_info("lmstudio-translate-root-ca.crt"), cert_bytes)
        archive.writestr(make_zip_info("Install-RootCA.command", executable=True), install_script.encode("utf-8"))
        archive.writestr(make_zip_info("README.txt"), bundle_readme.encode("utf-8"))
    return buffer.getvalue()


def build_linux_onboarding_bundle(runtime: dict) -> bytes:
    cert_bytes = CA_CERT_PATH.read_bytes()
    lan_url = preferred_lan_url(runtime)
    bundle_readme = build_bundle_readme("Linux", runtime, "install-root-ca.sh")
    install_script = f"""#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CERT_PATH="$SCRIPT_DIR/lmstudio-translate-root-ca.crt"

if [[ ! -f "$CERT_PATH" ]]; then
  echo "Certificate file not found: $CERT_PATH"
  exit 1
fi

if command -v update-ca-certificates >/dev/null 2>&1; then
  sudo cp "$CERT_PATH" /usr/local/share/ca-certificates/lmstudio-translate-root-ca.crt
  sudo update-ca-certificates
elif command -v update-ca-trust >/dev/null 2>&1; then
  sudo cp "$CERT_PATH" /etc/pki/ca-trust/source/anchors/lmstudio-translate-root-ca.crt
  sudo update-ca-trust
else
  echo "未检测到常见证书更新命令。请手动把证书导入系统信任区。"
fi

echo ""
echo "根证书导入流程已完成。"
echo "下一步："
echo "1. 打开 {lan_url}"
echo "2. 输入主机页面显示的 6 位 PIN"
echo ""
read -r -p "按回车键继续..."
"""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(make_zip_info("lmstudio-translate-root-ca.crt"), cert_bytes)
        archive.writestr(make_zip_info("install-root-ca.sh", executable=True), install_script.encode("utf-8"))
        archive.writestr(make_zip_info("README.txt"), bundle_readme.encode("utf-8"))
    return buffer.getvalue()


def platform_label(platform: str) -> str:
    return {
        "ios": "iPhone / iPad",
        "android": "Android",
        "windows": "Windows",
        "macos": "macOS",
        "linux": "Linux",
        "unknown": "未知系统",
    }.get(platform, platform)


def build_bundle_readme(platform_label: str, runtime: dict, install_file: str) -> str:
    lan_url = preferred_lan_url(runtime)
    return f"""LM Studio Translate Web 局域网接入包

适用系统：
{platform_label}

1. 运行同目录下的 {install_file}
2. 按提示把根证书导入当前系统信任区
3. 导入完成后，在这台设备上打开：
   {lan_url}
4. 打开网页后点击“发送接入申请”
5. 回到主机网页批准这台设备

根证书 SHA-256 指纹：
{runtime["ca_thumbprint_display"]}
"""


def build_windows_onboarding_bundle(runtime: dict) -> bytes:
    cert_bytes = CA_CERT_PATH.read_bytes()
    lan_url = preferred_lan_url(runtime)
    bundle_readme = build_bundle_readme("Windows", runtime, "Install-RootCA.ps1")
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
Write-Host "2. 在网页里点击发送接入申请"
Write-Host "3. 回到主机网页批准这台设备"
Write-Host ""
Pause
"""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(make_zip_info("lmstudio-translate-root-ca.crt"), cert_bytes)
        archive.writestr(make_zip_info("Install-RootCA.ps1"), install_script.encode("utf-8"))
        archive.writestr(make_zip_info("README.txt"), bundle_readme.encode("utf-8"))
    return buffer.getvalue()


def build_macos_onboarding_bundle(runtime: dict) -> bytes:
    cert_bytes = CA_CERT_PATH.read_bytes()
    lan_url = preferred_lan_url(runtime)
    bundle_readme = build_bundle_readme("macOS", runtime, "Install-RootCA.command")
    install_script = f"""#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CERT_PATH="$SCRIPT_DIR/lmstudio-translate-root-ca.crt"

if [ ! -f "$CERT_PATH" ]; then
  echo "Certificate file not found: $CERT_PATH"
  exit 1
fi

sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain "$CERT_PATH"

echo ""
echo "根证书已导入系统钥匙串。"
echo "下一步："
echo "1. 打开 {lan_url}"
echo "2. 在网页里点击发送接入申请"
echo "3. 回到主机网页批准这台设备"
echo ""
read -r -p "按回车键继续..."
"""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(make_zip_info("lmstudio-translate-root-ca.crt"), cert_bytes)
        archive.writestr(make_zip_info("Install-RootCA.command", executable=True), install_script.encode("utf-8"))
        archive.writestr(make_zip_info("README.txt"), bundle_readme.encode("utf-8"))
    return buffer.getvalue()


def build_linux_onboarding_bundle(runtime: dict) -> bytes:
    cert_bytes = CA_CERT_PATH.read_bytes()
    lan_url = preferred_lan_url(runtime)
    bundle_readme = build_bundle_readme("Linux", runtime, "install-root-ca.sh")
    install_script = f"""#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CERT_PATH="$SCRIPT_DIR/lmstudio-translate-root-ca.crt"

if [[ ! -f "$CERT_PATH" ]]; then
  echo "Certificate file not found: $CERT_PATH"
  exit 1
fi

if command -v update-ca-certificates >/dev/null 2>&1; then
  sudo cp "$CERT_PATH" /usr/local/share/ca-certificates/lmstudio-translate-root-ca.crt
  sudo update-ca-certificates
elif command -v update-ca-trust >/dev/null 2>&1; then
  sudo cp "$CERT_PATH" /etc/pki/ca-trust/source/anchors/lmstudio-translate-root-ca.crt
  sudo update-ca-trust
else
  echo "未检测到常见证书更新命令。请手动把证书导入系统信任区。"
fi

echo ""
echo "根证书导入流程已完成。"
echo "下一步："
echo "1. 打开 {lan_url}"
echo "2. 在网页里点击发送接入申请"
echo "3. 回到主机网页批准这台设备"
echo ""
read -r -p "按回车键继续..."
"""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(make_zip_info("lmstudio-translate-root-ca.crt"), cert_bytes)
        archive.writestr(make_zip_info("install-root-ca.sh", executable=True), install_script.encode("utf-8"))
        archive.writestr(make_zip_info("README.txt"), bundle_readme.encode("utf-8"))
    return buffer.getvalue()


def build_qr_svg_data_uri(value: str) -> str:
    qr = qrcode.QRCode(border=1, box_size=8)
    qr.add_data(value)
    qr.make(fit=True)
    image = qr.make_image(image_factory=qrcode.image.svg.SvgPathImage)
    buffer = io.BytesIO()
    image.save(buffer)
    svg = buffer.getvalue().decode("utf-8").replace("#", "%23").replace("\n", "")
    return f"data:image/svg+xml;utf8,{svg}"


def build_apple_mobileconfig(runtime: dict) -> bytes:
    cert_text = CA_CERT_PATH.read_text(encoding="utf-8")
    cert_b64 = (
        cert_text.replace("-----BEGIN CERTIFICATE-----", "")
        .replace("-----END CERTIFICATE-----", "")
        .replace("\n", "")
        .strip()
    )
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>PayloadContent</key>
  <array>
    <dict>
      <key>PayloadCertificateFileName</key>
      <string>lmstudio-translate-root-ca.crt</string>
      <key>PayloadContent</key>
      <data>{cert_b64}</data>
      <key>PayloadDescription</key>
      <string>Install LM Studio Translate Root CA</string>
      <key>PayloadDisplayName</key>
      <string>LM Studio Translate Root CA</string>
      <key>PayloadIdentifier</key>
      <string>local.lmstudio.translate.rootca.cert</string>
      <key>PayloadType</key>
      <string>com.apple.security.root</string>
      <key>PayloadUUID</key>
      <string>{secrets.token_hex(16)}</string>
      <key>PayloadVersion</key>
      <integer>1</integer>
    </dict>
  </array>
  <key>PayloadDescription</key>
  <string>Install LM Studio Translate Root CA for iPhone and iPad access.</string>
  <key>PayloadDisplayName</key>
  <string>LM Studio Translate Mobile Access</string>
  <key>PayloadIdentifier</key>
  <string>local.lmstudio.translate.mobile</string>
  <key>PayloadRemovalDisallowed</key>
  <false/>
  <key>PayloadType</key>
  <string>Configuration</string>
  <key>PayloadUUID</key>
  <string>{secrets.token_hex(16)}</string>
  <key>PayloadVersion</key>
  <integer>1</integer>
</dict>
</plist>
""".encode("utf-8")


def detect_client_platform(user_agent: str | None) -> str:
    ua = (user_agent or "").lower()
    if "iphone" in ua or "ipad" in ua or "ipod" in ua:
        return "ios"
    if "android" in ua:
        return "android"
    if "windows" in ua:
        return "windows"
    if "mac os x" in ua or "macintosh" in ua:
        return "macos"
    if "linux" in ua or "x11" in ua:
        return "linux"
    return "unknown"


def platform_label(platform: str) -> str:
    return {
        "ios": "iPhone / iPad",
        "android": "Android",
        "windows": "Windows",
        "macos": "macOS",
        "linux": "Linux",
        "unknown": "未知系统",
    }.get(platform, platform)


def build_platform_onboarding_bundle(runtime: dict, platform: str) -> tuple[bytes, str]:
    if platform == "windows":
        return build_windows_onboarding_bundle(runtime), "lmstudio-lan-windows-bundle.zip"
    if platform == "macos":
        return build_macos_onboarding_bundle(runtime), "lmstudio-lan-macos-bundle.zip"
    if platform == "linux":
        return build_linux_onboarding_bundle(runtime), "lmstudio-lan-linux-bundle.zip"
    if platform == "ios":
        return build_apple_mobileconfig(runtime), "lmstudio-translate.mobileconfig"
    if platform == "android":
        return CA_CERT_PATH.read_bytes(), "lmstudio-translate-root-ca.crt"
    return build_windows_onboarding_bundle(runtime), "lmstudio-lan-windows-bundle.zip"


def summarize_device_access(security: dict) -> dict:
    pending_devices = sorted(
        (device_record_payload(device) for device in security.get("pending_devices", [])),
        key=lambda item: item.get("last_requested_at_display", ""),
        reverse=True,
    )
    approved_devices = sorted(
        (device_record_payload(device) for device in security.get("approved_devices", [])),
        key=lambda item: item.get("last_seen_at_display", ""),
        reverse=True,
    )
    return {
        "pending_devices": pending_devices,
        "approved_devices": approved_devices,
        "pending_count": len(pending_devices),
        "approved_count": len(approved_devices),
    }


def build_access_request_context(security: dict, raw_device_id: str) -> dict:
    platform = current_device_platform()
    remote_ip = current_device_ip()
    status, record = current_device_status(security, raw_device_id)
    record_payload = device_record_payload(record) if record else None
    return {
        "access_status": status,
        "device_label": (record or {}).get("device_label") or default_device_label(platform, remote_ip),
        "device_platform_label": platform_label(platform),
        "device_ip": remote_ip,
        "request_record": record_payload,
    }


def prepare_runtime() -> dict:
    security = load_security_config()
    ca_key, ca_cert = ensure_ca_certificate()
    ensure_server_certificate(ca_key, ca_cert)
    thumbprint = certificate_thumbprint(ca_cert)
    lan_urls = get_lan_urls()
    hostname_urls = get_hostname_urls()
    bootstrap_urls = get_bootstrap_urls()
    hostname_bootstrap_urls = get_hostname_bootstrap_urls()
    preferred_bootstrap_url = (
        bootstrap_urls[0]
        if bootstrap_urls
        else (hostname_bootstrap_urls[0] if hostname_bootstrap_urls else f"http://127.0.0.1:{BOOTSTRAP_PORT}/bootstrap")
    )
    device_access = summarize_device_access(security)

    return {
        "local_url": f"https://127.0.0.1:{APP_PORT}/",
        "lan_urls": lan_urls,
        "hostname_urls": hostname_urls,
        "bootstrap_urls": bootstrap_urls,
        "hostname_bootstrap_urls": hostname_bootstrap_urls,
        "preferred_bootstrap_url": preferred_bootstrap_url,
        "mobile_bootstrap_qr_data_uri": build_qr_svg_data_uri(preferred_bootstrap_url),
        "ca_cert_path": str(CA_CERT_PATH),
        "ca_thumbprint": thumbprint,
        "ca_thumbprint_display": format_thumbprint(thumbprint),
        "server_cert_path": str(SERVER_CERT_PATH),
        "server_key_path": str(SERVER_KEY_PATH),
        **device_access,
    }


class ThreadedWSGIServer(ThreadingMixIn, WSGIServer):
    daemon_threads = True
    allow_reuse_address = True


class ReloadingSSLWSGIServer(ThreadedWSGIServer):
    certfile: str = ""
    keyfile: str = ""

    def get_request(self):
        client_socket, client_address = super().get_request()
        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_context.load_cert_chain(certfile=self.certfile, keyfile=self.keyfile)
        return ssl_context.wrap_socket(client_socket, server_side=True), client_address


class QuietWSGIRequestHandler(WSGIRequestHandler):
    def log_message(self, format: str, *args) -> None:
        return


def run_http_bootstrap_server() -> None:
    with make_server(
        APP_HOST,
        BOOTSTRAP_PORT,
        app,
        server_class=ThreadedWSGIServer,
        handler_class=QuietWSGIRequestHandler,
    ) as server:
        server.serve_forever()


def run_https_server(runtime: dict) -> None:
    ReloadingSSLWSGIServer.certfile = runtime["server_cert_path"]
    ReloadingSSLWSGIServer.keyfile = runtime["server_key_path"]
    with make_server(
        APP_HOST,
        APP_PORT,
        app,
        server_class=ReloadingSSLWSGIServer,
        handler_class=QuietWSGIRequestHandler,
    ) as server:
        server.serve_forever()


def get_request_port() -> int | None:
    try:
        return int(request.host.split(":")[-1])
    except (ValueError, AttributeError):
        return None


def is_bootstrap_request() -> bool:
    return not request.is_secure and get_request_port() == BOOTSTRAP_PORT


@app.before_request
def restrict_client_network():
    remote_ip = get_remote_ip()
    if not is_private_client(remote_ip):
        return make_response("只允许本机或局域网私有地址访问。", 403)

    if is_bootstrap_request():
        allowed_endpoints = {"bootstrap", "download_bundle", "download_public_ca_cert", "static"}
        if request.endpoint not in allowed_endpoints:
            return redirect(url_for("bootstrap"))
        return None

    security = load_security_config()
    protected_endpoints = {"api_models", "api_translate", "api_translate_stream"}
    if request.endpoint in protected_endpoints and not is_authorized_client(security):
        return jsonify({"ok": False, "error": "未授权。请先发送接入申请，并等待主端批准。"}), 403


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
    if is_bootstrap_request():
        return redirect(url_for("bootstrap"))

    security = load_security_config()
    runtime = prepare_runtime()
    raw_device_id, should_set_device_cookie = ensure_device_id()
    if not is_authorized_client(security):
        response = make_response(
            render_template(
                "login.html",
                error_message="",
                **build_access_request_context(security, raw_device_id),
            )
        )
        if should_set_device_cookie:
            attach_device_cookie(response, raw_device_id)
        return response

    if not is_local_admin_request():
        if find_device_record(security.get("approved_devices", []), hash_device_id(raw_device_id)) is None:
            queue_device_access_request(security, raw_device_id)
            approve_device_request(security, hash_device_id(raw_device_id))
            security = load_security_config()
        touch_approved_device(security, raw_device_id)

    config = load_config()
    base_url, models, model_error = resolve_lmstudio_base_url(config)
    if base_url:
        config["base_url"] = base_url
    if models and (not config["model_name"] or config["model_name"] not in models):
        config["model_name"] = pick_default_model(models)
    save_config(config)

    response = make_response(
        render_template(
            "index.html",
            config=config,
            models=models,
            language_options=LANGUAGE_OPTIONS,
            initial_error=model_error or "",
            lan_urls=runtime["lan_urls"] if is_local_admin_request() else [],
            hostname_urls=runtime["hostname_urls"] if is_local_admin_request() else [],
            bootstrap_urls=runtime["bootstrap_urls"] if is_local_admin_request() else [],
            hostname_bootstrap_urls=runtime["hostname_bootstrap_urls"] if is_local_admin_request() else [],
            preferred_bootstrap_url=runtime["preferred_bootstrap_url"] if is_local_admin_request() else "",
            mobile_bootstrap_qr_data_uri=runtime["mobile_bootstrap_qr_data_uri"] if is_local_admin_request() else "",
            ca_thumbprint_display=runtime["ca_thumbprint_display"] if is_local_admin_request() else "",
            pending_devices=runtime["pending_devices"] if is_local_admin_request() else [],
            approved_devices=runtime["approved_devices"] if is_local_admin_request() else [],
            pending_count=runtime["pending_count"] if is_local_admin_request() else 0,
            approved_count=runtime["approved_count"] if is_local_admin_request() else 0,
            local_admin=is_local_admin_request(),
        )
    )
    if should_set_device_cookie and not is_local_admin_request():
        attach_device_cookie(response, raw_device_id)
    return response


@app.post("/access/request")
def access_request():
    security = load_security_config()
    raw_device_id, should_set_device_cookie = ensure_device_id()
    payload = request.get_json(silent=True) or {}
    record = queue_device_access_request(security, raw_device_id, payload.get("device_label"))
    approved = find_device_record(security.get("approved_devices", []), hash_device_id(raw_device_id)) is not None
    message = "这台设备已经被批准，正在进入翻译页。" if approved else "接入申请已提交，请到主端网页批准这台设备。"
    response = make_response(
        jsonify(
            {
                "ok": True,
                "status": "approved" if approved else "pending",
                "message": message,
                "request_record": device_record_payload(record),
            }
        )
    )
    if should_set_device_cookie:
        attach_device_cookie(response, raw_device_id)
    return response


@app.get("/access/status")
def access_status():
    security = load_security_config()
    raw_device_id, should_set_device_cookie = ensure_device_id()
    status, record = current_device_status(security, raw_device_id)
    response = make_response(
        jsonify(
            {
                "ok": True,
                "status": status,
                "authorized": status == "approved",
                "request_record": device_record_payload(record) if record else None,
            }
        )
    )
    if should_set_device_cookie:
        attach_device_cookie(response, raw_device_id)
    return response


@app.post("/logout")
def logout():
    security = load_security_config()
    raw_device_id = request.cookies.get(DEVICE_ID_COOKIE_NAME)
    if raw_device_id:
        device_id_hash = hash_device_id(raw_device_id)
        revoke_approved_device(security, device_id_hash)
        reject_device_request(security, device_id_hash)
    remove_device_session(security, request.cookies.get(COOKIE_NAME))
    response = make_response(redirect(url_for("index")))
    response.delete_cookie(COOKIE_NAME)
    response.delete_cookie(DEVICE_ID_COOKIE_NAME)
    return response


@app.post("/login")
def login():
    return make_response(("此版本已改为主端审批，不再使用 PIN 登录。", 410))


@app.post("/admin/pin/regenerate")
def regenerate_pin():
    return jsonify({"ok": False, "error": "此版本已改为主端审批，不再使用 PIN。"}), 410


@app.get("/admin/runtime")
def admin_runtime():
    if not is_local_admin_request():
        return jsonify({"ok": False, "error": "仅允许本机查看局域网接入信息。"}), 403

    runtime = prepare_runtime()
    return jsonify(
        {
            "ok": True,
            "lan_urls": runtime["lan_urls"],
            "hostname_urls": runtime["hostname_urls"],
            "bootstrap_urls": runtime["bootstrap_urls"],
            "hostname_bootstrap_urls": runtime["hostname_bootstrap_urls"],
            "preferred_bootstrap_url": runtime["preferred_bootstrap_url"],
            "mobile_bootstrap_qr_data_uri": runtime["mobile_bootstrap_qr_data_uri"],
            "pending_devices": runtime["pending_devices"],
            "approved_devices": runtime["approved_devices"],
            "pending_count": runtime["pending_count"],
            "approved_count": runtime["approved_count"],
        }
    )


@app.post("/admin/access/approve")
def approve_access_device():
    if not is_local_admin_request():
        return jsonify({"ok": False, "error": "仅允许本机管理员审批设备。"}), 403

    payload = request.get_json(silent=True) or {}
    device_id_hash = str(payload.get("device_id_hash", "")).strip()
    if not device_id_hash:
        return jsonify({"ok": False, "error": "缺少设备标识。"}), 400

    security = load_security_config()
    try:
        approve_device_request(security, device_id_hash)
    except ValueError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 404
    runtime = prepare_runtime()
    return jsonify(
        {
            "ok": True,
            "message": "已批准这台设备，后续它会长期保持访问权限，直到你手动撤销。",
            "pending_devices": runtime["pending_devices"],
            "approved_devices": runtime["approved_devices"],
            "pending_count": runtime["pending_count"],
            "approved_count": runtime["approved_count"],
        }
    )


@app.post("/admin/access/reject")
def reject_access_device():
    if not is_local_admin_request():
        return jsonify({"ok": False, "error": "仅允许本机管理员拒绝设备。"}), 403

    payload = request.get_json(silent=True) or {}
    device_id_hash = str(payload.get("device_id_hash", "")).strip()
    if not device_id_hash:
        return jsonify({"ok": False, "error": "缺少设备标识。"}), 400

    security = load_security_config()
    if not reject_device_request(security, device_id_hash):
        return jsonify({"ok": False, "error": "未找到待审批设备。"}), 404
    runtime = prepare_runtime()
    return jsonify(
        {
            "ok": True,
            "message": "已拒绝这台设备的接入申请。",
            "pending_devices": runtime["pending_devices"],
            "approved_devices": runtime["approved_devices"],
            "pending_count": runtime["pending_count"],
            "approved_count": runtime["approved_count"],
        }
    )


@app.post("/admin/access/revoke")
def revoke_access_device():
    if not is_local_admin_request():
        return jsonify({"ok": False, "error": "仅允许本机管理员撤销设备。"}), 403

    payload = request.get_json(silent=True) or {}
    device_id_hash = str(payload.get("device_id_hash", "")).strip()
    if not device_id_hash:
        return jsonify({"ok": False, "error": "缺少设备标识。"}), 400

    security = load_security_config()
    if not revoke_approved_device(security, device_id_hash):
        return jsonify({"ok": False, "error": "未找到已批准设备。"}), 404
    runtime = prepare_runtime()
    return jsonify(
        {
            "ok": True,
            "message": "已撤销这台设备的长期访问权限。",
            "pending_devices": runtime["pending_devices"],
            "approved_devices": runtime["approved_devices"],
            "pending_count": runtime["pending_count"],
            "approved_count": runtime["approved_count"],
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


@app.get("/bootstrap")
def bootstrap():
    runtime = prepare_runtime()
    detected_platform = detect_client_platform(request.headers.get("User-Agent"))
    bundle_platform = detected_platform if detected_platform != "unknown" else "windows"
    return render_template(
        "bootstrap.html",
        detected_platform=detected_platform,
        detected_platform_label=platform_label(detected_platform),
        bundle_platform=bundle_platform,
        runtime=runtime,
    )


@app.get("/download/root-ca")
def download_public_ca_cert():
    prepare_runtime()
    return send_file(
        CA_CERT_PATH,
        as_attachment=True,
        download_name="lmstudio-translate-root-ca.crt",
        mimetype="application/x-x509-ca-cert",
    )


@app.get("/download/bundle")
def download_bundle():
    runtime = prepare_runtime()
    requested_platform = str(request.args.get("platform", "auto")).strip().lower()
    if requested_platform == "auto":
        requested_platform = detect_client_platform(request.headers.get("User-Agent"))
    if requested_platform not in {"windows", "macos", "linux", "ios", "android"}:
        requested_platform = "windows"

    bundle, filename = build_platform_onboarding_bundle(runtime, requested_platform)
    response = make_response(bundle)
    if filename.endswith(".mobileconfig"):
        response.headers["Content-Type"] = "application/x-apple-aspen-config"
    elif filename.endswith(".crt"):
        response.headers["Content-Type"] = "application/x-x509-ca-cert"
    else:
        response.headers["Content-Type"] = "application/zip"
    response.headers["Content-Disposition"] = f'attachment; filename="{filename}"'
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
    queue_state = TRANSLATION_QUEUE.acquire()
    plan = build_translation_plan(config, source_text)
    started_at = time.perf_counter()

    try:
        translated_text, chunk_count = translate_text(config, plan, config["base_url"], source_text)
    except Exception as exc:
        TRANSLATION_QUEUE.release()
        return jsonify({"ok": False, "error": format_request_error(exc, "翻译")}), 400

    TRANSLATION_QUEUE.release()
    elapsed_ms = round((time.perf_counter() - started_at) * 1000, 1)

    message = "翻译完成。"
    if chunk_count > 1:
        message = f"长文本已自动分段翻译，共 {chunk_count} 段。"
    if queue_state["queued_ahead"] > 0 or queue_state["wait_ms"] >= 200:
        message += (
            f" 提交时前面有 {queue_state['queued_ahead']} 个任务，"
            f"等待 {round(queue_state['wait_ms'] / 1000, 2)} 秒后开始。"
        )

    return jsonify(
        {
            "ok": True,
            "translated_text": translated_text,
            "base_url": config["base_url"],
            "message": message,
            "model_name": config["model_name"],
            "chunk_count": chunk_count,
            "elapsed_ms": elapsed_ms,
            "elapsed_seconds": round(elapsed_ms / 1000, 2),
            "effective_max_tokens": plan["effective_max_tokens"],
            "configured_max_tokens": plan["configured_max_tokens"],
            "chunk_char_limit": plan["chunk_char_limit"],
            "effective_timeout": plan["effective_timeout"],
            "hardware_tier": plan["hardware_tier"],
            "estimated_chunk_count": plan["estimated_chunk_count"],
            "tuning_summary": plan["tuning_summary"],
            "auto_tokens_enabled": plan["auto_tokens_enabled"],
            "gpu": gpu_snapshot_response(plan["gpu_snapshot"]),
            "system": system_snapshot_response(plan["memory_snapshot"]),
            "queue_wait_ms": queue_state["wait_ms"],
            "queue_wait_seconds": round(queue_state["wait_ms"] / 1000, 2),
            "queue_position_at_submit": queue_state["queued_ahead"] + 1,
        }
    )


@app.post("/api/translate/stream")
def api_translate_stream():
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
    queue_state = TRANSLATION_QUEUE.acquire()
    plan = build_translation_plan(config, source_text)
    chunks = split_text_for_translation_v3(source_text, estimate_chunk_char_limit(plan))

    def stream_event(payload: dict) -> str:
        return json.dumps(payload, ensure_ascii=False) + "\n"

    def build_completion_message(chunk_count: int) -> str:
        message = "翻译完成。"
        if chunk_count > 1:
            message = f"长文本已自动分段翻译，共 {chunk_count} 段。"
        if queue_state["queued_ahead"] > 0 or queue_state["wait_ms"] >= 200:
            message += (
                f" 提交时前面有 {queue_state['queued_ahead']} 个任务，"
                f"等待 {round(queue_state['wait_ms'] / 1000, 2)} 秒后开始。"
            )
        return message

    @stream_with_context
    def generate():
        started_at = time.perf_counter()
        translated_chunks = [""] * len(chunks)
        try:
            yield stream_event(
                {
                    "ok": True,
                    "event": "start",
                    "chunk_count": len(chunks),
                    "queue_wait_ms": queue_state["wait_ms"],
                    "queue_wait_seconds": round(queue_state["wait_ms"] / 1000, 2),
                    "queue_position_at_submit": queue_state["queued_ahead"] + 1,
                }
            )

            for chunk_index, chunk in enumerate(chunks, start=1):
                last_partial = ""
                for partial in request_translation_stream(config, plan, config["base_url"], chunk):
                    last_partial = partial.strip()
                    translated_chunks[chunk_index - 1] = last_partial
                    partial_ratio = (
                        (chunk_index - 1)
                        + min(0.92, max(0.08, len(last_partial) / max(1, len(chunk))))
                    ) / max(1, len(chunks))
                    yield stream_event(
                        {
                            "ok": True,
                            "event": "progress",
                            "chunk_index": chunk_index,
                            "chunk_count": len(chunks),
                            "translated_chunk": last_partial,
                            "translated_text": join_translated_chunks(translated_chunks),
                            "progress_ratio": round(partial_ratio, 4),
                        }
                    )

                translated_chunks[chunk_index - 1] = last_partial
                yield stream_event(
                    {
                        "ok": True,
                        "event": "chunk_done",
                        "chunk_index": chunk_index,
                        "chunk_count": len(chunks),
                        "translated_chunk": last_partial,
                        "translated_text": join_translated_chunks(translated_chunks),
                        "progress_ratio": round(chunk_index / max(1, len(chunks)), 4),
                    }
                )

            elapsed_ms = round((time.perf_counter() - started_at) * 1000, 1)
            yield stream_event(
                {
                    "ok": True,
                    "event": "done",
                    "translated_text": join_translated_chunks(translated_chunks),
                    "base_url": config["base_url"],
                    "message": build_completion_message(len(chunks)),
                    "model_name": config["model_name"],
                    "chunk_count": len(chunks),
                    "elapsed_ms": elapsed_ms,
                    "elapsed_seconds": round(elapsed_ms / 1000, 2),
                    "effective_max_tokens": plan["effective_max_tokens"],
                    "configured_max_tokens": plan["configured_max_tokens"],
                    "chunk_char_limit": plan["chunk_char_limit"],
                    "effective_timeout": plan["effective_timeout"],
                    "hardware_tier": plan["hardware_tier"],
                    "estimated_chunk_count": plan["estimated_chunk_count"],
                    "tuning_summary": plan["tuning_summary"],
                    "auto_tokens_enabled": plan["auto_tokens_enabled"],
                    "gpu": gpu_snapshot_response(plan["gpu_snapshot"]),
                    "system": system_snapshot_response(plan["memory_snapshot"]),
                    "queue_wait_ms": queue_state["wait_ms"],
                    "queue_wait_seconds": round(queue_state["wait_ms"] / 1000, 2),
                    "queue_position_at_submit": queue_state["queued_ahead"] + 1,
                }
            )
        except Exception as exc:
            yield stream_event(
                {
                    "ok": False,
                    "event": "error",
                    "error": format_request_error(exc, "翻译"),
                }
            )
        finally:
            TRANSLATION_QUEUE.release()

    return Response(generate(), content_type="application/x-ndjson; charset=utf-8")


if __name__ == "__main__":
    runtime = prepare_runtime()
    threading.Thread(target=run_http_bootstrap_server, daemon=True).start()
    run_https_server(runtime)
