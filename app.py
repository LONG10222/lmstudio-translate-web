from __future__ import annotations

import ipaddress
import json
import secrets
from pathlib import Path
from urllib.parse import urlparse

import requests
from flask import Flask, jsonify, make_response, redirect, render_template, request, url_for
from requests import exceptions as request_exceptions


BASE_DIR = Path(__file__).resolve().parent
CONFIG_PATH = BASE_DIR / "config.json"
SECURITY_PATH = BASE_DIR / "security.json"
COOKIE_NAME = "lmstudio_translate_session"
APP_HOST = "0.0.0.0"
APP_PORT = 7870
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
    if SECURITY_PATH.exists():
        with open(SECURITY_PATH, "r", encoding="utf-8") as file:
            security = json.load(file)
    else:
        security = {}

    if not security.get("lan_access_token"):
        security["lan_access_token"] = secrets.token_urlsafe(24)
        save_security_config(security)

    return security


def save_security_config(security: dict) -> None:
    with open(SECURITY_PATH, "w", encoding="utf-8") as file:
        json.dump(security, file, ensure_ascii=False, indent=2)


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


def is_authorized_client(security: dict) -> bool:
    remote_ip = get_remote_ip()
    if remote_ip and remote_ip.is_loopback:
        return True
    return request.cookies.get(COOKIE_NAME) == security["lan_access_token"]


def is_admin_view(security: dict) -> bool:
    remote_ip = get_remote_ip()
    return bool(remote_ip and remote_ip.is_loopback and is_authorized_client(security))


@app.before_request
def restrict_client_network():
    remote_ip = get_remote_ip()
    if not is_private_client(remote_ip):
        return make_response("只允许本机或局域网私有地址访问。", 403)

    security = load_security_config()
    if request.endpoint and request.endpoint.startswith("api_") and not is_authorized_client(security):
        return jsonify({"ok": False, "error": "未授权。请先在局域网访问页输入访问令牌。"}), 403


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
        lan_access_token=security["lan_access_token"] if is_admin_view(security) else "",
    )


@app.post("/login")
def login():
    security = load_security_config()
    token = request.form.get("access_token", "").strip()
    if token != security["lan_access_token"]:
        return render_template("login.html", error_message="访问令牌错误。"), 403

    response = make_response(redirect(url_for("index")))
    response.set_cookie(
        COOKIE_NAME,
        token,
        max_age=12 * 60 * 60,
        httponly=True,
        samesite="Strict",
        secure=request.is_secure,
    )
    return response


@app.post("/logout")
def logout():
    response = make_response(redirect(url_for("index")))
    response.delete_cookie(COOKIE_NAME)
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
    load_security_config()
    app.run(host=APP_HOST, port=APP_PORT, debug=False)
