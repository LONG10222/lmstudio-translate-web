from __future__ import annotations

import ipaddress
import json
from pathlib import Path
from urllib.parse import urlparse

import requests
from flask import Flask, jsonify, render_template, request
from requests import exceptions as request_exceptions


BASE_DIR = Path(__file__).resolve().parent
CONFIG_PATH = BASE_DIR / "config.json"

DEFAULT_CONFIG = {
    "base_url": "http://127.0.0.1:1234/v1",
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


def normalize_base_url(base_url: str) -> str:
    url = (base_url or "").strip()
    if not url:
        url = DEFAULT_CONFIG["base_url"]
    return url.rstrip("/")


def ensure_local_base_url(base_url: str) -> str:
    normalized = normalize_base_url(base_url)
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


def list_models(config: dict) -> tuple[list[str], str | None]:
    try:
        base_url = ensure_local_base_url(config["base_url"])
        with make_session() as session:
            response = session.get(
                f"{base_url}/models",
                headers={"Authorization": f"Bearer {config['api_key']}"},
                timeout=10,
            )
        response.raise_for_status()
        payload = response.json()
        models = [item["id"] for item in payload.get("data", []) if item.get("id")]
        return models, None
    except Exception as exc:
        return [], format_request_error(exc, "读取模型列表")


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
            f"{action}失败：无法连接到 LM Studio 本地接口。"
            "请确认 LM Studio 已启动，并且本地服务正在监听 "
            "http://127.0.0.1:1234 。"
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


def translate_text(config: dict, text: str) -> str:
    base_url = ensure_local_base_url(config["base_url"])
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


@app.get("/")
def index():
    config = load_config()
    models, model_error = list_models(config)
    if not config["model_name"] and models:
        config["model_name"] = pick_default_model(models)
        save_config(config)

    return render_template(
        "index.html",
        config=config,
        models=models,
        language_options=LANGUAGE_OPTIONS,
        initial_error=model_error or "",
    )


@app.post("/api/models")
def api_models():
    payload = request.get_json(silent=True) or {}
    config = sanitize_config(payload)
    save_config(config)

    models, error_message = list_models(config)
    if error_message:
        return jsonify({"ok": False, "error": error_message}), 400

    if not config["model_name"] and models:
        config["model_name"] = pick_default_model(models)
        save_config(config)

    return jsonify(
        {
            "ok": True,
            "models": models,
            "model_name": config["model_name"],
            "message": f"已刷新模型列表，共 {len(models)} 个模型。",
        }
    )


@app.post("/api/translate")
def api_translate():
    payload = request.get_json(silent=True) or {}
    config = sanitize_config(payload)
    source_text = str(payload.get("source_text", "")).strip()

    if not source_text:
        return jsonify({"ok": False, "error": "请输入要翻译的文本。"}), 400

    models, error_message = list_models(config)
    if error_message:
        return jsonify({"ok": False, "error": error_message}), 400

    if not config["model_name"]:
        config["model_name"] = pick_default_model(models)

    if not config["model_name"]:
        return jsonify({"ok": False, "error": "请先选择或手动填写模型名。"}), 400

    save_config(config)

    try:
        translated_text = translate_text(config, source_text)
    except Exception as exc:
        return jsonify({"ok": False, "error": format_request_error(exc, "翻译")}), 400

    return jsonify(
        {
            "ok": True,
            "translated_text": translated_text,
            "message": "翻译完成。",
            "model_name": config["model_name"],
        }
    )


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=7870, debug=False)
