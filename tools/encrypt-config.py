#!/usr/bin/env python3
"""Generate site/encrypted-config.js without logging plaintext secrets."""

from __future__ import annotations

import base64
import getpass
import json
import os
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

ITERATIONS = 310_000
AAD = b"dental-dispute-ai/api-key/v1"
OUTPUT = Path(__file__).resolve().parents[1] / "site" / "encrypted-config.js"


def b64(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def main() -> None:
    api_key = os.environ.get("FEIFEIMIAO_API_KEY") or getpass.getpass("FEIFEIMIAO API Key（输入不回显）：")
    password = os.environ.get("SHARED_ACCESS_PASSWORD") or getpass.getpass("共享访问密码（输入不回显）：")
    if len(api_key) < 16 or any(char.isspace() for char in api_key):
        raise SystemExit("API Key 格式不合理。")
    if len(password) < 8:
        raise SystemExit("共享访问密码至少需要 8 个字符。")

    salt = os.urandom(16)
    iv = os.urandom(12)
    key = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=ITERATIONS).derive(password.encode())
    ciphertext = AESGCM(key).encrypt(iv, api_key.encode(), AAD)
    config = {
        "version": 1,
        "baseUrl": "https://api.feifeimiao.top/v1",
        "endpoint": "https://api.feifeimiao.top/v1/responses",
        "model": "gpt-5.4",
        "reasoningEffort": "xhigh",
        "maxOutputTokens": 2400,
        "timeoutMs": 90000,
        "dailyLimit": 30,
        "minRequestIntervalMs": 4000,
        "iterations": ITERATIONS,
        "salt": b64(salt),
        "iv": b64(iv),
        "ciphertext": b64(ciphertext),
        "aad": AAD.decode(),
    }
    OUTPUT.write_text(
        "/* Generated with tools/encrypt-config.py. Never place plaintext secrets here. */\n"
        f"window.ENCRYPTED_CONFIG = Object.freeze({json.dumps(config, ensure_ascii=False, indent=2)});\n",
        encoding="utf-8",
    )
    print(f"加密配置已写入：{OUTPUT}")
    print("未输出 API Key 或共享密码；请立即执行安全扫描并检查 Git diff。")


if __name__ == "__main__":
    main()
