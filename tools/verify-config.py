#!/usr/bin/env python3
"""Interactively verify that the encrypted config decrypts, without printing secrets."""

import base64
import getpass
import json
import re
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

config_text = (Path(__file__).resolve().parents[1] / "site" / "encrypted-config.js").read_text(encoding="utf-8")
match = re.search(r"Object\.freeze\((\{[\s\S]*\})\);", config_text)
if not match:
    raise SystemExit("无法解析 encrypted-config.js")
config = json.loads(match.group(1))
password = getpass.getpass("共享访问密码（输入不回显）：")
salt = base64.b64decode(config["salt"])
key = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=config["iterations"]).derive(password.encode())
try:
    plaintext = AESGCM(key).decrypt(base64.b64decode(config["iv"]), base64.b64decode(config["ciphertext"]), config["aad"].encode())
except InvalidTag:
    raise SystemExit("验证失败：密码错误或密文无效")
if len(plaintext) < 16 or any(chr(byte).isspace() for byte in plaintext):
    raise SystemExit("验证失败：解密结果格式异常")
print("验证成功：密文可用；未输出解密内容。")
