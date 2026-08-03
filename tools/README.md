# 本地加密工具

运行 `node tools/encrypt-config.mjs`，按提示在终端中输入 API Key 和共享访问密码。输入不会回显。没有 Node 时，也可运行 `python3 tools/encrypt-config.py`（需要 Python `cryptography`）。工具使用 PBKDF2-SHA-256（310000 次）派生 AES-GCM 256 位密钥，并以随机 salt、随机 12 字节 IV 和固定 AAD 生成 `site/encrypted-config.js`。

也可临时通过 `FEIFEIMIAO_API_KEY` 与 `SHARED_ACCESS_PASSWORD` 环境变量传入，但不要把变量写入仓库、脚本或 shell 历史。生成后运行 `npm test`。更换 Key 或密码时重新运行即可；已有浏览器案件使用旧密码加密，建议更换前先主动导出所需案件，再清空本机数据。
