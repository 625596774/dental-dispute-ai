# 口腔纠纷法律咨询助手

面向中国大陆口腔门诊与患者纠纷的一般法律信息、材料整理和处理路径参考工具。回答由 AI 自动生成且无人审核，不构成正式律师意见、医疗诊断或鉴定结论。

## 架构与功能

项目是可直接发布到 GitHub Pages 的原生 HTML/CSS/JavaScript 静态站点：没有服务器、数据库、账号系统、文件上传、分析埋点或 CORS 代理。它支持连续案件摘要、最近对话上下文、五类快捷文书、确定性医疗/法律高风险提示、停止与重新生成、复制和 TXT 导出，以及来自本地 allowlist 的官方法规依据卡片。

API 请求使用 `https://api.feifeimiao.top/v1/responses`、`gpt-5.4`、Responses API 格式和 `store: false`。默认推理强度为 `medium`，请求超时为 180 秒；reasoning 参数不兼容时，只针对明确的参数不支持 400 错误依次尝试兼容格式和省略 reasoning 参数。超时后服务端可能仍在处理，请勿反复重新生成，以免产生重复请求和额外用量。

## 密钥与本地数据

API Key 不以明文保存在项目中。`tools/encrypt-config.mjs` 使用共享密码、PBKDF2-SHA-256（310000 次）、随机 16 字节 salt、AES-GCM 256 位、随机 12 字节 IV 和固定 AAD，生成可发布的 `site/encrypted-config.js` 密文。运行：

```bash
node tools/encrypt-config.mjs
npm test
```

工具会在交互终端隐藏输入。没有 Node 时可运行 `python3 tools/encrypt-config.py`（需要 `cryptography`）。更换 API Key 或共享密码时重新运行工具。不要把秘密放进命令、`.env`、README、构建日志或 Git 历史。

案件完整历史只在当前浏览器的 LocalStorage 中以独立 salt、AAD 和每次保存的新 IV 加密；API Key、密码和解密密钥不会写入 LocalStorage、SessionStorage、Cookie、IndexedDB 或 URL。刷新、立即锁定或 30 分钟无操作后需要重新输入密码。用户可导出当前案件、清空当前案件或清空全部本机数据；换设备不会同步，清除浏览器数据后记录会丢失。

## 部署

推送 `main` 后，`.github/workflows/deploy-pages.yml` 使用 GitHub 官方 Pages Actions 发布 `site/`。仓库首次部署时若尚未启用 Actions Source，只需在 **Settings → Pages → Source → GitHub Actions** 选择一次。

本地预览可运行：

```bash
python3 -m http.server 8000 --directory site
```

然后访问 `http://localhost:8000/`。不要直接使用 `file://` 测试 Web Crypto 和跨域请求。

## CORS 限制

浏览器会从 GitHub Pages 域名直接向模型接口发送带 `Authorization` 的跨域 POST。服务端必须允许实际 Pages Origin、`POST`、`authorization` 和 `content-type`。纯静态网页无法绕过服务端 CORS；项目不会使用 `mode: no-cors` 或公共代理。“测试接口连接”会发起一次很短的真实模型请求并计入本机用量。

## 安全边界与隐私

这是适合小范围可信用户的纯前端共享密码方案，不是商业级密钥隔离。拥有共享密码且熟悉浏览器开发工具的人，技术上可能从页面内存或网络请求取得 API Key；JavaScript 也无法承诺彻底擦除字符串内存。前端失败次数与每日用量限制仅用于防误操作，均可被有意绕过。

咨询内容会发送给模型服务商生成答复。网页自身不设置数据库、不接收文件上传；建议不要输入身份证号、银行卡号、完整住址等非必要敏感信息。医疗健康信息属于敏感个人信息，使用者应自行判断发送的必要性。

## 法律资料

内置资料核验于 2026-08-03，来源限于最高人民法院、国家卫生健康委员会和中国人大网等官方站点，包括《民法典》医疗损害责任条款、《医疗纠纷预防和处理条例》《医疗机构投诉管理办法》和《个人信息保护法》。法律和政策可能变化，实际使用时仍需复核现行文本并在必要时咨询执业律师或有关主管部门。
