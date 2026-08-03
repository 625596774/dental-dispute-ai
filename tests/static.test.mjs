import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { test } from "node:test";

const read = (name) => readFile(new URL(`../${name}`, import.meta.url), "utf8");

test("页面无外部脚本、文件上传或危险模型 HTML 渲染", async () => {
  const [html, app] = await Promise.all([read("site/index.html"), read("site/app.js")]);
  assert.doesNotMatch(html, /<script[^>]+https?:\/\//i);
  assert.doesNotMatch(html, /type=["']file["']/i);
  assert.doesNotMatch(app, /\.innerHTML\s*=/);
  assert.match(app, /textContent = text/);
  assert.match(app, /renderSafeMarkdown/);
  assert.match(app, /createDocumentFragment/);
  assert.doesNotMatch(app, /DOMParser|insertAdjacentHTML/);
  assert.doesNotMatch(app, /scrollIntoView/);
});

test("API 请求禁用存储并支持取消、超时与 reasoning 回退", async () => {
  const app = await read("site/app.js");
  assert.match(app, /store: false/);
  assert.match(app, /AbortController/);
  assert.match(app, /config\.timeoutMs/);
  assert.match(app, /body\.reasoning =/);
  assert.match(app, /body\.reasoning_effort =/);
  assert.match(app, /Thinking · 思考中/);
  assert.match(app, /阶段估计/);
});

test("本地案件仅以 AES-GCM 密文信封持久化", async () => {
  const app = await read("site/app.js");
  assert.match(app, /AES-GCM/);
  assert.match(app, /ciphertext: bytesToBase64/);
  assert.doesNotMatch(app, /localStorage\.setItem\([^,]+,\s*secrets\.apiKey/);
  assert.doesNotMatch(app, /sessionStorage|indexedDB|document\.cookie/);
});

test("确定性高风险规则与无人工表述存在", async () => {
  const app = await read("site/app.js");
  assert.match(app, /呼吸困难/);
  assert.match(app, /篡改病历/);
  assert.match(app, /本平台没有人工律师或人工审核/);
  assert.doesNotMatch(app, /正在转接律师|已提交人工审核|专家稍后联系|正在通知法律顾问/);
});

test("密文配置不含秘密占位变量或 Bearer 值", async () => {
  const config = await read("site/encrypted-config.js");
  assert.doesNotMatch(config, /FEIFEIMIAO_API_KEY|SHARED_ACCESS_PASSWORD|Authorization|Bearer\s+\S+/);
  assert.match(config, /gpt-5\.4/);
});

test("官方依据均为本地 allowlist 和政府站点", async () => {
  const legal = await read("site/legal-sources.js");
  for (const id of ["civil_code_1218", "civil_code_1219", "civil_code_1221", "civil_code_1222", "civil_code_1224", "civil_code_1225", "civil_code_1226", "civil_code_1227", "medical_record_copy", "complaint_first_contact", "pip_sensitive_health"]) {
    assert.match(legal, new RegExp(`${id}:`));
  }
  const urls = [...legal.matchAll(/officialUrl: "([^"]+)"/g)].map((match) => new URL(match[1]).hostname);
  assert.ok(urls.length >= 12);
  urls.forEach((host) => assert.ok(host.endsWith(".gov.cn"), `${host} 不是政府域名`));
});

test("Pages workflow 只发布 site 目录", async () => {
  const workflow = await read(".github/workflows/deploy-pages.yml");
  assert.match(workflow, /path: site/);
  assert.match(workflow, /pages: write/);
  assert.match(workflow, /id-token: write/);
});
