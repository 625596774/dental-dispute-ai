#!/usr/bin/env node
import { webcrypto } from "node:crypto";
import { mkdir, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const { subtle } = webcrypto;
const encoder = new TextEncoder();
const here = dirname(fileURLToPath(import.meta.url));
const defaultOutput = resolve(here, "../site/encrypted-config.js");
const API_AAD = "dental-dispute-ai/api-key/v1";
const ITERATIONS = 310000;

function argument(name) {
  const index = process.argv.indexOf(name);
  return index >= 0 ? process.argv[index + 1] : undefined;
}

function hiddenPrompt(label) {
  if (!process.stdin.isTTY) return Promise.reject(new Error(`${label} 未提供，且当前终端不可交互。`));
  return new Promise((resolvePrompt, reject) => {
    let value = "";
    process.stdout.write(label);
    process.stdin.setRawMode(true);
    process.stdin.resume();
    process.stdin.setEncoding("utf8");
    const cleanup = () => { process.stdin.setRawMode(false); process.stdin.pause(); process.stdin.removeListener("data", onData); };
    const onData = (chunk) => {
      for (const char of chunk) {
        if (char === "\u0003") { cleanup(); process.stdout.write("\n"); reject(new Error("已取消。")); return; }
        if (char === "\r" || char === "\n") { cleanup(); process.stdout.write("\n"); resolvePrompt(value); return; }
        if (char === "\u007f") { value = value.slice(0, -1); continue; }
        value += char;
      }
    };
    process.stdin.on("data", onData);
  });
}

function toBase64(value) { return Buffer.from(value).toString("base64"); }

async function encrypt(apiKey, password) {
  const salt = webcrypto.getRandomValues(new Uint8Array(16));
  const iv = webcrypto.getRandomValues(new Uint8Array(12));
  const material = await subtle.importKey("raw", encoder.encode(password), "PBKDF2", false, ["deriveKey"]);
  const key = await subtle.deriveKey(
    { name: "PBKDF2", hash: "SHA-256", salt, iterations: ITERATIONS },
    material,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt"]
  );
  const ciphertext = await subtle.encrypt(
    { name: "AES-GCM", iv, additionalData: encoder.encode(API_AAD) },
    key,
    encoder.encode(apiKey)
  );
  return { salt: toBase64(salt), iv: toBase64(iv), ciphertext: toBase64(ciphertext) };
}

const output = resolve(argument("--output") || defaultOutput);
const envApiKey = process.env.FEIFEIMIAO_API_KEY;
const envPassword = process.env.SHARED_ACCESS_PASSWORD;
const apiKey = envApiKey || await hiddenPrompt("FEIFEIMIAO API Key（输入不回显）：");
const password = envPassword || await hiddenPrompt("共享访问密码（输入不回显）：");
if (apiKey.length < 16 || /\s/.test(apiKey)) throw new Error("API Key 格式不合理。 ");
if (password.length < 8) throw new Error("共享访问密码至少需要 8 个字符。 ");
const encrypted = await encrypt(apiKey, password);
const generated = `/* Generated with tools/encrypt-config.mjs. Never place plaintext secrets here. */
window.ENCRYPTED_CONFIG = Object.freeze(${JSON.stringify({
  version: 1,
  baseUrl: "https://api.feifeimiao.top/v1",
  endpoint: "https://api.feifeimiao.top/v1/responses",
  model: "gpt-5.4",
  reasoningEffort: "medium",
  maxOutputTokens: 2400,
  timeoutMs: 180000,
  dailyLimit: 30,
  minRequestIntervalMs: 4000,
  iterations: ITERATIONS,
  ...encrypted,
  aad: API_AAD
}, null, 2)});
`;
await mkdir(dirname(output), { recursive: true });
await writeFile(output, generated, { mode: 0o644 });
console.log(`加密配置已写入：${output}`);
console.log("未输出 API Key 或共享密码；请立即执行安全扫描并检查 Git diff。");
