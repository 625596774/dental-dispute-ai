(() => {
  "use strict";

  const config = window.ENCRYPTED_CONFIG;
  const sources = window.LEGAL_SOURCES;
  const API_AAD = "dental-dispute-ai/api-key/v1";
  const STORAGE_AAD = "dental-dispute-ai/local-storage/v1";
  const STORAGE_KEY = "dental-dispute-ai:cases:v1";
  const THROTTLE_KEY = "dental-dispute-ai:unlock-throttle:v1";
  const USAGE_KEY = "dental-dispute-ai:usage:v1";
  const encoder = new TextEncoder();
  const decoder = new TextDecoder();

  const $ = (id) => document.getElementById(id);
  const els = {
    unlockView: $("unlockView"), appView: $("appView"), unlockForm: $("unlockForm"), password: $("password"),
    unlockError: $("unlockError"), chatForm: $("chatForm"), input: $("messageInput"), messages: $("messages"),
    welcome: $("welcome"), risk: $("riskBanner"), status: $("status"), stop: $("stopBtn"), send: $("sendBtn"),
    count: $("charCount")
  };

  const emptyMemory = () => ({
    treatment_type: "", dispute_types: [], confirmed_facts: [], unconfirmed_facts: [], user_goals: [],
    available_evidence: [], missing_evidence: [], risk_flags: []
  });
  const newCase = () => ({ id: crypto.randomUUID(), createdAt: new Date().toISOString(), updatedAt: new Date().toISOString(), memory: emptyMemory(), citations: [], messages: [] });
  let secrets = { apiKey: null, storageKey: null };
  let data = { currentCaseId: null, cases: [] };
  let controller = null;
  let busy = false;
  let lastRequestAt = 0;
  let inactivityTimer = null;
  let thinkingTimer = null;
  let lastUserPrompt = "";

  function bytesToBase64(bytes) {
    let value = "";
    bytes.forEach((byte) => { value += String.fromCharCode(byte); });
    return btoa(value);
  }

  function base64ToBytes(value) {
    const raw = atob(value);
    return Uint8Array.from(raw, (char) => char.charCodeAt(0));
  }

  async function deriveKey(password, salt, usage) {
    const material = await crypto.subtle.importKey("raw", encoder.encode(password), "PBKDF2", false, ["deriveKey"]);
    return crypto.subtle.deriveKey(
      { name: "PBKDF2", hash: "SHA-256", salt, iterations: config.iterations },
      material,
      { name: "AES-GCM", length: 256 },
      false,
      usage
    );
  }

  async function decryptApiKey(password) {
    if (!config.ciphertext || !config.salt || !config.iv) throw new Error("CONFIG_MISSING");
    if (config.aad !== API_AAD) throw new Error("CONFIG_INVALID");
    const salt = base64ToBytes(config.salt);
    const key = await deriveKey(password, salt, ["decrypt"]);
    const plaintext = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: base64ToBytes(config.iv), additionalData: encoder.encode(config.aad) },
      key,
      base64ToBytes(config.ciphertext)
    );
    const apiKey = decoder.decode(plaintext);
    if (apiKey.length < 16 || /\s/.test(apiKey)) throw new Error("CONFIG_INVALID");
    return apiKey;
  }

  async function deriveStorageKey(password, salt) {
    return deriveKey(password, salt, ["encrypt", "decrypt"]);
  }

  function getThrottle() {
    try { return JSON.parse(localStorage.getItem(THROTTLE_KEY)) || { failures: 0, blockedUntil: 0 }; }
    catch { return { failures: 0, blockedUntil: 0 }; }
  }

  function recordUnlockFailure() {
    const state = getThrottle();
    state.failures += 1;
    if (state.failures >= 5) { state.blockedUntil = Date.now() + 5 * 60 * 1000; state.failures = 0; }
    localStorage.setItem(THROTTLE_KEY, JSON.stringify(state));
  }

  async function loadCases(password) {
    const packed = localStorage.getItem(STORAGE_KEY);
    if (!packed) {
      const salt = crypto.getRandomValues(new Uint8Array(16));
      secrets.storageKey = await deriveStorageKey(password, salt);
      data = { currentCaseId: null, cases: [], storageSalt: bytesToBase64(salt) };
      return;
    }
    const envelope = JSON.parse(packed);
    if (envelope.version !== 1 || !envelope.salt || !envelope.iv || !envelope.ciphertext) throw new Error("STORAGE_INVALID");
    const salt = base64ToBytes(envelope.salt);
    secrets.storageKey = await deriveStorageKey(password, salt);
    const plaintext = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: base64ToBytes(envelope.iv), additionalData: encoder.encode(STORAGE_AAD) },
      secrets.storageKey,
      base64ToBytes(envelope.ciphertext)
    );
    data = JSON.parse(decoder.decode(plaintext));
    data.storageSalt = envelope.salt;
  }

  async function saveCases() {
    if (!secrets.storageKey) return;
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const payload = { currentCaseId: data.currentCaseId, cases: data.cases };
    const ciphertext = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv, additionalData: encoder.encode(STORAGE_AAD) },
      secrets.storageKey,
      encoder.encode(JSON.stringify(payload))
    );
    localStorage.setItem(STORAGE_KEY, JSON.stringify({
      version: 1, salt: data.storageSalt, iv: bytesToBase64(iv), ciphertext: bytesToBase64(new Uint8Array(ciphertext)), updatedAt: new Date().toISOString()
    }));
  }

  function currentCase(create = true) {
    let item = data.cases.find((candidate) => candidate.id === data.currentCaseId);
    if (!item && create) { item = newCase(); data.cases.push(item); data.currentCaseId = item.id; }
    return item;
  }

  function resetInactivity() {
    if (!secrets.apiKey) return;
    clearTimeout(inactivityTimer);
    inactivityTimer = setTimeout(() => lock("已因 30 分钟无操作自动锁定。"), 30 * 60 * 1000);
  }

  function lock(message = "") {
    if (controller) controller.abort();
    clearTimeout(inactivityTimer);
    stopThinkingStatus();
    secrets.apiKey = null;
    secrets.storageKey = null;
    data = { currentCaseId: null, cases: [] };
    lastUserPrompt = "";
    els.messages.replaceChildren();
    els.appView.hidden = true;
    els.unlockView.hidden = false;
    els.password.value = "";
    els.unlockError.textContent = message;
    els.password.focus();
  }

  function usageState() {
    const today = new Date().toISOString().slice(0, 10);
    try {
      const state = JSON.parse(localStorage.getItem(USAGE_KEY));
      return state && state.date === today ? state : { date: today, count: 0 };
    } catch { return { date: today, count: 0 }; }
  }

  function updateUsage(increment = false) {
    const usage = usageState();
    if (increment) usage.count += 1;
    localStorage.setItem(USAGE_KEY, JSON.stringify(usage));
    return usage;
  }

  function classifyRisk(text) {
    const emergency = ["呼吸困难", "吞咽困难", "出血不止", "大量出血", "面颈部越来越肿", "面颈部快速", "严重药物过敏", "意识异常", "危及生命"];
    const legal = ["死亡", "永久性神经损伤", "严重伤残", "毁容", "病历伪造", "篡改病历", "销毁病历", "法院传票", "诉讼材料", "诉讼时效", "未成年人", "人身威胁", "自伤", "暴力"];
    if (emergency.some((word) => text.includes(word))) return { level: "emergency", message: "医疗紧急提示：你描述的情况可能需要立即医疗处置。请立即就近就医或拨打当地急救电话；法律分析不能替代紧急医疗处置。确认安全后，可继续获取证据保存和法律流程建议。" };
    if (legal.some((word) => text.includes(word))) return { level: "high", message: "高法律风险提示：本平台没有人工律师或人工审核。该问题可能需要执业律师、专业鉴定机构、人民调解组织、卫生健康主管部门或法院进一步处理。建议优先整理律师咨询摘要、证据缺口及下一步外部处理路径。" };
    return { level: "normal", message: "" };
  }

  function showRisk(result) {
    els.risk.hidden = !result.message;
    els.risk.textContent = result.message;
  }

  function scrollMessagesToEnd() {
    requestAnimationFrame(() => { els.messages.scrollTop = els.messages.scrollHeight; });
  }

  function startThinkingStatus(connectionOnly = false) {
    const startedAt = Date.now();
    const phases = connectionOnly
      ? [[0, "正在建立安全连接"], [5, "正在等待接口响应"], [15, "接口响应时间较长，仍在等待"]]
      : [[0, "正在理解问题和案件上下文"], [6, "正在梳理争议焦点与证据"], [15, "正在匹配内置法律依据"], [30, "正在组织回答与行动建议"], [60, "问题较复杂，仍在深入分析"]];
    const update = () => {
      const seconds = Math.floor((Date.now() - startedAt) / 1000);
      const phase = [...phases].reverse().find(([threshold]) => seconds >= threshold)?.[1] || phases[0][1];
      els.status.textContent = `Thinking · 思考中 ${seconds} 秒 · ${phase}（阶段估计）`;
    };
    clearInterval(thinkingTimer);
    els.status.classList.add("thinking");
    els.status.setAttribute("aria-busy", "true");
    update();
    thinkingTimer = setInterval(update, 1000);
  }

  function stopThinkingStatus() {
    clearInterval(thinkingTimer);
    thinkingTimer = null;
    els.status.classList.remove("thinking");
    els.status.removeAttribute("aria-busy");
  }

  function appendInlineMarkdown(parent, value) {
    const pattern = /(`[^`\n]+`|\*\*[^*\n]+\*\*|__[^_\n]+__|\*[^*\n]+\*|_[^_\n]+_)/g;
    let cursor = 0;
    for (const match of value.matchAll(pattern)) {
      if (match.index > cursor) parent.append(document.createTextNode(value.slice(cursor, match.index)));
      const token = match[0];
      let element;
      if (token.startsWith("`")) element = document.createElement("code");
      else if (token.startsWith("**") || token.startsWith("__")) element = document.createElement("strong");
      else element = document.createElement("em");
      const trim = token.startsWith("**") || token.startsWith("__") ? 2 : 1;
      element.textContent = token.slice(trim, -trim);
      parent.append(element);
      cursor = match.index + token.length;
    }
    if (cursor < value.length) parent.append(document.createTextNode(value.slice(cursor)));
  }

  function renderSafeMarkdown(markdown) {
    const fragment = document.createDocumentFragment();
    const lines = String(markdown).replace(/\r\n?/g, "\n").split("\n");
    let paragraphLines = [];
    let currentList = null;
    let codeLines = null;

    const flushParagraph = () => {
      if (!paragraphLines.length) return;
      const paragraph = document.createElement("p");
      paragraphLines.forEach((line, index) => {
        if (index) paragraph.append(document.createElement("br"));
        appendInlineMarkdown(paragraph, line);
      });
      fragment.append(paragraph);
      paragraphLines = [];
    };
    const closeList = () => { currentList = null; };
    const appendCode = () => {
      const pre = document.createElement("pre");
      const code = document.createElement("code");
      code.textContent = (codeLines || []).join("\n");
      pre.append(code);
      fragment.append(pre);
      codeLines = null;
    };

    for (const line of lines) {
      if (/^\s*```/.test(line)) {
        if (codeLines) appendCode();
        else { flushParagraph(); closeList(); codeLines = []; }
        continue;
      }
      if (codeLines) { codeLines.push(line); continue; }
      if (!line.trim()) { flushParagraph(); closeList(); continue; }

      const heading = line.match(/^\s*(#{1,3})\s*(.+?)\s*#*\s*$/);
      if (heading) {
        flushParagraph(); closeList();
        const title = document.createElement(`h${Math.min(5, heading[1].length + 2)}`);
        appendInlineMarkdown(title, heading[2]);
        fragment.append(title);
        continue;
      }
      if (/^\s*(?:---+|___+|\*\*\*+)\s*$/.test(line)) {
        flushParagraph(); closeList(); fragment.append(document.createElement("hr")); continue;
      }

      const unordered = line.match(/^\s*(?:[-+]\s*|\*\s+)(.+)$/);
      const ordered = line.match(/^\s*\d+[.)]\s*(.+)$/);
      if (unordered || ordered) {
        flushParagraph();
        const type = ordered ? "ol" : "ul";
        if (!currentList || currentList.tagName.toLowerCase() !== type) {
          currentList = document.createElement(type);
          fragment.append(currentList);
        }
        const item = document.createElement("li");
        appendInlineMarkdown(item, (ordered || unordered)[1]);
        currentList.append(item);
        continue;
      }

      const quote = line.match(/^\s*>\s?(.*)$/);
      if (quote) {
        flushParagraph(); closeList();
        const blockquote = document.createElement("blockquote");
        appendInlineMarkdown(blockquote, quote[1]);
        fragment.append(blockquote);
        continue;
      }
      closeList();
      paragraphLines.push(line);
    }
    if (codeLines) appendCode();
    flushParagraph();
    return fragment;
  }

  function appendMessage(role, text, citations = [], canRegenerate = false) {
    els.welcome.hidden = true;
    const card = document.createElement("article");
    card.className = `message ${role}`;
    card.setAttribute("aria-label", role === "user" ? "用户" : "AI 助手");
    const content = document.createElement("div");
    content.className = "message-content";
    if (role === "assistant") content.append(renderSafeMarkdown(text));
    else content.textContent = text;
    card.append(content);
    if (role === "assistant") {
      const actionRow = document.createElement("div");
      actionRow.className = "actions";
      const copy = document.createElement("button"); copy.type = "button"; copy.textContent = "复制回答";
      copy.addEventListener("click", async () => { await navigator.clipboard.writeText(text); copy.textContent = "已复制"; });
      actionRow.append(copy);
      if (canRegenerate) {
        const retry = document.createElement("button"); retry.type = "button"; retry.textContent = "重新生成";
        retry.title = "请勿反复点击，避免重复请求和可能的重复计费";
        retry.addEventListener("click", () => {
          if (!window.confirm("请勿反复点击“重新生成”。上一次请求可能仍在服务端处理，重复请求可能产生额外用量。确认重新生成吗？")) return;
          sendMessage(lastUserPrompt, { displayUser: false });
        });
        actionRow.append(retry);
      }
      card.append(actionRow, citationCards(citations));
    }
    els.messages.append(card);
    scrollMessagesToEnd();
  }

  function citationCards(ids) {
    const wrap = document.createElement("div"); wrap.className = "citations";
    const allowed = [...new Set(ids)].map((id) => sources[id]).filter(Boolean);
    if (!allowed.length) {
      const note = document.createElement("div"); note.className = "citation"; note.textContent = "本回答未匹配到内置官方依据，请进一步核验。"; wrap.append(note);
      return wrap;
    }
    allowed.forEach((source) => {
      const card = document.createElement("div"); card.className = "citation";
      const title = document.createElement("strong"); title.textContent = `${source.law} ${source.article}`;
      const summary = document.createElement("p"); summary.textContent = source.summary;
      const link = document.createElement("a"); link.href = source.officialUrl; link.target = "_blank"; link.rel = "noopener noreferrer"; link.textContent = `官方来源（核验于 ${source.verifiedAt}）`;
      card.append(title, summary, link); wrap.append(card);
    });
    return wrap;
  }

  function renderHistory() {
    els.messages.replaceChildren();
    const item = currentCase(false);
    els.welcome.hidden = Boolean(item?.messages.length);
    item?.messages.forEach((message) => appendMessage(message.role, message.text, message.citations || [], false));
  }

  function parseModelResponse(raw) {
    let text = typeof raw.output_text === "string" ? raw.output_text : "";
    if (!text && Array.isArray(raw.output)) {
      const pieces = [];
      raw.output.forEach((item) => {
        if (typeof item.text === "string") pieces.push(item.text);
        (item.content || []).forEach((part) => {
          if (typeof part === "string") pieces.push(part);
          else if (typeof part?.text === "string") pieces.push(part.text);
          else if (typeof part?.output_text === "string") pieces.push(part.output_text);
        });
      });
      text = pieces.join("\n");
    }
    if (!text) {
      const compatible = raw.choices?.[0]?.message?.content;
      text = typeof compatible === "string" ? compatible : "";
    }
    if (!text) throw new Error("EMPTY_RESPONSE");
    const extract = (tag) => {
      const match = text.match(new RegExp(`<${tag}>\\s*([\\s\\S]*?)\\s*</${tag}>`, "i"));
      if (!match) return null;
      try { return JSON.parse(match[1]); } catch { return null; }
    };
    const visible = text.replace(/<(CASE_MEMORY|CITATIONS|RISK)>[\s\S]*?<\/\1>/gi, "").trim();
    return { visible: visible || "模型返回了空白正文。", memory: extract("CASE_MEMORY"), citations: extract("CITATIONS") || [], risk: extract("RISK") };
  }

  function legalContext() {
    return Object.entries(sources).map(([id, item]) => `${id}: ${item.law}${item.article}；${item.summary}`).join("\n");
  }

  function buildInput(userText) {
    const item = currentCase();
    const recent = item.messages.slice(-10).map((message) => `${message.role === "user" ? "用户" : "助手"}: ${message.text}`).join("\n").slice(-14000);
    return `可用法律依据 ID（只能从中选择）：\n${legalContext()}\n\n当前案件摘要：\n${JSON.stringify(item.memory)}\n\n最近对话：\n${recent || "（无）"}\n\n当前用户请求：\n${userText}`;
  }

  function apiError(status, details = "") {
    if (status === 401 || status === 403) return "密钥无效、权限不足或已失效。";
    if (status === 402) return "模型服务余额不足。";
    if (status === 429) return "调用频率或额度受限，请稍后再试。";
    if (status === 400) return `模型名、参数或请求格式不兼容。${details ? ` ${details.slice(0, 160)}` : ""}`;
    return `接口返回错误（HTTP ${status}）。`;
  }

  async function postResponses(userText, reasoningStyle = "reasoning", connectionOnly = false) {
    controller = new AbortController();
    const timeout = setTimeout(() => controller.abort("timeout"), config.timeoutMs);
    const body = connectionOnly
      ? { model: config.model, store: false, max_output_tokens: 64, input: "只回复：连接正常。" }
      : { model: config.model, store: false, max_output_tokens: config.maxOutputTokens, instructions: window.DENTAL_PROMPT, input: buildInput(userText) };
    if (reasoningStyle === "reasoning") body.reasoning = { effort: config.reasoningEffort };
    if (reasoningStyle === "legacy") body.reasoning_effort = config.reasoningEffort;
    try {
      const response = await fetch(config.endpoint, {
        method: "POST", mode: "cors", cache: "no-store", credentials: "omit", signal: controller.signal,
        headers: { "Content-Type": "application/json", Authorization: `Bearer ${secrets.apiKey}` },
        body: JSON.stringify(body)
      });
      const rawText = await response.text();
      let json = {}; try { json = rawText ? JSON.parse(rawText) : {}; } catch { /* handled below */ }
      if (!response.ok) {
        const details = String(json?.error?.message || rawText || "");
        const unsupported = response.status === 400 && /unsupported|unknown parameter|unrecognized|reasoning/i.test(details);
        if (unsupported && reasoningStyle === "reasoning") return postResponses(userText, "legacy", connectionOnly);
        if (unsupported && reasoningStyle === "legacy") return postResponses(userText, "none", connectionOnly);
        throw new Error(apiError(response.status, details));
      }
      return parseModelResponse(json);
    } catch (error) {
      if (error.name === "AbortError" || controller?.signal.aborted) throw new Error(controller?.signal.reason === "timeout" ? "请求已等待 180 秒并超时。服务端可能仍在处理，请至少等待 30 秒后再重新生成；请勿反复点击，以免产生重复请求和额外用量。" : "已停止生成。");
      if (error instanceof TypeError) throw new Error("网络请求失败：当前接口可能未允许本页面跨域访问，或网络/接口不可用。这不是访问密码错误；纯静态网页无法绕过服务端 CORS。请勿使用 no-cors 或公共代理。 ");
      throw error;
    } finally { clearTimeout(timeout); }
  }

  async function sendMessage(text, options = {}) {
    const userText = String(text || "").trim();
    if (!userText || busy) return;
    if (userText.length > 5000) { els.status.textContent = "单条输入不能超过 5000 字。"; return; }
    const usage = usageState();
    if (usage.count >= config.dailyLimit) { els.status.textContent = `已达到本机今日柔性限制（${config.dailyLimit} 次）。`; return; }
    const wait = config.minRequestIntervalMs - (Date.now() - lastRequestAt);
    if (wait > 0) { els.status.textContent = `请求过快，请等待 ${Math.ceil(wait / 1000)} 秒。`; return; }
    const risk = classifyRisk(userText); showRisk(risk);
    if (risk.level === "emergency" && !window.confirm("检测到可能的医疗紧急情况。请优先就医。是否仍要继续生成法律流程和证据保存建议？")) return;

    const item = currentCase();
    if (options.displayUser !== false) {
      item.messages.push({ role: "user", text: userText, createdAt: new Date().toISOString() });
      appendMessage("user", userText);
      lastUserPrompt = userText;
    }
    busy = true; lastRequestAt = Date.now(); updateUsage(true); resetInactivity();
    els.send.disabled = true; els.stop.hidden = false; startThinkingStatus(Boolean(options.connectionOnly));
    try {
      const parsed = await postResponses(userText, "reasoning", Boolean(options.connectionOnly));
      if (parsed.memory && typeof parsed.memory === "object" && !Array.isArray(parsed.memory)) item.memory = { ...item.memory, ...parsed.memory };
      const citations = Array.isArray(parsed.citations) ? parsed.citations.filter((id) => Object.hasOwn(sources, id)) : [];
      item.citations = [...new Set([...(item.citations || []), ...citations])];
      item.messages.push({ role: "assistant", text: parsed.visible, citations, createdAt: new Date().toISOString() });
      item.updatedAt = new Date().toISOString();
      appendMessage("assistant", parsed.visible, citations, true);
      await saveCases();
      stopThinkingStatus();
      els.status.textContent = "回答已生成并加密保存到本机浏览器。";
    } catch (error) { stopThinkingStatus(); els.status.textContent = error.message || "请求失败，请稍后重试。"; }
    finally { stopThinkingStatus(); busy = false; controller = null; els.send.disabled = false; els.stop.hidden = true; }
  }

  async function unlock(event) {
    event.preventDefault();
    const throttle = getThrottle();
    if (throttle.blockedUntil > Date.now()) {
      els.unlockError.textContent = `尝试次数过多，请约 ${Math.ceil((throttle.blockedUntil - Date.now()) / 60000)} 分钟后再试。`;
      return;
    }
    if (!config.ciphertext) { els.unlockError.textContent = "尚未生成加密配置。请先运行 tools/encrypt-config.mjs。"; return; }
    els.unlockError.textContent = "正在验证…";
    try {
      const password = els.password.value;
      secrets.apiKey = await decryptApiKey(password);
      await loadCases(password);
      localStorage.removeItem(THROTTLE_KEY);
      els.password.value = "";
      els.unlockView.hidden = true; els.appView.hidden = false;
      currentCase(); await saveCases(); renderHistory(); updateUsage(); resetInactivity(); els.input.focus();
    } catch (error) {
      secrets.apiKey = null; secrets.storageKey = null; recordUnlockFailure();
      els.unlockError.textContent = error.message === "CONFIG_MISSING" ? "尚未生成加密配置。" : "密码错误或加密配置无效";
    }
  }

  async function startNewCase() {
    if (!window.confirm("新建案件会切换上下文，原案件仍以密文保存在本机。继续吗？")) return;
    const item = newCase(); data.cases.push(item); data.currentCaseId = item.id; lastUserPrompt = ""; showRisk({}); await saveCases(); renderHistory();
  }

  async function clearCurrent() {
    if (!window.confirm("确定清空当前案件吗？此操作不可恢复。")) return;
    data.cases = data.cases.filter((item) => item.id !== data.currentCaseId); data.currentCaseId = null; currentCase(); await saveCases(); renderHistory();
  }

  function clearAll() {
    if (!window.confirm("确定清空全部本机案件和用量记录吗？此操作不可恢复。")) return;
    localStorage.removeItem(STORAGE_KEY); localStorage.removeItem(USAGE_KEY); lock("本机数据已清空。请重新输入密码。 ");
  }

  function exportCurrent() {
    const item = currentCase(false); if (!item) return;
    const text = item.messages.map((message) => `${message.role === "user" ? "用户" : "AI 助手"}：\n${message.text}`).join("\n\n");
    const blob = new Blob([`口腔纠纷案件导出\n导出时间：${new Date().toLocaleString()}\n\n${text}`], { type: "text/plain;charset=utf-8" });
    const link = document.createElement("a"); link.href = URL.createObjectURL(blob); link.download = `口腔纠纷案件-${new Date().toISOString().slice(0, 10)}.txt`; link.click(); setTimeout(() => URL.revokeObjectURL(link.href), 0);
  }

  els.unlockForm.addEventListener("submit", unlock);
  els.chatForm.addEventListener("submit", (event) => { event.preventDefault(); const value = els.input.value; els.input.value = ""; els.count.textContent = "0 / 5000"; sendMessage(value); });
  els.input.addEventListener("input", () => { els.count.textContent = `${els.input.value.length} / 5000`; resetInactivity(); });
  els.input.addEventListener("keydown", (event) => { if (event.key === "Enter" && !event.shiftKey) { event.preventDefault(); els.chatForm.requestSubmit(); } });
  els.stop.addEventListener("click", () => controller?.abort("user"));
  $("lockBtn").addEventListener("click", () => lock("已立即锁定。"));
  $("newCaseBtn").addEventListener("click", startNewCase);
  $("clearCaseBtn").addEventListener("click", clearCurrent);
  $("clearAllBtn").addEventListener("click", clearAll);
  $("exportBtn").addEventListener("click", exportCurrent);
  $("connectionBtn").addEventListener("click", () => sendMessage("测试接口连接", { displayUser: true, connectionOnly: true }));
  $("examples").addEventListener("click", (event) => { if (event.target.matches("button")) { els.input.value = event.target.textContent; els.input.dispatchEvent(new Event("input")); els.input.focus(); } });
  $("quickActions").addEventListener("click", (event) => { const task = event.target.dataset.task; if (task && window.QUICK_TASKS[task]) sendMessage(window.QUICK_TASKS[task]); });
  ["pointerdown", "keydown"].forEach((name) => document.addEventListener(name, resetInactivity, { passive: true }));
  window.addEventListener("pageshow", () => { if (performance.getEntriesByType("navigation")[0]?.type === "back_forward") lock(); });
})();
