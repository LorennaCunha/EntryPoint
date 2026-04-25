// Pentest Recon — frontend logic
// Comunicação simples com a API do backend FastAPI.

const $ = (sel) => document.querySelector(sel);

const form        = $("#scan-form");
const urlInput    = $("#url");
const scanType    = $("#scan_type");
const wordlistSel = $("#wordlist");
const wordlistUp  = $("#wordlist-upload");
const runBtn      = $("#run-btn");

const statusCard = $("#status-card");
const statusLine = $("#status-line");
const scoreLine  = $("#score-line");
const outputCard = $("#output-card");
const terminal   = $("#terminal-output");
const sectionsEl = $("#sections");
const tpl        = $("#section-template");
const copyAllBtn = $("#copy-all");

let pollTimer = null;

// -------------------- helpers --------------------

function toast(msg) {
  let t = document.querySelector(".toast");
  if (!t) {
    t = document.createElement("div");
    t.className = "toast";
    document.body.appendChild(t);
  }
  t.textContent = msg;
  t.classList.add("show");
  setTimeout(() => t.classList.remove("show"), 1800);
}

async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text);
    toast("Copiado");
  } catch {
    toast("Falha ao copiar");
  }
}

function scoreClass(score) {
  if (score >= 85) return "score-ok";
  if (score >= 60) return "score-warn";
  if (score >= 30) return "score-bad";
  return "score-crit";
}

// -------------------- carregar wordlists --------------------

async function loadWordlists() {
  try {
    const r = await fetch("/api/wordlists");
    const data = await r.json();
    wordlistSel.innerHTML = '<option value="">— padrão —</option>';
    for (const wl of data.wordlists) {
      const o = document.createElement("option");
      o.value = wl.name;
      o.textContent = `${wl.name} (${(wl.size/1024).toFixed(1)} KB)`;
      wordlistSel.appendChild(o);
    }
  } catch (e) {
    console.error(e);
  }
}

wordlistUp.addEventListener("change", async () => {
  const f = wordlistUp.files[0];
  if (!f) return;
  const fd = new FormData();
  fd.append("file", f);
  const r = await fetch("/api/wordlists/upload", { method: "POST", body: fd });
  if (!r.ok) {
    const err = await r.json().catch(() => ({}));
    toast("Erro: " + (err.detail || r.status));
    return;
  }
  const data = await r.json();
  toast(`Upload: ${data.name}`);
  await loadWordlists();
  wordlistSel.value = data.name;
  wordlistUp.value = "";
});

// -------------------- executar scan --------------------

form.addEventListener("submit", async (ev) => {
  ev.preventDefault();
  runBtn.disabled = true;
  runBtn.textContent = "Executando…";

  if (pollTimer) { clearInterval(pollTimer); pollTimer = null; }

  const body = {
    url: urlInput.value.trim(),
    scan_type: scanType.value,
    wordlist: wordlistSel.value || null,
  };
  let r, data;
  try {
    r = await fetch("/api/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    data = await r.json();
  } catch (e) {
    toast("Erro de rede");
    runBtn.disabled = false; runBtn.textContent = "Executar scan";
    return;
  }
  if (!r.ok) {
    toast("Erro: " + (data.detail || r.status));
    runBtn.disabled = false; runBtn.textContent = "Executar scan";
    return;
  }

  statusCard.classList.remove("hidden");
  outputCard.classList.add("hidden");
  statusLine.textContent = `scan_id=${data.scan_id} — running…`;
  scoreLine.textContent = "";

  pollScan(data.scan_id);
});

function pollScan(scanId) {
  let elapsed = 0;
  pollTimer = setInterval(async () => {
    elapsed += 2;
    let res;
    try { res = await fetch(`/api/scan/${scanId}`); }
    catch { return; }
    if (!res.ok) return;
    const data = await res.json();
    statusLine.textContent = `scan_id=${data.scan_id} — ${data.status} (${elapsed}s)`;
    if (data.status === "done" || data.status === "error") {
      clearInterval(pollTimer); pollTimer = null;
      runBtn.disabled = false; runBtn.textContent = "Executar scan";
      renderResult(data);
    }
  }, 2000);
}

// -------------------- renderizar resultado --------------------

function renderResult(data) {
  outputCard.classList.remove("hidden");

  if (data.error) {
    terminal.textContent = `ERRO: ${data.error}`;
    sectionsEl.innerHTML = "";
    scoreLine.textContent = "";
    return;
  }

  scoreLine.innerHTML = `Score: <span class="${scoreClass(data.score)}">${data.score}/100</span>  |  Status: ${data.score_status}`;
  terminal.textContent = data.terminal_output || "(sem saída)";

  // Seções individuais — mesma string formatada que o terminal,
  // mas separada para copy/paste por bloco
  const labels = {
    headers: "HEADERS",
    tls: "TLS / SSL",
    sitemap: "SITEMAP (ffuf)",
    params: "PARAM DISCOVERY (arjun)",
    vulnerabilities: "VULNERABILITIES (nuclei + nikto + custom)",
  };
  sectionsEl.innerHTML = "";
  for (const [key, title] of Object.entries(labels)) {
    const text = data.sections?.[key];
    if (!text) continue;
    const node = tpl.content.cloneNode(true);
    node.querySelector(".title").textContent = title;
    const body = node.querySelector(".body");
    body.textContent = text;
    node.querySelector(".copy-btn").addEventListener("click", () => copyText(text));
    sectionsEl.appendChild(node);
  }
}

copyAllBtn.addEventListener("click", () => copyText(terminal.textContent));

// -------------------- init --------------------
loadWordlists();
