import './styles.css';
import { ITER, encryptFile, decryptFile, hashKeyfile } from './crypto.js';

const $ = (s) => document.querySelector(s);
const state = {
  mode: 'enc',
  queues: { enc: [], dec: [] },
  keyHash: null,
  busy: false,
  nextId: 1,
};

/* ---------- utilidades ---------- */
const fmtSize = (n) => {
  const u = ['B', 'KB', 'MB', 'GB', 'TB'];
  let i = 0, v = n;
  while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
  return v.toLocaleString('pt-BR', { maximumFractionDigits: i ? 1 : 0 }) + ' ' + u[i];
};
const fmtTime = (s) => {
  if (!isFinite(s) || s < 0) return '--:--';
  s = Math.round(s);
  return String(Math.floor(s / 60)).padStart(2, '0') + ':' + String(s % 60).padStart(2, '0');
};
const hex = (u8) => [...u8].map((b) => b.toString(16).padStart(2, '0')).join('');
const tick = () => new Promise((r) => setTimeout(r, 0));

function log(msg, kind) {
  const pre = $('#log');
  const t = new Date().toLocaleTimeString('pt-BR');
  const line = document.createElement('div');
  const ts = document.createElement('span');
  ts.className = 'dim'; ts.textContent = '[' + t + '] ';
  const tx = document.createElement('span');
  if (kind) tx.className = kind;
  tx.textContent = msg;
  line.append(ts, tx);
  pre.appendChild(line);
  pre.scrollTop = pre.scrollHeight;
}

/* ============================================================
   Núcleo criptográfico (Web Crypto API)
   ============================================================ */
/* ============================================================
   Credenciais
   ============================================================ */
function strength(pw) {
  if (!pw) return 0;
  let s = 0;
  if (pw.length >= 8) s++;
  if (pw.length >= 12) s++;
  const classes = [/[a-z]/, /[A-Z]/, /\d/, /[^A-Za-z0-9]/].filter((r) => r.test(pw)).length;
  if (classes >= 3) s++;
  if (pw.length >= 16 && classes >= 3) s++;
  return Math.max(1, Math.min(4, s));
}
const strengthLabels = ['Use frases longas, com letras, números e símbolos.', 'Fraca', 'Razoável', 'Boa', 'Forte'];

$('#pw').addEventListener('input', (e) => {
  const s = strength(e.target.value);
  $('#meter').dataset.s = s;
  const h = $('#pwHelp');
  h.textContent = s ? 'Força da senha: ' + strengthLabels[s] : strengthLabels[0];
  h.classList.remove('err');
});
$('#pwToggle').addEventListener('click', () => {
  const i = $('#pw');
  const show = i.type === 'password';
  i.type = show ? 'text' : 'password';
  $('#pwToggle').setAttribute('aria-label', show ? 'Ocultar senha' : 'Mostrar senha');
});

async function setKeyfile(file) {
  if (!file) return;
  if (file.size > 256 * 1024 * 1024) { log('Keyfile maior que 256 MB: escolha um arquivo menor.', 'er'); return; }
  const hash = await hashKeyfile(file);
  state.keyHash = hash;
  $('#kfName').textContent = file.name;
  $('#kfFp').textContent = 'SHA-256 ' + hex(hash).slice(0, 16) + '…';
  $('#kfChip').classList.add('show');
  log('Keyfile carregado: ' + file.name + ' (' + fmtSize(file.size) + ').');
}
function clearKeyfile() {
  state.keyHash = null;
  $('#kfChip').classList.remove('show');
  $('#kfInput').value = '';
}
$('#kfInput').addEventListener('change', (e) => setKeyfile(e.target.files[0]));
$('#kfClear').addEventListener('click', () => { clearKeyfile(); log('Keyfile removido.'); });
const kfDrop = $('#kfDrop');
kfDrop.addEventListener('click', () => $('#kfInput').click());
kfDrop.addEventListener('keydown', (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); $('#kfInput').click(); } });
['dragenter', 'dragover'].forEach((ev) => kfDrop.addEventListener(ev, (e) => { e.preventDefault(); kfDrop.classList.add('over'); }));
['dragleave', 'drop'].forEach((ev) => kfDrop.addEventListener(ev, (e) => { e.preventDefault(); kfDrop.classList.remove('over'); }));
kfDrop.addEventListener('drop', (e) => { const f = e.dataTransfer.files[0]; if (f) setKeyfile(f); });

/* ============================================================
   Fila
   ============================================================ */
const queue = () => state.queues[state.mode];

function addEntries(entries) {
  const q = queue();
  let n = 0;
  for (const { file, path } of entries) {
    q.push({ id: state.nextId++, file, path, size: file.size, status: 'pending', msg: '', result: null, outName: '' });
    n++;
  }
  if (n) log(n + (n === 1 ? ' item adicionado' : ' itens adicionados') + ' à fila de ' + (state.mode === 'enc' ? 'criptografia' : 'descriptografia') + '.');
  renderQueue();
}

async function entriesFromDrop(dt) {
  const out = [];
  const items = [...(dt.items || [])];
  const roots = items.map((i) => (i.webkitGetAsEntry ? i.webkitGetAsEntry() : null)).filter(Boolean);
  if (!roots.length) return [...dt.files].map((f) => ({ file: f, path: f.name }));
  const walk = async (e, prefix) => {
    if (e.isFile) {
      const f = await new Promise((res, rej) => e.file(res, rej));
      out.push({ file: f, path: prefix + f.name });
    } else if (e.isDirectory) {
      const r = e.createReader();
      let batch;
      do {
        batch = await new Promise((res, rej) => r.readEntries(res, rej));
        for (const c of batch) await walk(c, prefix + e.name + '/');
      } while (batch.length);
    }
  };
  for (const e of roots) await walk(e, '');
  return out;
}

const drop = $('#drop');
drop.addEventListener('click', () => $('#fileInput').click());
drop.addEventListener('keydown', (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); $('#fileInput').click(); } });
['dragenter', 'dragover'].forEach((ev) => drop.addEventListener(ev, (e) => { e.preventDefault(); drop.classList.add('over'); }));
drop.addEventListener('dragleave', () => drop.classList.remove('over'));
drop.addEventListener('drop', async (e) => {
  e.preventDefault(); drop.classList.remove('over');
  if (state.busy) return;
  addEntries(await entriesFromDrop(e.dataTransfer));
});
$('#pickFiles').addEventListener('click', () => $('#fileInput').click());
$('#pickDir').addEventListener('click', () => $('#dirInput').click());
$('#fileInput').addEventListener('change', (e) => {
  addEntries([...e.target.files].map((f) => ({ file: f, path: f.name })));
  e.target.value = '';
});
$('#dirInput').addEventListener('change', (e) => {
  addEntries([...e.target.files].map((f) => ({ file: f, path: f.webkitRelativePath || f.name })));
  e.target.value = '';
});
$('#clearQueue').addEventListener('click', () => { queue().length = 0; renderQueue(); log('Fila esvaziada.'); });

const statusTag = (it) => {
  const m = { pending: ['gray', 'Pendente'], working: ['blue', 'Processando'], done: ['green', 'Concluído'], error: ['red', 'Erro'] }[it.status];
  const s = document.createElement('span');
  s.className = 'tag ' + m[0];
  s.textContent = m[1];
  return s;
};

function renderQueue() {
  const q = queue();
  const enc_ = state.mode === 'enc';
  $('#queueTitle').textContent = enc_ ? 'Fila de criptografia' : 'Fila de descriptografia';
  const total = q.reduce((a, i) => a + i.size, 0);
  $('#queueDesc').textContent = q.length + (q.length === 1 ? ' item' : ' itens') + (q.length ? ' · ' + fmtSize(total) : '');
  $('#clearQueue').disabled = state.busy || !q.length;
  $('#saveAll').disabled = state.busy || !q.some((i) => i.status === 'done');
  $('#runBtn').disabled = state.busy || !q.some((i) => i.status === 'pending' || i.status === 'error');

  const host = $('#tableHost');
  host.textContent = '';
  if (!q.length) {
    const d = document.createElement('div');
    d.className = 'empty';
    d.innerHTML = '<div class="t"></div><div></div>';
    d.firstChild.textContent = 'Nenhum arquivo na fila';
    d.lastChild.textContent = enc_ ? 'Adicione arquivos ou pastas para começar.' : 'Adicione arquivos .cofre para descriptografar.';
    host.appendChild(d);
    return;
  }
  const wrap = document.createElement('div');
  wrap.className = 'table-wrap';
  const t = document.createElement('table');
  t.innerHTML = '<thead><tr><th>Nome</th><th class="num">Tamanho</th><th>Status</th><th></th></tr></thead>';
  const tb = document.createElement('tbody');
  for (const it of q) {
    const tr = document.createElement('tr');
    const c1 = document.createElement('td'); c1.className = 'nm'; c1.textContent = it.path; c1.title = it.path;
    const c2 = document.createElement('td'); c2.className = 'num'; c2.textContent = fmtSize(it.size);
    const c3 = document.createElement('td'); c3.appendChild(statusTag(it));
    if (it.status === 'error' && it.msg) { const em = document.createElement('span'); em.className = 'errmsg'; em.textContent = it.msg; c3.appendChild(em); }
    const c4 = document.createElement('td'); c4.className = 'act';
    if (it.status === 'done') {
      const b = document.createElement('button');
      b.className = 'btn sm ghost'; b.type = 'button';
      b.innerHTML = '<span>Salvar</span>';
      b.addEventListener('click', () => saveItem(it));
      c4.appendChild(b);
    }
    if (!state.busy && it.status !== 'working') {
      const x = document.createElement('button');
      x.className = 'icon-btn'; x.type = 'button'; x.setAttribute('aria-label', 'Remover da fila'); x.title = 'Remover da fila';
      x.innerHTML = '<svg width="16" height="16" viewBox="0 0 32 32" fill="currentColor"><path d="M24 9.4 22.6 8 16 14.6 9.4 8 8 9.4l6.6 6.6L8 22.6 9.4 24l6.6-6.6 6.6 6.6 1.4-1.4-6.6-6.6z"/></svg>';
      x.addEventListener('click', () => { const i = q.indexOf(it); if (i >= 0) q.splice(i, 1); renderQueue(); });
      c4.appendChild(x);
    }
    tr.append(c1, c2, c3, c4);
    tb.appendChild(tr);
  }
  t.appendChild(tb);
  wrap.appendChild(t);
  host.appendChild(wrap);
}

/* ============================================================
   Modo
   ============================================================ */
function setMode(m) {
  if (state.busy) return;
  state.mode = m;
  const e = m === 'enc';
  $('#tabEnc').setAttribute('aria-selected', e);
  $('#tabDec').setAttribute('aria-selected', !e);
  $('#dropTitle').textContent = e ? 'Arraste arquivos ou pastas para criptografar' : 'Arraste arquivos .cofre para descriptografar';
  $('#dropDesc').textContent = e ? 'Pastas inteiras são percorridas e cada arquivo vira um item da fila.' : 'Use a mesma senha (e o mesmo keyfile) da criptografia.';
  $('#runLabel').textContent = e ? 'Criptografar' : 'Descriptografar';
  $('#runIcon').innerHTML = e
    ? '<path d="M24 14h-2V9a6 6 0 0 0-12 0v5H8a2 2 0 0 0-2 2v12a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2V16a2 2 0 0 0-2-2zM12 9a4 4 0 0 1 8 0v5h-8zm12 19H8V16h16z"/>'
    : '<path d="M24 14h-10V9a4 4 0 0 1 7.6-1.7l1.9-.7A6 6 0 0 0 12 9v5H8a2 2 0 0 0-2 2v12a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2V16a2 2 0 0 0-2-2zm0 14H8V16h16z"/>';
  $('#progress').hidden = true;
  renderQueue();
}
$('#tabEnc').addEventListener('click', () => setMode('enc'));
$('#tabDec').addEventListener('click', () => setMode('dec'));

/* ============================================================
   Processamento
   ============================================================ */
function outputName(it) {
  const base = it.path.replace(/\//g, '__');
  if (state.mode === 'enc') return base + '.cofre';
  const n = base.replace(/\.cofre(\.txt)?$/i, '');
  return n === base ? base + '.decifrado' : n;
}

async function run() {
  const pw = $('#pw').value;
  if (!pw) { $('#pwHelp').textContent = 'Informe a senha mestra.'; $('#pwHelp').classList.add('err'); $('#pw').focus(); return; }
  if (state.mode === 'enc' && pw.length < 8) {
    $('#pwHelp').textContent = 'Use ao menos 8 caracteres para criptografar.'; $('#pwHelp').classList.add('err'); $('#pw').focus(); return;
  }
  const q = queue();
  const todo = q.filter((i) => i.status === 'pending' || i.status === 'error');
  if (!todo.length) return;

  state.busy = true;
  todo.forEach((i) => { i.status = 'pending'; i.msg = ''; });
  const total = todo.reduce((a, i) => a + Math.max(i.size, 1), 0);
  let done = 0;
  const t0 = performance.now();
  const prog = $('#progress'), fill = $('#barFill'), bar = $('#bar');
  prog.hidden = false; bar.classList.remove('done');
  renderQueue();
  log((state.mode === 'enc' ? 'Criptografando ' : 'Descriptografando ') + todo.length + ' item(ns)…');

  let raf = 0;
  const paint = (label) => {
    if (raf) return;
    raf = requestAnimationFrame(() => {
      raf = 0;
      const pct = Math.min(100, (done / total) * 100);
      fill.style.width = pct + '%';
      bar.setAttribute('aria-valuenow', Math.round(pct));
      const el = (performance.now() - t0) / 1000;
      const speed = el > 0 ? done / el : 0;
      const eta = speed > 0 ? (total - done) / speed : Infinity;
      $('#progLabel').textContent = label + ' · ' + Math.round(pct) + '%';
      $('#progTel').textContent = (speed / 1048576).toLocaleString('pt-BR', { maximumFractionDigits: 1 }) + ' MB/s · ETA ' + fmtTime(eta);
    });
  };

  let ok = 0, fail = 0;
  for (const it of todo) {
    it.status = 'working'; renderQueue();
    const label = it.path;
    paint(label);
    let counted = 0;
    try {
      const fn = state.mode === 'enc' ? encryptFile : decryptFile;
      it.result = await fn(it.file, pw, state.keyHash, (n) => { done += n; counted += n; paint(label); });
      it.outName = outputName(it);
      it.status = 'done'; ok++;
      log('✓ ' + it.path + ' → ' + it.outName + ' (' + fmtSize(it.result.size) + ')', 'ok');
    } catch (err) {
      it.status = 'error'; it.msg = err.message || String(err); fail++;
      log('✗ ' + it.path + ': ' + it.msg, 'er');
    }
    done += Math.max(Math.max(it.size, 1) - counted, 0);
    paint(label);
    renderQueue();
  }
  paint('Concluído');
  await new Promise((r) => setTimeout(r, 160));
  fill.style.width = '100%';
  bar.classList.add('done');
  const sec = ((performance.now() - t0) / 1000).toFixed(1).replace('.', ',');
  $('#progLabel').textContent = 'Concluído · ' + ok + ' ok, ' + fail + ' com erro';
  log('Fim: ' + ok + ' ok, ' + fail + ' com erro em ' + sec + ' s.', fail ? 'er' : 'ok');
  state.busy = false;
  renderQueue();
}
$('#runBtn').addEventListener('click', run);

/* ============================================================
   Salvar
   ============================================================ */
function saveItem(it) {
  if (!it.result) return;
  const a = document.createElement('a');
  a.href = URL.createObjectURL(it.result);
  a.download = it.outName;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(a.href), 10000);
  log('Download iniciado: ' + it.outName, 'ok');
}

$('#saveAll').addEventListener('click', async () => {
  for (const it of queue().filter((i) => i.status === 'done')) {
    saveItem(it);
    await new Promise((r) => setTimeout(r, 250)); // evita bloqueio de múltiplos downloads
  }
});

/* ============================================================
   Sessão, tema, log
   ============================================================ */
$('#lockBtn').addEventListener('click', () => {
  if (state.busy) return;
  $('#pw').value = ''; $('#pw').type = 'password';
  $('#meter').dataset.s = 0; $('#pwHelp').textContent = strengthLabels[0]; $('#pwHelp').classList.remove('err');
  clearKeyfile();
  state.queues.enc.length = 0; state.queues.dec.length = 0;
  $('#progress').hidden = true;
  renderQueue();
  log('Sessão limpa: senha, keyfile e filas removidos da memória.');
});
$('#logClear').addEventListener('click', () => { $('#log').textContent = ''; });

$('#themeBtn').addEventListener('click', () => {
  const r = document.documentElement;
  const cur = r.dataset.theme || (matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');
  r.dataset.theme = cur === 'dark' ? 'light' : 'dark';
});

if (!(window.crypto && crypto.subtle)) {
  log('Web Crypto API indisponível neste contexto. É necessário HTTPS.', 'er');
  $('#runBtn').disabled = true;
}
renderQueue();
log('Cofre Forte pronto. AES-256-GCM · PBKDF2-SHA-256 (' + ITER.toLocaleString('pt-BR') + ' iterações).');
