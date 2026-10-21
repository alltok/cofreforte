/**
 * Motor criptográfico do Cofre Forte (Web Crypto API).
 *
 * Formato .cofre (v1)
 *   [0..4]  "COFRE"            magic
 *   [5]     0x01               versão
 *   [6..9]  iterações PBKDF2   u32 little-endian
 *   [10..41] salt              32 bytes aleatórios
 *   por bloco: [u32 LE tamanho do cifrado][12 bytes IV][cifrado + tag de 16 bytes]
 *   AAD de cada bloco = índice do bloco (u32 LE) + flag de último bloco (1 byte)
 */

const enc = new TextEncoder();

export const MAGIC = enc.encode('COFRE');
export const VERSION = 1;
export const SALT_LEN = 32;
export const IV_LEN = 12;
export const TAG_LEN = 16;
export const CHUNK = 1024 * 1024; // 1 MiB
export const ITER = 600000;
export const HEADER = 5 + 1 + 4 + SALT_LEN;

const tick = () => new Promise((r) => setTimeout(r, 0));

export async function deriveKey(password, keyHash, salt, iterations, usage) {
  const pw = enc.encode(password);
  const mat = new Uint8Array(pw.length + (keyHash ? keyHash.length : 0));
  mat.set(pw, 0);
  if (keyHash) mat.set(keyHash, pw.length);
  const base = await crypto.subtle.importKey('raw', mat, 'PBKDF2', false, ['deriveKey']);
  mat.fill(0); pw.fill(0);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations, hash: 'SHA-256' },
    base, { name: 'AES-GCM', length: 256 }, false, [usage]
  );
}

export function chunkAad(index, isFinal) {
  const b = new Uint8Array(5);
  new DataView(b.buffer).setUint32(0, index, true);
  b[4] = isFinal ? 1 : 0;
  return b;
}

export async function encryptFile(file, password, keyHash, onBytes = () => {}, iterations = ITER) {
  const salt = crypto.getRandomValues(new Uint8Array(SALT_LEN));
  const key = await deriveKey(password, keyHash, salt, iterations, 'encrypt');
  const header = new Uint8Array(HEADER);
  header.set(MAGIC, 0);
  header[5] = VERSION;
  new DataView(header.buffer).setUint32(6, iterations, true);
  header.set(salt, 10);

  const parts = [header];
  const size = file.size;
  let off = 0, idx = 0;
  do {
    const end = Math.min(off + CHUNK, size);
    const pt = await file.slice(off, end).arrayBuffer();
    const isFinal = end >= size;
    const iv = crypto.getRandomValues(new Uint8Array(IV_LEN));
    const ct = new Uint8Array(await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv, additionalData: chunkAad(idx, isFinal), tagLength: 128 }, key, pt));
    const len = new Uint8Array(4);
    new DataView(len.buffer).setUint32(0, ct.length, true);
    parts.push(len, iv, ct);
    onBytes(end - off);
    await tick();
    off = end; idx++;
  } while (off < size);
  return new Blob(parts, { type: 'application/octet-stream' });
}

export async function decryptFile(file, password, keyHash, onBytes = () => {}) {
  if (file.size < HEADER + 4 + IV_LEN + TAG_LEN) throw new Error('Arquivo inválido ou muito curto.');
  const head = new Uint8Array(await file.slice(0, HEADER).arrayBuffer());
  for (let i = 0; i < MAGIC.length; i++) {
    if (head[i] !== MAGIC[i]) throw new Error('Este arquivo não foi criado pelo Cofre Forte.');
  }
  if (head[5] !== VERSION) throw new Error('Versão do formato não suportada (' + head[5] + ').');
  const iter = new DataView(head.buffer).getUint32(6, true);
  if (iter < 100000 || iter > 10000000) throw new Error('Cabeçalho corrompido.');
  const salt = head.slice(10, 10 + SALT_LEN);
  const key = await deriveKey(password, keyHash, salt, iter, 'decrypt');

  const parts = [];
  let off = HEADER, idx = 0;
  while (off < file.size) {
    if (off + 4 > file.size) throw new Error('Arquivo truncado ou corrompido.');
    const lenBuf = await file.slice(off, off + 4).arrayBuffer();
    const len = new DataView(lenBuf).getUint32(0, true);
    if (len < TAG_LEN || len > CHUNK + TAG_LEN) throw new Error('Bloco inválido: arquivo corrompido.');
    const start = off + 4, end = start + IV_LEN + len;
    if (end > file.size) throw new Error('Arquivo truncado ou corrompido.');
    const buf = await file.slice(start, end).arrayBuffer();
    const iv = new Uint8Array(buf, 0, IV_LEN);
    const ct = new Uint8Array(buf, IV_LEN);
    const isFinal = end === file.size;
    let pt;
    try {
      pt = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv, additionalData: chunkAad(idx, isFinal), tagLength: 128 }, key, ct);
    } catch (_) {
      throw new Error('Falha na autenticação: senha ou keyfile incorretos, ou arquivo adulterado.');
    }
    parts.push(pt);
    onBytes(end - off);
    await tick();
    off = end; idx++;
  }
  return new Blob(parts, { type: 'application/octet-stream' });
}

/** SHA-256 de um Blob/File (usado como segundo fator). */
export async function hashKeyfile(file) {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', await file.arrayBuffer()));
}
