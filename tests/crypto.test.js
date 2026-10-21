import { describe, it, expect } from 'vitest';
import {
  encryptFile, decryptFile, hashKeyfile,
  HEADER, CHUNK, MAGIC, TAG_LEN, IV_LEN,
} from '../src/crypto.js';

// Iterações reduzidas só nos testes, para velocidade. O app usa ITER (600.000).
const FAST = 100000; // mínimo aceito pelo decifrador
const PW = 'correct horse battery staple';

const bytes = (n, seed = 7) => {
  const u = new Uint8Array(n);
  let x = seed;
  for (let i = 0; i < n; i++) { x = (x * 1103515245 + 12345) & 0x7fffffff; u[i] = x & 0xff; }
  return u;
};
const enc = (blobLike, pw = PW, kh = null) => encryptFile(new Blob([blobLike]), pw, kh, () => {}, FAST);
const toU8 = async (blob) => new Uint8Array(await blob.arrayBuffer());
const equal = (a, b) => a.length === b.length && a.every((v, i) => v === b[i]);

describe('ida e volta', () => {
  it('arquivo pequeno', async () => {
    const data = bytes(1234);
    const out = await decryptFile(await enc(data), PW, null);
    expect(equal(await toU8(out), data)).toBe(true);
  });

  it('arquivo vazio', async () => {
    const out = await decryptFile(await enc(new Uint8Array(0)), PW, null);
    expect(out.size).toBe(0);
  });

  it('exatamente 1 bloco (1 MiB)', async () => {
    const data = bytes(CHUNK);
    const out = await decryptFile(await enc(data), PW, null);
    expect(equal(await toU8(out), data)).toBe(true);
  });

  it('vários blocos (2,5 MiB)', async () => {
    const data = bytes(Math.floor(CHUNK * 2.5));
    const out = await decryptFile(await enc(data), PW, null);
    expect(equal(await toU8(out), data)).toBe(true);
  });

  it('senha com acentos e emoji', async () => {
    const pw = 'sênha-ção-🔐';
    const data = bytes(500);
    const out = await decryptFile(await enc(data, pw), pw, null);
    expect(equal(await toU8(out), data)).toBe(true);
  });

  it('relata progresso em bytes', async () => {
    const data = bytes(CHUNK * 2 + 10);
    let total = 0;
    await encryptFile(new Blob([data]), PW, null, (n) => { total += n; }, FAST);
    expect(total).toBe(data.length);
  });
});

describe('formato', () => {
  it('cabeçalho: magic, versão e iterações', async () => {
    const blob = await enc(bytes(10));
    const u = await toU8(blob);
    expect([...u.slice(0, 5)]).toEqual([...MAGIC]);
    expect(u[5]).toBe(1);
    expect(new DataView(u.buffer).getUint32(6, true)).toBe(FAST);
    expect(u.length).toBe(HEADER + 4 + IV_LEN + 10 + TAG_LEN);
  });

  it('salt e IV diferem a cada execução (mesmo arquivo)', async () => {
    const data = bytes(100);
    const a = await toU8(await enc(data));
    const b = await toU8(await enc(data));
    expect(equal(a.slice(10, 42), b.slice(10, 42))).toBe(false);
    expect(equal(a, b)).toBe(false);
  });
});

describe('autenticação e falhas', () => {
  it('senha errada', async () => {
    const blob = await enc(bytes(300));
    await expect(decryptFile(blob, 'outra senha', null)).rejects.toThrow(/autentica/i);
  });

  it('keyfile: exige o mesmo arquivo', async () => {
    const kf1 = await hashKeyfile(new Blob([bytes(64, 1)]));
    const kf2 = await hashKeyfile(new Blob([bytes(64, 2)]));
    const data = bytes(300);
    const blob = await enc(data, PW, kf1);
    const ok = await decryptFile(blob, PW, kf1);
    expect(equal(await toU8(ok), data)).toBe(true);
    await expect(decryptFile(blob, PW, kf2)).rejects.toThrow(/autentica/i);
    await expect(decryptFile(blob, PW, null)).rejects.toThrow(/autentica/i);
  });

  it('um bit alterado no texto cifrado', async () => {
    const u = await toU8(await enc(bytes(400)));
    u[u.length - 20] ^= 1;
    await expect(decryptFile(new Blob([u]), PW, null)).rejects.toThrow(/autentica/i);
  });

  it('cabeçalho adulterado (salt)', async () => {
    const u = await toU8(await enc(bytes(400)));
    u[12] ^= 1;
    await expect(decryptFile(new Blob([u]), PW, null)).rejects.toThrow();
  });

  it('arquivo truncado', async () => {
    const u = await toU8(await enc(bytes(400)));
    await expect(decryptFile(new Blob([u.slice(0, u.length - 5)]), PW, null)).rejects.toThrow();
  });

  it('remover o último bloco é detectado', async () => {
    const data = bytes(CHUNK * 2 + 100); // 3 blocos
    const u = await toU8(await enc(data));
    // percorre blocos e corta o último inteiro
    let off = HEADER, lastStart = off;
    while (off < u.length) {
      lastStart = off;
      off += 4 + IV_LEN + new DataView(u.buffer).getUint32(off, true);
    }
    await expect(decryptFile(new Blob([u.slice(0, lastStart)]), PW, null)).rejects.toThrow(/autentica/i);
  });

  it('reordenar blocos é detectado', async () => {
    const data = bytes(CHUNK * 2); // 2 blocos cheios + 1 vazio? (2 blocos)
    const u = await toU8(await enc(data));
    const dv = new DataView(u.buffer);
    const l1 = 4 + IV_LEN + dv.getUint32(HEADER, true);
    const b1 = u.slice(HEADER, HEADER + l1);
    const b2 = u.slice(HEADER + l1);
    const swapped = new Uint8Array([...u.slice(0, HEADER), ...b2, ...b1]);
    await expect(decryptFile(new Blob([swapped]), PW, null)).rejects.toThrow(/autentica/i);
  });

  it('não é arquivo Cofre Forte', async () => {
    await expect(decryptFile(new Blob([bytes(200)]), PW, null)).rejects.toThrow(/Cofre Forte|inválido/i);
  });

  it('arquivo muito curto', async () => {
    await expect(decryptFile(new Blob([bytes(10)]), PW, null)).rejects.toThrow();
  });
});
