// Blag-mas Secret Santa — draw builder.
//
//   node build.mjs test                     -> blagmas-test.html (fake @blagmas.test emails)
//   node build.mjs live emails.json         -> blagmas-live.html (real emails, NEVER commit emails.json)
//
// The draw is made here, sealed per person (AES-GCM, key = PBKDF2(name|email)),
// and only the sealed envelopes go into the page. The pairs are never printed.

import { webcrypto, randomInt } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const subtle = webcrypto.subtle;
const here = path.dirname(fileURLToPath(import.meta.url));

const PEOPLE = ['Sue', 'Simon', 'Laura', 'George', 'Katie', 'Biff', 'Dorothy'];
const EXCLUDE = [['George', 'Laura'], ['Biff', 'Katie'], ['Sue', 'Simon']];
const ITER = 150000;
const PAD_TO = 48; // every envelope is the same size, so length can't hint at the name

const mode = process.argv[2] || 'test';
let emails;
if (mode === 'test') {
  emails = Object.fromEntries(PEOPLE.map(p => [p, `${p.toLowerCase()}@blagmas.test`]));
} else if (mode === 'live') {
  const file = process.argv[3];
  if (!file) throw new Error('live mode needs a path to emails.json');
  emails = JSON.parse(fs.readFileSync(file, 'utf8'));
  for (const p of PEOPLE) if (!emails[p]) throw new Error(`missing email for ${p}`);
} else throw new Error('mode must be test or live');

const norm = s => String(s).trim().toLowerCase();
const blocked = (a, b) => a === b || EXCLUDE.some(([x, y]) => (x === a && y === b) || (x === b && y === a));

function* perms(arr) {
  if (arr.length <= 1) { yield arr.slice(); return; }
  for (let i = 0; i < arr.length; i++) {
    const rest = arr.slice(0, i).concat(arr.slice(i + 1));
    for (const p of perms(rest)) yield [arr[i], ...p];
  }
}

// Every valid draw, then one picked with a crypto-strength random index (uniform).
const valid = [];
for (const p of perms(PEOPLE)) if (p.every((to, i) => !blocked(PEOPLE[i], to))) valid.push(p);
if (!valid.length) throw new Error('no valid draw exists');
const pick = valid[randomInt(valid.length)];
const draw = Object.fromEntries(PEOPLE.map((g, i) => [g, pick[i]]));

// Independent re-check of the chosen draw.
const received = Object.values(draw);
if (new Set(received).size !== PEOPLE.length) throw new Error('duplicate receiver');
for (const g of PEOPLE) if (blocked(g, draw[g])) throw new Error('rule broken');

const b64 = u8 => Buffer.from(u8).toString('base64');
const enc = new TextEncoder();

async function keyFor(name, email, salt, usage) {
  const base = await subtle.importKey('raw', enc.encode(`${norm(name)}|${norm(email)}`), 'PBKDF2', false, ['deriveKey']);
  return subtle.deriveKey({ name: 'PBKDF2', salt, iterations: ITER, hash: 'SHA-256' }, base,
    { name: 'AES-GCM', length: 256 }, false, [usage]);
}

const envelopes = {};
for (const g of PEOPLE) {
  const salt = webcrypto.getRandomValues(new Uint8Array(16));
  const iv = webcrypto.getRandomValues(new Uint8Array(12));
  const plain = JSON.stringify({ to: draw[g] }).padEnd(PAD_TO, ' ');
  const key = await keyFor(g, emails[g], salt, 'encrypt');
  const ct = new Uint8Array(await subtle.encrypt({ name: 'AES-GCM', iv }, key, enc.encode(plain)));
  envelopes[g] = { s: b64(salt), i: b64(iv), c: b64(ct) };
}

// Round-trip every envelope before shipping.
for (const g of PEOPLE) {
  const e = envelopes[g];
  const key = await keyFor(g, emails[g], Buffer.from(e.s, 'base64'), 'decrypt');
  const pt = await subtle.decrypt({ name: 'AES-GCM', iv: Buffer.from(e.i, 'base64') }, key, Buffer.from(e.c, 'base64'));
  if (JSON.parse(new TextDecoder().decode(pt)).to !== draw[g]) throw new Error('round-trip failed');
}

const data = {
  mode, iter: ITER, people: PEOPLE, budget: '£50', envelopes,
  // Test logins only ever ship in the test build.
  testLogins: mode === 'test' ? emails : null,
  excludes: mode === 'test' ? EXCLUDE : null,
  builtAt: new Date().toISOString().slice(0, 10),
};

const tpl = fs.readFileSync(path.join(here, 'template.html'), 'utf8');
if (!tpl.includes('/*__DATA__*/null')) throw new Error('template placeholder missing');
const out = path.join(here, mode === 'test' ? 'blagmas-test.html' : 'blagmas-live.html');
fs.writeFileSync(out, tpl.replace('/*__DATA__*/null', JSON.stringify(data)));

console.log(`valid draws possible: ${valid.length}`);
console.log(`checks passed: 7 envelopes, no self-draws, no duplicates, exclusions respected, all round-trip`);
console.log(`wrote ${path.basename(out)}`);
