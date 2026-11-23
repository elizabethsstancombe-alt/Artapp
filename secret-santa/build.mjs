// Blag-mas Secret Santa — draw builder.
//
//   node build.mjs test                     -> blagmas-test.html (fake Ofcom drama numbers + codes)
//   node build.mjs live mobiles.json        -> blagmas-live.html + elf-codes.txt (NEVER commit either input or codes)
//
// The draw is made here, sealed per person (AES-GCM, key = PBKDF2(name|mobile|elf code)),
// and only the sealed envelopes go into the page. The pairs are never printed.

import { webcrypto, randomInt } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const subtle = webcrypto.subtle;
const here = path.dirname(fileURLToPath(import.meta.url));

const PEOPLE = ['Sue', 'Simon', 'Laura', 'George', 'Katie', 'Biff', 'Dorothy'];
// [giver, receiver, bothWays]
const RULES = [
  ['George', 'Laura', true],
  ['Biff', 'Katie', true],
  ['Sue', 'Simon', true],
  ['George', 'Katie', true],   // siblings
  ['Dorothy', 'Simon', false], // one way: Simon can still get Dorothy
];
const CODE_DIGITS = 6;
const ITER = 150000;
const PAD_TO = 48; // every envelope is the same size, so length can't hint at the name

const mode = process.argv[2] || 'test';
const newCode = () => String(randomInt(10 ** CODE_DIGITS)).padStart(CODE_DIGITS, '0');
let mobiles;
if (mode === 'test') {
  // 07700 900000-900999 is Ofcom's range reserved for TV drama: never a real phone.
  mobiles = Object.fromEntries(PEOPLE.map((p, i) => [p, `07700 900${String(101 + i * 111).padStart(3, '0')}`]));
} else if (mode === 'live') {
  const file = process.argv[3];
  if (!file) throw new Error('live mode needs a path to mobiles.json');
  mobiles = JSON.parse(fs.readFileSync(file, 'utf8'));
  for (const p of PEOPLE) if (!mobiles[p]) throw new Error(`missing mobile for ${p}`);
} else throw new Error('mode must be test or live');
const codes = Object.fromEntries(PEOPLE.map(p => [p, newCode()]));

const norm = s => String(s).trim().toLowerCase();
// Same rules as the page: digits only, +44 / 0044 / missing 0 all become 07...
function normMobile(s) {
  let d = String(s).replace(/\D/g, '');
  if (d.startsWith('0044')) d = '0' + d.slice(4);
  else if (d.startsWith('44')) d = '0' + d.slice(2);
  else if (!d.startsWith('0')) d = '0' + d;
  return d;
}
const normCode = s => String(s).replace(/\D/g, '');
const secretFor = p => `${norm(p)}|${normMobile(mobiles[p])}|${normCode(codes[p])}`;
const blocked = (g, r) => g === r || RULES.some(([a, b, both]) => (g === a && r === b) || (both && g === b && r === a));
for (const p of PEOPLE) if (normMobile(mobiles[p]).length !== 11) throw new Error(`${p}'s mobile doesn't look like a UK mobile`);

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

async function keyFor(secret, salt, usage) {
  const base = await subtle.importKey('raw', enc.encode(secret), 'PBKDF2', false, ['deriveKey']);
  return subtle.deriveKey({ name: 'PBKDF2', salt, iterations: ITER, hash: 'SHA-256' }, base,
    { name: 'AES-GCM', length: 256 }, false, [usage]);
}

const envelopes = {};
for (const g of PEOPLE) {
  const salt = webcrypto.getRandomValues(new Uint8Array(16));
  const iv = webcrypto.getRandomValues(new Uint8Array(12));
  const plain = JSON.stringify({ to: draw[g] }).padEnd(PAD_TO, ' ');
  const key = await keyFor(secretFor(g), salt, 'encrypt');
  const ct = new Uint8Array(await subtle.encrypt({ name: 'AES-GCM', iv }, key, enc.encode(plain)));
  envelopes[g] = { s: b64(salt), i: b64(iv), c: b64(ct) };
}

// Round-trip every envelope before shipping.
for (const g of PEOPLE) {
  const e = envelopes[g];
  const key = await keyFor(secretFor(g), Buffer.from(e.s, 'base64'), 'decrypt');
  const pt = await subtle.decrypt({ name: 'AES-GCM', iv: Buffer.from(e.i, 'base64') }, key, Buffer.from(e.c, 'base64'));
  if (JSON.parse(new TextDecoder().decode(pt)).to !== draw[g]) throw new Error('round-trip failed');
}

const data = {
  mode, iter: ITER, people: PEOPLE, budget: '£50', envelopes,
  // Test logins only ever ship in the test build.
  testLogins: mode === 'test' ? Object.fromEntries(PEOPLE.map(p => [p, { mobile: mobiles[p], code: codes[p] }])) : null,
  rules: mode === 'test' ? RULES : null,
  builtAt: new Date().toISOString().slice(0, 10),
};

const tpl = fs.readFileSync(path.join(here, 'template.html'), 'utf8');
if (!tpl.includes('/*__DATA__*/null')) throw new Error('template placeholder missing');
const out = path.join(here, mode === 'test' ? 'blagmas-test.html' : 'blagmas-live.html');
fs.writeFileSync(out, tpl.replace('/*__DATA__*/null', JSON.stringify(data)));

if (mode === 'live') {
  // For the organiser to text out. Gitignored. Contains codes, not pairs.
  const lines = PEOPLE.map(p => `${p}: elf code ${codes[p].slice(0, 3)} ${codes[p].slice(3)}`);
  fs.writeFileSync(path.join(here, 'elf-codes.txt'), lines.join('\n') + '\n');
  console.log('wrote elf-codes.txt (text each person their own code, then delete it)');
}
console.log(`valid draws possible: ${valid.length}`);
console.log(`checks passed: 7 envelopes, no self-draws, no duplicates, exclusions respected, all round-trip`);
console.log(`wrote ${path.basename(out)}`);
