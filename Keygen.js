#!/usr/bin/env node
/**
 * Email Automation Pro — Licence Key Generator
 * Spike Wright © 2026
 *
 * KEEP THIS SCRIPT PRIVATE — never ship it to users.
 * Run with: node keygen.js
 */

'use strict';
const crypto = require('crypto');
const readline = require('readline');

// ── SECRET ─────────────────────────────────────────────────────────────────
// This MUST match LICENCE_SECRET in main.js exactly.
// Change both together if you ever rotate the secret.
const LICENCE_SECRET = 'SWxEP-2026-f7Kx9mQ2pLrN8vBcZjYtRh';
const PRODUCT_ID     = 'SWEP1'; // Spike Wright Email Pro v1
// ───────────────────────────────────────────────────────────────────────────

const BASE32_CHARS = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // no 0/O/I/1

function toBase32(buf) {
  let bits = 0, value = 0, output = '';
  for (let i = 0; i < buf.length; i++) {
    value = (value << 8) | buf[i];
    bits += 8;
    while (bits >= 5) {
      output += BASE32_CHARS[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) output += BASE32_CHARS[(value << (5 - bits)) & 31];
  return output;
}

function generateKey(email, expiryDate) {
  // Payload: productId|email|expiry(YYYY-MM)
  const expiry  = expiryDate.slice(0, 7); // YYYY-MM
  const payload = `${PRODUCT_ID}|${email.toLowerCase().trim()}|${expiry}`;

  // HMAC-SHA256 → take first 16 bytes → base32 → 26 chars → split into groups
  const mac   = crypto.createHmac('sha256', LICENCE_SECRET).update(payload).digest();
  const key20 = toBase32(mac.slice(0, 16)).slice(0, 20);

  // Format: SWEP1-XXXXX-XXXXX-XXXXX-XXXXX
  const groups = [
    PRODUCT_ID,
    key20.slice(0,  5),
    key20.slice(5,  10),
    key20.slice(10, 15),
    key20.slice(15, 20)
  ];
  return { key: groups.join('-'), payload, expiry };
}

// ── CLI ─────────────────────────────────────────────────────────────────────
const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
const ask = (q) => new Promise(res => rl.question(q, res));

async function main() {
  console.log('\n═══════════════════════════════════════════');
  console.log('  Email Automation Pro — Licence Keygen');
  console.log('  Spike Wright © 2026 — KEEP PRIVATE');
  console.log('═══════════════════════════════════════════\n');

  const email = await ask('User email address : ');
  const name  = await ask('User name          : ');

  console.log('\nExpiry options:');
  console.log('  1 — 1 year  from today');
  console.log('  2 — 2 years from today');
  console.log('  3 — Lifetime (2099-12)');
  console.log('  4 — Custom date (YYYY-MM-DD)');
  const choice = await ask('Choice [1]: ');

  let expiryDate;
  const now = new Date();
  if (choice === '2') {
    expiryDate = new Date(now.getFullYear() + 2, now.getMonth(), 1).toISOString();
  } else if (choice === '3') {
    expiryDate = '2099-12-31';
  } else if (choice === '4') {
    expiryDate = await ask('Enter expiry date (YYYY-MM-DD): ');
  } else {
    expiryDate = new Date(now.getFullYear() + 1, now.getMonth(), 1).toISOString();
  }

  const { key, expiry } = generateKey(email, expiryDate);

  console.log('\n───────────────────────────────────────────');
  console.log(`  Name    : ${name}`);
  console.log(`  Email   : ${email.toLowerCase().trim()}`);
  console.log(`  Expires : ${expiry}`);
  console.log(`\n  LICENCE KEY:\n`);
  console.log(`  ${key}`);
  console.log('───────────────────────────────────────────\n');
  console.log('Send the key above to the user. Do not send this script.\n');

  rl.close();
}

main().catch(e => { console.error(e); process.exit(1); });
