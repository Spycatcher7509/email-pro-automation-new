'use strict';

// Polyfill Web API globals that some packages expect but Electron's Node doesn't provide
if (typeof File === 'undefined') {
  const { Blob } = require('buffer');
  global.File = class File extends Blob {
    constructor(chunks, name, opts = {}) {
      super(chunks, opts);
      this.name = name;
      this.lastModified = opts.lastModified || Date.now();
    }
  };
}

const { app, BrowserWindow, ipcMain, dialog, shell, session } = require('electron');
const { google } = require('googleapis');
const fs     = require('fs');
const fsp    = fs.promises;
const path   = require('path');
const http   = require('http');
const crypto = require('crypto');

/* ─── lazy-load optional deps ─── */
let QRCode, openpgp, mlKem768, mlKem1024;
try { QRCode   = require('qrcode');  } catch(e) { console.warn('qrcode unavailable'); }
try { openpgp  = require('openpgp'); } catch(e) { console.warn('openpgp unavailable'); }
try {
  ({ ml_kem768: mlKem768, ml_kem1024: mlKem1024 } = require('@noble/post-quantum/ml-kem'));
  const _loaded = [mlKem1024 && 'ML-KEM-1024', mlKem768 && 'ML-KEM-768'].filter(Boolean).join(', ');
  console.log('✅ Post-quantum KEM loaded:', _loaded);
} catch(e) { console.warn('@noble/post-quantum/ml-kem unavailable — X25519-only fallback:', e.message); }

/** Returns the ML-KEM implementation for a given variant ('1024' or '768'). Falls back gracefully. */
function getKemLib(variant) {
  if (variant === '1024' && mlKem1024) return mlKem1024;
  if (mlKem768) return mlKem768;
  return null;
}

/* ═══════════════════════════════════════════
   PATHS & CONSTANTS
═══════════════════════════════════════════ */
const DATA_DIR     = app.getPath('userData');
const TOKEN_PATH   = path.join(DATA_DIR, 'token.json');
const DB_JSON_PATH = path.join(DATA_DIR, 'email-automation-db.json');
const MY_KEYS_PATH = path.join(DATA_DIR, 'my-keys.json');
const LICENCE_PATH = path.join(DATA_DIR, 'licence.json');

// ── Licence ─────────────────────────────────────────────────────────────────
// MUST match keygen.js exactly. Change both together if rotating secret.
const LICENCE_SECRET = 'SWxEP-2026-f7Kx9mQ2pLrN8vBcZjYtRh';
const PRODUCT_ID     = 'SWEP1';
const BASE32_CHARS   = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';

function toBase32Lic(buf) {
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

function generateLicenceKey(email, expiryYYYYMM) {
  const expiry  = expiryYYYYMM.slice(0, 7);
  const payload = `${PRODUCT_ID}|${email.toLowerCase().trim()}|${expiry}`;
  const mac     = crypto.createHmac('sha256', LICENCE_SECRET).update(payload).digest();
  const key20   = toBase32Lic(mac.slice(0, 16)).slice(0, 20);
  const groups  = [PRODUCT_ID, key20.slice(0,5), key20.slice(5,10), key20.slice(10,15), key20.slice(15,20)];
  return { key: groups.join('-'), expiry };
}

function validateLicenceKey(rawKey, email) {
  try {
    // Owner bypass — checked FIRST before any format or key validation
    const OWNER_EMAILS = ['spike@thewrightsupport.com'];
    if (OWNER_EMAILS.includes(email.toLowerCase().trim())) {
      return { valid: true, expiry: '2099-12', email: email.toLowerCase().trim(), reason: null };
    }

    const key   = rawKey.toUpperCase().replace(/\s/g, '');
    const parts = key.split('-');
    if (parts.length !== 5) return { valid: false, reason: 'Invalid key format' };

    // Walk-up key — SWEPW prefix, not tied to email
    // We cannot re-derive these (they use a random seed stored only in the log)
    // so we validate format and expiry from the stored licence file only.
    // On first entry we accept any well-formed SWEPW key and store it.
    if (parts[0] === 'SWEPW') {
      const now = new Date();
      // Walk-up keys are self-certifying on first use — we trust the format
      // and store them. Expiry is tracked via stored licence file.
      return {
        valid:   true,
        expiry:  '2099-12', // walk-up keys shown as lifetime in app
        email:   email.toLowerCase().trim(),
        walkup:  true,
        reason:  null
      };
    }

    if (parts[0] !== PRODUCT_ID) return { valid: false, reason: 'Invalid key format' };

    // Try each possible expiry month for the last 12 months back and 24 months forward
    // (we don't store expiry in the key itself — we brute-check plausible months)
    const keyBody = parts.slice(1).join('');
    const now     = new Date();

    for (let offset = -1; offset <= 36; offset++) {
      const d = new Date(now.getFullYear(), now.getMonth() + offset, 1);
      const expiry  = `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}`;
      const payload = `${PRODUCT_ID}|${email.toLowerCase().trim()}|${expiry}`;
      const mac     = crypto.createHmac('sha256', LICENCE_SECRET).update(payload).digest();
      const expected = toBase32Lic(mac.slice(0, 16)).slice(0, 20);
      if (keyBody === expected) {
        const expiryDate = new Date(d.getFullYear(), d.getMonth() + 1, 0); // last day of month
        const expired    = expiryDate < now && expiry !== '2099-12';
        return {
          valid:   !expired,
          reason:  expired ? `Licence expired ${expiry}` : null,
          expiry,
          email:   email.toLowerCase().trim(),
          expired
        };
      }
    }
    return { valid: false, reason: 'Key does not match this email address' };
  } catch(e) {
    return { valid: false, reason: e.message };
  }
}

function loadStoredLicence() {
  try { return JSON.parse(fs.readFileSync(LICENCE_PATH, 'utf8')); } catch { return null; }
}

function saveStoredLicence(data) {
  try { fs.writeFileSync(LICENCE_PATH, JSON.stringify(data, null, 2)); } catch {}
}
// ────────────────────────────────────────────────────────────────────────────

const CREDENTIALS_PATH = app.isPackaged
  ? path.join(process.resourcesPath, 'credentials.json')
  : path.join(__dirname, 'credentials.json');

const SCOPES          = ['https://www.googleapis.com/auth/gmail.send'];
const MAX_EMAIL_BYTES = 20 * 1024 * 1024;
const POLL_INTERVAL   = 30_000;

/* ═══════════════════════════════════════════
   DATABASE  (sql.js – pure JS WASM)
═══════════════════════════════════════════ */
let db;

function persistDB() {
  if (!db) return;
  try { fs.writeFileSync(DB_JSON_PATH, JSON.stringify(Array.from(db.export()))); }
  catch(e) { console.error('DB persist error:', e.message); }
}

async function initDB() {
  let sqljs;
  try { sqljs = require('sql.js'); } catch { console.warn('sql.js unavailable'); return; }
  const SQL = await sqljs();
  let dbData;
  try { dbData = new Uint8Array(JSON.parse(fs.readFileSync(DB_JSON_PATH, 'utf8'))); } catch {}
  db = dbData ? new SQL.Database(dbData) : new SQL.Database();
  db.run(`
    CREATE TABLE IF NOT EXISTS tasks (
      id TEXT PRIMARY KEY, name TEXT NOT NULL, recipient TEXT NOT NULL,
      schedule TEXT NOT NULL, enabled INTEGER DEFAULT 1,
      created_at TEXT DEFAULT (datetime('now')), updated_at TEXT DEFAULT (datetime('now'))
    );
    CREATE TABLE IF NOT EXISTS folder_pairs (
      id TEXT PRIMARY KEY, task_id TEXT NOT NULL,
      name TEXT NOT NULL, source TEXT NOT NULL, dest TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS checksums (
      id TEXT PRIMARY KEY, file_path TEXT NOT NULL, file_name TEXT NOT NULL,
      sha256 TEXT NOT NULL, size_bytes INTEGER NOT NULL,
      task_id TEXT, pair_id TEXT, computed_at TEXT DEFAULT (datetime('now'))
    );
    CREATE TABLE IF NOT EXISTS receipts (
      id TEXT PRIMARY KEY, task_id TEXT, task_name TEXT, recipient TEXT,
      subject TEXT, file_names TEXT, checksum_ids TEXT,
      sent_at TEXT DEFAULT (datetime('now')), qr_data TEXT
    );
    CREATE TABLE IF NOT EXISTS contacts (
      id TEXT PRIMARY KEY, name TEXT NOT NULL, email TEXT NOT NULL UNIQUE,
      enc_mode TEXT NOT NULL DEFAULT 'selfcontained',
      mlkem_variant TEXT NOT NULL DEFAULT '768',
      cipher TEXT NOT NULL DEFAULT 'aes-256-gcm',
      pgp_compat INTEGER NOT NULL DEFAULT 0,
      imessage_handle TEXT,
      mlkem_pub TEXT, x25519_pub TEXT, pgp_pub TEXT, notes TEXT,
      created_at TEXT DEFAULT (datetime('now')), updated_at TEXT DEFAULT (datetime('now'))
    );
  `);
  persistDB();
  console.log('✅ Database ready');
}

function dbRun(sql, params = []) {
  if (!db) return;
  try { db.run(sql, params); persistDB(); } catch(e) { console.error('DB run:', e.message); }
}
function dbAll(sql, params = []) {
  if (!db) return [];
  try {
    const res = db.exec(sql, params);
    if (!res.length) return [];
    const { columns, values } = res[0];
    return values.map(row => Object.fromEntries(columns.map((c,i) => [c, row[i]])));
  } catch(e) { console.error('DB all:', e.message); return []; }
}
function dbGet(sql, params = []) { return dbAll(sql, params)[0] || null; }

/* ═══════════════════════════════════════════
   IN-MEMORY FALLBACK
═══════════════════════════════════════════ */
let memTasks = [], memChecksums = [], memReceipts = [], memContacts = [];
function loadMem() {
  try { memTasks    = JSON.parse(fs.readFileSync(path.join(DATA_DIR, 'tasks.json'),    'utf8')); } catch {}
  try { memContacts = JSON.parse(fs.readFileSync(path.join(DATA_DIR, 'contacts.json'), 'utf8')); } catch {}
}
function saveMem() {
  fs.writeFileSync(path.join(DATA_DIR, 'tasks.json'),    JSON.stringify(memTasks,    null, 2));
  fs.writeFileSync(path.join(DATA_DIR, 'contacts.json'), JSON.stringify(memContacts, null, 2));
}
function uid() { return crypto.randomUUID(); }

/* ═══════════════════════════════════════════
   ██████  HYBRID POST-QUANTUM ENCRYPTION
═══════════════════════════════════════════ */

let myKeys = null; // { x25519:{pub,priv}, kyber:{pub,priv}, pgp:{pub,priv}, name, email }

async function loadMyKeys() {
  try { myKeys = JSON.parse(fs.readFileSync(MY_KEYS_PATH, 'utf8')); console.log('🔑 Loaded keys for', myKeys.email); }
  catch { myKeys = null; }
}

async function generateMyKeys(name, email, kemVariant = '1024') {
  // ML-KEM keypair (post-quantum component) — variant: '1024' (recommended) or '768'
  let mlkem = null;
  const kemLib = getKemLib(kemVariant);
  const resolvedVariant = kemLib ? (kemVariant === '1024' && mlKem1024 ? '1024' : '768') : null;
  if (kemLib) {
    const kp = kemLib.keygen();
    mlkem = {
      pub:     Buffer.from(kp.publicKey).toString('base64'),
      priv:    Buffer.from(kp.secretKey).toString('base64'),
      variant: resolvedVariant
    };
  }

  // X25519 keypair (classical, always generated)
  const x25519kp = crypto.generateKeyPairSync('x25519', {
    publicKeyEncoding:  { type: 'spki',  format: 'der' },
    privateKeyEncoding: { type: 'pkcs8', format: 'der' }
  });

  // OpenPGP keypair — v6 key format (RFC 9580) with Ed25519/X25519 keys.
  // v6 keys support AEAD (including ChaCha20-Poly1305) and are not readable by
  // GPG < 2.4.7 or Thunderbird < 128. For legacy compatibility, contacts have a
  // v4 compatibility flag which generates a v4-format key on their send path.
  let pgp = null;
  if (openpgp) {
    try {
      const { privateKey, publicKey } = await openpgp.generateKey({
        type: 'ecc', curve: 'curve25519',
        userIDs: [{ name, email }], format: 'armored',
        config: { v6Keys: true }   // OpenPGP v6 (RFC 9580) — AEAD support, ChaCha20
      });
      pgp = { pub: publicKey, priv: privateKey };
    } catch(e) {
      // Fallback to v4 if v6 not supported by installed openpgp version
      try {
        const { privateKey, publicKey } = await openpgp.generateKey({
          type: 'ecc', curve: 'curve25519',
          userIDs: [{ name, email }], format: 'armored'
        });
        pgp = { pub: publicKey, priv: privateKey };
        console.warn('OpenPGP v6 key generation not supported — generated v4 key. Run: npm install openpgp@^6.0.0');
      } catch(e2) { console.warn('PGP keygen failed:', e2.message); }
    }
  }

  myKeys = {
    mlkem,
    x25519: {
      pub:  Buffer.from(x25519kp.publicKey).toString('base64'),
      priv: Buffer.from(x25519kp.privateKey).toString('base64')
    },
    pgp, name, email,
    mlkem_variant: resolvedVariant || null,
    created_at: new Date().toISOString()
  };
  fs.writeFileSync(MY_KEYS_PATH, JSON.stringify(myKeys, null, 2));
  console.log('🔑 Keys generated for', email, mlkem ? `(ML-KEM-${resolvedVariant} + X25519)` : '(X25519 only)');
  return myKeys;
}

/* ── Hybrid KEM encrypt ──
   ML-KEM-768 + X25519 → HKDF(both shared secrets) → AES-256-GCM
   If mlKem768 unavailable: X25519-only fallback.
*/
async function hybridEncrypt(plaintext, contact) {
  let sharedSecret, kemCiphertext, x25519Ephem, algorithm;

  // Always do X25519 ECDH
  const ephem = crypto.generateKeyPairSync('x25519', {
    publicKeyEncoding:  { type: 'spki',  format: 'der' },
    privateKeyEncoding: { type: 'pkcs8', format: 'der' }
  });
  const ephemPrivKey = crypto.createPrivateKey({ key: Buffer.from(ephem.privateKey), format: 'der', type: 'pkcs8' });
  const recipX25519  = crypto.createPublicKey({ key: Buffer.from(contact.x25519_pub, 'base64'), format: 'der', type: 'spki' });
  const x25519SS     = crypto.diffieHellman({ privateKey: ephemPrivKey, publicKey: recipX25519 });
  x25519Ephem        = Buffer.from(ephem.publicKey).toString('base64');

  const contactKemVariant = contact.mlkem_variant || '768';
  const encKemLib = getKemLib(contactKemVariant);
  // Determine symmetric cipher — ChaCha20-Poly1305 not available in Web Crypto,
  // so self-contained mode always uses AES-256-GCM; registry mode honours contact preference.
  const symCipher = (contact.cipher === 'chacha20-poly1305') ? 'chacha20-poly1305' : 'aes-256-gcm';
  const symLabel  = symCipher === 'chacha20-poly1305' ? 'ChaCha20-Poly1305' : 'AES-256-GCM';

  if (encKemLib && contact.mlkem_pub) {
    const recipMLKEM   = Buffer.from(contact.mlkem_pub, 'base64');
    const { cipherText, sharedSecret: mlkemSS } = encKemLib.encapsulate(recipMLKEM);
    const combined     = Buffer.concat([x25519SS, Buffer.from(mlkemSS)]);
    sharedSecret       = Buffer.from(crypto.hkdfSync('sha256', combined, Buffer.alloc(0), Buffer.from('email-automation-v2-hybrid'), 32));
    kemCiphertext      = Buffer.from(cipherText).toString('base64');
    const resolvedKemVariant = (contactKemVariant === '1024' && mlKem1024) ? '1024' : '768';
    algorithm          = `ML-KEM-${resolvedKemVariant}+X25519+${symLabel}`;
  } else {
    sharedSecret       = Buffer.from(crypto.hkdfSync('sha256', x25519SS, Buffer.alloc(0), Buffer.from('email-automation-v2'), 32));
    kemCiphertext      = null;
    algorithm          = `X25519+${symLabel}`;
  }

  const iv     = crypto.randomBytes(12);
  const cipherOpts = symCipher === 'chacha20-poly1305' ? { authTagLength: 16 } : {};
  const cipher = crypto.createCipheriv(symCipher, sharedSecret, iv, cipherOpts);
  const ct     = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag    = cipher.getAuthTag();

  return {
    ciphertext:    ct.toString('base64'),
    kemCiphertext,
    x25519Ephem,
    iv:            iv.toString('base64'),
    tag:           tag.toString('base64'),
    cipher:        symCipher,
    algorithm
  };
}

async function hybridDecrypt(envelope, privKeys) {
  let sharedSecret;

  const myX25519  = crypto.createPrivateKey({ key: Buffer.from(privKeys.x25519.priv, 'base64'), format: 'der', type: 'pkcs8' });
  const ephPub    = crypto.createPublicKey({ key: Buffer.from(envelope.x25519Ephem, 'base64'), format: 'der', type: 'spki' });
  const x25519SS  = crypto.diffieHellman({ privateKey: myX25519, publicKey: ephPub });

  if (privKeys.mlkem && envelope.kemCiphertext && envelope.algorithm?.includes('ML-KEM')) {
    const envelopeVariant = envelope.algorithm?.includes('ML-KEM-1024') ? '1024' : '768';
    const decKemLib = getKemLib(envelopeVariant);
    if (!decKemLib) throw new Error(`ML-KEM-${envelopeVariant} library not available — run: npm install @noble/post-quantum`);
    const mlkemSS  = decKemLib.decapsulate(Buffer.from(envelope.kemCiphertext, 'base64'), Buffer.from(privKeys.mlkem.priv, 'base64'));
    const combined = Buffer.concat([x25519SS, Buffer.from(mlkemSS)]);
    sharedSecret   = Buffer.from(crypto.hkdfSync('sha256', combined, Buffer.alloc(0), Buffer.from('email-automation-v2-hybrid'), 32));
  } else {
    sharedSecret   = Buffer.from(crypto.hkdfSync('sha256', x25519SS, Buffer.alloc(0), Buffer.from('email-automation-v2'), 32));
  }

  const iv        = Buffer.from(envelope.iv,  'base64');
  const tag       = Buffer.from(envelope.tag, 'base64');
  const symCipher = envelope.cipher || 'aes-256-gcm'; // backward-compatible default
  const decOpts   = symCipher === 'chacha20-poly1305' ? { authTagLength: 16 } : {};
  const decipher  = crypto.createDecipheriv(symCipher, sharedSecret, iv, decOpts);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(Buffer.from(envelope.ciphertext, 'base64')), decipher.final()]);
}

/* ── Mode: SELF-CONTAINED ── */
async function encryptSelfContained(bodyText, fileBuffers, fileNames) {
  const ephem = crypto.generateKeyPairSync('x25519', {
    publicKeyEncoding:  { type: 'spki',  format: 'der' },
    privateKeyEncoding: { type: 'pkcs8', format: 'der' }
  });
  const fakeContact = { x25519_pub: Buffer.from(ephem.publicKey).toString('base64') };
  const payload   = JSON.stringify({ body: bodyText, files: fileBuffers.map((b,i) => ({ name: fileNames[i], data: b.toString('base64') })) });
  const envelope  = await hybridEncrypt(Buffer.from(payload), fakeContact);
  envelope.decryptPriv = { x25519: { priv: Buffer.from(ephem.privateKey).toString('base64') } };
  return buildDecryptionHTML(envelope);
}

/* ── Password-protected self-contained HTML ──
   PBKDF2 derives a wrapping key from the user's password.
   That wrapping key decrypts the ephemeral X25519 private key.
   Then normal X25519+HKDF+AES-GCM decryption proceeds unchanged.
*/
function buildPasswordDecryptionHTML(envelope) {
  const envJson = JSON.stringify(envelope);
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Encrypted Message — Password Required</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:system-ui,sans-serif;background:#0d1117;color:#e6edf3;padding:40px;min-height:100vh}
.card{max-width:720px;margin:0 auto;background:#161b22;border:1px solid #30363d;border-radius:14px;padding:36px}
.badge{display:inline-flex;align-items:center;gap:6px;background:rgba(88,166,255,0.1);border:1px solid rgba(88,166,255,0.3);color:#58a6ff;padding:5px 12px;border-radius:20px;font-size:12px;font-weight:600;letter-spacing:.04em;margin-bottom:20px}
.badge-pw{background:rgba(245,158,11,0.1);border-color:rgba(245,158,11,0.3);color:#f5a623}
h1{font-size:22px;margin-bottom:8px;color:#fff}
.sub{color:#8b949e;font-size:13px;line-height:1.6;margin-bottom:24px}
.sub strong{color:#e6edf3}
.pw-wrap{display:flex;gap:8px;margin-bottom:16px}
.pw-input{flex:1;background:#0d1117;border:1px solid #30363d;border-radius:8px;color:#e6edf3;font-size:15px;padding:10px 14px;outline:none;letter-spacing:.05em}
.pw-input:focus{border-color:#58a6ff}
.btn{background:#238636;color:#fff;border:none;padding:11px 22px;border-radius:8px;cursor:pointer;font-size:14px;font-weight:600;transition:background .15s;white-space:nowrap}
.btn:hover{background:#2ea043}
.btn:disabled{background:#333;cursor:default;color:#666}
.btn-blue{background:#1f6feb}.btn-blue:hover{background:#388bfd}
#output{margin-top:24px;white-space:pre-wrap;word-break:break-word;background:#0d1117;border:1px solid #30363d;border-radius:8px;padding:18px;font-size:13px;line-height:1.6;display:none}
#files{margin-top:16px;display:none}
.files-label{color:#8b949e;font-size:11px;text-transform:uppercase;letter-spacing:.08em;margin-bottom:8px}
.file-btn{background:#1f6feb;color:#fff;border:none;padding:7px 14px;border-radius:6px;cursor:pointer;font-size:12px;margin:3px;transition:background .15s}
.file-btn:hover{background:#388bfd}
.algo{color:#8b949e;font-size:11px;margin-top:16px}
#status{margin-top:10px;font-size:12px;min-height:18px}
.progress{display:none;margin-top:10px}
.progress-bar{height:4px;background:#30363d;border-radius:2px;overflow:hidden}
.progress-fill{height:100%;background:#58a6ff;border-radius:2px;animation:prog 1.5s ease-in-out infinite}
@keyframes prog{0%{width:0%}50%{width:70%}100%{width:100%}}
</style>
</head>
<body>
<div class="card">
  <div class="badge">&#x1F512; Hybrid Post-Quantum Encrypted</div>
  <span class="badge badge-pw" style="margin-left:8px">&#x1F511; Password Protected</span>
  <h1 style="margin-top:16px">Encrypted Message</h1>
  <div class="sub">
    This message is encrypted with <strong>${envelope.algorithm || 'X25519+AES-256-GCM'}</strong> and protected by a password.<br>
    Enter the password you received (via text message or in person) to decrypt. Everything runs locally &mdash; nothing is sent anywhere.
  </div>
  <div class="pw-wrap">
    <input class="pw-input" type="password" id="pwdInput" placeholder="Enter password&hellip;" onkeydown="if(event.key==='Enter')decrypt()">
    <button class="btn btn-blue" onclick="toggleShow()" id="showBtn" title="Show/hide password">&#x1F441;</button>
    <button class="btn" onclick="decrypt()" id="decBtn">&#x1F513; Decrypt</button>
  </div>
  <div class="progress" id="progress"><div class="progress-bar"><div class="progress-fill"></div></div></div>
  <div id="status"></div>
  <div id="output"></div>
  <div id="files"></div>
  <div class="algo">Algorithm: ${envelope.algorithm || 'X25519+AES-256-GCM'} &middot; Key protection: PBKDF2-SHA256 (${envelope.pbkdf2?.iterations?.toLocaleString() || '600,000'} iterations) + AES-256-GCM</div>
</div>
<script>
const ENV = ${envJson};
let shown = false;
function toggleShow() {
  shown = !shown;
  const inp = document.getElementById('pwdInput');
  inp.type = shown ? 'text' : 'password';
  document.getElementById('showBtn').textContent = shown ? '&#x1F648;' : '&#x1F441;';
}
function status(msg, colour) {
  const el = document.getElementById('status');
  el.textContent = msg;
  el.style.color = colour || '#8b949e';
}
function b64ToBytes(b64) {
  return Uint8Array.from(atob(b64), c => c.charCodeAt(0));
}
function mergeCtTag(ct, tag) {
  const out = new Uint8Array(ct.length + tag.length);
  out.set(ct); out.set(tag, ct.length);
  return out;
}
async function importX25519(b64, type) {
  const der = b64ToBytes(b64);
  return crypto.subtle.importKey(
    type === 'pub' ? 'spki' : 'pkcs8', der,
    { name: 'X25519' }, false,
    type === 'pub' ? [] : ['deriveBits']
  );
}
async function decrypt() {
  const btn = document.getElementById('decBtn');
  const prog = document.getElementById('progress');
  const password = document.getElementById('pwdInput').value;
  if (!password) { status('Please enter the password.'); return; }
  btn.disabled = true;
  prog.style.display = 'block';
  status('Deriving key from password (this takes a moment for security)\\u2026');
  try {
    // Step 1: PBKDF2 — derive wrapping key from password
    const keyMaterial = await crypto.subtle.importKey(
      'raw', new TextEncoder().encode(password),
      'PBKDF2', false, ['deriveKey']
    );
    const wrapKey = await crypto.subtle.deriveKey(
      {
        name: 'PBKDF2',
        salt: b64ToBytes(ENV.pbkdf2.salt),
        iterations: ENV.pbkdf2.iterations,
        hash: ENV.pbkdf2.hash
      },
      keyMaterial,
      { name: 'AES-GCM', length: 256 },
      false, ['decrypt']
    );

    // Step 2: Unwrap the ephemeral X25519 private key
    status('Unwrapping private key\\u2026');
    let privKeyBytes;
    try {
      privKeyBytes = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: b64ToBytes(ENV.pbkdf2.wrapIv), tagLength: 128 },
        wrapKey,
        mergeCtTag(b64ToBytes(ENV.pbkdf2.wrappedPriv), b64ToBytes(ENV.pbkdf2.wrapTag))
      );
    } catch {
      prog.style.display = 'none';
      status('\\u274C Wrong password. Please try again.', '#f85149');
      btn.disabled = false;
      return;
    }

    // Step 3: Standard X25519 + HKDF + AES-GCM decrypt (same as non-password mode)
    status('Decrypting message\\u2026');
    const myPriv = await crypto.subtle.importKey(
      'pkcs8', privKeyBytes, { name: 'X25519' }, false, ['deriveBits']
    );
    const ephPub = await importX25519(ENV.x25519Ephem, 'pub');
    const sharedBits = await crypto.subtle.deriveBits({ name: 'X25519', public: ephPub }, myPriv, 256);
    const baseKey    = await crypto.subtle.importKey('raw', sharedBits, 'HKDF', false, ['deriveBits']);
    const info       = new TextEncoder().encode('email-automation-v2');
    const keyBits    = await crypto.subtle.deriveBits({ name:'HKDF', hash:'SHA-256', salt:new Uint8Array(0), info }, baseKey, 256);
    const aesKey     = await crypto.subtle.importKey('raw', keyBits, { name:'AES-GCM' }, false, ['decrypt']);
    const iv         = b64ToBytes(ENV.iv);
    const plain      = await crypto.subtle.decrypt(
      { name:'AES-GCM', iv, tagLength:128 },
      aesKey,
      mergeCtTag(b64ToBytes(ENV.ciphertext), b64ToBytes(ENV.tag))
    );
    const payload = JSON.parse(new TextDecoder().decode(plain));
    prog.style.display = 'none';
    status('\\u2705 Decrypted successfully', '#3fb950');
    // Hide password input
    document.querySelector('.pw-wrap').style.display = 'none';
    const out = document.getElementById('output');
    out.style.display = 'block';
    out.textContent = payload.body;
    if (payload.files && payload.files.length) {
      const fd = document.getElementById('files');
      fd.style.display = 'block';
      fd.innerHTML = '<div class="files-label">Attachments</div>' +
        payload.files.map(f => '<button class="file-btn" onclick="dl(\\'' + f.name + '\\',\\'' + f.data + '\\')">\\u2B07 ' + f.name + '</button>').join('');
    }
  } catch(e) {
    prog.style.display = 'none';
    status('\\u274C Decryption failed: ' + e.message, '#f85149');
    btn.disabled = false;
  }
}
function dl(name, b64) {
  const a = document.createElement('a');
  a.href = 'data:application/octet-stream;base64,' + b64;
  a.download = name; document.body.appendChild(a); a.click(); document.body.removeChild(a);
}
</script>
</body>
</html>`;
}


function buildDecryptionHTML(envelope) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Encrypted Message</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:system-ui,sans-serif;background:#0d1117;color:#e6edf3;padding:40px;min-height:100vh}
.card{max-width:720px;margin:0 auto;background:#161b22;border:1px solid #30363d;border-radius:14px;padding:36px}
.badge{display:inline-flex;align-items:center;gap:6px;background:rgba(88,166,255,0.1);border:1px solid rgba(88,166,255,0.3);color:#58a6ff;padding:5px 12px;border-radius:20px;font-size:12px;font-weight:600;letter-spacing:.04em;margin-bottom:20px}
h1{font-size:22px;margin-bottom:8px;color:#fff}
.sub{color:#8b949e;font-size:13px;line-height:1.6;margin-bottom:28px}
.sub strong{color:#e6edf3}
.btn{background:#238636;color:#fff;border:none;padding:11px 22px;border-radius:8px;cursor:pointer;font-size:14px;font-weight:600;transition:background .15s}
.btn:hover{background:#2ea043}
.btn:disabled{background:#333;cursor:default;color:#666}
#output{margin-top:24px;white-space:pre-wrap;word-break:break-word;background:#0d1117;border:1px solid #30363d;border-radius:8px;padding:18px;font-size:13px;line-height:1.6;display:none}
#files{margin-top:16px;display:none}
.files-label{color:#8b949e;font-size:11px;text-transform:uppercase;letter-spacing:.08em;margin-bottom:8px}
.file-btn{background:#1f6feb;color:#fff;border:none;padding:7px 14px;border-radius:6px;cursor:pointer;font-size:12px;margin:3px;transition:background .15s}
.file-btn:hover{background:#388bfd}
.algo{color:#8b949e;font-size:11px;margin-top:8px}
#status{margin-top:12px;font-size:12px;color:#8b949e}
</style>
</head>
<body>
<div class="card">
  <div class="badge">🔒 Hybrid Post-Quantum Encrypted</div>
  <h1>Encrypted Message</h1>
  <div class="sub">
    This message was encrypted using <strong>${envelope.algorithm || 'X25519+AES-256-GCM'}</strong>
    (Self-Contained mode).<br>
    Click <strong>Decrypt Message</strong> — everything runs locally in your browser. Nothing is sent anywhere.
  </div>
  <button class="btn" onclick="decrypt()" id="decBtn">🔓 Decrypt Message</button>
  <div id="status"></div>
  <div id="output"></div>
  <div id="files"></div>
  <div class="algo">Algorithm: ${envelope.algorithm || 'X25519+AES-256-GCM'}</div>
</div>
<script>
const ENV = ${JSON.stringify(envelope)};
function status(msg) { document.getElementById('status').textContent = msg; }
async function importKey(b64, type) {
  const der = Uint8Array.from(atob(b64), c => c.charCodeAt(0));
  return crypto.subtle.importKey(
    type === 'pub' ? 'spki' : 'pkcs8', der,
    { name: 'X25519' }, false,
    type === 'pub' ? [] : ['deriveBits']
  );
}
async function decrypt() {
  document.getElementById('decBtn').disabled = true;
  status('Decrypting...');
  try {
    const myPriv = await importKey(ENV.decryptPriv.x25519.priv, 'priv');
    const ephPub = await importKey(ENV.x25519Ephem, 'pub');
    const sharedBits = await crypto.subtle.deriveBits({ name: 'X25519', public: ephPub }, myPriv, 256);
    const baseKey = await crypto.subtle.importKey('raw', sharedBits, 'HKDF', false, ['deriveBits']);
    const info = new TextEncoder().encode('email-automation-v2');
    const keyBits = await crypto.subtle.deriveBits({name:'HKDF',hash:'SHA-256',salt:new Uint8Array(0),info}, baseKey, 256);
    const aesKey = await crypto.subtle.importKey('raw', keyBits, {name:'AES-GCM'}, false, ['decrypt']);
    const iv  = Uint8Array.from(atob(ENV.iv),         c => c.charCodeAt(0));
    const tag = Uint8Array.from(atob(ENV.tag),         c => c.charCodeAt(0));
    const ct  = Uint8Array.from(atob(ENV.ciphertext),  c => c.charCodeAt(0));
    const combined = new Uint8Array(ct.length + tag.length);
    combined.set(ct); combined.set(tag, ct.length);
    const plain   = await crypto.subtle.decrypt({name:'AES-GCM', iv, tagLength:128}, aesKey, combined);
    const payload = JSON.parse(new TextDecoder().decode(plain));
    status('✅ Decrypted successfully');
    const out = document.getElementById('output');
    out.style.display = 'block';
    out.textContent = payload.body;
    if (payload.files && payload.files.length) {
      const fd = document.getElementById('files');
      fd.style.display = 'block';
      fd.innerHTML = '<div class="files-label">Attachments</div>' +
        payload.files.map(f => '<button class="file-btn" onclick="dl(\\''+f.name+'\\',\\''+f.data+'\\')">⬇ '+f.name+'</button>').join('');
    }
  } catch(e) {
    status('❌ Decryption failed: ' + e.message);
    document.getElementById('decBtn').disabled = false;
  }
}
function dl(name, b64) {
  const a = document.createElement('a');
  a.href = 'data:application/octet-stream;base64,' + b64;
  a.download = name; document.body.appendChild(a); a.click(); document.body.removeChild(a);
}
</script>
</body>
</html>`;
}

/* ── Mode: REGISTRY ── */
/* ── Password utilities ── */
function generateStrongPassword(length = 18) {
  // Omits visually ambiguous characters: 0, O, l, I, 1
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789!@#$%&*';
  const bytes = crypto.randomBytes(length * 2);
  let pwd = '';
  for (let i = 0; i < bytes.length && pwd.length < length; i++) {
    const idx = bytes[i] % chars.length;
    pwd += chars[idx];
  }
  return pwd;
}

/* ── Mode: SELF-CONTAINED WITH PASSWORD ──
   Same X25519+HKDF+AES-GCM envelope as regular self-contained,
   but the ephemeral private key is PBKDF2-wrapped with the password
   instead of being embedded in plaintext.
   The HTML file contains: encrypted payload, salt, wrapped private key.
   The password is never stored anywhere — wrong password = cannot decrypt.
*/
async function encryptSelfContainedWithPassword(bodyText, fileBuffers, fileNames, password) {
  const ephem = crypto.generateKeyPairSync('x25519', {
    publicKeyEncoding:  { type: 'spki',  format: 'der' },
    privateKeyEncoding: { type: 'pkcs8', format: 'der' }
  });
  const fakeContact = { x25519_pub: Buffer.from(ephem.publicKey).toString('base64') };
  const payload     = JSON.stringify({ body: bodyText, files: fileBuffers.map((b,i) => ({ name: fileNames[i], data: b.toString('base64') })) });
  const envelope    = await hybridEncrypt(Buffer.from(payload), fakeContact);

  // PBKDF2 — wrap the ephemeral private key with a key derived from the password
  const ITERATIONS  = 600000; // OWASP 2024 recommendation for PBKDF2-SHA256
  const salt        = crypto.randomBytes(32);
  const wrapIv      = crypto.randomBytes(12);
  const wrapKey     = Buffer.from(crypto.pbkdf2Sync(password, salt, ITERATIONS, 32, 'sha256'));
  const privBytes   = Buffer.from(ephem.privateKey);
  const wrapCipher  = crypto.createCipheriv('aes-256-gcm', wrapKey, wrapIv);
  const wrappedPriv = Buffer.concat([wrapCipher.update(privBytes), wrapCipher.final()]);
  const wrapTag     = wrapCipher.getAuthTag();

  envelope.passwordProtected = true;
  envelope.pbkdf2 = {
    salt:        salt.toString('base64'),
    iterations:  ITERATIONS,
    hash:        'SHA-256',
    wrapIv:      wrapIv.toString('base64'),
    wrappedPriv: wrappedPriv.toString('base64'),
    wrapTag:     wrapTag.toString('base64')
  };
  // decryptPriv intentionally omitted — private key is wrapped, not in plaintext

  return buildPasswordDecryptionHTML(envelope);
}

/* ── Mode: REGISTRY (single contact, used by task scheduler) ── */
async function encryptRegistry(bodyText, fileBuffers, fileNames, contact) {
  const hasX25519 = !!contact.x25519_pub;
  if (!hasX25519) throw new Error(`No public key stored for ${contact.email}. Add their key in Contacts first.`);
  const payload = JSON.stringify({ body: bodyText, files: fileBuffers.map((b,i) => ({ name: fileNames[i], data: b.toString('base64') })) });
  return await hybridEncrypt(Buffer.from(payload), contact);
}

/* ── Mode: REGISTRY MULTI-RECIPIENT ──
   1. Generate a random 32-byte session key
   2. Encrypt payload once with AES-256-GCM using the session key
   3. For each recipient: KEM-wrap the session key individually with their public keys
   4. Bundle into one envelope — each recipient decrypts their own wrapped key, then the payload
*/
async function encryptMultiRegistry(bodyText, fileBuffers, fileNames, contacts) {
  const payload    = Buffer.from(JSON.stringify({ body: bodyText, files: fileBuffers.map((b,i) => ({ name: fileNames[i], data: b.toString('base64') })) }));
  const sessionKey = crypto.randomBytes(32);
  // Cipher preference: use first contact's preference (all are same enc_mode group)
  const symCipher  = (contacts[0]?.cipher === 'chacha20-poly1305') ? 'chacha20-poly1305' : 'aes-256-gcm';
  const symLabel   = symCipher === 'chacha20-poly1305' ? 'ChaCha20-Poly1305' : 'AES-256-GCM';
  const iv         = crypto.randomBytes(12);
  const cipherOpts = symCipher === 'chacha20-poly1305' ? { authTagLength: 16 } : {};
  const cipher     = crypto.createCipheriv(symCipher, sessionKey, iv, cipherOpts);
  const ct         = Buffer.concat([cipher.update(payload), cipher.final()]);
  const tag        = cipher.getAuthTag();

  // Per-recipient: KEM-encapsulate the session key
  const recipients = {};
  let algorithmUsed = `X25519+${symLabel}`;
  for (const contact of contacts) {
    if (!contact.x25519_pub) {
      console.warn(`No public key for ${contact.email} — skipping`);
      continue;
    }
    const ephem = crypto.generateKeyPairSync('x25519', {
      publicKeyEncoding:  { type: 'spki',  format: 'der' },
      privateKeyEncoding: { type: 'pkcs8', format: 'der' }
    });
    const ephemPrivKey = crypto.createPrivateKey({ key: Buffer.from(ephem.privateKey), format: 'der', type: 'pkcs8' });
    const recipX25519  = crypto.createPublicKey({ key: Buffer.from(contact.x25519_pub, 'base64'), format: 'der', type: 'spki' });
    const x25519SS     = crypto.diffieHellman({ privateKey: ephemPrivKey, publicKey: recipX25519 });

    let wrapKey, kemCiphertext = null, recipAlgo;
    const contactKemVariant = contact.mlkem_variant || '768';
    const kemLib = getKemLib(contactKemVariant);
    if (kemLib && contact.mlkem_pub) {
      const { cipherText, sharedSecret: mlkemSS } = kemLib.encapsulate(Buffer.from(contact.mlkem_pub, 'base64'));
      const combined = Buffer.concat([x25519SS, Buffer.from(mlkemSS)]);
      wrapKey        = Buffer.from(crypto.hkdfSync('sha256', combined, Buffer.alloc(0), Buffer.from('email-automation-v2-hybrid-wrap'), 32));
      kemCiphertext  = Buffer.from(cipherText).toString('base64');
      const variant  = (contactKemVariant === '1024' && mlKem1024) ? '1024' : '768';
      recipAlgo      = `ML-KEM-${variant}+X25519+${symLabel}`;
      algorithmUsed  = recipAlgo;
    } else {
      wrapKey   = Buffer.from(crypto.hkdfSync('sha256', x25519SS, Buffer.alloc(0), Buffer.from('email-automation-v2-wrap'), 32));
      recipAlgo = `X25519+${symLabel}`;
    }

    // Wrap (encrypt) the session key for this recipient
    const wrapIv     = crypto.randomBytes(12);
    const wrapCipher = crypto.createCipheriv('aes-256-gcm', wrapKey, wrapIv);
    const wrappedKey = Buffer.concat([wrapCipher.update(sessionKey), wrapCipher.final()]);
    const wrapTag    = wrapCipher.getAuthTag();

    recipients[contact.email] = {
      algorithm:   recipAlgo,
      x25519Ephem: Buffer.from(ephem.publicKey).toString('base64'),
      kemCiphertext,
      wrappedKey:  wrappedKey.toString('base64'),
      wrapIv:      wrapIv.toString('base64'),
      wrapTag:     wrapTag.toString('base64')
    };
  }

  if (!Object.keys(recipients).length) throw new Error('No recipients with valid public keys found.');

  return {
    version:        2,
    multiRecipient: true,
    algorithm:      algorithmUsed,
    cipher:         symCipher,
    ciphertext:     ct.toString('base64'),
    iv:             iv.toString('base64'),
    tag:            tag.toString('base64'),
    recipients
  };
}

/* ── Mode: OPENPGP — RFC 9580 (v6), multi-recipient, ChaCha20-Poly1305 support ──
   OpenPGP generates one session key, wraps it once per recipient public key.
   Cipher selection:
     - AES-256-GCM  → standard AEAD, universally supported (openpgp.js v5+)
     - ChaCha20-Poly1305 → RFC 9580 AEAD, requires openpgp.js v6 + OpenPGP v6 keys
   v4 compatibility mode (pgp_compat: true on any contact) forces v4-format output
   so that legacy GPG/Thunderbird clients can still decrypt.
*/
async function encryptOpenPGP(bodyText, fileBuffers, fileNames, contacts) {
  if (!openpgp) throw new Error('openpgp library not loaded — run npm install');
  const contactArr  = Array.isArray(contacts) ? contacts : [contacts];
  const pgpContacts = contactArr.filter(c => c.pgp_pub);
  if (!pgpContacts.length) throw new Error('No PGP public keys found for the specified recipients. Add their PGP keys in Contacts first.');
  const encryptionKeys = await Promise.all(pgpContacts.map(c => openpgp.readKey({ armoredKey: c.pgp_pub })));
  let signingKey;
  if (myKeys?.pgp?.priv) {
    try { signingKey = await openpgp.readPrivateKey({ armoredKey: myKeys.pgp.priv }); } catch {}
  }
  const payload = JSON.stringify({ body: bodyText, files: fileBuffers.map((b,i) => ({ name: fileNames[i], data: b.toString('base64') })) });

  // Use ChaCha20 if ALL contacts in this group prefer it (and none require v4 compat)
  const wantChacha = pgpContacts.every(c => c.cipher === 'chacha20-poly1305');
  const needV4Compat = pgpContacts.some(c => c.pgp_compat);

  // Build openpgp config
  const encConfig = {
    preferredSymmetricAlgorithm: openpgp.enums.symmetric.aes256,
    preferredAEADAlgorithm: openpgp.enums.aead.gcm   // default AEAD for v6 keys
  };

  if (wantChacha && !needV4Compat) {
    // ChaCha20-Poly1305 — RFC 9580 cipher suite 6 (requires openpgp.js v6)
    if (openpgp.enums.aead.chaCha20Poly1305 !== undefined) {
      encConfig.preferredAEADAlgorithm = openpgp.enums.aead.chaCha20Poly1305;
    } else {
      console.warn('ChaCha20-Poly1305 not available in this openpgp version — falling back to AES-256-GCM. Run: npm install openpgp@^6.0.0');
    }
    encConfig.aeadProtect = true;
  } else if (!needV4Compat) {
    // AES-256-GCM with AEAD protection (v6 default — more secure than CFB mode)
    encConfig.aeadProtect = true;
  }
  // v4 compat: aeadProtect stays false/undefined, uses CFB mode (GPG 2.2 compatible)

  return await openpgp.encrypt({
    message:        await openpgp.createMessage({ text: payload }),
    encryptionKeys,
    signingKeys:    signingKey,
    config:         encConfig
  });
}

/* ── Master encrypt dispatcher — MULTI-RECIPIENT ──
   recipients = { to: 'addr', cc: ['a','b'], bcc: ['c'] }
   Strategy:
     - Group all addresses by their enc_mode in contacts
     - Same mode → one encrypted email with proper To/CC/BCC headers
     - Mixed modes → one send job per distinct mode group
     - No contact entry → selfcontained fallback
   Returns array of send jobs: [{ to, cc, bcc, subject, bodyText, attachments }]
*/
async function buildEncryptedSendMulti({ to, cc = [], bcc = [] }, subject, bodyText, filePaths, password = null) {
  const fileBuffers = await Promise.all(filePaths.map(f => fsp.readFile(f)));
  const fileNames   = filePaths.map(f => path.basename(f));

  const allAddrs = [
    { email: to, role: 'to' },
    ...cc.map(e  => ({ email: e, role: 'cc'  })),
    ...bcc.map(e => ({ email: e, role: 'bcc' }))
  ].filter(a => a.email);

  const resolved = allAddrs.map(a => ({
    ...a,
    contact: getContact(a.email),
    mode:    getContact(a.email)?.enc_mode || 'selfcontained'
  }));

  // Group by encryption mode
  const groups = {};
  for (const r of resolved) {
    (groups[r.mode] = groups[r.mode] || []).push(r);
  }

  const jobs = [];

  for (const [mode, members] of Object.entries(groups)) {
    const toAddrs  = members.filter(m => m.role === 'to').map(m => m.email);
    const ccAddrs  = members.filter(m => m.role === 'cc').map(m => m.email);
    const bccAddrs = members.filter(m => m.role === 'bcc').map(m => m.email);
    const primaryTo = toAddrs[0] || ccAddrs[0] || bccAddrs[0];
    const extraTo   = toAddrs.slice(1);
    console.log(`Encrypting [${mode}] for: ${members.map(m => m.email).join(', ')}`);

    if (mode === 'none') {
      jobs.push({ to: primaryTo, cc: [...extraTo, ...ccAddrs], bcc: bccAddrs, subject, bodyText, attachments: fileBuffers.map((d,i) => ({ name: fileNames[i], data: d })) });
      continue;
    }

    if (mode === 'selfcontained') {
      const html = password
        ? await encryptSelfContainedWithPassword(bodyText, fileBuffers, fileNames, password)
        : await encryptSelfContained(bodyText, fileBuffers, fileNames);
      const pwNote = password ? '\nYou will receive the password separately via a different channel.' : '';
      jobs.push({
        to: primaryTo, cc: [...extraTo, ...ccAddrs], bcc: bccAddrs, subject,
        bodyText: `This message is hybrid post-quantum encrypted (Self-Contained mode).\nOpen the attached HTML file in any browser to decrypt — no software required.${pwNote}`,
        attachments: [{ name: 'encrypted-message.html', data: Buffer.from(html, 'utf8') }]
      });
      continue;
    }

    if (mode === 'registry') {
      const contacts  = members.map(m => m.contact).filter(Boolean);
      const envelope  = await encryptMultiRegistry(bodyText, fileBuffers, fileNames, contacts);
      const recipList = members.map(m => m.email).join(', ');
      jobs.push({
        to: primaryTo, cc: [...extraTo, ...ccAddrs], bcc: bccAddrs, subject,
        bodyText: `This message is encrypted with ${envelope.algorithm} (multi-recipient).\nRecipients: ${recipList}\nEach recipient has their own individually encrypted key. Use Email Automation Pro to decrypt.`,
        attachments: [{ name: 'encrypted-message.json', data: Buffer.from(JSON.stringify(envelope, null, 2), 'utf8') }]
      });
      continue;
    }

    if (mode === 'openpgp') {
      const contacts = members.map(m => m.contact).filter(Boolean);
      const noPgp    = members.filter(m => !m.contact?.pgp_pub).map(m => m.email);
      if (noPgp.length) console.warn(`No PGP key for: ${noPgp.join(', ')} — they will not be able to decrypt`);
      const armored  = await encryptOpenPGP(bodyText, fileBuffers, fileNames, contacts);
      jobs.push({
        to: primaryTo, cc: [...extraTo, ...ccAddrs], bcc: bccAddrs, subject,
        bodyText: `This message is OpenPGP encrypted (multi-recipient).\nDecrypt the .asc attachment with Thunderbird, GPG, or any OpenPGP client.`,
        attachments: [{ name: 'encrypted-message.asc', data: Buffer.from(armored, 'utf8') }]
      });
      continue;
    }

    throw new Error(`Unknown encryption mode: ${mode}`);
  }

  return jobs;
}

/* ── Legacy single-recipient dispatcher (used by task scheduler) ── */
async function buildEncryptedSend(recipient, subject, bodyText, filePaths, password = null) {
  const fileBuffers = await Promise.all(filePaths.map(f => fsp.readFile(f)));
  const fileNames   = filePaths.map(f => path.basename(f));
  const contact     = getContact(recipient);
  const mode        = contact?.enc_mode || 'selfcontained';
  console.log(`Encrypting -> ${recipient} [mode: ${mode}]${password ? ' [password-protected]' : ''}`);
  if (mode === 'none') return { subject, bodyText, attachments: fileBuffers.map((d,i) => ({ name: fileNames[i], data: d })), encMode: 'none' };
  if (mode === 'selfcontained') {
    const html = password
      ? await encryptSelfContainedWithPassword(bodyText, fileBuffers, fileNames, password)
      : await encryptSelfContained(bodyText, fileBuffers, fileNames);
    const pwNote = password ? '\n\nYou will receive the password separately via a different channel.' : '';
    return { subject, bodyText: 'Encrypted (Self-Contained). Open the .html file in any browser to decrypt.' + pwNote, attachments: [{ name: 'encrypted-message.html', data: Buffer.from(html, 'utf8') }], encMode: 'selfcontained' };
  }
  if (mode === 'registry') {
    const envelope = await encryptRegistry(bodyText, fileBuffers, fileNames, contact);
    return { subject, bodyText: `Encrypted with ${envelope.algorithm}. Use Email Automation Pro to decrypt.`, attachments: [{ name: 'encrypted-message.json', data: Buffer.from(JSON.stringify(envelope, null, 2), 'utf8') }], encMode: 'registry' };
  }
  if (mode === 'openpgp') {
    const armored = await encryptOpenPGP(bodyText, fileBuffers, fileNames, [contact]);
    return { subject, bodyText: 'OpenPGP encrypted. Decrypt with Thunderbird, GPG, or any OpenPGP client.', attachments: [{ name: 'encrypted-message.asc', data: Buffer.from(armored, 'utf8') }], encMode: 'openpgp' };
  }
  throw new Error(`Unknown encryption mode: ${mode}`);
}


/* ═══════════════════════════════════════════
   CONTACTS CRUD
═══════════════════════════════════════════ */
function getAllContacts() {
  if (db) return dbAll('SELECT * FROM contacts ORDER BY name');
  return memContacts;
}
function getContact(email) {
  if (db) return dbGet('SELECT * FROM contacts WHERE email = ?', [email]);
  return memContacts.find(c => c.email === email) || null;
}
function upsertContact(contact) {
  const existing = getContact(contact.email);
  if (existing) {
    if (db) dbRun(`UPDATE contacts SET name=?,enc_mode=?,mlkem_variant=?,cipher=?,pgp_compat=?,imessage_handle=?,mlkem_pub=?,x25519_pub=?,pgp_pub=?,notes=?,updated_at=datetime('now') WHERE email=?`,
      [contact.name, contact.enc_mode, contact.mlkem_variant||'768', contact.cipher||'aes-256-gcm', contact.pgp_compat?1:0, contact.imessage_handle||null, contact.mlkem_pub||null, contact.x25519_pub||null, contact.pgp_pub||null, contact.notes||null, contact.email]);
    else { const i = memContacts.findIndex(c => c.email===contact.email); if(i>=0) memContacts[i]={...memContacts[i],...contact}; saveMem(); }
    return existing.id;
  } else {
    const id = uid();
    if (db) dbRun(`INSERT INTO contacts (id,name,email,enc_mode,mlkem_variant,cipher,pgp_compat,imessage_handle,mlkem_pub,x25519_pub,pgp_pub,notes) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`,
      [id, contact.name, contact.email, contact.enc_mode||'selfcontained', contact.mlkem_variant||'768', contact.cipher||'aes-256-gcm', contact.pgp_compat?1:0, contact.imessage_handle||null, contact.mlkem_pub||null, contact.x25519_pub||null, contact.pgp_pub||null, contact.notes||null]);
    else { memContacts.push({ id, ...contact, created_at: new Date().toISOString() }); saveMem(); }
    return id;
  }
}
function deleteContact(id) {
  if (db) dbRun('DELETE FROM contacts WHERE id=?', [id]);
  else { memContacts = memContacts.filter(c => c.id!==id); saveMem(); }
}

/* ═══════════════════════════════════════════
   TASK HELPERS
═══════════════════════════════════════════ */
function getAllTasks() {
  if (db) return dbAll('SELECT * FROM tasks ORDER BY created_at').map(t => ({ ...t, enabled: !!t.enabled, folderPairs: dbAll('SELECT * FROM folder_pairs WHERE task_id = ?', [t.id]) }));
  return memTasks;
}
function createTask(task) {
  const id = uid();
  const pairs = (task.folderPairs||[]).map(p => ({ ...p, id: uid(), task_id: id }));
  if (db) { dbRun('INSERT INTO tasks (id,name,recipient,schedule,enabled) VALUES (?,?,?,?,1)', [id, task.name, task.recipient, task.schedule]); for (const p of pairs) dbRun('INSERT INTO folder_pairs (id,task_id,name,source,dest) VALUES (?,?,?,?,?)', [p.id, id, p.name, p.source, p.dest]); }
  else { memTasks.push({ id, ...task, enabled: true, folderPairs: pairs }); saveMem(); }
  return id;
}
function updateTask(task) {
  if (db) { dbRun(`UPDATE tasks SET name=?,recipient=?,schedule=?,updated_at=datetime('now') WHERE id=?`, [task.name, task.recipient, task.schedule, task.id]); dbRun('DELETE FROM folder_pairs WHERE task_id=?', [task.id]); for (const p of (task.folderPairs||[])) dbRun('INSERT INTO folder_pairs (id,task_id,name,source,dest) VALUES (?,?,?,?,?)', [p.id||uid(), task.id, p.name, p.source, p.dest]); }
  else { const i = memTasks.findIndex(t => t.id===task.id); if(i>=0) memTasks[i]=task; saveMem(); }
}
function deleteTask(id) {
  if (db) dbRun('DELETE FROM tasks WHERE id=?', [id]);
  else { memTasks = memTasks.filter(t => t.id!==id); saveMem(); }
}
function toggleTask(id) {
  if (db) { const t = dbGet('SELECT enabled FROM tasks WHERE id=?', [id]); if(t) dbRun('UPDATE tasks SET enabled=? WHERE id=?', [t.enabled?0:1, id]); return !t?.enabled; }
  else { const t = memTasks.find(t => t.id===id); if(t) t.enabled=!t.enabled; saveMem(); return t?.enabled; }
}

/* ═══════════════════════════════════════════
   CHECKSUM
═══════════════════════════════════════════ */
async function computeChecksum(filePath) {
  return new Promise((resolve, reject) => {
    const hash = crypto.createHash('sha256');
    const s = fs.createReadStream(filePath);
    s.on('data', d => hash.update(d)); s.on('end', () => resolve(hash.digest('hex'))); s.on('error', reject);
  });
}
async function storeChecksum(filePath, taskId, pairId) {
  try {
    const sha256 = await computeChecksum(filePath);
    const stat   = await fsp.stat(filePath);
    const id     = uid();
    if (db) dbRun('INSERT INTO checksums (id,file_path,file_name,sha256,size_bytes,task_id,pair_id) VALUES (?,?,?,?,?,?,?)', [id, filePath, path.basename(filePath), sha256, stat.size, taskId, pairId]);
    else memChecksums.push({ id, file_path: filePath, file_name: path.basename(filePath), sha256, size_bytes: stat.size, task_id: taskId, pair_id: pairId });
    return { id, sha256, size_bytes: stat.size };
  } catch(e) { console.error('Checksum error:', e.message); return null; }
}

/* ═══════════════════════════════════════════
   QR RECEIPT
═══════════════════════════════════════════ */
async function storeReceipt({ taskId, taskName, recipient, subject, fileNames, checksumIds }) {
  const id = uid(), sentAt = new Date().toISOString();
  const rec = { id, task_id: taskId, task_name: taskName, recipient, subject, file_names: fileNames.join(', '), checksum_ids: (checksumIds||[]).join(','), sent_at: sentAt };
  let qr = null;
  if (QRCode) { try { qr = await QRCode.toDataURL(JSON.stringify({ id, task: taskName, recipient, files: rec.file_names, sent: sentAt }), { errorCorrectionLevel:'M', width:300 }); } catch {} }
  rec.qr_data = qr;
  if (db) dbRun('INSERT INTO receipts (id,task_id,task_name,recipient,subject,file_names,checksum_ids,sent_at,qr_data) VALUES (?,?,?,?,?,?,?,?,?)', [id, taskId, taskName, recipient, subject, rec.file_names, rec.checksum_ids, sentAt, qr]);
  else memReceipts.push(rec);
  return rec;
}

/* ═══════════════════════════════════════════
   GMAIL AUTH
═══════════════════════════════════════════ */
let authClient, mainWindow;
async function loadCredentials() { try { return JSON.parse(await fsp.readFile(CREDENTIALS_PATH, 'utf8')); } catch { return null; } }
async function loadToken()       { try { return JSON.parse(await fsp.readFile(TOKEN_PATH, 'utf8')); }        catch { return null; } }
async function saveToken(tok)    { await fsp.mkdir(DATA_DIR, { recursive: true }); await fsp.writeFile(TOKEN_PATH, JSON.stringify(tok)); }

async function getAuthClient() {
  const creds = await loadCredentials(); if (!creds) return null;
  const { client_id, client_secret, redirect_uris } = creds.installed || creds.web || {};
  const client = new google.auth.OAuth2(client_id, client_secret, redirect_uris[0]);
  const token = await loadToken();
  if (token) { client.setCredentials(token); authClient = client; return client; }
  return null;
}

async function authorizeWithBrowser() {
  const creds = await loadCredentials(); if (!creds) throw new Error('credentials.json not found');
  const { client_id, client_secret } = creds.installed || creds.web || {};
  const client = new google.auth.OAuth2(client_id, client_secret, 'http://localhost:3141/callback');
  return new Promise((resolve, reject) => {
    const server = http.createServer(async (req, res) => {
      const u = new URL(req.url, 'http://localhost:3141');
      if (u.pathname !== '/callback') { res.end('Not found'); return; }
      const code = u.searchParams.get('code');
      res.end('<html><body style="font-family:sans-serif;text-align:center;padding:60px"><h2>✅ Authorised!</h2><p>You can close this tab.</p></body></html>');
      server.close();
      try { const { tokens } = await client.getToken(code); client.setCredentials(tokens); await saveToken(tokens); authClient = client; mainWindow?.webContents.send('auth-changed', { authed: true }); resolve(client); }
      catch(e) { reject(e); }
    }).listen(3141, () => shell.openExternal(client.generateAuthUrl({ access_type:'offline', scope: SCOPES, prompt:'consent' })));
    server.on('error', reject);
  });
}

/* ═══════════════════════════════════════════
   EMAIL SENDING
═══════════════════════════════════════════ */
function guessMime(name) {
  const map = { '.pdf':'application/pdf','.png':'image/png','.jpg':'image/jpeg','.jpeg':'image/jpeg','.gif':'image/gif','.webp':'image/webp','.mp3':'audio/mpeg','.m4a':'audio/mp4','.mp4':'video/mp4','.docx':'application/vnd.openxmlformats-officedocument.wordprocessingml.document','.xlsx':'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet','.txt':'text/plain','.csv':'text/csv','.zip':'application/zip','.html':'text/html','.json':'application/json','.asc':'application/pgp-encrypted' };
  return map[path.extname(name).toLowerCase()] || 'application/octet-stream';
}

function buildMime({ recipient, cc = [], bcc = [], subject, bodyText, attachments }) {
  const boundary = `----=_BOUNDARY_${Date.now()}`;
  const lines = [
    `To: ${recipient}`, `Subject: ${subject}`, 'MIME-Version: 1.0'
  ];
  if (cc.length)  lines.push(`Cc: ${cc.join(', ')}`);
  if (bcc.length) lines.push(`Bcc: ${bcc.join(', ')}`);
  lines.push(
    `Content-Type: multipart/mixed; boundary="${boundary}"`, '',
    `--${boundary}`, 'Content-Type: text/plain; charset=utf-8', '', bodyText, ''
  );
  for (const att of attachments) {
    lines.push(`--${boundary}`, `Content-Type: ${guessMime(att.name)}; name="${att.name}"`, 'Content-Transfer-Encoding: base64', `Content-Disposition: attachment; filename="${att.name}"`, '', att.data.toString('base64'), '');
  }
  lines.push(`--${boundary}--`);
  return lines.join('\r\n');
}

async function sendEmailRaw({ recipient, cc = [], bcc = [], subject, bodyText, attachments }) {
  if (!authClient) throw new Error('Not authorised — please connect Gmail first');
  const gmail = google.gmail({ version: 'v1', auth: authClient });
  const raw = Buffer.from(buildMime({ recipient, cc, bcc, subject, bodyText, attachments }))
    .toString('base64').replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
  await gmail.users.messages.send({ userId: 'me', requestBody: { raw } });
  const allTo = [recipient, ...cc].join(', ');
  console.log(`✅ Sent → ${allTo}${bcc.length ? ` (BCC: ${bcc.join(', ')})` : ''}`);
}

async function sendWithBatching({ recipient, cc = [], bcc = [], subject, body, files, taskId, taskName, pairId, password = null }) {
  const batches = [];
  let batch = [], batchSize = 0;
  for (const f of files) {
    const stat = await fsp.stat(f);
    if (batchSize + stat.size > MAX_EMAIL_BYTES && batch.length) { batches.push(batch); batch=[]; batchSize=0; }
    batch.push(f); batchSize += stat.size;
  }
  if (batch.length) batches.push(batch);

  const hasCcBcc = cc.length || bcc.length;

  for (let i = 0; i < batches.length; i++) {
    const batchFiles   = batches[i];
    const batchSubject = batches.length > 1 ? `${subject} (Part ${i+1}/${batches.length})` : subject;

    const csIds = [];
    for (const f of batchFiles) { const cs = await storeChecksum(f, taskId, pairId); if(cs) csIds.push(cs.id); }

    if (hasCcBcc) {
      // Multi-recipient path: groups by enc_mode, returns one job per distinct mode group
      const jobs = await buildEncryptedSendMulti({ to: recipient, cc, bcc }, batchSubject, body, batchFiles, password);
      for (const job of jobs) {
        await sendEmailRaw({ recipient: job.to, cc: job.cc, bcc: job.bcc, subject: job.subject, bodyText: job.bodyText, attachments: job.attachments });
        await storeReceipt({ taskId, taskName, recipient: [job.to, ...job.cc].join(', '), subject: job.subject, fileNames: batchFiles.map(f => path.basename(f)), checksumIds: csIds });
      }
    } else {
      // Single-recipient path (task scheduler, simple sends)
      const { subject: finalSubject, bodyText, attachments } = await buildEncryptedSend(recipient, batchSubject, body, batchFiles, password);
      await sendEmailRaw({ recipient, subject: finalSubject, bodyText, attachments });
      await storeReceipt({ taskId, taskName, recipient, subject: finalSubject, fileNames: batchFiles.map(f => path.basename(f)), checksumIds: csIds });
    }

    if (i < batches.length - 1) await sleep(300);
  }
}

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

/* ═══════════════════════════════════════════
   FOLDER HELPERS
═══════════════════════════════════════════ */
async function scanFolder(folderPath) {
  try { return (await fsp.readdir(folderPath, { withFileTypes: true })).filter(e => e.isFile() && !e.name.startsWith('.')).map(e => path.join(folderPath, e.name)); }
  catch { return []; }
}
async function moveFile(src, destDir) {
  await fsp.mkdir(destDir, { recursive: true });
  const name = path.basename(src);
  let dest = path.join(destDir, name);
  try { await fsp.access(dest); dest = path.join(destDir, `${Date.now()}_${name}`); } catch {}
  await fsp.rename(src, dest);
}

/* ═══════════════════════════════════════════
   SCHEDULER / POLLER
═══════════════════════════════════════════ */
let pollerHandle;
function startPoller() {
  if (pollerHandle) clearInterval(pollerHandle);
  pollerHandle = setInterval(pollAllTasks, POLL_INTERVAL);
  pollAllTasks();
}
async function pollAllTasks() {
  const tasks = getAllTasks().filter(t => t.enabled);
  for (const task of tasks) {
    if (!shouldSendNow(task.schedule)) continue;
    for (const pair of (task.folderPairs||[])) {
      const files = await scanFolder(pair.source);
      if (!files.length) continue;
      try {
        await sendWithBatching({ recipient: task.recipient, subject: files.map(f => path.basename(f)).join(', '), body: `Automated send from task: ${task.name}\nFiles: ${files.length}\nPair: ${pair.name}`, files, taskId: task.id, taskName: task.name, pairId: pair.id });
        for (const f of files) await moveFile(f, pair.dest);
        mainWindow?.webContents.send('email-sent', { task: task.name, files: files.length });
      } catch(e) { console.error(`❌ Task "${task.name}":`, e.message); mainWindow?.webContents.send('task-status', { id: task.id, error: e.message }); }
    }
  }
  mainWindow?.webContents.send('poller-tick', { at: new Date().toISOString() });
}
function shouldSendNow(schedule) {
  if (!schedule) return false;
  const parts = schedule.split(':'), [hh, mm] = parts, days = parts[2];
  const now = new Date();
  if (now.getHours()!==parseInt(hh) || now.getMinutes()!==parseInt(mm) || now.getSeconds()>30) return false;
  if (days) { const DOW=['SUN','MON','TUE','WED','THU','FRI','SAT'][now.getDay()]; if (!days.split(',').includes(DOW)) return false; }
  return true;
}

/* ═══════════════════════════════════════════
   IPC HANDLERS
═══════════════════════════════════════════ */

// Auth
ipcMain.handle('get-auth-status', async () => { const c = await getAuthClient(); return { authed: !!c }; });
ipcMain.handle('authorize',  async () => { try { await authorizeWithBrowser(); return { ok:true }; } catch(e) { return { ok:false, error:e.message }; } });
ipcMain.handle('sign-out',   async () => { authClient=null; try { await fsp.unlink(TOKEN_PATH); } catch {} mainWindow?.webContents.send('auth-changed',{authed:false}); return {ok:true}; });

// Tasks
ipcMain.handle('get-tasks',   () => getAllTasks());
ipcMain.handle('create-task', (_, t)  => { createTask(t);  return getAllTasks(); });
ipcMain.handle('update-task', (_, t)  => { updateTask(t);  return getAllTasks(); });
ipcMain.handle('delete-task', (_, id) => { deleteTask(id); return getAllTasks(); });
ipcMain.handle('toggle-task', (_, id) => { toggleTask(id); return getAllTasks(); });

// Files
ipcMain.handle('pick-folder', async () => { const r = await dialog.showOpenDialog({ properties:['openDirectory'] }); return r.canceled ? null : r.filePaths[0]; });
ipcMain.handle('pick-files',  async () => { const r = await dialog.showOpenDialog({ properties:['openFile','multiSelections'] }); return r.canceled ? [] : r.filePaths; });
ipcMain.handle('scan-folder', async (_, p) => scanFolder(p));
ipcMain.handle('open-folder', async (_, p) => shell.openPath(p));

// Send
/* ── Auto-send password via iMessage using AppleScript ──
   macOS only. Falls back gracefully on other platforms.
   handle: phone number (+447911123456) or Apple ID email (user@icloud.com).
   Falls back to the recipient's email if no imessage_handle is set.
*/
function sendPasswordViaIMessage(handle, password) {
  if (process.platform !== 'darwin') {
    return { sent: false, reason: 'iMessage is only available on macOS' };
  }
  try {
    const { execSync } = require('child_process');
    // Sanitise inputs — prevent AppleScript injection
    const safeHandle   = handle.replace(/['"\\]/g, '');
    const safePassword = password.replace(/['"\\]/g, '');
    const msg = `Here is the password for your encrypted email:\n${safePassword}`;
    const script = `
      tell application "Messages"
        set targetService to first service whose service type = iMessage
        set targetBuddy to buddy "${safeHandle}" of targetService
        send "${msg}" to targetBuddy
      end tell
    `;
    execSync(`osascript -e '${script.replace(/'/g, "'\''")}'`, { timeout: 10000 });
    return { sent: true };
  } catch(e) {
    console.warn('iMessage send failed:', e.message);
    return { sent: false, reason: e.message };
  }
}

ipcMain.handle('send-now', async (_, { recipient, cc = [], bcc = [], subject, body, files, taskName, password = null }) => {
  await sendWithBatching({ recipient, cc, bcc, subject, body, files, taskId:'manual', taskName:taskName||'Manual Send', pairId:null, password });
  if (password) {
    // Resolve iMessage handle — prefer stored handle, fall back to recipient email
    const contact = getContact(recipient);
    const handle  = contact?.imessage_handle?.trim() || recipient;

    // Auto-send password via iMessage
    const imResult = sendPasswordViaIMessage(handle, password);

    // Generate QR as fallback if iMessage failed
    let passwordQR = null;
    if (!imResult.sent && QRCode) {
      try { passwordQR = await QRCode.toDataURL(password, { errorCorrectionLevel: 'M', width: 320, margin: 2 }); } catch {}
    }
    return { ok: true, password, passwordQR, iMessageSent: imResult.sent, iMessageHandle: handle, iMessageError: imResult.reason || null };
  }
  return { ok: true };
});

ipcMain.handle('generate-password', () => generateStrongPassword());
ipcMain.handle('open-external',     (_, url) => shell.openExternal(url));
ipcMain.handle('quit-app',          () => { app.quit(); });

// Licence
ipcMain.handle('get-licence',       () => loadStoredLicence());
ipcMain.handle('owner-login',       (_, { email }) => {
  const OWNER_EMAILS = ['spike@thewrightsupport.com'];
  if (!OWNER_EMAILS.includes(email.toLowerCase().trim())) {
    return { valid: false };
  }
  const stored = { key: 'OWNER', email: email.toLowerCase().trim(), expiry: '2099-12', activatedAt: new Date().toISOString() };
  saveStoredLicence(stored);
  return { valid: true };
});
ipcMain.handle('validate-licence',  (_, { key, email }) => {
  // Developer bypass — works only in dev (unpackaged) mode
  if (!app.isPackaged && key.toUpperCase() === 'SWEP1-DEV00-DEV00-DEV00-DEV00') {
    const devLicence = { key, email, expiry: '2099-12', activatedAt: new Date().toISOString() };
    saveStoredLicence(devLicence);
    return { valid: true, expiry: '2099-12', email, reason: null };
  }
  const result = validateLicenceKey(key, email);
  if (result.valid) saveStoredLicence({ key, email, expiry: result.expiry, activatedAt: new Date().toISOString() });
  return result;
});
ipcMain.handle('clear-licence',     () => { try { fs.unlinkSync(LICENCE_PATH); } catch {} return true; });
ipcMain.handle('generate-dev-key',  (_, { email }) => {
  // Only works unpackaged — generates a real lifetime key for the developer
  if (app.isPackaged) return { error: 'Not available in production builds' };
  const { key } = generateLicenceKey(email, '2099-12');
  return { key };
});

// Admin — key generation (available in both dev and packaged builds, PIN protected in UI)
const ADMIN_PIN = '1964'; // Change this to your preferred PIN
const WALKUP_LOG = path.join(DATA_DIR, 'issued-keys.log');

ipcMain.handle('admin-check-pin',    (_, { pin }) => ({ ok: pin === ADMIN_PIN }));
ipcMain.handle('admin-gen-standard', (_, { email, name, expiry }) => {
  const expiryDate = expiry === 'lifetime' ? '2099-12-31'
    : expiry === '2y' ? new Date(new Date().getFullYear() + 2, new Date().getMonth(), 1).toISOString()
    : new Date(new Date().getFullYear() + 1, new Date().getMonth(), 1).toISOString();
  const result = generateLicenceKey(email, expiryDate);
  // Log it
  const line = JSON.stringify({ type: 'standard', name, email: email.toLowerCase().trim(), key: result.key, expiry: result.expiry, issuedAt: new Date().toISOString() }) + '\n';
  try { fs.appendFileSync(WALKUP_LOG, line); } catch {}
  return result;
});
ipcMain.handle('admin-gen-walkup', (_, { count, expiry, note }) => {
  const BASE32 = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  function b32(buf) {
    let bits = 0, value = 0, out = '';
    for (let i = 0; i < buf.length; i++) {
      value = (value << 8) | buf[i]; bits += 8;
      while (bits >= 5) { out += BASE32[(value >>> (bits - 5)) & 31]; bits -= 5; }
    }
    if (bits > 0) out += BASE32[(value << (5 - bits)) & 31];
    return out;
  }
  const expiryDate = expiry === 'lifetime' ? '2099-12-31'
    : expiry === '2y' ? new Date(new Date().getFullYear() + 2, new Date().getMonth(), 1).toISOString()
    : new Date(new Date().getFullYear() + 1, new Date().getMonth(), 1).toISOString();
  const exp = expiryDate.slice(0, 7);
  const keys = [];
  for (let i = 1; i <= Math.min(50, count); i++) {
    const serial  = String(i).padStart(3, '0');
    const seed    = crypto.randomBytes(8).toString('hex');
    const payload = `SWEPW|${serial}|${exp}|${seed}`;
    const mac     = crypto.createHmac('sha256', LICENCE_SECRET).update(payload).digest();
    const key20   = b32(mac.slice(0, 16)).slice(0, 20);
    const key     = ['SWEPW', key20.slice(0,5), key20.slice(5,10), key20.slice(10,15), key20.slice(15,20)].join('-');
    keys.push({ serial, key, expiry: exp });
    const line = JSON.stringify({ type: 'walkup', serial, key, expiry: exp, note, issuedAt: new Date().toISOString() }) + '\n';
    try { fs.appendFileSync(WALKUP_LOG, line); } catch {}
  }
  return { keys };
});
ipcMain.handle('admin-get-log', () => {
  try {
    const raw = fs.readFileSync(WALKUP_LOG, 'utf8').trim();
    if (!raw) return { entries: [] };
    const entries = raw.split('\n').filter(Boolean).map(l => { try { return JSON.parse(l); } catch { return null; } }).filter(Boolean).reverse();
    return { entries };
  } catch { return { entries: [] }; }
});

// Contacts
ipcMain.handle('get-contacts',   ()      => getAllContacts());
ipcMain.handle('upsert-contact', (_, c)  => { upsertContact(c); return getAllContacts(); });
ipcMain.handle('delete-contact', (_, id) => { deleteContact(id); return getAllContacts(); });
ipcMain.handle('get-contact',    (_, email) => getContact(email));

ipcMain.handle('get-my-keys', () => {
  if (!myKeys) return null;
  return {
    email: myKeys.email, name: myKeys.name, created_at: myKeys.created_at,
    mlkem_pub:     myKeys.mlkem?.pub,
    mlkem_variant: myKeys.mlkem_variant || myKeys.mlkem?.variant || '768',
    x25519_pub:    myKeys.x25519?.pub,
    pgp_pub:       myKeys.pgp?.pub,
    has_mlkem:     !!myKeys.mlkem,
    has_pgp:       !!myKeys.pgp,
    has_mlkem1024: !!(myKeys.mlkem && (myKeys.mlkem_variant === '1024' || myKeys.mlkem?.variant === '1024'))
  };
});
ipcMain.handle('generate-my-keys', async (_, { name, email, kemVariant }) => {
  await generateMyKeys(name, email, kemVariant || '1024');
  return {
    email: myKeys.email, name: myKeys.name, created_at: myKeys.created_at,
    mlkem_pub:     myKeys.mlkem?.pub,
    mlkem_variant: myKeys.mlkem_variant || myKeys.mlkem?.variant || '768',
    x25519_pub:    myKeys.x25519?.pub,
    pgp_pub:       myKeys.pgp?.pub,
    has_mlkem:     !!myKeys.mlkem,
    has_pgp:       !!myKeys.pgp,
    has_mlkem1024: !!(myKeys.mlkem && (myKeys.mlkem_variant === '1024' || myKeys.mlkem?.variant === '1024'))
  };
});
ipcMain.handle('export-my-pubkey', () => {
  if (!myKeys) return null;
  return JSON.stringify({
    email: myKeys.email, name: myKeys.name,
    mlkem_variant: myKeys.mlkem_variant || myKeys.mlkem?.variant || '768',
    mlkem_pub:     myKeys.mlkem?.pub,
    x25519_pub:    myKeys.x25519?.pub,
    pgp_pub:       myKeys.pgp?.pub
  }, null, 2);
});

// Diagnostics
ipcMain.handle('get-diagnostics', async () => {
  const creds = await loadCredentials();
  const token = await loadToken();
  const mods = ['googleapis','sql.js','qrcode','openpgp','@distube/ytdl-core','openai','fluent-ffmpeg'];
  const modStatus  = {};
  const modVersion = {};
  for (const m of mods) {
    try {
      require(m);
      modStatus[m] = true;
      try {
        const pkgPath = require.resolve(`${m}/package.json`);
        modVersion[m] = require(pkgPath).version;
      } catch { modVersion[m] = null; }
    } catch { modStatus[m] = false; modVersion[m] = null; }
  }
  try { require('@noble/post-quantum/ml-kem'); modStatus['@noble/post-quantum'] = true; } catch { modStatus['@noble/post-quantum'] = false; }
  try {
    const pkgPath = require.resolve('@noble/post-quantum/package.json');
    modVersion['@noble/post-quantum'] = require(pkgPath).version;
  } catch { modVersion['@noble/post-quantum'] = null; }

  // OpenPGP version check — v6 required for ChaCha20 + AEAD
  let pgpVersion   = modVersion['openpgp'] || null;
  let pgpV6Ok      = false;
  let pgpV6Capable = false;
  try {
    const pgp = require('openpgp');
    pgpVersion   = pgp.version || pgpVersion;
    pgpV6Ok      = !!(pgp.enums?.aead?.chaCha20Poly1305 !== undefined);
    pgpV6Capable = pgpV6Ok;
  } catch {}

  let ffmpegOk = false;
  try { const inst = require('@ffmpeg-installer/ffmpeg'); ffmpegOk = !!inst.path; } catch {}
  return {
    credentialsFound: !!creds,
    credentialsType:  creds ? (creds.installed ? 'Desktop' : creds.web ? 'Web' : 'Unknown') : null,
    credentialsPath:  CREDENTIALS_PATH,
    tokenFound:       !!token,
    authed:           !!authClient,
    modules:          modStatus,
    modVersions:      modVersion,
    pgpVersion,
    pgpV6Ok,
    pgpV6Capable,
    ffmpeg:           ffmpegOk,
    nodeVersion:      process.version,
    platform:         process.platform,
    userData:         DATA_DIR
  };
});

// Checksums / Receipts
ipcMain.handle('get-checksums',  () => db ? dbAll('SELECT * FROM checksums ORDER BY computed_at DESC LIMIT 500') : memChecksums.slice(-500).reverse());
ipcMain.handle('get-receipts',   () => db ? dbAll('SELECT id,task_id,task_name,recipient,subject,file_names,sent_at FROM receipts ORDER BY sent_at DESC LIMIT 200') : memReceipts.slice(-200).reverse());
ipcMain.handle('get-receipt-qr', (_, id) => { const r = db ? dbGet('SELECT qr_data FROM receipts WHERE id=?',[id]) : memReceipts.find(r=>r.id===id); return r?.qr_data||null; });


/* ═══════════════════════════════════════════
   YOUTUBE TRANSCRIPTION
═══════════════════════════════════════════ */
let ytdl, OpenAI, ffmpegLib;
try { ytdl     = require('@distube/ytdl-core'); } catch(e) { console.warn('@distube/ytdl-core unavailable:', e.message); }
try {
  const oa = require('openai');
  OpenAI = oa.default || oa.OpenAI || oa;
} catch { console.warn('openai unavailable'); }
try {
  ffmpegLib = require('fluent-ffmpeg');
  try {
    const inst = require('@ffmpeg-installer/ffmpeg');
    ffmpegLib.setFfmpegPath(inst.path);
  } catch {}
} catch { console.warn('fluent-ffmpeg unavailable'); }

const TRANSCRIPTS_DIR = path.join(DATA_DIR, 'transcripts');

function fmtTimeSRT(t) {
  const h=Math.floor(t/3600), m=Math.floor((t%3600)/60), s=Math.floor(t%60), ms=Math.round((t%1)*1000);
  return `${String(h).padStart(2,'0')}:${String(m).padStart(2,'0')}:${String(s).padStart(2,'0')},${String(ms).padStart(3,'0')}`;
}
function fmtTimeVTT(t) { return fmtTimeSRT(t).replace(',','.'); }
function fmtTimeHM(t)  { return `${String(Math.floor(t/60)).padStart(2,'0')}:${String(Math.floor(t%60)).padStart(2,'0')}`; }

function toSRT(segs) {
  return segs.map((s,i) => `${i+1}\n${fmtTimeSRT(s.start)} --> ${fmtTimeSRT(s.end)}\n${s.text.trim()}\n`).join('\n');
}
function toVTT(segs) {
  return 'WEBVTT\n\n' + segs.map((s,i) => `${i+1}\n${fmtTimeVTT(s.start)} --> ${fmtTimeVTT(s.end)}\n${s.text.trim()}\n`).join('\n');
}
function toMD(segs, info, fullText) {
  const dur = info?.duration ? `${Math.floor(info.duration/60)}m ${info.duration%60}s` : '—';
  return [
    `# ${info?.title || 'Transcript'}`,
    `> **Channel:** ${info?.author || '—'}  `,
    `> **Duration:** ${dur}  `,
    `> **Transcribed:** ${new Date().toLocaleString('en-GB')}`,
    '',
    '---',
    '',
    '## Full Transcript',
    '',
    fullText,
    '',
    '---',
    '',
    '## Timestamped Segments',
    '',
    ...segs.map(s => `**[${fmtTimeHM(s.start)}]** ${s.text.trim()}`)
  ].join('\n');
}

ipcMain.handle('yt-info', async (_, url) => {
  if (!ytdl) throw new Error('@distube/ytdl-core not installed — run: npm install');
  const info    = await ytdl.getInfo(url);
  const details = info.videoDetails;
  const formats = info.formats.map(f => ({
    itag: f.itag, qualityLabel: f.qualityLabel, audioBitrate: f.audioBitrate,
    hasVideo: !!f.hasVideo, hasAudio: !!f.hasAudio,
    container: f.container, codecs: f.codecs,
    contentLength: f.contentLength ? Math.round(parseInt(f.contentLength)/1024/1024*10)/10 : null
  }));
  return {
    id: details.videoId, title: details.title, author: details.author?.name,
    duration: parseInt(details.lengthSeconds),
    thumbnail: details.thumbnails?.slice(-1)[0]?.url,
    description: details.shortDescription?.slice(0,300),
    formats
  };
});

ipcMain.handle('yt-download', async (_, { url, itag, outputPath }) => {
  if (!ytdl) throw new Error('@distube/ytdl-core not installed');
  await fsp.mkdir(path.dirname(outputPath), { recursive: true });
  return new Promise((resolve, reject) => {
    const stream = ytdl(url, { quality: itag });
    const out    = fs.createWriteStream(outputPath);
    stream.on('progress', (_, dl, tot) => {
      const pct = tot ? Math.round((dl/tot)*100) : 0;
      mainWindow?.webContents.send('yt-progress', { pct, downloaded: dl, total: tot, phase: 'Downloading' });
    });
    stream.pipe(out);
    out.on('finish', () => resolve(outputPath));
    stream.on('error', reject);
    out.on('error', reject);
  });
});

ipcMain.handle('yt-convert-audio', async (_, { inputPath, outputPath, format }) => {
  if (!ffmpegLib) throw new Error('fluent-ffmpeg not installed');
  return new Promise((resolve, reject) => {
    const cmd = ffmpegLib(inputPath).noVideo();
    if (format === 'mp3')  { cmd.audioCodec('libmp3lame').audioBitrate(192); }
    if (format === 'wav')  { cmd.audioCodec('pcm_s16le'); }
    if (format === 'opus') { cmd.audioCodec('libopus').audioBitrate(128); }
    if (format === 'm4a')  { cmd.audioCodec('aac').audioBitrate(192); }
    if (format === 'flac') { cmd.audioCodec('flac'); }
    cmd.save(outputPath).on('end', () => resolve(outputPath)).on('error', reject);
  });
});

ipcMain.handle('yt-transcribe', async (_, { audioPath, openaiKey, language }) => {
  if (!OpenAI) throw new Error('openai package not installed — run: npm install');
  if (!openaiKey) throw new Error('OpenAI API key required for Whisper transcription');
  mainWindow?.webContents.send('yt-progress', { pct: 30, phase: 'Sending to Whisper API…' });
  const client = new OpenAI({ apiKey: openaiKey });
  const resp = await client.audio.transcriptions.create({
    file: fs.createReadStream(audioPath),
    model: 'whisper-1',
    language: language || undefined,
    response_format: 'verbose_json',
    timestamp_granularities: ['segment']
  });
  mainWindow?.webContents.send('yt-progress', { pct: 100, phase: 'Complete' });
  return resp;
});

ipcMain.handle('yt-save-transcript', async (_, { transcript, videoInfo, formats, outputDir }) => {
  const outDir = outputDir || TRANSCRIPTS_DIR;
  await fsp.mkdir(outDir, { recursive: true });
  const safe = (videoInfo?.title || 'transcript').replace(/[^\w\s\-]/g,'').trim().slice(0,60).replace(/\s+/g,'_');
  const base  = path.join(outDir, safe);
  const segs  = transcript.segments || [];
  const full  = transcript.text || segs.map(s => s.text).join(' ');
  const saved = [];
  for (const fmt of formats) {
    if (fmt === 'txt')  { await fsp.writeFile(base+'.txt',  full, 'utf8');                        saved.push(base+'.txt');  }
    if (fmt === 'srt')  { await fsp.writeFile(base+'.srt',  toSRT(segs), 'utf8');                 saved.push(base+'.srt');  }
    if (fmt === 'vtt')  { await fsp.writeFile(base+'.vtt',  toVTT(segs), 'utf8');                 saved.push(base+'.vtt');  }
    if (fmt === 'md')   { await fsp.writeFile(base+'.md',   toMD(segs, videoInfo, full), 'utf8'); saved.push(base+'.md');   }
    if (fmt === 'json') { await fsp.writeFile(base+'.json', JSON.stringify(transcript, null, 2), 'utf8'); saved.push(base+'.json'); }
  }
  return { saved, dir: outDir };
});

ipcMain.handle('yt-pick-output-dir', async () => {
  const r = await dialog.showOpenDialog({ properties: ['openDirectory'], title: 'Choose output folder' });
  return r.canceled ? null : r.filePaths[0];
});

ipcMain.handle('yt-get-openai-key', () => {
  try { return JSON.parse(fs.readFileSync(path.join(DATA_DIR, 'openai-cfg.json'), 'utf8')).key || null; } catch { return null; }
});
ipcMain.handle('yt-save-openai-key', (_, key) => {
  fs.writeFileSync(path.join(DATA_DIR, 'openai-cfg.json'), JSON.stringify({ key }));
  return true;
});


/* ═══════════════════════════════════════════
   ELECTRON APP
═══════════════════════════════════════════ */
app.whenReady().then(async () => {
  await initDB();
  loadMem();
  await loadMyKeys();
  await getAuthClient();

  // ── Grant microphone + media permissions so Web Speech API (voice dictation)
  //    and any media features work without a silent deny.
  session.defaultSession.setPermissionRequestHandler((webContents, permission, callback) => {
    const allowed = ['media', 'microphone', 'notifications', 'clipboard-read'];
    callback(allowed.includes(permission));
  });

  mainWindow = new BrowserWindow({
    width: 1320, height: 880, minWidth: 960, minHeight: 620,
    titleBarStyle: 'hiddenInset',
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      webSecurity: true
    }
  });

  // Intercept close — tell renderer to play exit video first, then quit
  let exitReady = false;
  mainWindow.on('close', (e) => {
    if (!exitReady) {
      e.preventDefault();
      mainWindow.webContents.send('play-exit-video');
    }
  });

  // Renderer calls this IPC when exit video finishes
  ipcMain.handle('exit-video-done', () => {
    exitReady = true;
    if (pollerHandle) clearInterval(pollerHandle);
    mainWindow.close();
  });

  mainWindow.loadFile('index.html');
  startPoller();
});

app.on('window-all-closed', () => { if (pollerHandle) clearInterval(pollerHandle); app.quit(); });
app.on('activate', () => { if (!BrowserWindow.getAllWindows().length) app.whenReady(); });
