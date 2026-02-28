# Email Automation Pro — Setup Guide

## Why nothing works yet

Two things are needed before the app functions:
1. **`npm install`** — install all dependencies
2. **`credentials.json`** — your Google OAuth credentials file

---

## Step 1: npm install

```bash
cd /Users/spionageabwehr/rust-projects/email-pro
npm install
```

If you see errors about `@noble/post-quantum`, try:
```bash
npm install --legacy-peer-deps
```

---

## Step 2: Get Google OAuth credentials

The app needs a **credentials.json** from Google Cloud Console to send Gmail.

1. Go to [console.cloud.google.com](https://console.cloud.google.com)
2. Create a new project (or use an existing one)
3. Go to **APIs & Services → Library** → search for **Gmail API** → click **Enable**
4. Go to **APIs & Services → OAuth consent screen**
   - Choose **External**
   - App name: anything (e.g. "Email Automation Pro")
   - Support email: your Gmail
   - Click through to the end and **Save**
5. Go to **APIs & Services → Credentials**
   - Click **+ Create Credentials → OAuth client ID**
   - Application type: **Desktop app**
   - Name: anything
   - Click **Create**
6. Click **⬇ Download JSON** on the created credential
7. Rename the file to **`credentials.json`**
8. Place it in: `/Users/spionageabwehr/rust-projects/email-pro/credentials.json`

> ⚠️ While on the **OAuth consent screen**, also add your Gmail address under **Test users** — this is required while the app is in "Testing" mode.

---

## Step 3: Start the app

```bash
npm start
```

---

## Step 4: Connect Gmail

1. Click **"Connect Gmail"** in the bottom-left sidebar
2. A browser window opens — log in and approve access
3. The sidebar shows **"Gmail connected"** ✅

---

## Step 5: YouTube Transcription (optional)

1. Click **Transcribe** in the sidebar
2. Enter your OpenAI API key (get one at [platform.openai.com/api-keys](https://platform.openai.com/api-keys))
3. Paste a YouTube URL and click **Fetch**

> ffmpeg is needed for audio conversion: `brew install ffmpeg`

---

## Diagnostic: run this if something still doesn't work

```bash
cd /Users/spionageabwehr/rust-projects/email-pro
node -e "
const fs = require('fs');
const path = require('path');

console.log('Node version:', process.version);

// Check credentials
const credPath = path.join(__dirname, 'credentials.json');
if (fs.existsSync(credPath)) {
  const c = JSON.parse(fs.readFileSync(credPath,'utf8'));
  const cfg = c.installed || c.web || {};
  console.log('✅ credentials.json found');
  console.log('   client_id:', cfg.client_id?.slice(0,20)+'...');
  console.log('   type:', c.installed ? 'Desktop/Installed' : c.web ? 'Web' : 'Unknown');
} else {
  console.log('❌ credentials.json MISSING — see SETUP.md Step 2');
}

// Check modules
const mods = ['googleapis','sql.js','qrcode','openpgp','@noble/post-quantum','ytdl-core','openai','fluent-ffmpeg'];
for (const m of mods) {
  try { require(m); console.log('✅', m); } 
  catch(e) { console.log('❌', m, '—', e.message.split('\n')[0]); }
}
"
```

