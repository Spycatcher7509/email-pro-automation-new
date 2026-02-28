# Email Automation Pro v2.0

Complete rebuild with:
- ⚡ **Tasks** — named tasks with recipient, schedule, and multiple folder pairs
- 📁 **Folder Pairs** — source → destination per task, 30-second poller
- 🔐 **Checksums** — SHA-256 for every processed file, stored in SQLite
- 🧾 **QR Receipts** — scannable QR code per send, phone-friendly
- 📤 **Send Now** — manual compose with attachments + voice dictation
- 📦 **20MB batching** — auto-splits large sends into multiple emails
- 🗂️ **Auto-move** — files move to destination after successful send

---

## Setup

### 1. Install dependencies
```bash
npm install
```

### 2. Add Gmail credentials
Place your `credentials.json` from Google Cloud Console in this folder.
(OAuth 2.0 Desktop app credentials — same file as before)

### 3. Run
```bash
npm start
```

### 4. Connect Gmail
Click **Connect Gmail** in the bottom-left sidebar. Your browser opens for OAuth. After approving, come back — it's ready.

---

## How Tasks Work

1. **Create a Task** — give it a name, recipient email, send time + days
2. **Add Folder Pairs** — each pair has a Source folder and Destination folder
3. **Enable the task** — toggle it on
4. **Drop files** into the Source folder
5. At the scheduled time, the poller sends all files as email attachments, then moves them to Destination

**Scheduling format:** `HH:MM:DAY,DAY` e.g. `08:45:MON,FRI`

---

## Dependencies

- `googleapis` — Gmail API
- `sql.js` — SQLite compiled to WebAssembly — **no native build required**, works on any Node version
- `qrcode` — QR code generation for receipts
- `electron` — desktop shell

---

## Build

```bash
# macOS ARM64
npm run build-mac

# Windows x64
npm run build-win
```
