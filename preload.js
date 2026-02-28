'use strict';
const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('API', {
  // Auth
  authorize:          ()      => ipcRenderer.invoke('authorize'),
  getAuthStatus:      ()      => ipcRenderer.invoke('get-auth-status'),
  signOut:            ()      => ipcRenderer.invoke('sign-out'),

  // Tasks
  getTasks:           ()      => ipcRenderer.invoke('get-tasks'),
  createTask:         (t)     => ipcRenderer.invoke('create-task', t),
  updateTask:         (t)     => ipcRenderer.invoke('update-task', t),
  deleteTask:         (id)    => ipcRenderer.invoke('delete-task', id),
  toggleTask:         (id)    => ipcRenderer.invoke('toggle-task', id),

  // Files / Folders
  pickFolder:         ()      => ipcRenderer.invoke('pick-folder'),
  pickFiles:          ()      => ipcRenderer.invoke('pick-files'),
  scanFolder:         (p)     => ipcRenderer.invoke('scan-folder', p),
  openFolder:         (p)     => ipcRenderer.invoke('open-folder', p),

  // Send
  sendNow:            (p)     => ipcRenderer.invoke('send-now', p),
  generatePassword:   ()      => ipcRenderer.invoke('generate-password'),
  openExternal:       (url)   => ipcRenderer.invoke('open-external', url),
  quitApp:            ()      => ipcRenderer.invoke('quit-app'),
  exitVideoDone:      ()      => ipcRenderer.invoke('exit-video-done'),

  // Licence
  getLicence:         ()           => ipcRenderer.invoke('get-licence'),
  ownerLogin:         (email)      => ipcRenderer.invoke('owner-login', { email }),
  validateLicence:    (key, email) => ipcRenderer.invoke('validate-licence', { key, email }),
  clearLicence:       ()           => ipcRenderer.invoke('clear-licence'),
  generateDevKey:     (email)      => ipcRenderer.invoke('generate-dev-key', { email }),

  // Admin
  adminCheckPin:      (pin)        => ipcRenderer.invoke('admin-check-pin',    { pin }),
  adminGenStandard:   (p)          => ipcRenderer.invoke('admin-gen-standard',  p),
  adminGenWalkup:     (p)          => ipcRenderer.invoke('admin-gen-walkup',    p),
  adminGetLog:        ()           => ipcRenderer.invoke('admin-get-log'),

  // Contacts
  getContacts:        ()      => ipcRenderer.invoke('get-contacts'),
  upsertContact:      (c)     => ipcRenderer.invoke('upsert-contact', c),
  deleteContact:      (id)    => ipcRenderer.invoke('delete-contact', id),
  getContact:         (email) => ipcRenderer.invoke('get-contact', email),

  // Key management
  getMyKeys:          ()      => ipcRenderer.invoke('get-my-keys'),
  generateMyKeys:     (opts)  => ipcRenderer.invoke('generate-my-keys', opts),
  exportMyPubkey:     ()      => ipcRenderer.invoke('export-my-pubkey'),

  // Checksums / Receipts
  getChecksums:       ()      => ipcRenderer.invoke('get-checksums'),
  getReceipts:        ()      => ipcRenderer.invoke('get-receipts'),
  getReceiptQR:       (id)    => ipcRenderer.invoke('get-receipt-qr', id),

  // Diagnostics
  getDiagnostics:     ()      => ipcRenderer.invoke('get-diagnostics'),

  // YouTube Transcription
  ytInfo:             (url)   => ipcRenderer.invoke('yt-info', url),
  ytDownload:         (p)     => ipcRenderer.invoke('yt-download', p),
  ytConvertAudio:     (p)     => ipcRenderer.invoke('yt-convert-audio', p),
  ytTranscribe:       (p)     => ipcRenderer.invoke('yt-transcribe', p),
  ytSaveTranscript:   (p)     => ipcRenderer.invoke('yt-save-transcript', p),
  ytPickOutputDir:    ()      => ipcRenderer.invoke('yt-pick-output-dir'),
  ytGetOpenAIKey:     ()      => ipcRenderer.invoke('yt-get-openai-key'),
  ytSaveOpenAIKey:    (key)   => ipcRenderer.invoke('yt-save-openai-key', key),

  // Events main → renderer
  on: (channel, cb) => {
    const valid = ['task-status','email-sent','poller-tick','auth-changed','yt-progress','play-exit-video'];
    if (valid.includes(channel)) ipcRenderer.on(channel, (_, ...args) => cb(...args));
  }
});
