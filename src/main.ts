import './style.css';

import type { TOTPHashAlg } from './totp';
import { generateTOTPWindow } from './totp';
import { parseOtpauthUri, fromManualInput } from './otpauth';
import { encryptAESGCM, decryptAESGCM } from './crypto';
import jsQR from 'jsqr';
import {
  listSecrets,
  addSecret,
  updateSecret,
  deleteSecret,
  reorderSecrets,
  metaGet,
  metaPut,
  toArrayBuffer,
  clearAll,
  DB_NAME,
} from './db';

type Maybe<T> = T | null;

interface DecryptedEntry {
  id: string;
  label: string;
  issuer?: string;
  alg: TOTPHashAlg;
  digits: 6 | 8;
  period: number;
  secretBytes: Uint8Array;
}

// In-memory session key (CryptoKey) and decrypted cache (per tab session only)
let sessionKey: Maybe<CryptoKey> = null;
let decryptedCache: Map<string, DecryptedEntry> = new Map();

// Temporary session-only cards (not persisted to IndexedDB)
let tempCards: DecryptedEntry[] = [];
let tempIdCounter = 0;

// UI root
const appEl = document.querySelector<HTMLDivElement>('#app');
if (!appEl) throw new Error('Missing #app root');

// State
let tickTimer: number | null = null;

// Boot
init();

async function init() {
  renderShell();
  wireGlobalActions();
  // Register service worker (offline)
  if ('serviceWorker' in navigator) {
    try {
      await navigator.serviceWorker.register('/sw.js');
    } catch {
      // ignore registration errors in dev if sw missing
    }
  }
  // Auto-initialize session key and load records with resilience
  try {
    await unlock();
  } catch (err) {
    console.error('Unlock failed', err);
    announce('Failed to load encrypted data. UI loaded without codes.');
    // Render empty list and keep ticker running so UI remains responsive
    await refreshList();
    startTicker();
  }
}

function renderShell() {
  appEl!.innerHTML = `
    <!-- SVG defs for countdown ring gradient -->
    <svg width="0" height="0" style="position:absolute">
      <defs>
        <linearGradient id="ringGrad" x1="0%" y1="0%" x2="100%" y2="100%">
          <stop offset="0%" stop-color="#8b5cf6"/>
          <stop offset="100%" stop-color="#a78bfa"/>
        </linearGradient>
      </defs>
    </svg>

    <header class="app-header">
      <div class="brand">
        <div class="logo">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" aria-hidden="true">
            <circle cx="12" cy="12" r="9" stroke="currentColor" stroke-width="2"></circle>
            <path d="M12 7v5l3 3" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"></path>
          </svg>
        </div>
        <span class="logo-text">CROTP</span>
      </div>
      <div class="actions">
        <button id="helpBtn" class="icon-btn" title="Help" aria-label="Help">
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <circle cx="12" cy="12" r="10"/><path d="M9.09 9a3 3 0 0 1 5.83 1c0 2-3 3-3 3"/><line x1="12" y1="17" x2="12.01" y2="17"/>
          </svg>
        </button>
        <button id="clearBtn" class="icon-btn danger" title="Clear all data" aria-label="Clear all data">
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/>
          </svg>
        </button>
      </div>
    </header>

    <main class="app-main">
      <section id="appSection" aria-hidden="false">
        <div class="toolbar">
          <button id="addManualBtn" class="primary">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" style="margin-right:6px;vertical-align:-2px">
              <line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/>
            </svg>
            Add OTP
          </button>
          <button id="addUriBtn" class="ghost">Import URI</button>
          <button id="scanQrBtn" class="ghost">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="margin-right:4px;vertical-align:-2px">
              <path d="M23 19a2 2 0 0 1-2 2H3a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h4l2-3h6l2 3h4a2 2 0 0 1 2 2z"/><circle cx="12" cy="13" r="4"/>
            </svg>
            Scan QR
          </button>
          <button id="quickAddBtn" class="ghost">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="margin-right:4px;vertical-align:-2px">
              <polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/>
            </svg>
            Quick
          </button>
          <div class="search-wrap">
            <span class="search-icon">
              <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/>
              </svg>
            </span>
            <input id="searchInput" type="search" placeholder="Search accounts..." aria-label="Search accounts">
          </div>
        </div>

        <div id="listContainer" class="grid"></div>

        <dialog id="manualDialog">
          <form id="manualForm" method="dialog">
            <div class="dialog-header">
              <h3>Add OTP</h3>
            </div>
            <div class="dialog-body">
              <label>Label<input id="mLabel" placeholder="e.g. john@example.com" required></label>
              <label>Issuer (optional)<input id="mIssuer" placeholder="e.g. GitHub"></label>
              <label>Secret (Base32)<input id="mSecret" placeholder="JBSWY3DPEHPK3PXP" required></label>
              <div class="row">
                <label>Algorithm
                  <select id="mAlg">
                    <option value="SHA-1" selected>SHA-1</option>
                    <option value="SHA-256">SHA-256</option>
                  </select>
                </label>
                <label>Digits
                  <select id="mDigits">
                    <option value="6" selected>6</option>
                    <option value="8">8</option>
                  </select>
                </label>
                <label>Period (s)<input id="mPeriod" type="number" min="5" max="300" value="30"></label>
              </div>
            </div>
            <div class="dialog-footer">
              <button type="reset" class="ghost">Cancel</button>
              <button type="submit" class="primary">Save</button>
            </div>
          </form>
        </dialog>

        <dialog id="uriDialog">
          <form id="uriForm" method="dialog">
            <div class="dialog-header">
              <h3>Import otpauth URI</h3>
            </div>
            <div class="dialog-body">
              <label>otpauth URI
                <input id="uUri" placeholder="otpauth://totp/Issuer:Label?secret=..." required>
              </label>
            </div>
            <div class="dialog-footer">
              <button type="reset" class="ghost">Cancel</button>
              <button type="submit" class="primary">Import</button>
            </div>
          </form>
        </dialog>

        <dialog id="qrDialog">
          <div class="dialog-header">
            <h3>Scan QR Code</h3>
          </div>
          <div class="dialog-body">
            <div class="row" style="margin-bottom:12px">
              <button id="qrStartBtn" class="primary">Start Camera</button>
              <button id="qrStopBtn" class="ghost">Stop</button>
            </div>
            <video id="qrVideo" playsinline muted></video>
            <canvas id="qrCanvas" hidden></canvas>
            <label style="margin-top:12px">Upload image (QR)<input id="qrFile" type="file" accept="image/*"></label>
            <p class="muted" style="margin-top:8px;font-size:12px">
              <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:-2px;margin-right:4px">
                <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>
              </svg>
              Offline QR decoding. No data leaves your device.
            </p>
          </div>
          <div class="dialog-footer">
            <button id="qrCloseBtn" class="ghost">Close</button>
          </div>
        </dialog>

        <dialog id="helpDialog">
          <div class="dialog-header">
            <h3>Help & Security</h3>
          </div>
          <div class="dialog-body">
            <p class="muted">CROTP works fully offline. Tips:</p>
            <ul style="margin:8px 0 0 18px;color:var(--text-secondary);font-size:13px;line-height:1.8">
              <li><strong>Time sync</strong>: ensure your device time is accurate. Codes depend on time; enable automatic date/time.</li>
              <li><strong>App key</strong>: secrets are encrypted with a locally generated key stored on this device. No password required.</li>
              <li><strong>Backups</strong>: keep a secure record of your original OTP secrets. Encrypted export will be added in a future update.</li>
              <li><strong>QR import</strong>: camera is only used locally to decode. You can also upload a QR image.</li>
              <li><strong>Privacy</strong>: no network requests are made by the app. A strict CSP forbids external connections.</li>
            </ul>
          </div>
          <div class="dialog-footer">
            <button id="helpCloseBtn" class="ghost">Close</button>
          </div>
        </dialog>

        <dialog id="quickDialog">
          <form id="quickForm" method="dialog">
            <div class="dialog-header">
              <h3>Quick Add</h3>
              <p class="muted" style="margin-top:4px;font-size:12px">Paste a secret key for instant access. Not saved — session only.</p>
            </div>
            <div class="dialog-body">
              <label>Secret (Base32)
                <input id="qSecret" placeholder="JBSWY3DPEHPK3PXP" required autofocus>
              </label>
            </div>
            <div class="dialog-footer">
              <button type="reset" class="ghost">Cancel</button>
              <button type="submit" class="primary">Generate</button>
            </div>
          </form>
        </dialog>

        <div aria-live="polite" aria-atomic="true" class="sr-only" id="ariaAnnounce"></div>
      </section>

      <footer class="app-footer">
        <div class="footer-inner">
          <div class="footer-meta">
            Offline encrypted TOTP authenticator · No data leaves your device
          </div>
          <div class="footer-links">
            <a href="https://github.com/creasydude/crotp-web" target="_blank" rel="noopener noreferrer" aria-label="GitHub" title="View source on GitHub">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor">
                <path d="M12 .5a11.5 11.5 0 0 0-3.64 22.41c.58.11.79-.25.79-.56v-2.2c-3.2.7-3.87-1.37-3.87-1.37-.53-1.34-1.3-1.7-1.3-1.7-1.06-.72.08-.71.08-.71 1.17.08 1.78 1.2 1.78 1.2 1.04 1.78 2.73 1.27 3.4.97.11-.76.41-1.27.74-1.56-2.55-.29-5.23-1.28-5.23-5.7 0-1.26.44-2.29 1.17-3.1-.12-.29-.5-1.45.11-3.02 0 0 .97-.31 3.18 1.18a11.02 11.02 0 0 1 5.79 0c2.2-1.49 3.17-1.18 3.17-1.18.61 1.57.23 2.73.11 3.02.73.81 1.16 1.84 1.16 3.1 0 4.43-2.69 5.41-5.25 5.69.42.36.79 1.06.79 2.15v3.19c0 .31.21.68.8.56A11.5 11.5 0 0 0 12 .5z"/>
              </svg>
            </a>
          </div>
        </div>
      </footer>
    </main>
  `;
}

function wireGlobalActions() {
  // Lock removed per user request
  const helpBtn = document.querySelector<HTMLButtonElement>('#helpBtn')!;
  helpBtn.addEventListener('click', () => (document.querySelector<HTMLDialogElement>('#helpDialog')!).showModal());
  const clearBtn = document.querySelector<HTMLButtonElement>('#clearBtn')!;
  clearBtn.addEventListener('click', async () => {
    const ok = confirm('This will permanently delete all saved OTP entries, app key, local caches, cookies and storage on this device. Continue?');
    if (!ok) return;
    await clearAppData();
  });

  /* No passphrase unlock; session key initializes automatically */

  // Dialog buttons
  const addManualBtn = document.querySelector<HTMLButtonElement>('#addManualBtn')!;
  const addUriBtn = document.querySelector<HTMLButtonElement>('#addUriBtn')!;
  const scanQrBtn = document.querySelector<HTMLButtonElement>('#scanQrBtn')!;
  addManualBtn.addEventListener('click', () => (document.querySelector<HTMLDialogElement>('#manualDialog')!).showModal());
  addUriBtn.addEventListener('click', () => (document.querySelector<HTMLDialogElement>('#uriDialog')!).showModal());
  scanQrBtn.addEventListener('click', () => (document.querySelector<HTMLDialogElement>('#qrDialog')!).showModal());

  // Manual form
  const manualForm = document.querySelector<HTMLFormElement>('#manualForm')!;
  manualForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    if (!sessionKey) {
      await ensureSessionKey();
    }
    const label = (document.querySelector<HTMLInputElement>('#mLabel')!).value.trim();
    const issuer = (document.querySelector<HTMLInputElement>('#mIssuer')!).value.trim() || undefined;
    const secretBase32 = (document.querySelector<HTMLInputElement>('#mSecret')!).value.trim();
    const algStr = (document.querySelector<HTMLSelectElement>('#mAlg')!).value;
    const digitsNum = parseInt((document.querySelector<HTMLSelectElement>('#mDigits')!).value, 10);
    const periodNum = parseInt((document.querySelector<HTMLInputElement>('#mPeriod')!).value, 10);

    try {
      const entry = fromManualInput(label, issuer, secretBase32, algStr, digitsNum, periodNum);
      await storeEntry(entry);
      (document.querySelector<HTMLDialogElement>('#manualDialog')!).close();
      await refreshList();
    } catch (err: any) {
      alert(err?.message || 'Failed to add entry');
    }
  });
  // Ensure the Cancel button (type=reset) closes the dialog
  manualForm.addEventListener('reset', () => (document.querySelector<HTMLDialogElement>('#manualDialog')!).close());

  // URI form
  const uriForm = document.querySelector<HTMLFormElement>('#uriForm')!;
  uriForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    if (!sessionKey) {
      await ensureSessionKey();
    }
    const uri = (document.querySelector<HTMLInputElement>('#uUri')!).value.trim();
    try {
      const parsed = parseOtpauthUri(uri);
      await storeEntry(parsed);
      (document.querySelector<HTMLDialogElement>('#uriDialog')!).close();
      await refreshList();
    } catch (err: any) {
      alert(err?.message || 'Invalid otpauth URI');
    }
  });
  // Ensure the Cancel button (type=reset) closes the dialog
  uriForm.addEventListener('reset', () => (document.querySelector<HTMLDialogElement>('#uriDialog')!).close());

  // QR dialog controls (decoder to be added in a separate module)
  const qrDialog = document.querySelector<HTMLDialogElement>('#qrDialog')!;
  const qrStartBtn = document.querySelector<HTMLButtonElement>('#qrStartBtn')!;
  const qrStopBtn = document.querySelector<HTMLButtonElement>('#qrStopBtn')!;
  const qrCloseBtn = document.querySelector<HTMLButtonElement>('#qrCloseBtn')!;
  const video = document.querySelector<HTMLVideoElement>('#qrVideo')!;
  const canvas = document.querySelector<HTMLCanvasElement>('#qrCanvas')!;
  const qrFile = document.querySelector<HTMLInputElement>('#qrFile')!;
  let stream: MediaStream | null = null;
  let qrTimer: number | null = null;
  let qrFound = false;

  qrStartBtn.addEventListener('click', async () => {
    try {
      stream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: 'environment' } });
      video.srcObject = stream;
      await video.play();
      canvas.width = 640;
      canvas.height = 480;
      canvas.hidden = false;
      qrFound = false;
      qrTimer = window.setInterval(async () => {
        if (qrFound) return;
        const ctx = canvas.getContext('2d');
        if (!ctx) return;
        ctx.drawImage(video, 0, 0, canvas.width, canvas.height);
        try {
          const img = ctx.getImageData(0, 0, canvas.width, canvas.height);
          const code = jsQR(img.data, img.width, img.height);
          if (code && code.data) {
            const text = code.data.trim();
            if (!sessionKey) {
              await ensureSessionKey();
            }
            let parsed;
            try {
              parsed = parseOtpauthUri(text);
            } catch {
              announce('QR is not a valid otpauth URI');
              return;
            }
            qrFound = true;
            await storeEntry(parsed);
            stopCamera();
            (document.querySelector<HTMLDialogElement>('#qrDialog')!).close();
            await refreshList();
            announce('Imported OTP from QR');
          }
        } catch {
          // ignore frame errors to keep scanning
        }
      }, 500);
    } catch (err) {
      alert('Camera access denied or unavailable');
    }
  });

  const stopCamera = () => {
    qrTimer && clearInterval(qrTimer);
    qrTimer = null;
    if (stream) {
      stream.getTracks().forEach((t) => t.stop());
      stream = null;
    }
    video.srcObject = null;
    canvas.hidden = true;
  };

  qrStopBtn.addEventListener('click', stopCamera);
  qrCloseBtn.addEventListener('click', () => {
    stopCamera();
    qrDialog.close();
  });
  const helpCloseBtn = document.querySelector<HTMLButtonElement>('#helpCloseBtn')!;
  helpCloseBtn.addEventListener('click', () => (document.querySelector<HTMLDialogElement>('#helpDialog')!).close());
  // Fallback: decode from uploaded image file
  qrFile.addEventListener('change', async () => {
    const file = qrFile.files && qrFile.files[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = async () => {
      const imgEl = new Image();
      imgEl.onload = async () => {
        canvas.width = imgEl.width;
        canvas.height = imgEl.height;
        const ctx = canvas.getContext('2d');
        if (!ctx) return;
        ctx.drawImage(imgEl, 0, 0);
        try {
          const img = ctx.getImageData(0, 0, canvas.width, canvas.height);
          const code = jsQR(img.data, img.width, img.height);
          if (code && code.data) {
            const text = code.data.trim();
            if (!sessionKey) {
              await ensureSessionKey();
            }
            try {
              const parsed = parseOtpauthUri(text);
              await storeEntry(parsed);
              (document.querySelector<HTMLDialogElement>('#qrDialog')!).close();
              await refreshList();
              announce('Imported OTP from image');
            } catch {
              announce('Image QR is not a valid otpauth URI');
            }
          } else {
            announce('No QR detected in image');
          }
        } catch {
          announce('Failed to read image for QR');
        }
      };
      imgEl.src = reader.result as string;
    };
    reader.readAsDataURL(file);
  });

  // Search
  const searchInput = document.querySelector<HTMLInputElement>('#searchInput')!;
  searchInput.addEventListener('input', () => filterList(searchInput.value.trim()));

  // Quick Add
  const quickAddBtn = document.querySelector<HTMLButtonElement>('#quickAddBtn')!;
  quickAddBtn.addEventListener('click', () => (document.querySelector<HTMLDialogElement>('#quickDialog')!).showModal());

  const quickForm = document.querySelector<HTMLFormElement>('#quickForm')!;
  quickForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const secretInput = document.querySelector<HTMLInputElement>('#qSecret')!;
    const secretB32 = secretInput.value.trim();
    if (!secretB32) return;
    try {
      const entry = fromManualInput('Quick · ' + secretB32.slice(0, 4) + '...', undefined, secretB32, undefined, undefined, undefined);
      const tempEntry: DecryptedEntry = {
        id: `temp-${++tempIdCounter}`,
        label: 'Quick · ' + secretB32.slice(0, 4) + '...',
        issuer: undefined,
        alg: entry.algorithm,
        digits: entry.digits,
        period: entry.period,
        secretBytes: entry.secretBytes,
      };
      tempCards.push(tempEntry);
      secretInput.value = '';
      (document.querySelector<HTMLDialogElement>('#quickDialog')!).close();
      await refreshList();
      announce('Quick card added — session only, not saved');
    } catch (err: any) {
      announce(err?.message || 'Invalid Base32 secret');
    }
  });
  quickForm.addEventListener('reset', () => (document.querySelector<HTMLDialogElement>('#quickDialog')!).close());
}

async function ensureSessionKey(): Promise<void> {
  if (sessionKey) return;
  // Load or create a local AES-GCM key (raw 256-bit) stored in IndexedDB meta
  const existing = await metaGet<ArrayBuffer>('appKey');
  let keyBytes: Uint8Array;
  if (existing) {
    keyBytes = new Uint8Array(existing);
  } else {
    keyBytes = new Uint8Array(32);
    crypto.getRandomValues(keyBytes);
    await metaPut('appKey', toArrayBuffer(keyBytes));
  }
  sessionKey = await crypto.subtle.importKey(
    'raw',
    toArrayBuffer(keyBytes),
    { name: 'AES-GCM' },
    false,
    ['encrypt', 'decrypt']
  );
}

async function unlock(): Promise<void> {
  await ensureSessionKey();
  // Load records and decrypt into in-memory cache
  decryptedCache.clear();
  const records = await listSecrets();
  for (const r of records) {
    const secretBytes = await decryptAESGCM(sessionKey!, new Uint8Array(r.iv), new Uint8Array(r.encSecret));
    decryptedCache.set(r.id, {
      id: r.id,
      label: r.label,
      issuer: r.issuer,
      alg: r.alg,
      digits: r.digits,
      period: r.period,
      secretBytes,
    });
  }
  await refreshList();
  startTicker();
}




async function storeEntry(entry: {
  label: string;
  issuer?: string;
  secretBytes: Uint8Array;
  algorithm: TOTPHashAlg;
  digits: 6 | 8;
  period: number;
}) {
  if (!sessionKey) await ensureSessionKey();
  const { ciphertext, iv } = await encryptAESGCM(sessionKey!, entry.secretBytes);
  const rec = await addSecret({
    label: entry.label,
    issuer: entry.issuer,
    alg: entry.algorithm,
    digits: entry.digits,
    period: entry.period,
    encSecret: ciphertext,
    iv,
  });
  decryptedCache.set(rec.id, {
    id: rec.id,
    label: rec.label,
    issuer: rec.issuer,
    alg: rec.alg,
    digits: rec.digits,
    period: rec.period,
    secretBytes: entry.secretBytes,
  });
}

function startTicker() {
  stopTicker();
  tickTimer = window.setInterval(() => updateCodes(), 1000);
}

function stopTicker() {
  if (tickTimer) {
    clearInterval(tickTimer);
    tickTimer = null;
  }
}

async function refreshList() {
  const container = document.querySelector<HTMLDivElement>('#listContainer')!;
  const orderRecords = await listSecrets();
  const all = orderRecords
    .map((r) => decryptedCache.get(r.id))
    .filter((e): e is DecryptedEntry => !!e);

  // Empty-state UI for first-time users (or after clearing data)
  if (all.length === 0) {
    container.innerHTML = `
      <div class="empty-wrap">
        <div class="card glass empty-state" role="region" aria-label="Get started">
          <div class="empty-visual">
            <svg width="36" height="36" viewBox="0 0 24 24" fill="none" aria-hidden="true">
              <circle cx="12" cy="12" r="9" stroke="currentColor" stroke-width="2"></circle>
              <path d="M12 8v8M8 12h8" stroke="currentColor" stroke-width="2" stroke-linecap="round"></path>
            </svg>
          </div>
          <h2>Add your first OTP</h2>
          <p class="muted">Import a QR code, paste an otpauth URI, or enter your secret key manually.</p>
          <div class="cta-row">
            <button id="emptyAddBtn" class="primary">Add OTP</button>
            <button id="emptyImportBtn" class="ghost">Import URI</button>
            <button id="emptyScanBtn" class="ghost">Scan QR</button>
          </div>
        </div>
      </div>
    `;
    const addBtn = container.querySelector<HTMLButtonElement>('#emptyAddBtn');
    const importBtn = container.querySelector<HTMLButtonElement>('#emptyImportBtn');
    const scanBtn = container.querySelector<HTMLButtonElement>('#emptyScanBtn');
    addBtn?.addEventListener('click', () => (document.querySelector<HTMLDialogElement>('#manualDialog')!).showModal());
    importBtn?.addEventListener('click', () => (document.querySelector<HTMLDialogElement>('#uriDialog')!).showModal());
    scanBtn?.addEventListener('click', () => (document.querySelector<HTMLDialogElement>('#qrDialog')!).showModal());
    return;
  }

  const cards = await Promise.all(
    all.map(async (e) => {
      const windowData = await generateTOTPWindow({
        secret: e.secretBytes,
        period: e.period,
        digits: e.digits,
        algorithm: e.alg,
        timestamp: Date.now(),
      });
      return renderCard(
        e,
        windowData.current,
        windowData.prev,
        windowData.next,
        windowData.remainingSeconds,
        windowData.period
      );
    })
  );

  // Render temp (session-only) cards with a "temporary" badge
  const tempHtml = await Promise.all(
    tempCards.map(async (e) => {
      const windowData = await generateTOTPWindow({
        secret: e.secretBytes,
        period: e.period,
        digits: e.digits,
        algorithm: e.alg,
        timestamp: Date.now(),
      });
      return renderCard(
        e,
        windowData.current,
        windowData.prev,
        windowData.next,
        windowData.remainingSeconds,
        windowData.period,
        true // isTemp
      );
    })
  );

  container.innerHTML = cards.join('') + tempHtml.join('');
  wireCardActions();
}

async function updateCodes() {
  const now = Date.now();
  // Update persisted cards
  for (const e of decryptedCache.values()) {
    const windowData = await generateTOTPWindow({
      secret: e.secretBytes,
      period: e.period,
      digits: e.digits,
      algorithm: e.alg,
      timestamp: now,
    });
    const card = document.querySelector<HTMLDivElement>(`[data-id="${e.id}"]`);
    if (!card) continue;
    updateCardDOM(card, windowData);
  }
  // Update temp cards
  for (const e of tempCards) {
    const windowData = await generateTOTPWindow({
      secret: e.secretBytes,
      period: e.period,
      digits: e.digits,
      algorithm: e.alg,
      timestamp: now,
    });
    const card = document.querySelector<HTMLDivElement>(`[data-id="${e.id}"]`);
    if (!card) continue;
    updateCardDOM(card, windowData);
  }
}

function updateCardDOM(card: HTMLDivElement, windowData: { prev: string; current: string; next: string; remainingSeconds: number; period: number }) {
  const prevEl = card.querySelector<HTMLSpanElement>('.code-prev');
  const currEl = card.querySelector<HTMLSpanElement>('.code-current');
  const nextEl = card.querySelector<HTMLSpanElement>('.code-next');
  const ringProgress = card.querySelector<SVGCircleElement>('.ring-progress');
  const ringText = card.querySelector<SVGTextElement>('[data-text]');
  if (prevEl) prevEl.textContent = windowData.prev;
  if (currEl) currEl.textContent = windowData.current;
  if (nextEl) nextEl.textContent = windowData.next;
  if (ringProgress) {
    const circumference = parseFloat(ringProgress.getAttribute('data-circumference') || '175.93');
    const pct = (windowData.period - windowData.remainingSeconds - 1) / windowData.period;
    const offset = circumference * (1 - pct);
    ringProgress.style.strokeDashoffset = `${offset}`;
  }
  if (ringText) {
    ringText.textContent = `${windowData.remainingSeconds + 1}s`;
  }
}

// Avatar color from label hash
function avatarColor(label: string): string {
  const palette = ['#8b5cf6','#ec4899','#f59e0b','#22c55e','#3b82f6','#ef4444','#06b6d4','#84cc16'];
  let h = 0;
  for (let i = 0; i < label.length; i++) h = label.charCodeAt(i) + ((h << 5) - h);
  return palette[Math.abs(h) % palette.length];
}

function renderCard(
  e: DecryptedEntry,
  current: string,
  prev: string,
  next: string,
  remaining: number,
  period: number,
  isTemp = false
): string {
  const pct = ((period - remaining - 1) / period);
  const circumference = 2 * Math.PI * 28; // r=28
  const dashOffset = circumference * (1 - pct);
  const label = e.issuer ? `${e.issuer} · ${e.label}` : e.label;
  const initial = (e.issuer || e.label || '?')[0].toUpperCase();
  const color = avatarColor(e.issuer || e.label);
  const delay = Math.random() * 0.15; // stagger
  const tempBadge = isTemp ? '<span class="temp-badge">Session only</span>' : '';
  const removeBtn = isTemp ? `<button class="removeTempBtn icon-btn danger" title="Remove" aria-label="Remove temporary card"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg></button>` : '';

  return `
    <div class="card glass account-card${isTemp ? ' temp-card' : ''}" data-id="${e.id}" style="animation-delay:${delay}s">
      <div class="card-header">
        <div class="issuer-avatar" style="background:${color}">${initial}</div>
        <div class="card-info">
          <div class="card-label">${escapeHtml(label)} ${tempBadge}</div>
          <div class="card-meta">${e.alg} · ${e.digits} digits · ${e.period}s</div>
        </div>
      </div>

      <div class="countdown-ring">
        <svg width="68" height="68" viewBox="0 0 68 68">
          <circle class="ring-bg" cx="34" cy="34" r="28" stroke-width="4"/>
          <circle class="ring-progress" cx="34" cy="34" r="28" stroke-width="4"
            stroke-dasharray="${circumference}"
            stroke-dashoffset="${dashOffset}"
            transform="rotate(-90 34 34)"
            data-circumference="${circumference}"/>
          <text class="ring-text" x="34" y="34" text-anchor="middle" dominant-baseline="central"
            data-text="true">${remaining + 1}s</text>
        </svg>
      </div>

      <div class="codes">
        <span class="code code-prev" aria-label="Previous code">${prev}</span>
        <span class="code code-current" aria-label="Current code">${current}</span>
        <span class="code code-next" aria-label="Next code">${next}</span>
      </div>

      <div class="card-actions">
        <div class="action-left">
          <button class="copyBtn primary" title="Copy current code">
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" style="margin-right:4px;vertical-align:-2px">
              <rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>
            </svg>
            Copy
          </button>
        </div>
        <div class="action-right">
          ${!isTemp ? `
          <button class="upBtn icon-btn" title="Move up" aria-label="Move up">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="18 15 12 9 6 15"/></svg>
          </button>
          <button class="downBtn icon-btn" title="Move down" aria-label="Move down">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="6 9 12 15 18 9"/></svg>
          </button>
          <button class="renameBtn icon-btn" title="Rename" aria-label="Rename">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17 3a2.83 2.83 0 1 1 4 4L7.5 20.5 2 22l1.5-5.5L17 3z"/></svg>
          </button>
          <button class="deleteBtn icon-btn danger" title="Delete" aria-label="Delete">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg>
          </button>
          ` : `
          ${removeBtn}
          `}
        </div>
      </div>
    </div>
  `;
}

function wireCardActions() {
  const container = document.querySelector<HTMLDivElement>('#listContainer')!;
  // Copy
  container.querySelectorAll<HTMLButtonElement>('.copyBtn').forEach((btn) => {
    btn.addEventListener('click', async () => {
      const card = btn.closest('.account-card') as HTMLDivElement;
      const curr = card.querySelector<HTMLSpanElement>('.code-current')!;
      try {
        await navigator.clipboard.writeText(curr.textContent || '');
        announce('Copied current code to clipboard');
      } catch {
        announce('Clipboard permission denied');
      }
    });
  });
  // Rename
  container.querySelectorAll<HTMLButtonElement>('.renameBtn').forEach((btn) => {
    btn.addEventListener('click', async () => {
      if (!sessionKey) return;
      const card = btn.closest('.account-card') as HTMLDivElement;
      const id = card.dataset.id!;
      const cur = decryptedCache.get(id)!;
      const nextLabel = prompt('New label', cur.label)?.trim();
      if (!nextLabel) return;
      await updateSecret({ id, label: nextLabel });
      cur.label = nextLabel;
      await refreshList();
    });
  });
  // Delete
  container.querySelectorAll<HTMLButtonElement>('.deleteBtn').forEach((btn) => {
    btn.addEventListener('click', async () => {
      const card = btn.closest('.account-card') as HTMLDivElement;
      const id = card.dataset.id!;
      if (!confirm('Delete this OTP? This cannot be undone.')) return;
      await deleteSecret(id);
      const cur = decryptedCache.get(id);
      if (cur) cur.secretBytes.fill(0);
      decryptedCache.delete(id);
      await refreshList();
    });
  });
  // Reorder up/down
  const moveSecret = async (id: string, dir: 'up' | 'down') => {
    const records = await listSecrets();
    const idx = records.findIndex((r) => r.id === id);
    if (idx === -1) return;
    if (dir === 'up' && idx === 0) return;
    if (dir === 'down' && idx === records.length - 1) return;
    const swapIdx = dir === 'down' ? idx + 1 : idx - 1;
    const newOrder = records.map((r) => ({ id: r.id, order: r.order }));
    const tmp = newOrder[idx].order;
    newOrder[idx].order = newOrder[swapIdx].order;
    newOrder[swapIdx].order = tmp;
    await reorderSecrets(newOrder);
    await refreshList();
  };
  container.querySelectorAll<HTMLButtonElement>('.upBtn').forEach((btn) => {
    btn.addEventListener('click', async () => {
      const card = btn.closest('.account-card') as HTMLDivElement;
      const id = card.dataset.id!;
      await moveSecret(id, 'up');
    });
  });
  container.querySelectorAll<HTMLButtonElement>('.downBtn').forEach((btn) => {
    btn.addEventListener('click', async () => {
      const card = btn.closest('.account-card') as HTMLDivElement;
      const id = card.dataset.id!;
      await moveSecret(id, 'down');
    });
  });
  // Remove temp card
  container.querySelectorAll<HTMLButtonElement>('.removeTempBtn').forEach((btn) => {
    btn.addEventListener('click', async () => {
      const card = btn.closest('.account-card') as HTMLDivElement;
      const id = card.dataset.id!;
      tempCards = tempCards.filter((e) => e.id !== id);
      const cur = decryptedCache.get(id);
      if (cur) cur.secretBytes.fill(0);
      decryptedCache.delete(id);
      await refreshList();
      announce('Temporary card removed');
    });
  });
}

function filterList(query: string) {
  const cards = document.querySelectorAll<HTMLDivElement>('.account-card');
  const q = query.toLowerCase();
  cards.forEach((card) => {
    const label = card.querySelector('.card-label')!.textContent!.toLowerCase();
    card.style.display = label.includes(q) ? '' : 'none';
  });
}

function announce(msg: string) {
  const el = document.querySelector<HTMLDivElement>('#ariaAnnounce')!;
  el.textContent = msg;
}

function escapeHtml(s: string): string {
  return s.replace(/[&<>"]/g, (c) => ({ '&': '&', '<': '<', '>': '>', '"': '"' }[c] as string));
}

// Clear all local data: IndexedDB, caches, storage, cookies, service workers
async function clearAppData(): Promise<void> {
  try {
    // Stop periodic updates
    stopTicker();

    // Wipe in-memory data
    try {
      decryptedCache.forEach((e) => e.secretBytes.fill(0));
      decryptedCache.clear();
    } catch {}
    sessionKey = null;

    // Clear IndexedDB stores
    try {
      await clearAll();
    } catch {}

    // Drop the entire database (best-effort)
    try {
      await new Promise<void>((resolve) => {
        const req = indexedDB.deleteDatabase(DB_NAME);
        req.onsuccess = () => resolve();
        req.onerror = () => resolve();
        req.onblocked = () => resolve();
      });
    } catch {}

    // Clear Web Storage
    try { localStorage.clear(); } catch {}
    try { sessionStorage.clear(); } catch {}

    // Clear cookies (best-effort; domain/path variations may be limited)
    try {
      const cookies = document.cookie ? document.cookie.split(';') : [];
      for (const part of cookies) {
        const eq = part.indexOf('=');
        const name = (eq > -1 ? part.slice(0, eq) : part).trim();
        if (!name) continue;
        document.cookie = `${name}=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/;`;
      }
    } catch {}

    // Delete all CacheStorage entries
    try {
      if ('caches' in window) {
        const keys = await caches.keys();
        await Promise.all(keys.map((k) => caches.delete(k)));
      }
    } catch {}

    // Unregister all service workers
    try {
      const regs = await navigator.serviceWorker.getRegistrations();
      await Promise.all(regs.map((r) => r.unregister()));
    } catch {}

    announce('All local app data cleared');
  } finally {
    // Reload to re-initialize the app without any persisted state
    location.reload();
  }
}
