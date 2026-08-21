import './style.css';

import type { TOTPHashAlg } from './totp';
import { generateTOTPWindow, formatCodeGroupings } from './totp';
import { parseOtpauthUri, fromManualInput } from './otpauth';
import { encryptAESGCM, decryptAESGCM } from './crypto';
import jsQR from 'jsqr';
import { initThreeBackground, type ThreeBgController } from './threeBackground';
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

// In-memory session key (CryptoKey) and decrypted cache
let sessionKey: Maybe<CryptoKey> = null;
let decryptedCache: Map<string, DecryptedEntry> = new Map();

// Temporary session-only cards (not persisted to IndexedDB)
let tempCards: DecryptedEntry[] = [];
let tempIdCounter = 0;

// Active selected card for Spotlight Panel
let activeCardId: string | null = null;

// Three.js background controller
let threeBg: Maybe<ThreeBgController> = null;

// UI root
const appEl = document.querySelector<HTMLDivElement>('#app');
if (!appEl) throw new Error('Missing #app root');

// State
let tickTimer: number | null = null;
let lastStep = -1;

// Boot
init();

async function init() {
  // Init Three.js 3D background
  const bgContainer = document.getElementById('bg-canvas');
  if (bgContainer) {
    try {
      threeBg = initThreeBackground(bgContainer);
    } catch (e) {
      console.warn('Three.js background initialization error:', e);
    }
  }

  renderShell();
  wireGlobalActions();

  // Register service worker (offline support)
  if ('serviceWorker' in navigator) {
    try {
      await navigator.serviceWorker.register('/sw.js');
    } catch {
      // ignore registration errors in dev
    }
  }

  // Auto-initialize session key and load records
  try {
    await unlock();
  } catch (err) {
    console.error('Unlock failed', err);
    showToast('Failed to load encrypted vault data', 'error');
    await refreshList();
    startTicker();
  }
}

function renderShell() {
  appEl!.innerHTML = `
    <!-- SVG Definitions for Gradients -->
    <svg width="0" height="0" style="position:absolute">
      <defs>
        <linearGradient id="ringGrad" x1="0%" y1="0%" x2="100%" y2="100%">
          <stop offset="0%" stop-color="#8b5cf6"/>
          <stop offset="100%" stop-color="#06b6d4"/>
        </linearGradient>
        <linearGradient id="spotlightGrad" x1="0%" y1="0%" x2="100%" y2="100%">
          <stop offset="0%" stop-color="#a78bfa"/>
          <stop offset="50%" stop-color="#8b5cf6"/>
          <stop offset="100%" stop-color="#06b6d4"/>
        </linearGradient>
      </defs>
    </svg>

    <!-- Top HUD Header -->
    <header class="app-header">
      <div class="brand">
        <div class="logo">
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
            <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/>
            <path d="M7 11V7a5 5 0 0 1 10 0v4"/>
          </svg>
        </div>
        <div class="brand-text-wrap">
          <span class="logo-text">CROTP</span>
          <div class="security-badge">
            <span class="dot"></span>
            <span>OFFLINE // AES-256 GCM</span>
          </div>
        </div>
      </div>

      <!-- Real-Time HUD Clock & Sync Status -->
      <div class="hud-clock-widget">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="var(--accent-cyan-light)" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/>
        </svg>
        <span id="hudTimeDisplay" class="time-val">00:00:00 UTC</span>
        <span class="sync-tag">IN SYNC</span>
      </div>

      <!-- Header Actions -->
      <div class="header-actions">
        <button id="demoBtn" class="btn-icon" title="Generate Demo Account" aria-label="Demo Account">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/>
          </svg>
        </button>
        <button id="helpBtn" class="btn-icon" title="Help & Security" aria-label="Help">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <circle cx="12" cy="12" r="10"/><path d="M9.09 9a3 3 0 0 1 5.83 1c0 2-3 3-3 3"/><line x1="12" y1="17" x2="12.01" y2="17"/>
          </svg>
        </button>
        <button id="clearBtn" class="btn-icon danger" title="Wipe Vault Data" aria-label="Wipe Vault">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/>
          </svg>
        </button>
      </div>
    </header>

    <!-- Main Command Deck Workspace -->
    <main class="workspace-grid">
      <!-- Left Column: Spotlight Command Pane -->
      <section class="spotlight-pane">
        <!-- Spotlight Card Container -->
        <div id="spotlightContainer"></div>

        <!-- Command & Quick Action Hub -->
        <div class="command-hub">
          <div class="command-hub-title">Command Actions</div>
          <div class="quick-actions-grid">
            <button id="addManualBtn" class="action-card-btn highlight">
              <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round">
                <line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/>
              </svg>
              <span>Add OTP</span>
            </button>
            <button id="scanQrBtn" class="action-card-btn">
              <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <path d="M23 19a2 2 0 0 1-2 2H3a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h4l2-3h6l2 3h4a2 2 0 0 1 2 2z"/><circle cx="12" cy="13" r="4"/>
              </svg>
              <span>Scan QR</span>
            </button>
            <button id="addUriBtn" class="action-card-btn">
              <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/>
                <path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/>
              </svg>
              <span>Import URI</span>
            </button>
            <button id="quickAddBtn" class="action-card-btn">
              <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/>
              </svg>
              <span>Quick Key</span>
            </button>
          </div>

          <!-- Live Search Filter -->
          <div class="search-control">
            <span class="search-icon">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/>
              </svg>
            </span>
            <input id="searchInput" type="search" placeholder="Search tokens by issuer or name..." aria-label="Search tokens">
            <button id="clearSearchBtn" class="clear-search-btn" title="Clear Search">
              <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
            </button>
          </div>
        </div>
      </section>

      <!-- Right Column: Vault Deck Container -->
      <section class="vault-pane">
        <div class="vault-pane-header">
          <div class="vault-title-group">
            <h2 class="vault-pane-title">Vault Tokens</h2>
            <span id="vaultCountBadge" class="vault-counter-badge">0 KEYS</span>
          </div>
        </div>
        <div id="listContainer" class="vault-deck-container"></div>
      </section>
    </main>

    <!-- Dialogs -->
    <!-- Add Manual Modal -->
    <dialog id="manualDialog">
      <form id="manualForm" method="dialog">
        <div class="dialog-header">
          <h3>Add Encrypted TOTP Token</h3>
        </div>
        <div class="dialog-body">
          <label>Account Label / Email
            <input id="mLabel" placeholder="e.g. user@github.com" required autofocus>
          </label>
          <label>Issuer (Service Name)
            <input id="mIssuer" placeholder="e.g. GitHub, AWS, Google">
          </label>
          <label>Secret Key (Base32)
            <input id="mSecret" placeholder="JBSWY3DPEHPK3PXP" required spellcheck="false" autocomplete="off">
          </label>
          <div class="form-row-3">
            <label>Algorithm
              <select id="mAlg">
                <option value="SHA-1" selected>SHA-1</option>
                <option value="SHA-256">SHA-256</option>
              </select>
            </label>
            <label>Digits
              <select id="mDigits">
                <option value="6" selected>6 Digits</option>
                <option value="8">8 Digits</option>
              </select>
            </label>
            <label>Period
              <input id="mPeriod" type="number" min="5" max="300" value="30">
            </label>
          </div>
        </div>
        <div class="dialog-footer">
          <button type="reset" class="btn-secondary-cta">Cancel</button>
          <button type="submit" class="btn-primary-cta">Save to Vault</button>
        </div>
      </form>
    </dialog>

    <!-- Import URI Modal -->
    <dialog id="uriDialog">
      <form id="uriForm" method="dialog">
        <div class="dialog-header">
          <h3>Import otpauth URI</h3>
        </div>
        <div class="dialog-body">
          <label>otpauth:// URI String
            <input id="uUri" placeholder="otpauth://totp/Service:name@email?secret=..." required autofocus spellcheck="false">
          </label>
        </div>
        <div class="dialog-footer">
          <button type="reset" class="btn-secondary-cta">Cancel</button>
          <button type="submit" class="btn-primary-cta">Import</button>
        </div>
      </form>
    </dialog>

    <!-- QR Scanner Modal -->
    <dialog id="qrDialog">
      <div class="dialog-header">
        <h3>Scan QR Code</h3>
      </div>
      <div class="dialog-body">
        <div class="qr-scanner-viewport">
          <div class="qr-laser-line"></div>
          <div class="qr-target-reticle"></div>
          <video id="qrVideo" playsinline muted></video>
          <canvas id="qrCanvas" hidden></canvas>
        </div>
        <div style="display:flex;gap:8px;margin-top:10px;">
          <button id="qrStartBtn" class="btn-primary-cta" style="flex:1">Start Camera</button>
          <button id="qrStopBtn" class="btn-secondary-cta">Stop</button>
        </div>
        <label style="margin-top:12px">Or upload QR image file
          <input id="qrFile" type="file" accept="image/*">
        </label>
      </div>
      <div class="dialog-footer">
        <button id="qrCloseBtn" class="btn-secondary-cta">Close</button>
      </div>
    </dialog>

    <!-- Quick Session Key Modal -->
    <dialog id="quickDialog">
      <form id="quickForm" method="dialog">
        <div class="dialog-header">
          <h3>Quick Session Key</h3>
        </div>
        <div class="dialog-body">
          <p style="font-size:13px;color:var(--text-secondary)">Generate instant TOTP codes in-memory. This key will not be saved to IndexedDB.</p>
          <label>Secret Key (Base32)
            <input id="qSecret" placeholder="JBSWY3DPEHPK3PXP" required autofocus spellcheck="false" autocomplete="off">
          </label>
        </div>
        <div class="dialog-footer">
          <button type="reset" class="btn-secondary-cta">Cancel</button>
          <button type="submit" class="btn-primary-cta">Generate</button>
        </div>
      </form>
    </dialog>

    <!-- Help & Security Modal -->
    <dialog id="helpDialog">
      <div class="dialog-header">
        <h3>CROTP Security & Architecture</h3>
      </div>
      <div class="dialog-body" style="font-size:13px;line-height:1.7;color:var(--text-secondary)">
        <p><strong style="color:var(--text-primary)">Zero Network Overhead:</strong> CROTP runs 100% locally in your browser. No telemetry, no analytics, no external servers.</p>
        <p><strong style="color:var(--text-primary)">Hardware-Grade Encryption:</strong> All TOTP secrets are encrypted with AES-256 GCM using a device-local cryptographic key in IndexedDB.</p>
        <p><strong style="color:var(--text-primary)">Time Synchronization:</strong> TOTP relies on accurate system time. Ensure your device time is synchronized via NTP.</p>
        <p><strong style="color:var(--text-primary)">Camera Privacy:</strong> QR decoding happens strictly within WebAssembly / JS in-memory on your device.</p>
      </div>
      <div class="dialog-footer">
        <button id="helpCloseBtn" class="btn-primary-cta">Got it</button>
      </div>
    </dialog>

    <!-- Toast Notification Container -->
    <div id="toastContainer"></div>
    <div aria-live="polite" aria-atomic="true" class="sr-only" id="ariaAnnounce"></div>
  `;
}

// Toast Notifications
function showToast(message: string, type: 'info' | 'success' | 'error' = 'info') {
  const container = document.getElementById('toastContainer');
  if (!container) return;

  const toast = document.createElement('div');
  toast.className = `hud-toast ${type}`;

  const iconSvg =
    type === 'success'
      ? `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="var(--emerald)" stroke-width="2.5" stroke-linecap="round"><polyline points="20 6 9 17 4 12"/></svg>`
      : type === 'error'
      ? `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="var(--crimson)" stroke-width="2.5" stroke-linecap="round"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>`
      : `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="var(--accent-cyan)" stroke-width="2.5" stroke-linecap="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>`;

  toast.innerHTML = `
    ${iconSvg}
    <span>${escapeHtml(message)}</span>
  `;

  container.appendChild(toast);
  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transform = 'translateY(10px) scale(0.95)';
    setTimeout(() => toast.remove(), 250);
  }, 2800);

  announce(message);
}

function wireGlobalActions() {
  // Help Dialog
  const helpBtn = document.querySelector<HTMLButtonElement>('#helpBtn')!;
  const helpDialog = document.querySelector<HTMLDialogElement>('#helpDialog')!;
  const helpCloseBtn = document.querySelector<HTMLButtonElement>('#helpCloseBtn')!;
  helpBtn.addEventListener('click', () => helpDialog.showModal());
  helpCloseBtn.addEventListener('click', () => helpDialog.close());

  // Demo Token Generator Button
  const demoBtn = document.querySelector<HTMLButtonElement>('#demoBtn')!;
  demoBtn.addEventListener('click', async () => {
    await addDemoAccount();
  });

  // Clear Vault Button
  const clearBtn = document.querySelector<HTMLButtonElement>('#clearBtn')!;
  clearBtn.addEventListener('click', async () => {
    const ok = confirm('SECURITY WARNING:\nThis will permanently purge all encrypted secrets, session keys, and cache from this browser. Continue?');
    if (!ok) return;
    await clearAppData();
  });

  // Dialog openers
  const addManualBtn = document.querySelector<HTMLButtonElement>('#addManualBtn')!;
  const addUriBtn = document.querySelector<HTMLButtonElement>('#addUriBtn')!;
  const scanQrBtn = document.querySelector<HTMLButtonElement>('#scanQrBtn')!;
  const quickAddBtn = document.querySelector<HTMLButtonElement>('#quickAddBtn')!;

  const manualDialog = document.querySelector<HTMLDialogElement>('#manualDialog')!;
  const uriDialog = document.querySelector<HTMLDialogElement>('#uriDialog')!;
  const qrDialog = document.querySelector<HTMLDialogElement>('#qrDialog')!;
  const quickDialog = document.querySelector<HTMLDialogElement>('#quickDialog')!;

  addManualBtn.addEventListener('click', () => manualDialog.showModal());
  addUriBtn.addEventListener('click', () => uriDialog.showModal());
  scanQrBtn.addEventListener('click', () => qrDialog.showModal());
  quickAddBtn.addEventListener('click', () => quickDialog.showModal());

  // Manual form
  const manualForm = document.querySelector<HTMLFormElement>('#manualForm')!;
  manualForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    if (!sessionKey) await ensureSessionKey();

    const label = (document.querySelector<HTMLInputElement>('#mLabel')!).value.trim();
    const issuer = (document.querySelector<HTMLInputElement>('#mIssuer')!).value.trim() || undefined;
    const secretBase32 = (document.querySelector<HTMLInputElement>('#mSecret')!).value.trim();
    const algStr = (document.querySelector<HTMLSelectElement>('#mAlg')!).value;
    const digitsNum = parseInt((document.querySelector<HTMLSelectElement>('#mDigits')!).value, 10);
    const periodNum = parseInt((document.querySelector<HTMLInputElement>('#mPeriod')!).value, 10);

    try {
      const entry = fromManualInput(label, issuer, secretBase32, algStr, digitsNum, periodNum);
      await storeEntry(entry);
      manualForm.reset();
      manualDialog.close();
      await refreshList();
      showToast(`Added ${issuer ? issuer + ' (' + label + ')' : label}`, 'success');
      threeBg?.triggerPulse(0x10b981);
    } catch (err: any) {
      showToast(err?.message || 'Failed to add entry', 'error');
    }
  });
  manualForm.addEventListener('reset', () => manualDialog.close());

  // URI form
  const uriForm = document.querySelector<HTMLFormElement>('#uriForm')!;
  uriForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    if (!sessionKey) await ensureSessionKey();

    const uri = (document.querySelector<HTMLInputElement>('#uUri')!).value.trim();
    try {
      const parsed = parseOtpauthUri(uri);
      await storeEntry(parsed);
      uriForm.reset();
      uriDialog.close();
      await refreshList();
      showToast(`Imported ${parsed.issuer || parsed.label}`, 'success');
      threeBg?.triggerPulse(0x06b6d4);
    } catch (err: any) {
      showToast(err?.message || 'Invalid otpauth URI', 'error');
    }
  });
  uriForm.addEventListener('reset', () => uriDialog.close());

  // Quick Key form
  const quickForm = document.querySelector<HTMLFormElement>('#quickForm')!;
  quickForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const secretInput = document.querySelector<HTMLInputElement>('#qSecret')!;
    const secretB32 = secretInput.value.trim();
    if (!secretB32) return;
    try {
      const entry = fromManualInput('Session · ' + secretB32.slice(0, 4) + '..', 'QuickKey', secretB32, undefined, undefined, undefined);
      const tempEntry: DecryptedEntry = {
        id: `temp-${++tempIdCounter}`,
        label: 'Session · ' + secretB32.slice(0, 4) + '..',
        issuer: 'QuickKey',
        alg: entry.algorithm,
        digits: entry.digits,
        period: entry.period,
        secretBytes: entry.secretBytes,
      };
      tempCards.push(tempEntry);
      activeCardId = tempEntry.id;
      quickForm.reset();
      quickDialog.close();
      await refreshList();
      showToast('Quick session token active (in-memory only)', 'info');
      threeBg?.triggerPulse(0x8b5cf6);
    } catch (err: any) {
      showToast(err?.message || 'Invalid Base32 secret', 'error');
    }
  });
  quickForm.addEventListener('reset', () => quickDialog.close());

  // QR Scanner logic
  wireQrScanner();

  // Search
  const searchInput = document.querySelector<HTMLInputElement>('#searchInput')!;
  const clearSearchBtn = document.querySelector<HTMLButtonElement>('#clearSearchBtn')!;

  searchInput.addEventListener('input', () => filterList(searchInput.value.trim()));
  clearSearchBtn.addEventListener('click', () => {
    searchInput.value = '';
    filterList('');
  });
}

function wireQrScanner() {
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

  const stopCamera = () => {
    if (qrTimer) {
      clearInterval(qrTimer);
      qrTimer = null;
    }
    if (stream) {
      stream.getTracks().forEach((t) => t.stop());
      stream = null;
    }
    video.srcObject = null;
    canvas.hidden = true;
  };

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
            if (!sessionKey) await ensureSessionKey();
            try {
              const parsed = parseOtpauthUri(text);
              qrFound = true;
              await storeEntry(parsed);
              stopCamera();
              qrDialog.close();
              await refreshList();
              showToast(`Imported ${parsed.issuer || parsed.label} via QR`, 'success');
              threeBg?.triggerPulse(0x10b981);
            } catch {
              showToast('QR code is not a valid otpauth URI', 'error');
            }
          }
        } catch {
          // ignore scan frame errors
        }
      }, 400);
    } catch {
      showToast('Camera access denied or unavailable', 'error');
    }
  });

  qrStopBtn.addEventListener('click', stopCamera);
  qrCloseBtn.addEventListener('click', () => {
    stopCamera();
    qrDialog.close();
  });

  // Upload QR Image file fallback
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
            if (!sessionKey) await ensureSessionKey();
            try {
              const parsed = parseOtpauthUri(text);
              await storeEntry(parsed);
              qrDialog.close();
              await refreshList();
              showToast(`Imported ${parsed.issuer || parsed.label} from image`, 'success');
              threeBg?.triggerPulse(0x10b981);
            } catch {
              showToast('QR image is not a valid otpauth URI', 'error');
            }
          } else {
            showToast('No QR code detected in image', 'error');
          }
        } catch {
          showToast('Failed to process image', 'error');
        }
      };
      imgEl.src = reader.result as string;
    };
    reader.readAsDataURL(file);
  });
}

async function addDemoAccount() {
  const demos = [
    { label: 'security@cloudvault.io', issuer: 'CloudVault Zero', secret: 'JBSWY3DPEHPK3PXP' },
    { label: 'admin@matrix-mesh.net', issuer: 'Matrix Node', secret: 'KRSXG5CTMVRXEZLU' },
    { label: 'dev@github.com', issuer: 'GitHub Pro', secret: 'NBSWY3DPEHPK3PXP' },
  ];
  const demo = demos[Math.floor(Math.random() * demos.length)];
  try {
    const entry = fromManualInput(demo.label, demo.issuer, demo.secret, 'SHA-1', 6, 30);
    await storeEntry(entry);
    await refreshList();
    showToast(`Added demo token: ${demo.issuer}`, 'success');
    threeBg?.triggerPulse(0xa855f7);
  } catch (e: any) {
    showToast(e?.message || 'Could not add demo account', 'error');
  }
}

async function ensureSessionKey(): Promise<void> {
  if (sessionKey) return;
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
  activeCardId = rec.id;
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
  const spotlightContainer = document.querySelector<HTMLDivElement>('#spotlightContainer')!;
  const badgeEl = document.querySelector<HTMLSpanElement>('#vaultCountBadge')!;

  const orderRecords = await listSecrets();
  const persistedEntries = orderRecords
    .map((r) => decryptedCache.get(r.id))
    .filter((e): e is DecryptedEntry => !!e);

  const allEntries = [...persistedEntries, ...tempCards];

  // Update Vault Count Badge
  if (badgeEl) {
    badgeEl.textContent = `${allEntries.length} ${allEntries.length === 1 ? 'KEY' : 'KEYS'}`;
  }

  // Handle Active Card Selection
  if (!activeCardId || !allEntries.find((e) => e.id === activeCardId)) {
    activeCardId = allEntries.length > 0 ? allEntries[0].id : null;
  }

  // Render Empty State
  if (allEntries.length === 0) {
    spotlightContainer.innerHTML = '';
    container.innerHTML = `
      <div class="empty-vault-pane">
        <div class="empty-vault-visual">
          <svg width="44" height="44" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
          </svg>
        </div>
        <div>
          <h2 class="empty-vault-title">Encrypted Vault Empty</h2>
          <p class="empty-vault-desc">No 2FA tokens registered. Add an OTP secret, scan a QR code, or create a demo key to get started.</p>
        </div>
        <div class="empty-actions-row">
          <button id="emptyDemoBtn" class="btn-primary-cta">Generate Demo Token</button>
          <button id="emptyAddBtn" class="btn-secondary-cta">Add Manually</button>
          <button id="emptyScanBtn" class="btn-secondary-cta">Scan QR</button>
        </div>
      </div>
    `;

    document.querySelector('#emptyDemoBtn')?.addEventListener('click', addDemoAccount);
    document.querySelector('#emptyAddBtn')?.addEventListener('click', () => {
      document.querySelector<HTMLDialogElement>('#manualDialog')!.showModal();
    });
    document.querySelector('#emptyScanBtn')?.addEventListener('click', () => {
      document.querySelector<HTMLDialogElement>('#qrDialog')!.showModal();
    });
    return;
  }

  // Render Spotlight Card
  const activeEntry = allEntries.find((e) => e.id === activeCardId) || allEntries[0];
  const activeWindow = await generateTOTPWindow({
    secret: activeEntry.secretBytes,
    period: activeEntry.period,
    digits: activeEntry.digits,
    algorithm: activeEntry.alg,
    timestamp: Date.now(),
  });
  spotlightContainer.innerHTML = renderSpotlightCardHtml(activeEntry, activeWindow);
  wireSpotlightEvents();

  // Render Vault Deck Cards
  const cardsHtml = await Promise.all(
    allEntries.map(async (entry) => {
      const windowData = await generateTOTPWindow({
        secret: entry.secretBytes,
        period: entry.period,
        digits: entry.digits,
        algorithm: entry.alg,
        timestamp: Date.now(),
      });
      const isTemp = entry.id.startsWith('temp-');
      const isActive = entry.id === activeCardId;
      return renderDeckCardHtml(entry, windowData, isTemp, isActive);
    })
  );

  container.innerHTML = cardsHtml.join('');
  wireDeckCardActions();
}

// Render Spotlight Card HTML
function renderSpotlightCardHtml(
  e: DecryptedEntry,
  w: { prev: string; current: string; next: string; remainingSeconds: number; period: number }
): string {
  const pct = (w.period - w.remainingSeconds - 1) / w.period;
  const circumference = 2 * Math.PI * 30;
  const dashOffset = circumference * (1 - pct);
  const initial = (e.issuer || e.label || '?')[0].toUpperCase();
  const avatarBg = avatarColor(e.issuer || e.label);
  const formattedCode = formatCodeGroupings(w.current);
  const isTemp = e.id.startsWith('temp-');

  const warningClass = w.remainingSeconds <= 4 ? 'danger' : w.remainingSeconds <= 8 ? 'warning' : '';

  return `
    <div class="spotlight-card" id="spotlightCard" data-id="${e.id}">
      <div class="spotlight-header">
        <div class="spotlight-meta-info">
          <div class="spotlight-avatar" style="background:${avatarBg}">${initial}</div>
          <div class="spotlight-title-group">
            <div class="spotlight-title">${escapeHtml(e.issuer || e.label)}</div>
            <div class="spotlight-subtitle">${escapeHtml(e.label)} · ${e.alg} · ${e.digits}D</div>
          </div>
        </div>
        <span class="spotlight-status-tag">${isTemp ? 'SESSION' : 'SECURE'}</span>
      </div>

      <!-- Giant Monospace Digits Click to Copy -->
      <div class="spotlight-code-area" id="spotlightCodeArea" title="Click to copy code">
        <div class="spotlight-code-digits" id="spotlightDigits">${formattedCode}</div>
        <div class="click-to-copy-hint">
          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>
          </svg>
          <span>CLICK CODE TO COPY</span>
        </div>
      </div>

      <!-- Timeline Steps & Radial Chronometer -->
      <div class="spotlight-timeline-row">
        <div class="step-box">
          <span class="step-label">Previous</span>
          <span class="step-code" id="spotlightPrev">${formatCodeGroupings(w.prev)}</span>
        </div>

        <div class="spotlight-chronometer ${warningClass}" id="spotlightChronometer">
          <svg width="72" height="72" viewBox="0 0 72 72">
            <circle class="dial-bg" cx="36" cy="36" r="30" stroke-width="4.5"/>
            <circle class="dial-progress" cx="36" cy="36" r="30" stroke-width="4.5"
              stroke-dasharray="${circumference}"
              stroke-dashoffset="${dashOffset}"
              data-circumference="${circumference}"/>
          </svg>
          <span class="dial-text" id="spotlightRemaining">${w.remainingSeconds + 1}s</span>
        </div>

        <div class="step-box" style="text-align:right">
          <span class="step-label">Next</span>
          <span class="step-code" id="spotlightNext">${formatCodeGroupings(w.next)}</span>
        </div>
      </div>

      <!-- Action Button -->
      <button class="spotlight-copy-btn" id="spotlightCopyBtn">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
          <rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>
        </svg>
        <span>COPY CURRENT CODE</span>
      </button>
    </div>
  `;
}

// Render Deck Card HTML
function renderDeckCardHtml(
  e: DecryptedEntry,
  w: { prev: string; current: string; next: string; remainingSeconds: number; period: number },
  isTemp: boolean,
  isActive: boolean
): string {
  const pct = (w.period - w.remainingSeconds - 1) / w.period;
  const circumference = 2 * Math.PI * 13;
  const dashOffset = circumference * (1 - pct);
  const initial = (e.issuer || e.label || '?')[0].toUpperCase();
  const avatarBg = avatarColor(e.issuer || e.label);
  const formattedCode = formatCodeGroupings(w.current);

  return `
    <div class="token-card ${isActive ? 'active-spotlight' : ''} ${isTemp ? 'temp-card' : ''}" data-id="${e.id}">
      <div class="card-top-row">
        <div class="card-identity">
          <div class="card-avatar" style="background:${avatarBg}">${initial}</div>
          <div class="card-names">
            <div class="card-label-text">${escapeHtml(e.issuer ? e.issuer : e.label)}</div>
            <div class="card-meta-text">${escapeHtml(e.issuer ? e.label : e.alg + ' · ' + e.period + 's')}</div>
          </div>
        </div>
        ${isTemp ? `<span style="font-size:9.5px;color:var(--accent-cyan);font-weight:700">TEMP</span>` : ''}
      </div>

      <div class="card-code-row">
        <span class="card-code-digits">${formattedCode}</span>
        <div class="card-mini-timer">
          <svg width="34" height="34" viewBox="0 0 34 34">
            <circle class="mini-dial-bg" cx="17" cy="17" r="13" stroke-width="2.5"/>
            <circle class="mini-dial-progress" cx="17" cy="17" r="13" stroke-width="2.5"
              stroke-dasharray="${circumference}"
              stroke-dashoffset="${dashOffset}"
              data-circumference="${circumference}"/>
          </svg>
          <span class="mini-dial-text">${w.remainingSeconds + 1}</span>
        </div>
      </div>

      <div class="card-footer-actions">
        <button class="card-copy-btn" title="Copy Code">
          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
          <span>Copy</span>
        </button>

        <div class="card-tool-buttons">
          ${
            !isTemp
              ? `
            <button class="btn-icon up-btn" title="Move Up" aria-label="Move Up">
              <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round"><polyline points="18 15 12 9 6 15"/></svg>
            </button>
            <button class="btn-icon down-btn" title="Move Down" aria-label="Move Down">
              <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round"><polyline points="6 9 12 15 18 9"/></svg>
            </button>
            <button class="btn-icon rename-btn" title="Rename" aria-label="Rename">
              <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round"><path d="M17 3a2.83 2.83 0 1 1 4 4L7.5 20.5 2 22l1.5-5.5L17 3z"/></svg>
            </button>
            <button class="btn-icon danger delete-btn" title="Delete" aria-label="Delete">
              <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg>
            </button>
          `
              : `
            <button class="btn-icon danger remove-temp-btn" title="Remove Temporary Key" aria-label="Remove">
              <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
            </button>
          `
          }
        </div>
      </div>
    </div>
  `;
}

// Wire Spotlight Card Mouse 3D Tilt & Events
function wireSpotlightEvents() {
  const card = document.getElementById('spotlightCard');
  const copyBtn = document.getElementById('spotlightCopyBtn');
  const codeArea = document.getElementById('spotlightCodeArea');
  const digitsEl = document.getElementById('spotlightDigits');

  if (!card) return;

  // 3D Tilt Parallax on hover
  card.addEventListener('mousemove', (e) => {
    const rect = card.getBoundingClientRect();
    const x = e.clientX - rect.left;
    const y = e.clientY - rect.top;
    const centerX = rect.width / 2;
    const centerY = rect.height / 2;
    const rotateX = ((y - centerY) / centerY) * -7;
    const rotateY = ((x - centerX) / centerX) * 7;
    card.style.transform = `perspective(1000px) rotateX(${rotateX}deg) rotateY(${rotateY}deg) scale3d(1.02, 1.02, 1.02)`;
  });

  card.addEventListener('mouseleave', () => {
    card.style.transform = 'perspective(1000px) rotateX(0deg) rotateY(0deg) scale3d(1, 1, 1)';
  });

  // Copy Action handler
  const triggerCopy = async () => {
    const rawDigits = digitsEl?.textContent?.replace(/\s/g, '') || '';
    if (!rawDigits) return;
    try {
      await navigator.clipboard.writeText(rawDigits);
      showToast(`Copied code ${rawDigits} to clipboard!`, 'success');
      threeBg?.triggerPulse(0x8b5cf6);
    } catch {
      showToast('Clipboard permission denied', 'error');
    }
  };

  copyBtn?.addEventListener('click', triggerCopy);
  codeArea?.addEventListener('click', triggerCopy);
}

// Wire Vault Deck Card Actions
function wireDeckCardActions() {
  const container = document.querySelector<HTMLDivElement>('#listContainer')!;

  // Card Selection (Select for Spotlight)
  container.querySelectorAll<HTMLDivElement>('.token-card').forEach((card) => {
    card.addEventListener('click', async (e) => {
      const target = e.target as HTMLElement;
      if (target.closest('button')) return; // Ignore if clicked a tool button
      const id = card.dataset.id!;
      if (activeCardId !== id) {
        activeCardId = id;
        await refreshList();
      }
    });
  });

  // Copy button
  container.querySelectorAll<HTMLButtonElement>('.card-copy-btn').forEach((btn) => {
    btn.addEventListener('click', async (e) => {
      e.stopPropagation();
      const card = btn.closest('.token-card') as HTMLDivElement;
      const digits = card.querySelector('.card-code-digits')?.textContent?.replace(/\s/g, '') || '';
      try {
        await navigator.clipboard.writeText(digits);
        showToast(`Copied code ${digits} to clipboard!`, 'success');
        threeBg?.triggerPulse(0x8b5cf6);
      } catch {
        showToast('Clipboard permission denied', 'error');
      }
    });
  });

  // Reorder Up
  container.querySelectorAll<HTMLButtonElement>('.up-btn').forEach((btn) => {
    btn.addEventListener('click', async (e) => {
      e.stopPropagation();
      const card = btn.closest('.token-card') as HTMLDivElement;
      const id = card.dataset.id!;
      await moveSecret(id, 'up');
    });
  });

  // Reorder Down
  container.querySelectorAll<HTMLButtonElement>('.down-btn').forEach((btn) => {
    btn.addEventListener('click', async (e) => {
      e.stopPropagation();
      const card = btn.closest('.token-card') as HTMLDivElement;
      const id = card.dataset.id!;
      await moveSecret(id, 'down');
    });
  });

  // Rename
  container.querySelectorAll<HTMLButtonElement>('.rename-btn').forEach((btn) => {
    btn.addEventListener('click', async (e) => {
      e.stopPropagation();
      if (!sessionKey) return;
      const card = btn.closest('.token-card') as HTMLDivElement;
      const id = card.dataset.id!;
      const cur = decryptedCache.get(id)!;
      const nextLabel = prompt('Enter new account label:', cur.label)?.trim();
      if (!nextLabel) return;
      await updateSecret({ id, label: nextLabel });
      cur.label = nextLabel;
      await refreshList();
      showToast('Token label updated', 'success');
    });
  });

  // Delete
  container.querySelectorAll<HTMLButtonElement>('.delete-btn').forEach((btn) => {
    btn.addEventListener('click', async (e) => {
      e.stopPropagation();
      const card = btn.closest('.token-card') as HTMLDivElement;
      const id = card.dataset.id!;
      const cur = decryptedCache.get(id);
      const name = cur?.issuer || cur?.label || 'this token';
      if (!confirm(`Delete ${name} from your encrypted vault? This cannot be undone.`)) return;
      await deleteSecret(id);
      if (cur) cur.secretBytes.fill(0);
      decryptedCache.delete(id);
      if (activeCardId === id) activeCardId = null;
      await refreshList();
      showToast(`Deleted ${name}`, 'info');
    });
  });

  // Remove Temporary Key
  container.querySelectorAll<HTMLButtonElement>('.remove-temp-btn').forEach((btn) => {
    btn.addEventListener('click', async (e) => {
      e.stopPropagation();
      const card = btn.closest('.token-card') as HTMLDivElement;
      const id = card.dataset.id!;
      tempCards = tempCards.filter((e) => e.id !== id);
      const cur = decryptedCache.get(id);
      if (cur) cur.secretBytes.fill(0);
      decryptedCache.delete(id);
      if (activeCardId === id) activeCardId = null;
      await refreshList();
      showToast('Temporary key removed', 'info');
    });
  });
}

// Move secret up/down
async function moveSecret(id: string, dir: 'up' | 'down') {
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
}

// Update Codes & Timers Every Second
async function updateCodes() {
  const now = Date.now();

  // Update HUD Clock
  const clockEl = document.getElementById('hudTimeDisplay');
  if (clockEl) {
    const d = new Date(now);
    const h = String(d.getUTCHours()).padStart(2, '0');
    const m = String(d.getUTCMinutes()).padStart(2, '0');
    const s = String(d.getUTCSeconds()).padStart(2, '0');
    clockEl.textContent = `${h}:${m}:${s} UTC`;
  }

  const allEntries = [...decryptedCache.values(), ...tempCards];
  if (allEntries.length === 0) return;

  // Check if step rolled over
  const firstEntry = allEntries[0];
  const curStep = Math.floor(now / 1000 / firstEntry.period);
  if (lastStep !== -1 && curStep !== lastStep) {
    threeBg?.triggerPulse(0x06b6d4);
  }
  lastStep = curStep;

  // Update Spotlight Card
  const activeEntry = allEntries.find((e) => e.id === activeCardId) || allEntries[0];
  if (activeEntry) {
    const w = await generateTOTPWindow({
      secret: activeEntry.secretBytes,
      period: activeEntry.period,
      digits: activeEntry.digits,
      algorithm: activeEntry.alg,
      timestamp: now,
    });

    const digitsEl = document.getElementById('spotlightDigits');
    const prevEl = document.getElementById('spotlightPrev');
    const nextEl = document.getElementById('spotlightNext');
    const remainingEl = document.getElementById('spotlightRemaining');
    const chronometerEl = document.getElementById('spotlightChronometer');
    const dialProgress = chronometerEl?.querySelector<SVGCircleElement>('.dial-progress');

    if (digitsEl) digitsEl.textContent = formatCodeGroupings(w.current);
    if (prevEl) prevEl.textContent = formatCodeGroupings(w.prev);
    if (nextEl) nextEl.textContent = formatCodeGroupings(w.next);
    if (remainingEl) remainingEl.textContent = `${w.remainingSeconds + 1}s`;

    if (chronometerEl) {
      chronometerEl.classList.remove('warning', 'danger');
      if (w.remainingSeconds <= 4) chronometerEl.classList.add('danger');
      else if (w.remainingSeconds <= 8) chronometerEl.classList.add('warning');
    }

    if (dialProgress) {
      const circumference = parseFloat(dialProgress.getAttribute('data-circumference') || '188.5');
      const pct = (w.period - w.remainingSeconds - 1) / w.period;
      dialProgress.style.strokeDashoffset = `${circumference * (1 - pct)}`;
    }
  }

  // Update Deck Cards
  for (const entry of allEntries) {
    const cardEl = document.querySelector<HTMLDivElement>(`.token-card[data-id="${entry.id}"]`);
    if (!cardEl) continue;

    const w = await generateTOTPWindow({
      secret: entry.secretBytes,
      period: entry.period,
      digits: entry.digits,
      algorithm: entry.alg,
      timestamp: now,
    });

    const codeEl = cardEl.querySelector('.card-code-digits');
    const timerText = cardEl.querySelector('.mini-dial-text');
    const timerProgress = cardEl.querySelector<SVGCircleElement>('.mini-dial-progress');

    if (codeEl) codeEl.textContent = formatCodeGroupings(w.current);
    if (timerText) timerText.textContent = `${w.remainingSeconds + 1}`;
    if (timerProgress) {
      const circumference = parseFloat(timerProgress.getAttribute('data-circumference') || '81.68');
      const pct = (w.period - w.remainingSeconds - 1) / w.period;
      timerProgress.style.strokeDashoffset = `${circumference * (1 - pct)}`;
    }
  }
}

// Avatar Color Hash
function avatarColor(label: string): string {
  const palette = ['#8b5cf6', '#06b6d4', '#ec4899', '#10b981', '#f59e0b', '#3b82f6', '#f43f5e', '#6366f1'];
  let h = 0;
  for (let i = 0; i < label.length; i++) h = label.charCodeAt(i) + ((h << 5) - h);
  return palette[Math.abs(h) % palette.length];
}

// Filter List
function filterList(query: string) {
  const cards = document.querySelectorAll<HTMLDivElement>('.token-card');
  const q = query.toLowerCase();
  cards.forEach((card) => {
    const label = card.querySelector('.card-label-text')?.textContent?.toLowerCase() || '';
    const meta = card.querySelector('.card-meta-text')?.textContent?.toLowerCase() || '';
    const match = label.includes(q) || meta.includes(q);
    card.style.display = match ? '' : 'none';
  });
}

function announce(msg: string) {
  const el = document.querySelector<HTMLDivElement>('#ariaAnnounce');
  if (el) el.textContent = msg;
}

function escapeHtml(s: string): string {
  return s.replace(/[&<>"]/g, (c) => ({ '&': '&', '<': '<', '>': '>', '"': '"' }[c] as string));
}

// Clear all local app data
async function clearAppData(): Promise<void> {
  try {
    stopTicker();
    decryptedCache.forEach((e) => e.secretBytes.fill(0));
    decryptedCache.clear();
    sessionKey = null;

    try { await clearAll(); } catch {}
    try {
      await new Promise<void>((resolve) => {
        const req = indexedDB.deleteDatabase(DB_NAME);
        req.onsuccess = () => resolve();
        req.onerror = () => resolve();
        req.onblocked = () => resolve();
      });
    } catch {}

    try { localStorage.clear(); } catch {}
    try { sessionStorage.clear(); } catch {}

    try {
      if ('caches' in window) {
        const keys = await caches.keys();
        await Promise.all(keys.map((k) => caches.delete(k)));
      }
    } catch {}

    try {
      const regs = await navigator.serviceWorker.getRegistrations();
      await Promise.all(regs.map((r) => r.unregister()));
    } catch {}

    showToast('Vault data purged successfully', 'info');
  } finally {
    location.reload();
  }
}
