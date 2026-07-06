<div align="center">

# ⏱️ CROTP

**Offline encrypted TOTP authenticator for the web**

[![Deploy to Cloudflare Pages](https://img.shields.io/badge/Deploy-Cloudflare%20Pages-blue?logo=cloudflare)](https://dash.cloudflare.com)
![GitHub Actions](https://img.shields.io/github/actions/workflow/status/creasydude/crotp-web/ci.yml?branch=main&label=CI)
[![GitHub Stars](https://img.shields.io/github/stars/creasydude/crotp-web?style=flat&color=yellow)](https://github.com/creasydude/crotp-web)
[![License](https://img.shields.io/github/license/creasydude/crotp-web)](LICENSE)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.9-blue?logo=typescript)](https://www.typescriptlang.org/)
[![Vite](https://img.shields.io/badge/Vite-7-purple?logo=vite)](https://vite.dev/)
[![PWA](https://img.shields.io/badge/PWA-Offline%20Ready-green?logo=pwa)](https://web.dev/articles/what-are-pwas)

All codes are generated locally in your browser. **No network requests. No backend. No accounts.**

</div>

---

## Features

- **🔒 End-to-end encrypted** — AES-256-GCM encryption, keys stay on your device
- **📱 Fully offline** — works without internet after first load (PWA)
- **⚡ Instant codes** — TOTP generation via WebCrypto, no library overhead
- **📷 QR scanner** — scan or upload QR codes, decoded entirely on-device
- **⚡ Quick Add** — paste a secret, get a code instantly (session-only, no save)
- **🌙 Dark & Light** — premium glass UI, adapts to your system theme
- **📲 Responsive** — works on desktop, tablet, and mobile
- **🔐 No password required** — auto-generated local encryption key

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Framework | Vanilla TypeScript |
| Bundler | Vite 7 |
| Crypto | WebCrypto API (AES-256-GCM) |
| TOTP | Custom RFC 6238 implementation |
| QR | [jsQR](https://github.com/nicbarker/jsQR) (on-device) |
| Storage | IndexedDB |
| Hosting | Cloudflare Pages |

## Quick Start

```bash
# Install dependencies
npm install

# Start dev server (http://localhost:5173)
npm run dev
```

## Build & Deploy

```bash
# Build for production
npm run build

# Deploy to Cloudflare Pages
npm run deploy
```

> **Prerequisites:** [Wrangler CLI](https://developers.cloudflare.com/workers/wrangler/) authenticated with your Cloudflare account.

## Project Structure

```
crotp-web/
├── index.html            # App shell
├── src/
│   ├── main.ts           # UI + app logic
│   ├── style.css         # Premium design system
│   ├── totp.ts           # RFC 6238 TOTP core
│   ├── otpauth.ts        # otpauth:// URI parser
│   ├── crypto.ts         # AES-GCM encrypt/decrypt
│   └── db.ts             # IndexedDB storage
├── public/
│   ├── manifest.webmanifest
│   └── sw.js             # Service worker (offline)
├── wrangler.toml         # Cloudflare Pages config
└── package.json
```

## Security

- Secrets are encrypted with **AES-256-GCM** before being stored in IndexedDB
- Encryption key is auto-generated and never leaves your browser
- **Zero network requests** — enforced by a strict Content Security Policy
- Camera access for QR scanning is processed entirely on-device
- Clear all data anytime with the built-in wipe function

## License

[MIT](LICENSE)

---

<div align="center">
  <sub>Built with care by <a href="https://github.com/creasydude">creasydude</a></sub>
</div>
