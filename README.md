<div align="center">

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

| Layer     | Technology                                           |
| --------- | ---------------------------------------------------- |
| Framework | Vanilla TypeScript                                   |
| Bundler   | Vite 7                                               |
| Crypto    | WebCrypto API (AES-256-GCM)                          |
| TOTP      | Custom RFC 6238 implementation                       |
| QR        | [jsQR](https://github.com/nicbarker/jsQR) (on-device) |
| Storage   | IndexedDB                                            |
| Hosting   | Cloudflare Pages                                     |

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
