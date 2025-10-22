# CROTP Web

Minimal, offline-first TOTP authenticator PWA built with Vite + TypeScript. All codes are generated locally in your browser; no backend required.

## Quick start

1) Install dependencies

```
npm install
```

2) Run the dev server (Vite at http://localhost:5173)

```
npm run dev
```

3) Build for production (output to dist/)

```
npm run build
```

4) Preview the build locally (http://localhost:4173)

```
npm run preview
```

## Deploy to Cloudflare Pages

Prerequisites: Cloudflare account and Wrangler CLI authenticated

```
npx wrangler login
```

Build, then deploy

```
npm run build
npm run deploy
```

The deploy script runs: wrangler pages deploy dist --branch main using config from wrangler.toml (pages_build_output_dir = "dist").

## Project layout (high level)

- index.html — app shell
- src/ — TypeScript sources
- public/ — static assets (manifest, service worker)
- dist/ — build output (generated)

## Notes

- This app is fully client-side; secrets stay in your browser.
- Clear your browser data to remove locally stored secrets.