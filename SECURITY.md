# Mediaforge security model

Mediaforge is a static site. All media processing happens **in the visitor's browser**. There is no backend, no upload endpoint, no database and no accounts.

## Threat model in one paragraph
The things worth protecting are the user's files and the integrity of the page. Files never leave the device: the processing engine (FFmpeg compiled to WebAssembly) runs in a Web Worker in the same tab, and the CSP's `connect-src 'self' blob: data:` means page scripts *cannot* send data to any other origin, even if a bug or a malicious file tried to. Page integrity comes from self-hosting every script, a strict CSP with no `unsafe-inline` or `unsafe-eval`, no inline event handlers, and `textContent`-only rendering of anything user-controlled.

## Controls

| Control | Where | Notes |
|---|---|---|
| Content-Security-Policy | `<meta>` in every page + `_headers`, `netlify.toml`, `vercel.json` | `default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; worker-src 'self' blob:; connect-src 'self' blob: data:; img-src 'self' blob: data:; media-src 'self' blob: mediastream:; style-src 'self'; font-src 'self'; object-src 'none'; base-uri 'none'; form-action 'none'; manifest-src 'self'; frame-src 'none'`. The header version also adds `frame-ancestors 'none'; upgrade-insecure-requests`, which can't go in a meta tag and would break `http://localhost`. `'wasm-unsafe-eval'` is the narrow permission WebAssembly compilation needs. The FFmpeg core uses no JS `eval`/`new Function`. |
| No inline script/style | all pages | Theme bootstrap is `/js/theme.js`. Styles are only in `/css/style.css`; dynamic sizes use CSSOM (`el.style.setProperty`), which CSP allows. JSON-LD blocks are data, not executed. |
| No inline event handlers | all pages | Every listener is attached with `addEventListener` in `/js/*.js`. Tests grep the built HTML for `on*=` attributes. |
| Self-hosted dependencies | `/vendor/` | `@ffmpeg/ffmpeg` 0.12.15 (MIT), `@ffmpeg/core` 0.12.10 single-threaded (FFmpeg LGPL/GPL), JSZip (MIT). Zero third-party requests, so no SRI is needed. If you ever move to a CDN, add `integrity="sha384-…"` + `crossorigin="anonymous"`. |
| Frame protection | headers | `frame-ancestors 'none'` + `X-Frame-Options: DENY`. |
| MIME sniffing | headers | `X-Content-Type-Options: nosniff`; `.wasm` is served as `application/wasm`. |
| Referrer | headers + meta | `strict-origin-when-cross-origin`. |
| Permissions-Policy | headers | `camera=(self), microphone=(self), display-capture=(self)`. Everything else (geolocation, payment, USB, sensors, topics, …) is disabled. |
| HSTS | headers | `max-age=63072000; includeSubDomains; preload`. Only submit to the preload list once every subdomain serves HTTPS. |
| Isolation | headers | `Cross-Origin-Opener-Policy: same-origin`, `Cross-Origin-Embedder-Policy: require-corp`, `Cross-Origin-Resource-Policy: same-origin`. The single-threaded core does **not** need cross-origin isolation, so these are defense-in-depth. See "Turning on ads", because COEP blocks AdSense. |
| Engine in a Web Worker | `/vendor/ffmpeg/worker.js` | FFmpeg runs off the main thread in its own worker. Cancel = `worker.terminate()`. |
| Input validation | `js/media.js → sniff()` | Files are identified by **magic bytes**, not extension or MIME: MP4/MOV/3GP/M4A (`ftyp`), WebM/MKV (EBML), AVI/WAV (RIFF), Ogg, FLAC, MP3 (ID3/frame sync), AAC ADTS, FLV, MPEG-TS/PS, ASF, AMR, AIFF, CAF, GIF. Anything else is rejected with a clear message. |
| Size limits | `js/media.js` | 2 GB per file (1 GB when `navigator.deviceMemory ≤ 4`), max 100 files per batch, empty files rejected. The limit exists because browsers cap WebAssembly memory. Large inputs are **mounted** (WORKERFS) instead of copied into wasm memory. |
| Output names | `safeBase()` | Path components, control characters, bidi overrides (`U+202A–202E`, `U+2066–2069`) and reserved characters `<>:"/\|?*` are stripped, and length is capped. |
| DOM safety | `js/app.js → h()` | User-derived strings (file names, FFmpeg log excerpts) are only ever set via `textContent`/attributes. `innerHTML` is used only for constant SVG icon strings from `tools-meta.js`. |
| Object URLs | `js/app.js` | Every `blob:` URL is tracked and revoked when a file or result is removed, when the tool changes, after thumbnails and the wasm load, and on `pagehide`. |
| Storage | `localStorage` only | Theme, favorites, recent settings per tool, total bytes processed locally, ad-consent choice. **No cookies** are set by Mediaforge. |
| Tracking | none | No analytics, no fingerprinting, no third-party requests while ads are disabled. |

## Turning on ads (AdSense)
1. Edit **`src/js/ads-config.js`**, the single config spot: set `enabled: true`, your `client` (`ca-pub-…`) and the four slot IDs. Rebuild with `node dev/build.mjs`.
2. **Widen the CSP** in `dev/build.mjs` (`CSP_META`, which feeds the meta tag and all three header files). Add:
   - `script-src https://pagead2.googlesyndication.com https://*.adtrafficquality.google https://www.googletagservices.com https://partner.googleadservices.com`
   - `frame-src https://googleads.g.doubleclick.net https://tpc.googlesyndication.com https://*.googlesyndication.com https://www.google.com`
   - `img-src https://*.googlesyndication.com https://*.doubleclick.net https://*.google.com https://*.gstatic.com`
   - `connect-src https://pagead2.googlesyndication.com https://*.adtrafficquality.google https://*.doubleclick.net`
   - `style-src 'unsafe-inline'`. AdSense injects inline styles; this is the main weakening, and it is unavoidable with AdSense.
3. **Remove `Cross-Origin-Embedder-Policy: require-corp`** (and change CORP to `cross-origin` if needed). Ad iframes and scripts are not served with CORP headers, so COEP would block them. The app keeps working because the single-threaded FFmpeg core does not need `SharedArrayBuffer`.
4. Note that `connect-src` then allows Google ad hosts. Media still never leaves the device (the app never sends file data anywhere), but the "can't exfiltrate even if buggy" guarantee becomes "only to Google ad endpoints".
5. The consent banner (`#consent`, `js/ads.js`) appears automatically once `enabled` is true. "Accept" loads personalized ads; "Non-personalized only" sets `requestNonPersonalizedAds = 1`. The choice is stored in `localStorage['mf-consent']` and can be changed from the footer link. For EEA/UK traffic, Google requires a certified CMP. Enable Google's own "Privacy & messaging" CMP in AdSense, or replace the banner with a TCF v2.2 CMP.
6. Ad slots have fixed reserved sizes (728×90 or 320×50, 300×250, 300×250, responsive with min-height 250) and sit outside all controls, so they cause no layout shift and never cover buttons.

## Reporting a vulnerability
Please email the site operator (add your address here) with steps to reproduce. Do not include personal media files.
