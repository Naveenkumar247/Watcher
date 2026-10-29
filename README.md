# AI Firewall — Isolated Browser & Packet Monitoring Lab

A local learning/demo project combining an isolated Playwright browser container, TShark packet-metadata capture, Socket.IO live updates, and an optional VirusTotal URL-report lookup.

## What it does

- Opens HTTP/HTTPS URLs in a separate Docker container using Playwright.
- Displays browser screenshots in the dashboard (the preview is screenshot-based, not a fully interactive remote desktop).
- Captures packet metadata from the browser worker container with TShark: timestamp, source/destination IPs and ports, protocol, and frame size.
- Streams packet events to the dashboard using Socket.IO.
- Offers an optional VirusTotal lookup for an existing URL report. It does **not** automatically submit URLs for scanning.
- Blocks common private/reserved IP ranges and local hostnames in URL validation and re-validates browser requests/redirects.

## Requirements

- Docker Desktop or Docker Engine with the Compose plugin.
- Internet access to pull the images and to load public test sites.

## Quick start

1. Copy `.env.example` to `.env`.
2. Change `INTERNAL_API_TOKEN` to a long random value. Keep `.env` private.
3. Optionally add your VirusTotal API key to `VIRUSTOTAL_API_KEY` in `.env`.
4. From this directory, run:

   ```bash
   docker compose up --build -d
   ```

5. Open `http://localhost:3000`.
6. Enter a public URL, e.g. `https://example.com`, then choose **Open in Sandbox**.
7. Observe packet metadata as it arrives. Use **Check VirusTotal** to look up an existing report.

Stop the project with:

```bash
docker compose down
```

View logs:

```bash
docker compose logs -f app browser-worker
```

## Security notes — read before use

- This is a **local educational prototype**, not a production malware-analysis sandbox. A Docker container is not equivalent to a dedicated VM or hardened remote-browser service.
- The dashboard is bound to `127.0.0.1:3000`; do not expose it publicly without authentication, authorization, rate limiting, stronger isolation, and security review.
- The browser worker has `NET_RAW` and `NET_ADMIN` capabilities to support packet capture. It is not privileged and its port is not published to the host, but those capabilities still increase risk.
- URL checks block common private/reserved ranges, but application-level DNS validation is not a complete defense against DNS rebinding or every network-routing edge case. For untrusted URLs, use a dedicated VM and enforce egress-deny rules at the host/hypervisor/network layer. Do not use this prototype to visit known malware or hostile sites.
- Only inspect systems you own or are authorized to test.
- TShark captures packet **metadata only** with this configuration; it does not save packet payloads. HTTPS content remains encrypted in normal circumstances.
- “OBSERVED” means traffic was captured, not that the firewall allowed or blocked it. Actual packet blocking is not implemented in this starter project. Heuristic alerts are examples, not malware verdicts.
- VirusTotal lookup requires an API key and is subject to your account's permissions and quotas. The current endpoint only looks up an existing report; a missing report is not submitted automatically.
- A browser preview is refreshed from screenshots. Back/Forward/Reload are supported; direct mouse/keyboard interaction with the rendered page is not implemented.

## Troubleshooting

- If the page does not load, run `docker compose logs -f browser-worker`.
- If packet rows remain empty, check TShark startup/errors in the browser-worker logs and verify Docker supports `NET_RAW` / `NET_ADMIN` capabilities.
- If the browser worker cannot start, verify the image tag can be pulled and the machine has enough memory. Playwright/Chromium benefits from the configured 1 GB shared-memory allocation.
- On Linux, some Docker setups may restrict packet capture even with the added capabilities. Do not solve this by making the whole container privileged without understanding the security impact.
- If VirusTotal shows “not configured,” add the key to `.env`, then restart with `docker compose up -d --build`.

## Project structure

```text
ai-firewall-browser-lab/
├── browser-worker/
│   ├── Dockerfile
│   ├── package.json
│   └── index.js
├── public/
│   ├── index.html
│   ├── styles.css
│   └── app.js
├── .env.example
├── .gitignore
├── Dockerfile
├── docker-compose.yml
├── package.json
├── server.js
└── README.md
```
