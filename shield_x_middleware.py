"""
Shield-X V8 [FINAL HARDENED EDITION]
- Naprawione: URL Decoding (unquote) - łapie zakodowane ataki SQLi/XSS
- Naprawione: Whitelist (pusta, aby skanować localhost)
- Naprawione: Proxy (wyłączone, aby nie muliło bez backendu)
"""

from __future__ import annotations
import asyncio
import hashlib
import ipaddress
import logging
import os
import re
import time
import urllib.parse  # KLUCZOWE: Do odkodowania URL
from collections import deque
from contextlib import asynccontextmanager
from datetime import timedelta
from typing import Callable

import httpx
import redis.asyncio as aioredis
import uvicorn
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

# Konfiguracja Logowania
logger = logging.getLogger("shieldx")
logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")

# --- KONFIGURACJA SYSTEMU ---
REDIS_URL           = "redis://localhost:6379"
BAN_TTL             = timedelta(minutes=60)
BAN_CACHE_TTL       = 30
BOT_SCORE_THRESHOLD = 50  # Próg czułości

# Whitelist pusta, by system nie ignorował Twoich testów z 127.0.0.1
WHITELISTED_IPS: set[str] = set() 
PROXY_ROUTES: dict[str, str] = {}

# Wzorce Ataków (Regex)
ATTACK_PATTERNS: dict[str, str] = {
    "SQL_INJECTION": r"(\b(union\s+select|select\s+.*from|drop\s+table|insert\s+into|update\s+.*set|delete\s+from|exec\s*\(|xp_\w+)\b|--|'|;)",
    "XSS": r"(<script[\s>]|javascript\s*:|on\w+\s*=\s*[\"']|alert\s*\(|document\s*\.\s*cookie|<iframe|<svg\s+on)",
    "PATH_TRAVERSAL": r"(\.\./|\.\.\\|%2e%2e(?:%2f|/|\\)|(?:/|\\)\.\.(?:/|\\))",
    "CMD_INJECTION": r"(?<![a-zA-Z0-9])(;\s*|\|\s*|\$\(|`\s*)(ls|cat|rm|wget|curl|bash|sh|python|nc\b|ncat)\b",
}

# Stan Globalny
redis_client: aioredis.Redis | None = None
_ban_cache: dict[str, float] = {}
event_buffer: deque = deque(maxlen=1000)

# --- HELPERS ---
def _is_ban_cached(key: str) -> bool:
    exp = _ban_cache.get(key)
    if exp is None: return False
    if time.monotonic() > exp:
        _ban_cache.pop(key, None)
        return False
    return True

def _cache_ban(key: str, ttl_seconds: int = 3600) -> None:
    _ban_cache[key] = time.monotonic() + ttl_seconds

async def analyze_request(request: Request) -> tuple[int, str]:
    score = 0
    reasons = []
    
    # 1. Pobieramy surowy URL i go odkodowujemy (%27 -> ', %20 -> spacja)
    raw_payload = f"{request.url.path}?{request.url.query}"
    payload = urllib.parse.unquote(raw_payload)
    
    logger.info(f"🔍 Shield-X Scanning (Decoded): {payload}")
    
    # 2. Analiza Regex
    for name, pattern in ATTACK_PATTERNS.items():
        if re.search(pattern, payload, re.IGNORECASE):
            score = 100 # Natychmiastowe wykrycie
            reasons.append(name)
            break
            
    return score, (",".join(reasons) if reasons else "CLEAN")

async def ban_ip(ip: str, reason: str) -> None:
    _cache_ban(f"ban:{ip}")
    if redis_client:
        try:
            await redis_client.set(f"shieldx:ban:{ip}", reason, ex=3600)
            await redis_client.publish("shieldx:bans:ip", ip)
        except: pass
    logger.warning(f"🚫 [BAN-IP] {ip} zablokowany za: {reason}")

# --- MIDDLEWARE ---
class ShieldXMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        client_ip = request.client.host if request.client else "127.0.0.1"

        # 1. Sprawdź czy IP jest na czarnej liście (Cache/Redis)
        if _is_ban_cached(f"ban:{client_ip}"):
            return JSONResponse(status_code=403, content={"status": "BANNED", "msg": "Twoje IP jest na czarnej liście."})

        if redis_client and await redis_client.exists(f"shieldx:ban:{client_ip}"):
            _cache_ban(f"ban:{client_ip}")
            return JSONResponse(status_code=403, content={"status": "BANNED", "msg": "Twoje IP jest na czarnej liście (Redis)."})

        # 2. Heurystyczna Analiza L7
        score, reason = await analyze_request(request)
        if score >= BOT_SCORE_THRESHOLD:
            logger.error(f"🔥 ATAK WYKRYTY! {reason} z adresu {client_ip}")
            await ban_ip(client_ip, reason)
            return JSONResponse(status_code=403, content={"status": "BLOCKED", "threat": reason})

        # 3. Jeśli czysto - puść dalej
        return await call_next(request)

# --- LIFESPAN ---
@asynccontextmanager
async def lifespan(app: FastAPI):
    global redis_client
    try:
        redis_client = aioredis.from_url(REDIS_URL, decode_responses=True)
        await redis_client.ping()
        logger.info(f"✅ Shield-X: Połączono z Redis ({REDIS_URL})")
    except:
        logger.warning("⚠️ Shield-X: Redis offline. Tryb lokalny (tylko RAM).")
    
    yield
    if redis_client: await redis_client.aclose()

# --- APLIKACJA ---
app = FastAPI(lifespan=lifespan)
app.add_middleware(ShieldXMiddleware)

@app.get("/")
async def root():
    return {"message": "Shield-X API is Online and Secure"}

if __name__ == "__main__":
    # Odpalamy na 127.0.0.1:8000
    uvicorn.run("shield_x_middleware:app", host="127.0.0.1", port=8000, reload=False)