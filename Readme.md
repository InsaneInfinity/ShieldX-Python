# 🛡️ Shield-X: Hybrid Layer 7 WAF (Python & .NET)



---

## 🇺🇸 English Description

### 🚀 Overview
Shield-X is a distributed Layer 7 Web Application Firewall (WAF) ecosystem. It combines the rapid text-processing capabilities of **Python** (FastAPI) with the robust, high-performance infrastructure of **.NET 10**. The system features real-time threat synchronization via **Redis** and a live monitoring dashboard.

### 🏗️ Architecture & Flow
1. **Detection (Python)**: Decodes incoming requests, performs Deep Packet Inspection (DPI), and identifies SQLi/XSS patterns.
2. **Synchronization (Redis)**: Actively publishes bans to a shared Redis Pub/Sub channel.
3. **Defense & Visualization (.NET)**: Intercepts synchronized bans via Middleware and pushes live updates to the UI using **SignalR**.

### ✨ Key Features
* **Multi-Language Synergy**: Best of both worlds (Python's Regex + .NET's Performance).
* **L7 Deep Defense**: Protects against SQL Injection, XSS, and Path Traversal.
* **Real-time SOC Dashboard**: Live threat feed with zero-latency updates.
* **Distributed State**: Centralized ban management using Redis.

---

## 🇵🇱 Opis po Polsku

### 🚀 O projekcie
Shield-X to hybrydowy system bezpieczeństwa klasy WAF (Web Application Firewall) działający w warstwie 7. Projekt łączy elastyczność **Pythona** z wydajnością platformy **.NET 10**, tworząc spójny ekosystem ochrony aplikacji webowych.

### 🏗️ Architektura systemu
1. **Detekcja (Python)**: Analizuje zapytania HTTP, odkodowuje parametry URL i wykrywa próby ataków (SQLi/XSS).
2. **Synchronizacja (Redis)**: Wykorzystuje wzorzec Pub/Sub do natychmiastowego rozsyłania informacji o blokadach.
3. **Obrona i Monitoring (.NET)**: Zarządza ruchem przez Reverse Proxy (YARP) i wyświetla ataki na żywo dzięki **SignalR**.

### ✨ Kluczowe Funkcje
* **Hybrydowa Moc**: Połączenie dwóch potężnych technologii w jednym systemie obronnym.
* **Zaawansowana Analiza L7**: Blokowanie złośliwych payloadów i anomalii w nagłówkach.
* **Dashboard Real-time**: Podgląd ataków "na żywo" bez konieczności odświeżania strony.
* **TLS Hardening**: Wymuszona komunikacja przez bezpieczne protokoły TLS 1.2/1.3.

---

### 🛠️ Tech Stack
* **Languages**: Python 3.12, C# (.NET 10)
* **Messaging**: Redis (Pub/Sub & Key-Value Store)
* **Communication**: SignalR, WebSockets, REST
* **Frontend**: Tailwind CSS, HTML5 (Glassmorphism UI)