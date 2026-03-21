# 🛡️ Shield-X: Hybrid Layer 7 WAF (Python & .NET)

### 🚀 Overview
Shield-X to rozproszony system bezpieczeństwa klasy WAF (Web Application Firewall), który łączy elastyczność **Pythona** z wydajnością **.NET 10**. System wykrywa ataki na warstwie 7 (L7) i synchronizuje blokady w czasie rzeczywistym przez **Redis**.

### 🏗️ Architecture
System składa się z dwóch głównych modułów komunikujących się przez szynę danych Redis:
1.  **ShieldX-Python-WAF**: Lekki middleware (FastAPI) odpowiedzialny za Deep Packet Inspection, unquoting URL i detekcję wzorców SQLi/XSS.
2.  **ShieldX-Dashboard (.NET)**: Centrum dowodzenia oparte na YARP (Reverse Proxy) i SignalR, służące do monitorowania zagrożeń live.



### ✨ Key Features
* **Deep L7 Defense**: Wykrywanie SQL Injection, XSS, Path Traversal i anomalii w nagłówkach.
* **Distributed State**: Współdzielona baza banów w Redis (Pub/Sub synchronization).
* **Real-time Dashboard**: Wizualizacja ataków na żywo bez odświeżania strony (SignalR + TailwindCSS).
* **TLS Hardening**: Wymuszone protokoły TLS 1.2/1.3 dla bezpiecznej komunikacji.

### 🛠️ Tech Stack
* **Backend**: Python 3.x (FastAPI), .NET 10 (C#)
* **Database/Messaging**: Redis (StackExchange.Redis)
* **Frontend**: SignalR, Tailwind CSS
* **Security**: MaxMind Geo-IP, SHA256 Fingerprinting