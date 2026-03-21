async def dispatch(self, request: Request, call_next):
        client_ip = request.client.host
        
        # 1. Pobieramy SUROWE dane (ścieżka + parametry)
        # To wyciąga dokładnie to, co wpisałeś w przeglądarkę
        path = request.url.path
        raw_query = request.scope.get("query_string", b"").decode("utf-8")
        
        # Łączymy w jeden ciąg do skanowania
        payload_to_scan = f"{path}?{raw_query}"
        
        # Debugging (Tylko dla nas, żebyś widział w konsoli co skanujemy)
        print(f"🔍 Shield-X Scanning: {payload_to_scan}")

        # 2. Sprawdź Global Ban w Redis
        if r and r.sismember("banned_ips", client_ip):
            return JSONResponse(status_code=403, content={"message": "IP BANNED"})

        # 3. Analiza Heurystyczna (Teraz na 100% złapie!)
        attack_detected = None
        for attack_name, pattern in ATTACK_PATTERNS.items():
            if re.search(pattern, payload_to_scan, re.IGNORECASE):
                attack_detected = attack_name
                break

        if attack_detected:
            print(f"🔥 Shield-X: {attack_detected} DETECTED from {client_ip}!")
            # ... (reszta kodu z banowaniem w Redis zostaje bez zmian)
            return JSONResponse(
                status_code=403, 
                content={"status": "Blocked", "threat": attack_detected}
            )

        return await call_next(request)