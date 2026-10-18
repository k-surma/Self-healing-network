def classify_incident(alert_event):
    """
    Analizuje surowe zdarzenie z systemu IDS.
    Ekstrahuje adres IP intruza, znacznik czasu oraz sygnaturę.
    Klasyfikuje incydent do odpowiedniego wektora ataku.
    """
    # Ekstrakcja podstawowych danych o incydencie
    src_ip = alert_event.get('src_ip', 'Unknown')
    timestamp = alert_event.get('timestamp', 'Unknown')
    
    alert_data = alert_event.get('alert', {})
    signature = alert_data.get('signature', 'Unknown Signature')
    
    # Inicjalizacja domyślnego wektora
    attack_vector = "Unknown Vector"
    signature_lower = signature.lower()

    # Logika klasyfikacji oparta na dokumentacji projektowej
    if "ssh" in signature_lower or "brute" in signature_lower or "login" in signature_lower:
        attack_vector = "Vector 1: Brute-Force / Credential Access"
    elif "scan" in signature_lower or "recon" in signature_lower or "nmap" in signature_lower:
        attack_vector = "Vector 2: Reconnaissance / Scanning"
    elif "dos" in signature_lower or "flood" in signature_lower:
        attack_vector = "Vector 3: Volumetric DoS"

    print(f"[+] Incident classified: {attack_vector} | Source: {src_ip}")

    # Zwrócenie ustrukturyzowanych danych do głównej pętli
    return {
        'attacker_ip': src_ip,
        'timestamp': timestamp,
        'signature': signature,
        'vector': attack_vector
    }
