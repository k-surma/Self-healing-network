import config
from modules.alert_monitor import tail_eve_json
from modules.incident_classifier import classify_incident

def main():
    print("[*] Starting Middleware - Test Mode")
    
    # Inicjalizacja generatora czytającego na żywo plik logów
    alert_generator = tail_eve_json(config.SURICATA_LOG_PATH, config.POLL_INTERVAL)
    
    try:
        # Pętla odbierająca nowe alerty z generatora
        for alert_event in alert_generator:
            print("-" * 50)
            print("[*] Raw alert detected! Processing...")
            
            # Przekazanie surowego alertu do klasyfikatora
            incident_data = classify_incident(alert_event)
            
            # Wyświetlenie ustrukturyzowanych danych na ekranie
            print(f"    Target IP: {incident_data['attacker_ip']}")
            print(f"    Signature: {incident_data['signature']}")
            print(f"    Vector:    {incident_data['vector']}")
            print(f"    Timestamp: {incident_data['timestamp']}")
            print("-" * 50)
            
    except KeyboardInterrupt:
        print("\n[!] Middleware stopped by user.")

if __name__ == '__main__':
    main()


