import config
from modules.alert_monitor import tail_eve_json
from modules.incident_classifier import classify_incident
from modules.response_orchestrator import trigger_response

def main():
    print("[*] Starting Middleware - Active Defense Mode")
    alert_generator = tail_eve_json(config.SURICATA_LOG_PATH, config.POLL_INTERVAL)
    
    try:
        for alert_event in alert_generator:
            # Ekstrakcja i klasyfikacja
            incident_data = classify_incident(alert_event)
            
            # INŻYNIERSKA REDUKCJA SZUMU: Odrzucamy wszystko, co nie pasuje do wektorów
            if incident_data['vector'] == "Unknown Vector":
                continue
            
            # Wypisujemy informacje w konsoli TYLKO dla znanych zagrożeń
            print("-" * 50)
            print("[*] Raw alert detected! Processing...")
            print(f"    Target IP: {incident_data['attacker_ip']}")
            print(f"    Signature: {incident_data['signature']}")
            print(f"    Vector:    {incident_data['vector']}")
            
            # Wyzwolenie reakcji obronnej
            trigger_response(incident_data)
            print("-" * 50)
            
    except KeyboardInterrupt:
        print("\n[!] Middleware stopped by user.")

if __name__ == '__main__':
    main()
