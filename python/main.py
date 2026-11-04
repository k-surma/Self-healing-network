import config
from modules.alert_monitor import tail_eve_json
from modules.incident_classifier import classify_incident
from modules.response_orchestrator import trigger_response, should_mitigate

def main():
    print("[*] Starting Middleware - Active Defense Mode")
    alert_generator = tail_eve_json(config.SURICATA_LOG_PATH, config.POLL_INTERVAL)
    
    try:
        for alert_event in alert_generator:
            incident_data = classify_incident(alert_event)
            
            # 1. Ignoruj wbudowany szum informacyjny IDS
            if incident_data['vector'] == "Unknown Vector":
                continue
            
            # 2. Ignoruj po cichu ataki wpadające w okno czasowe (Cooldown)
            if not should_mitigate(incident_data):
                continue
            
            # Wypisujemy informacje TYLKO dla alertów, na które fizycznie zareagujemy
            print("-" * 50)
            print("[*] Actionable alert detected! Processing...")
            print(f"    Target IP: {incident_data['attacker_ip']}")
            print(f"    Signature: {incident_data['signature']}")
            print(f"    Vector:    {incident_data['vector']}")
            
            trigger_response(incident_data)
            print("-" * 50)
            
    except KeyboardInterrupt:
        print("\n[!] Middleware stopped by user.")

if __name__ == '__main__':
    main()
