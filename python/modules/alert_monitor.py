import json
import time
import os

def tail_eve_json(log_path, poll_interval):
    """
    Monitoruje plik logów w trybie ciągłym.
    Odfiltrowuje statystyki i zwraca wyłącznie zdarzenia typu 'alert'.
    """
    if not os.path.exists(log_path):
        print(f"[!] Błąd: Plik logów {log_path} nie istnieje.")
        return

    print(f"[*] Uruchomiono nasłuch warstwy detekcji: {log_path}")
    
    with open(log_path, 'r') as file:
        # Przesunięcie wskaźnika na koniec pliku - czytamy tylko nowe zdarzenia
        file.seek(0, 2)
        
        while True:
            line = file.readline()
            if not line:
                # Jeśli nie ma nowej linii, skrypt czeka określony czas
                time.sleep(poll_interval)
                continue
            
            try:
                event = json.loads(line)
                # Izolacja informacji o wpisach 'event_type':'alert'
                if event.get('event_type') == 'alert':
                    yield event
            except json.JSONDecodeError:
                # Ignorowanie zniekształconych linii (odporność na błędy zapisu)
                continue
