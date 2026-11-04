import time
import subprocess
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
import config

PROJECT_ROOT = Path(__file__).resolve().parent.parent
ANSIBLE_DIR = PROJECT_ROOT / 'ansible'

# Konfiguracja Recovery (W sekundach, dla PoC używamy 60 sekund)
# W srodowisku produkcyjnym byloby to np. 900 sekund (15 minut)
IDLE_THRESHOLD_SECONDS = 60
POLL_INTERVAL = 10

def _get_last_success_time():
    """Analizuje plik audytowy i zwraca czas ostatniej udanej mitygacji."""
    if not os.path.exists(config.AUDIT_LOG_PATH):
        return None
        
    last_success_timestamp = None
    try:
        with open(config.AUDIT_LOG_PATH, 'r', encoding='utf-8') as file:
            for line in file:
                # Szukamy logów ze znacznikiem STATUS=SUCCESS
                if "STATUS=SUCCESS" in line and "ACTION=" in line:
                    # Wyciągnięcie daty z nawiasów [2026-11-04T13:55:04...]
                    try:
                        timestamp_str = line.split('[')[1].split(']')[0]
                        # Logi audytowe były zapisane jako datetime.now().isoformat()
                        last_success_timestamp = datetime.fromisoformat(timestamp_str)
                    except (IndexError, ValueError):
                        continue
    except OSError as e:
        print(f"[!] Nie mozna odczytac logu audytowego: {e}")
        
    return last_success_timestamp

def _write_audit_event(message):
    audit_msg = f"[{datetime.now().isoformat()}] {message}\n"
    try:
        with open(config.AUDIT_LOG_PATH, 'a', encoding='utf-8') as log_file:
            log_file.write(audit_msg)
    except OSError as error:
        print(f"[!] Błąd zapisu logu audytowego: {error}")

def execute_rollback():
    """Uruchamia playbook przywracający konfigurację początkową."""
    playbook_path = ANSIBLE_DIR / 'rollback.yml'
    print(f"\n[*] Rozpoczynanie procedury Recovery (Rollback).")
    
    custom_env = os.environ.copy()
    custom_env["ANSIBLE_DEPRECATION_WARNINGS"] = "False"
    
    try:
        process = subprocess.Popen(
            [
                'ansible-playbook',
                '-i',
                str(ANSIBLE_DIR / 'inventory.ini'),
                str(playbook_path),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1
        )

        for line in iter(process.stdout.readline, ''):
            if not line.strip() or "[WARNING]" in line:
                continue
            sys.stdout.write(line)
            sys.stdout.flush()

        process.stdout.close()
        return_code = process.wait()

        if return_code != 0:
            raise subprocess.CalledProcessError(return_code, process.args)

        print(f"[+] Recovery zakonczone sukcesem. Srodowisko wyczyszczone.")
        _write_audit_event("ACTION=RECOVERY STATUS=SUCCESS INFO='System restored to baseline'")
        return True

    except (subprocess.CalledProcessError, OSError) as error:
        print(f"[!] Procedura Recovery zakonczona bledem: {error}")
        _write_audit_event(f"ACTION=RECOVERY STATUS=FAILED ERROR='{error}'")
        return False

def main():
    print("[*] Uruchomiono Recovery Manager (Tryb Auto-Teardown)")
    print(f"[*] Czas oczekiwania po ataku: {IDLE_THRESHOLD_SECONDS} sekund")
    
    while True:
        last_success = _get_last_success_time()
        
        if last_success:
            # Obliczanie różnicy czasu (naive time, bo isoformat zapisywał bez tzinfo)
            idle_time = (datetime.now() - last_success).total_seconds()
            
            if idle_time >= IDLE_THRESHOLD_SECONDS:
                print(f"\n[*] Brak nowych atakow od {int(idle_time)}s. Wyzwalam Recovery.")
                success = execute_rollback()
                
                if success:
                    # Zabezpieczenie: Jeśli rollback się udał, przerywamy pętlę dla PoC 
                    # i kończymy skrypt, żeby nie usunąć logów w nieskończoność.
                    # W środowisku produkcyjnym skrypt działałby dalej.
                    print("[*] Zamykanie menedzera po udanym czyszczeniu (Tryb PoC).")
                    break
                else:
                    print("[!] Oczekuje na reczna interwencje po bledzie.")
                    break
                    
        time.sleep(POLL_INTERVAL)

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Menedzer Recovery zatrzymany przez uzytkownika.")
