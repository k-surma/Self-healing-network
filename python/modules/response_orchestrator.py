import json
import ipaddress
import subprocess
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

import config

PROJECT_ROOT = Path(__file__).resolve().parents[2]
ANSIBLE_DIR = PROJECT_ROOT / 'ansible'
PLAYBOOKS = {
    'Vector 1: Brute-Force / Credential Access': (
        'block_ip.yml',
        'BLOCK_IP',
    ),
    'Vector 2: Reconnaissance / Scanning': (
        'block_ip.yml',
        'BLOCK_IP',
    ),
    'Vector 3: Volumetric DoS': (
        'rate_limit.yml',
        'RATE_LIMIT',
    ),
}

_mitigation_history = {}
COOLDOWN_SECONDS = 60

def _write_audit_event(message):
    audit_msg = f"[{datetime.now().isoformat()}] {message}\n"
    try:
        with open(config.AUDIT_LOG_PATH, 'a', encoding='utf-8') as log_file:
            log_file.write(audit_msg)
    except OSError as error:
        print(f"[!] Audit log write failed: {error}")

def calculate_ttm(alert_timestamp_str):
    if not alert_timestamp_str or alert_timestamp_str == 'Unknown':
        return None
    try:
        alert_time = datetime.strptime(alert_timestamp_str, "%Y-%m-%dT%H:%M:%S.%f%z")
        current_time = datetime.now(timezone.utc)
        ttm = (current_time - alert_time).total_seconds()
        return max(round(ttm, 2), 0.01)
    except ValueError as e:
        print(f"[!] Warning: TTM calculation error: {e}")
        return None

def should_mitigate(incident_data):
    """
    Sprawdza deduplikację. Odciąża główną pętlę ze spamu logów.
    Dostosowuje klucz pamięci podręcznej zależnie od wektora ataku.
    """
    attacker_ip = incident_data.get('attacker_ip')
    vector = incident_data.get('vector')
    
    # INŻYNIERIA: Rozróżnienie logiki Cooldown
    # Dla Wektora 3 blokujemy po wektorze (chronimy ofiarę przed zmasowanym atakiem z losowych IP)
    # Dla Wektorów 1 i 2 blokujemy po IP atakującego
    if vector == 'Vector 3: Volumetric DoS':
        mitigation_key = f"GLOBAL-{vector}"
    else:
        mitigation_key = f"{attacker_ip}-{vector}"
        
    current_timestamp = datetime.now().timestamp()
    
    if mitigation_key in _mitigation_history:
        last_triggered = _mitigation_history[mitigation_key]
        if (current_timestamp - last_triggered) < COOLDOWN_SECONDS:
            return False

    _mitigation_history[mitigation_key] = current_timestamp
    return True

def trigger_response(incident_data):
    attacker_ip = incident_data.get('attacker_ip')
    vector = incident_data.get('vector')

    try:
        attacker_ip = str(ipaddress.IPv4Address(attacker_ip))
    except (ipaddress.AddressValueError, TypeError):
        print(f"[!] Invalid IPv4 address {attacker_ip!r}. Aborting mitigation.")
        return

    playbook_config = PLAYBOOKS.get(vector)
    if playbook_config is None:
        print(f"[!] No mitigation configured for vector {vector!r}.")
        return

    playbook_name, action = playbook_config
    playbook_path = ANSIBLE_DIR / playbook_name
    
    if action == 'BLOCK_IP':
        extra_vars = {'target_ip': attacker_ip}
    else:
        extra_vars = {
            'attacker_ip': attacker_ip,
            'protected_ip': config.PROTECTED_HOST_IP,
            'rate_limit_interface': config.RATE_LIMIT_INTERFACE,
            'rate_limit_bandwidth': config.RATE_LIMIT_BANDWIDTH,
            'rate_limit_burst': config.RATE_LIMIT_BURST,
            'rate_limit_default_bandwidth': config.RATE_LIMIT_DEFAULT_BANDWIDTH,
        }

    destination = ''
    destination_display = ''
    if action == 'RATE_LIMIT':
        destination = f" DESTINATION={config.PROTECTED_HOST_IP}"
        destination_display = f" -> {config.PROTECTED_HOST_IP}"
        
    print(f"[*] Initiating {action} mitigation for {attacker_ip}{destination_display} ({vector}).")
    _write_audit_event(f"ACTION={action} STATUS=STARTED SOURCE={attacker_ip}{destination} VECTOR={vector}")
    
    try:
        # Używamy subprocess.Popen do czytania wyjścia linijka po linijce
        process = subprocess.Popen(
            [
                'ansible-playbook',
                '-i',
                str(ANSIBLE_DIR / 'inventory.ini'),
                str(playbook_path),
                '-e',
                json.dumps(extra_vars),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,  # Przekieruj błędy na standardowe wyjście, żeby filtrować wszystko
            text=True,                 # Czytaj jako tekst, nie bajty
            bufsize=1                  # Buforowanie liniowe
        )

        # Filtruj wyjście na żywo
        for line in iter(process.stdout.readline, ''):
            # Ignoruj puste linie dla lepszej czytelności (opcjonalnie)
            if not line.strip():
                continue
            
            # MAGIA: Odfiltruj linie zawierające słowo [WARNING]
            if "[WARNING]" in line:
                continue
                
            # Wypisz czystą linię do konsoli
            sys.stdout.write(line)
            sys.stdout.flush()

        process.stdout.close()
        return_code = process.wait()

        # Sprawdź, czy Ansible zakończyło się błędem
        if return_code != 0:
            error_msg = f"Ansible playbook returned non-zero exit status {return_code}."
            raise subprocess.CalledProcessError(return_code, process.args, output=None, stderr=error_msg)

    except (subprocess.CalledProcessError, OSError) as error:
        print(f"\n[!] Ansible execution failed for {action}: {error}")
        _write_audit_event(f"ACTION={action} STATUS=FAILED SOURCE={attacker_ip} {destination} VECTOR={vector} ERROR={error}")
        return

    ttm = calculate_ttm(incident_data.get('timestamp'))
    ttm_info = f" [TTM: {ttm}s]" if ttm is not None else ""

    print(f"[+] SUCCESS: {action} mitigation applied to {attacker_ip}{destination_display}.{ttm_info}")
    _write_audit_event(f"ACTION={action} STATUS=SUCCESS SOURCE={attacker_ip}{destination} VECTOR={vector} TTM={ttm}")
