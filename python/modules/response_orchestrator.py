import json
import ipaddress
import subprocess
from datetime import datetime
from pathlib import Path

import config

# Pamięć podręczna dla deduplikacji (cooldown)
_mitigation_history = {}
# Liczba sekund, przez które ignorujemy kolejne alerty dla tego samego IP/Wektora
COOLDOWN_SECONDS = 60

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


def _write_audit_event(message):
    audit_msg = f"[{datetime.now().isoformat()}] {message}\n"
    try:
        with open(config.AUDIT_LOG_PATH, 'a', encoding='utf-8') as log_file:
            log_file.write(audit_msg)
    except OSError as error:
        print(f"[!] Audit log write failed: {error}")


def trigger_response(incident_data):
    """
    Wybiera playbook Ansible odpowiedni dla wektora i zapisuje wynik reakcji.
    """
    attacker_ip = incident_data.get('attacker_ip')
    vector = incident_data.get('vector')

   # INŻYNIERIA: Deduplikacja alertów (Cooldown)
    mitigation_key = f"{attacker_ip}-{vector}"
    current_time = datetime.now().timestamp()
    
    if mitigation_key in _mitigation_history:
        last_triggered = _mitigation_history[mitigation_key]
        if (current_time - last_triggered) < COOLDOWN_SECONDS:
            print(f"[-] Skipped mitigation for {attacker_ip} ({vector}) - inside cooldown window.")
            return

    # aktualizacja czasu ostatniego uruchomienia dla tego klucza
    _mitigation_history[mitigation_key] = current_time

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
    print(
        f"[*] Initiating {action} mitigation for {attacker_ip}"
        f"{destination_display} ({vector})."
    )
    _write_audit_event(
        f"ACTION={action} STATUS=STARTED SOURCE={attacker_ip}"
        f"{destination} VECTOR={vector}"
    )
    try:
        subprocess.run(
            [
                'ansible-playbook',
                '-i',
                str(ANSIBLE_DIR / 'inventory.ini'),
                str(playbook_path),
                '-e',
                json.dumps(extra_vars),
            ],
            check=True,
        )
    except (subprocess.CalledProcessError, OSError) as error:
        print(f"[!] Ansible execution failed for {action}: {error}")
        _write_audit_event(
            f"ACTION={action} STATUS=FAILED SOURCE={attacker_ip} "
            f"{destination} VECTOR={vector} ERROR={error}"
        )
        return

    print(
        f"[+] SUCCESS: {action} mitigation applied to {attacker_ip}"
        f"{destination_display}."
    )
    _write_audit_event(
        f"ACTION={action} STATUS=SUCCESS SOURCE={attacker_ip}"
        f"{destination} VECTOR={vector}"
    )
