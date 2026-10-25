import subprocess
from datetime import datetime

def trigger_response(incident_data):
    """
    Zapisuje incydent do logu audytowego i wyzwala playbook Ansible
    w celu mitygacji zagrożenia na routerze VyOS.
    """
    attacker_ip = incident_data.get('attacker_ip')
    vector = incident_data.get('vector')
    
    if attacker_ip == 'Unknown':
        print("[!] Invalid IP. Aborting mitigation.")
        return

    # Zapis trwałego śladu audytowego
    audit_msg = f"[{datetime.now().isoformat()}] BLOCKED IP: {attacker_ip} | VECTOR: {vector}\n"
    with open("/var/log/self-healing-audit.log", "a") as log_file:
        log_file.write(audit_msg)
        
    print(f"[*] Audit log saved. Initiating mitigation for: {attacker_ip}")

    # Wywołanie Ansible
    try:
        print("[*] Executing Ansible Playbook...")
        subprocess.run(["ansible-playbook", "-i", "/home/user/self-healing-network/ansible/inventory.ini", "/home/user/self-healing-network/ansible/block_ip.yml", "-e", f"target_ip={attacker_ip}"], check=True)
        print(f"[+] SUCCESS: Mitigation playbook triggered for {attacker_ip}")
    except subprocess.CalledProcessError as e:
        print(f"[!] ERROR: Ansible execution failed - {e}")
