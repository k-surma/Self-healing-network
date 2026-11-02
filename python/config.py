# Ścieżka do strumienia logów generowanych przez Suricatę
SURICATA_LOG_PATH = '/var/log/suricata/eve.json'

# Docelowy plik z dokuemntacją audytową
AUDIT_LOG_PATH = '/var/log/defense-audit.log'

# Interwał czasu na sprawdzanie nowych linii w logach (w sekundach)
POLL_INTERVAL = 0.5

# Ustawienia mitygacji Wektora 3
PROTECTED_HOST_IP = '10.0.1.10'
RATE_LIMIT_INTERFACE = 'eth0'
RATE_LIMIT_BANDWIDTH = '1mbit'
RATE_LIMIT_BURST = '15k'
RATE_LIMIT_DEFAULT_BANDWIDTH = '100%'

