# Self-Healing Network

Projekt pracy inżynierskiej przedstawia mechanizm automatycznej detekcji i
reakcji na wybrane zagrożenia sieciowe. Środowisko testowe działa w EVE-NG i
łączy Suricatę, middleware napisany w Pythonie, Ansible oraz router VyOS.
Repozytorium zawiera konfigurację początkową laboratorium, przetestowany PoC
reakcji dla Wektorów 1 i 2 oraz implementację reakcji dla Wektora 3. Rzeczywiste
wdrożenie i pomiary należy wykonywać wyłącznie w izolowanym środowisku testowym.

## Topologia laboratorium

| Urządzenie/strefa | Adres | Rola |
|---|---|---|
| Kali / WAN | `192.168.85.100` | Źródło kontrolowanych zdarzeń testowych |
| VyOS / WAN (`eth0`) | `192.168.85.130` | Brama brzegowa |
| VyOS / DMZ (`eth1`) | `10.0.1.1/24` | Brama dla hosta chronionego |
| Ubuntu / DMZ | `10.0.1.10` | Chroniony host |
| VyOS / MGMT (`eth3`) | `10.0.3.1/24` | Brama zarządzająca |
| Serwer SOC / MGMT | `10.0.3.50` | Suricata, logi i middleware |
| VyOS / mirror (`eth4`) | bez adresu IP | Odbiornik kopii ruchu SPAN |

Wartości adresów i nazwy interfejsów odpowiadają dostarczonemu opisowi
laboratorium oraz plikowi początkowej konfiguracji VyOS. Interfejsy `eth0` i
`eth1` mają w tej konfiguracji włączone offloady GRO, GSO, SG i TSO.

## Przepływ detekcji i reakcji

1. Suricata zapisuje zdarzenia w formacie EVE JSON w
   `/var/log/suricata/eve.json`.
2. `python/modules/alert_monitor.py` śledzi nowe wpisy pliku i przekazuje
   middleware tylko zdarzenia `event_type: alert`. Czytanie zaczyna się od
   końca pliku, więc przetwarzane są nowe alerty powstałe po uruchomieniu
   middleware.
3. `python/modules/incident_classifier.py` pobiera `src_ip` i sygnaturę alertu,
   po czym klasyfikuje ją po słowach kluczowych:
   - `ssh`, `brute` lub `login` → Wektor 1;
   - `scan`, `recon` lub `nmap` → Wektor 2;
   - `dos` lub `flood` → Wektor 3;
   - pozostałe sygnatury → `Unknown Vector`.
4. `python/main.py` przekazuje klasyfikację do
   `python/modules/response_orchestrator.py`.
5. Orkiestrator waliduje źródłowy adres IPv4, wybiera playbook i przekazuje
   zmienne do Ansible. Nieznany wektor ani nieprawidłowy adres nie uruchamiają
   playbooka.
6. Middleware zapisuje zdarzenia `STARTED`, `SUCCESS` lub `FAILED` do pliku
   wskazanego przez `AUDIT_LOG_PATH` w `python/config.py`.

Monitor pomija niekompletne/niepoprawne linie JSON. Błędy odczytu pliku, brak
uprawnień lub inne problemy operacyjne należy sprawdzać w logach procesu i
systemu.

## Wektory i reakcje

| Wektor | Klasyfikacja sygnatury | Reakcja |
|---|---|---|
| 1 — Brute-Force / Credential Access | `ssh`, `brute`, `login` | `ansible/block_ip.yml` dodaje źródło do grupy `BLOCKED_IPS` i nakłada regułę drop w IPv4 forward filter |
| 2 — Reconnaissance / Scanning | `scan`, `recon`, `nmap` | Ten sam playbook blokujący IP |
| 3 — Volumetric DoS | `dos`, `flood` | `ansible/rate_limit.yml` nakłada ingress limiter dla wskazanego źródła i hosta chronionego |

Nazwy wektorów muszą odpowiadać dokładnym etykietom zwracanym przez
klasyfikator, ponieważ orkiestrator mapuje je na playbooki po pełnym tekście.
Klasyfikacja jest heurystyką opartą na sygnaturze Suricaty, a nie analizą
przepływności. Nieznane sygnatury nie powodują automatycznej mitygacji.

### Wektory 1 i 2 — blokowanie źródła

`ansible/block_ip.yml` używa zmiennej `target_ip`. Reguła firewall ma numer `5`
oraz akcję `drop`, a adres dodawany jest do grupy `BLOCKED_IPS`. Playbook
wykorzystuje kolekcję `vyos.vyos` i ustawia `save: no`, aby nie zapisywać
automatycznie konfiguracji na dysk po każdej reakcji.

PoC tych dwóch reakcji został przetestowany w laboratorium według stanu
projektu przekazanego przez autorkę. Trwałość po restarcie wymaga osobnego
zapisu konfiguracji VyOS.

### Wektor 3 — ograniczanie przepływności

`ansible/rate_limit.yml` tworzy klasę `10` polityki `DOS-INGRESS`. Klasa
dopasowuje jednocześnie źródło (`attacker_ip`) oraz cel (`protected_ip`), a
następnie przypina politykę ingress do interfejsu WAN skonfigurowanego w
`RATE_LIMIT_INTERFACE`.

Parametry znajdują się w `python/config.py`:

| Ustawienie | Domyślna wartość | Znaczenie |
|---|---|---|
| `PROTECTED_HOST_IP` | `10.0.1.10` | Chroniony host w DMZ |
| `RATE_LIMIT_INTERFACE` | `eth0` | Interfejs WAN, na którego wejściu działa limiter |
| `RATE_LIMIT_BANDWIDTH` | `1mbit` | Limit średniej przepływności dopasowanej klasy |
| `RATE_LIMIT_BURST` | `15k` | Rozmiar burstu w bajtach; token-bucket może dopuścić krótkie skoki |
| `RATE_LIMIT_DEFAULT_BANDWIDTH` | `100%` | Ustawienie klasy domyślnej dla ruchu niedopasowanego |

Limiter jest ingress policerem: opiera się na token bucket, nie buforuje pakietów
w celu ich późniejszego wysłania, a nadmiarowe pakiety odrzuca. Nie jest to
kształtowanie ruchu, które opóźnia pakiety, ani ochrona pasma łącza WAN już
zajętego przed routerem. Celem tej polityki jest ograniczenie ruchu
przekazywanego dalej do DMZ.

Polityka jest wspólna dla interfejsu i ma jedną klasę ataku. Przy każdym nowym
incydencie konfiguracja klasy otrzymuje bieżący adres atakującego; playbook nie
utrzymuje osobnej klasy/limitu dla każdego wcześniejszego źródła. Konfiguracja
playbooka używa `save: no`, tak jak reakcja blokująca.

Przed właściwym pomiarem należy sprawdzić, czy używana wersja VyOS akceptuje
konfigurację limiter, dopasowanie IP, jednostki burstu i `100%` dla klasy
domyślnej. Potwierdź na routerze zastosowaną politykę i jej przypięcie do
interfejsu WAN. Do pomiaru efektu obciążenie musi wyraźnie przekraczać `1 Mbps`;
wcześniejszy pomiar bazowy około `1.6 Mbps` daje niewielki margines. Porównuj
przepływność docierającą do DMZ i liczniki polityki, traktując pomiar SPAN na
SOC jako obserwację ruchu skopiowanego w konkretnym punkcie toru.

## Konfiguracja VyOS i monitoring

Plik `configs/vyos-config/vyos_initial_config.txt` zawiera konfigurację
początkową routera, w tym:

- `eth0` jako WAN z adresem DHCP;
- `eth1` jako DMZ (`10.0.1.1/24`), `eth2` jako LAN
  (`10.0.2.1/24`) i `eth3` jako MGMT (`10.0.3.1/24`);
- mirror ingress i egress z `eth1` na `eth4`, używany do SPAN;
- reguły ochrony stref/firewall, w tym ochronę wejścia do routera z WAN,
  izolację DMZ oraz ograniczenie dostępu do strefy zarządzającej;
- NAT masquerade dla sieci `10.0.0.0/16` wychodzącej przez WAN oraz trasę
  domyślną przez `192.168.85.2`.

Ponieważ mirror z interfejsu DMZ wykorzystuje tę samą ścieżkę co QoS na
interfejsie wyjściowym DMZ, próba zastosowania shaper na `eth1` powodowała
konflikt `Cannot use QoS together with mirror!`. Wektor 3 korzysta zatem z
limitera ingress na `eth0`, a nie z shaper na interfejsie wyjściowym.

Konfiguracja bazowa nie zawiera pełnej konfiguracji Suricaty, jej reguł ani
konfiguracji samego SPAN po stronie SOC — log wejściowy middleware i elementy
routera opisano zgodnie z dostępnymi plikami projektu i stanem laboratorium.

## Ansible i dostęp do routera

`ansible/inventory.ini` definiuje host VyOS jako `10.0.3.1` oraz połączenie
`network_cli` z `ansible_network_os=vyos.vyos.vyos`. Inventory korzysta z:

- użytkownika `vyos`;
- klucza SSH `/home/user/.ssh/id_ed25519`;
- `ansible_command_timeout=60`;
- `StrictHostKeyChecking=no` w `ansible_ssh_common_args`.

Połączenie bez hasła zakłada, że publiczna część klucza jest poprawnie
zainstalowana na VyOS, a Ansible i kolekcja `vyos.vyos` są dostępne na serwerze
SOC. Wyłączenie weryfikacji klucza hosta jest uproszczeniem dla laboratorium;
nie należy przenosić go bez oceny do środowiska produkcyjnego.

Orkiestrator wylicza ścieżki do inventory i playbooków względem katalogu
repozytorium. Zmienna przekazywana do `block_ip.yml` nazywa się `target_ip`,
a zmienne dla limitera (`attacker_ip`, `protected_ip` i ustawienia QoS) są
przekazywane jako JSON w parametrze Ansible `-e`.

## Uruchamianie i kontrola

Middleware uruchamia się z katalogu `python`, aby import `config` oraz modułów
był dostępny:

```text
python main.py
```

Wymagane są: Python, dostęp do pliku EVE JSON i logu audytowego, polecenie
`ansible-playbook`, inventory z działającym dostępem SSH oraz kolekcja
`vyos.vyos` na hoście uruchamiającym Ansible. Ścieżki logów w `python/config.py`
odnoszą się do serwera SOC i muszą odpowiadać jego konfiguracji oraz
uprawnieniom użytkownika uruchamiającego middleware.

Po zmianie konfiguracji w laboratorium zweryfikuj stan firewall/QoS na VyOS,
wynik wykonania playbooka i log audytowy. Testy pomiarowe prowadź w EVE-NG i
porównuj identyczne warunki przed oraz po reakcji. Automatyczna klasyfikacja
zależy od treści sygnatury Suricaty, a chwilowe obciążenie widoczne na SOC może
różnić się od przepływności przekazywanej do hosta chronionego.

## Pliki projektu

```text
ansible/
  block_ip.yml
  rate_limit.yml
  inventory.ini
configs/
  Eng_Thesis_Self_healing_Net.unl
  vyos-config/
    vyos_initial_config.txt
    vyos_initial_sh_conf.txt
python/
  config.py
  main.py
  modules/
    alert_monitor.py
    incident_classifier.py
    response_orchestrator.py
```
