#!/usr/bin/env python3
# LearnMap - Educational Nmap Learning Tool
# Purpose: Teach how Nmap works (SAFE & EDUCATIONAL)

import os
import sys
import time
import socket
import random
import shutil
import subprocess
from datetime import datetime

# =========================
# GLOBAL FLAGS
# =========================
EDU_MODE = True
task_mode_active = False
expected = None
LAST_ACTION = None

COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "TELNET",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    443: "HTTPS"
}

# =========================
# UTILS
# =========================
def clear():
    os.system("cls" if os.name == "nt" else "clear")

def wait():
    input("\nDevam etmek için ENTER...")

# =========================
# BANNER
# =========================
def banner():
    clear()

    RED = "\033[31m"
    RESET = "\033[0m"

    print(f"""
{RED}
                                       ................                                        
                                       ................                                        
                                 .....:-+*#%@@@@@@@@@@@@@#*+=:.....                        
                                .:=*@@@@@@@@@@@@@@@@@@@@@@@@@@%=:.....                        
                             ..:+@@@@@@@@@@@-@@@@@@@@@@.@@@@@@@@@*-:..                        
                            ..-#@@@@@@@@@@#@@@@@@@@@@@@@@@@-@@@@@@@@#=:..                
                          .:+@@@@@@@@@@@@@@@@@+-:.....-*@@@@@.%@@@@@@@+:..                
                         .-@@@@@@@@@@*@@@@@-..::........=@@@@*=#@@@@@@@=..                
                         :@@@@@@@@@%.@@@@+...@@@@@@@=..:@@@%@@@-=#@@@@@@#-..                
                        .*@@@@@@#-.=@@@@=....@@@@@+@+..-@*@#@@@%=:-*%@@@@#-..        
                      ..=@@@@@%=-=+@@@@+....:@@@@@@@=..:@@@*=@@@+=-=#%%@@#+=..       
                    ..-+@@@@%#%%%##@@@@-....::::............:@@@+--=#%#%%*===..       
                    .:+%@@@@**#%%#*@@@@-....................:@@@+=-=*####*=-+..       
                    .:*##@@@@@@@%#**@@@+............. ... .=@@@+=--+*+*#*=--=*..        
                    .:+#%@@@@@@#*++=@@@@=............ .. .-@@@*---:=*++**=::=+..        
                     .-*%%%#%@%*==++=@@@@*:. .. ....=@@@@@@@@@@@@@@@@@@@@%#=..        
                     .:=%@@%*#@%+++=:=@@@@@+.... ..-@@@@@@@@@@@@@@@@@@@@@%+:..        
                      .:=#@@@@@@@@+---:@@@@@@%-:......=%@@@@@@@@@@@@@@@@#+=-:..         
                       ..:+%@@@@@@@@@@@@#=*@@@@@@@@@@@@@@@@++%@@@@@@@@@@@#=-:..          
                       ....-*@@@@@@@@@@@@@@@#*@@@@@@@@@@@+-%@@@@@@@@@@%#*=-..                 
                       ......:+#@@@@@@@@@@@@@@@@@@@@%@@@@@@@@@@@@@%*=-:..                   
                       .........-=*%@@@@@@@@@@@@@@@@@@@@@@%#*+=-:..                    
                       ............::-==+*###***++++++=--::..                        
{RESET}

                             L E A R N M A P  –  Learn Scanning Visually
    """)

# =========================
# EDUCATION OUTPUT
# =========================
def edu(msg):
    if EDU_MODE:
        print(f"[EDU] {msg}")

# =========================
# SCAN FUNCTIONS
# =========================
def scan_common_ports():
    target = input("Hedef IP (örn: 127.0.0.1): ")
    print("\n[+] Yaygın portlar taranıyor...\n")

    edu("Bu işlem nmap -sT mantığıyla TCP bağlantısı dener.")

    for port, service in COMMON_PORTS.items():
        try:
            s = socket.socket()
            s.settimeout(1)
            s.connect((target, port))
            print(f"[OPEN] {port}/tcp → {service}")
            s.close()
        except:
            pass

    edu("Gerçek nmap karşılığı: nmap -p 21,22,80,443 <hedef>")

def ping_scan():
    target = input("Hedef IP: ")
    print("\n[+] Host ayakta mı kontrol ediliyor...\n")

    edu("Bu işlem ICMP Ping Scan mantığıdır.")
    response = os.system(f"ping -n 1 {target}" if os.name == "nt" else f"ping -c 1 {target}")

    if response == 0:
        print("✅ Host AYAKTA")
    else:
        print("❌ Host CEVAP VERMİYOR")

    edu("Gerçek nmap karşılığı: nmap -sn <hedef>")

def slow_scan():
    target = input("Hedef IP: ")
    print("\n[+] Yavaş (sessiz) tarama başlatıldı...\n")

    edu("Yavaş tarama IDS/Firewall yakalanmamak için kullanılır.")

    for port in [22, 80, 443]:
        try:
            s = socket.socket()
            s.settimeout(2)
            s.connect((target, port))
            print(f"[OPEN] {port}/tcp")
            s.close()
        except:
            pass
        time.sleep(1)

    edu("Gerçek nmap karşılığı: nmap -T2 <hedef>")

# -------------------------
# Extended scan definitions
# -------------------------
SCANS = {
    "SYN Stealth": {"flag": "-sS", "desc": "SYN (stealth) taraması — yarı-açık TCP el sıkışması kullanır."},
    "TCP Connect": {"flag": "-sT", "desc": "TCP bağlanma taraması — işletim sistemi bağlantı çağrısı kullanır."},
    "UDP": {"flag": "-sU", "desc": "UDP taraması — UDP portlarını kontrol eder."},
    "ACK": {"flag": "-sA", "desc": "ACK taraması — paket filtresi/ACL keşfi için kullanılır."},
    "Window": {"flag": "-sW", "desc": "Window taraması — TCP window alanına dayanır."},
    "Maimon": {"flag": "-sM", "desc": "Maimon taraması — daha az yaygın, bazı stacklerde işe yarar."},
    "Null/Xmas/FIN": {"flag": "-sN/-sX/-sF", "desc": "Bayraksız/Xmas/FIN taramaları — bazı filtreleri atlatmak için."},
    "Idle (Zombie)": {"flag": "-sI", "desc": "Idle taraması — zombi host kullanarak tespitten kaçınır."},
    "Ping (Host discovery)": {"flag": "-sn", "desc": "Host keşfi (ping scan) — sadece canlı hostları gösterir."},
    "List Scan": {"flag": "-sL", "desc": "Listeleme — hedeflerin DNS çözümlemesini yapar ancak taramaz."},
    "Version Detection": {"flag": "-sV", "desc": "Servis sürümü tespiti."},
    "OS Detection": {"flag": "-O", "desc": "İşletim sistemi tespiti."},
}

FEATURES = {
    "Aggressive (A)": {"flag": "-A", "desc": "Birçok testi birleştirir: OS, version, script, traceroute."},
    "NSE Scripts": {"flag": "--script <script>", "desc": "Nmap Scripting Engine ile ek testler çalıştırma."},
    "Timing Templates": {"flag": "-T0..-T5", "desc": "Tarama hız/taktiklerini ayarlama."},
    "Decoys": {"flag": "-D <decoy1,decoy2,...>", "desc": "Hedefe yönlendirilen kaynak adreslerini maskeler."},
    "Fragmentation": {"flag": "-f", "desc": "Paketleri böler; bazı IDS'leri atlatmak için kullanılır."},
    "Output Formats": {"flag": "-oN/-oX/-oG", "desc": "Tarama sonuçlarını farklı formatlarda kaydetme."},
    "Traceroute": {"flag": "--traceroute", "desc": "Hedefe giden yolu gösterir."},
}


NMAP_FLAGS = {
    "-sS": "SYN Stealth taraması (yarı-açık).",
    "-sT": "TCP Connect (standart TCP bağlanma).",
    "-sU": "UDP taraması.",
    "-sA": "ACK taraması (filtre keşfi).",
    "-sW": "Window taraması.",
    "-sM": "Maimon taraması.",
    "-sN/-sF/-sX": "Null/FIN/Xmas bayrak varyasyonları.",
    "-sI": "Idle (zombie) taraması.",
    "-sn": "Host discovery (ping scan).",
    "-sL": "Listeleme (hedefleri listeler, taramaz).",
    "-sV": "Servis versiyon tespiti.",
    "-O": "İşletim sistemi tespiti.",
    "-A": "Aggressive; OS, versiyon, script, traceroute vb. birleşimi.",
    "--script": "NSE (Nmap Scripting Engine) seçenekleri.",
    "-T0..-T5": "Timing template'leri (yavaş→hızlı).",
    "-D": "Decoys (maskelenme).",
    "-f": "Fragmentation (paket bölme).",
    "-oN/-oX/-oG/-oA": "Çıkış formatları: normal/xml/grepable/tümü.",
}


def flags_menu():
    keys = list(NMAP_FLAGS.keys())
    while True:
        clear()
        print("-- Nmap Flagleri --\n")
        for i, k in enumerate(keys, 1):
            print(f"[{i}] {k}")
        print("[0] Geri")

        choice = input("Seçim: ").strip()
        if choice == "0":
            return
        try:
            idx = int(choice) - 1
            if 0 <= idx < len(keys):
                k = keys[idx]
                print(f"\n{k} — {NMAP_FLAGS[k]}")
                # Örnek komut
                target = input("Hedef (örn: 192.168.1.1): ")
                example = build_nmap_command(k.split()[0], target)
                print("\n[Örnek nmap komutu]")
                print(example)
                edu(NMAP_FLAGS[k])
                wait()
        except ValueError:
            continue


# -------------------------
# All nmap options (categorized) + indexed numeric map
# -------------------------
NMAP_ALL = {
    "Scan Types": {
        "-sS": "SYN Stealth taraması (yarı-açık)",
        "-sT": "TCP Connect taraması (standart)",
        "-sU": "UDP taraması",
        "-sN": "Null taraması",
        "-sF": "FIN taraması",
        "-sX": "Xmas taraması",
        "-sA": "ACK taraması",
        "-sW": "Window taraması",
        "-sM": "Maimon taraması",
        "-sI": "Idle (zombie) taraması",
    },
    "Host Discovery": {
        "-sn": "Ping scan (host discovery)",
        "-Pn": "Ping atlama (tüm hostları canlı varsayar)",
        "-PS": "TCP SYN ping",
        "-PA": "TCP ACK ping",
        "-PE": "ICMP Echo ping",
        "-PP": "ICMP Timestamp ping",
    },
    "Port Selection": {
        "-p": "Port veya port aralığı seçimi (örn: -p 1-65535 veya -p80,443)",
        "--top-ports": "En yoğun kullanılan portları tara (örn: --top-ports 100)",
    },
    "Service/OS Detection": {
        "-sV": "Servis versiyon tespiti",
        "-O": "İşletim sistemi tespiti",
        "--version-intensity": "Versiyon tespit yoğunluğu ayarı",
    },
    "Scripting (NSE)": {
        "--script": "Script veya kategorilere göre NSE çalıştırma",
        "--script-args": "Script argümanları geçme",
    },
    "Timing/Evasion": {
        "-T0..-T5": "Timing template'leri (0 en yavaş, 5 en hızlı)",
        "-f": "Fragmentation (paket parçalara bölme)",
        "-D": "Decoy/Maskelenme (örn: -D decoy1,ME,decoy2)",
        "--data-length": "Rastgele veri ekleme (paket boyu)",
    },
    "Output": {
        "-oN": "Normal output (insan okunur)",
        "-oX": "XML output",
        "-oG": "Grepable output",
        "-oA": "Hepsi (basename ile üç format)",
    },
    "Misc": {
        "-A": "Aggressive (OS, versiyon, script, traceroute)",
        "--traceroute": "Traceroute ile rota gösterme",
        "-v": "Verbose (ayrıntılı çıktı)",
        "-d": "Debug (detaylı hata/izleme)",
        "--reason": "Her sonuç için sebep gösterme",
    }
}


# Build a global numeric index for all options so external tools can pick by number
GLOBAL_OPTION_MAP = {}

def build_global_index():
    GLOBAL_OPTION_MAP.clear()
    idx = 1
    for cat, opts in NMAP_ALL.items():
        for flag, desc in opts.items():
            GLOBAL_OPTION_MAP[str(idx)] = {'category': cat, 'flag': flag, 'desc': desc}
            idx += 1


def categories_menu():
    build_global_index()
    cats = list(NMAP_ALL.keys())
    while True:
        clear()
        print("-- Nmap Kategorileri --\n")
        for i, c in enumerate(cats, 1):
            print(f"[{i}] {c}")
        print("[0] Geri")
        choice = input("Kategori seçim (numara): ").strip()
        if choice == '0':
            return
        try:
            ci = int(choice) - 1
            if 0 <= ci < len(cats):
                show_category_options(cats[ci])
        except ValueError:
            continue


def show_category_options(category):
    # Show options in the category with global numeric ids
    opts = NMAP_ALL.get(category, {})
    id_map = {k:v for k,v in GLOBAL_OPTION_MAP.items() if v['category']==category}
    while True:
        clear()
        print(f"-- {category} --\n")
        for gid, meta in id_map.items():
            print(f"[{gid}] {meta['flag']}  — {meta['desc']}")
        print("[b] Geri")
        sel = input("Seçim (numara veya b): ").strip()
        if sel.lower() == 'b':
            return
        if sel in id_map:
            meta = id_map[sel]
            show_scan_details_by_flag(meta['flag'], meta['desc'])
            wait()
        else:
            continue


def show_scan_details_by_flag(flag, desc):
    print(f"\n== {flag} ==")
    print(desc)
    target = input("Hedef (örn: 192.168.1.1 veya example.com): ").strip()
    ports = None
    if flag == '-p' or flag.startswith('-p'):
        ports = input("Portlar (örn: 80,443 veya 1-65535): ").strip()
    example = build_nmap_command(flag, target, ports=ports)
    print("\n[Örnek nmap komutu]")
    print(example)
    edu(desc)
    run_choice = input("Bu komutu çalıştırmak ister misiniz? (e/h): ").lower().strip()
    if run_choice.startswith('e'):
        run_with_output = input("Çıktıyı dosyaya kaydetmek ister misiniz? (e/h): ").lower().strip()
        out = None
        if run_with_output.startswith('e'):
            fname = input("Dosya adı (boş bırakılırsa otomatik isim verilir): ").strip()
            out = fname if fname else None
        confirm_and_run(example, outfile=out)



def build_nmap_command(flag, target, ports=None, extra=None):
    cmd = ["nmap"]
    if flag:
        cmd.append(flag)
    if ports:
        cmd.append(f"-p {ports}")
    if extra:
        cmd.append(extra)
    cmd.append(target)
    return " ".join(cmd)


def parse_ports(ports_str):
    # Accept comma-separated and ranges
    ports = set()
    if not ports_str:
        return []
    parts = ports_str.split(',')
    for p in parts:
        p = p.strip()
        if '-' in p:
            try:
                a,b = p.split('-',1)
                a=int(a); b=int(b)
                for x in range(a, b+1):
                    ports.add(x)
            except:
                continue
        else:
            try:
                ports.add(int(p))
            except:
                continue
    return sorted(ports)


def tcp_connect_scan(target, ports, timeout=1.0):
    print(f"\n[TCP Connect taraması] Hedef: {target}")
    for port in ports:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((target, port))
            print(f"[OPEN] {port}/tcp")
            # try simple banner grab
            try:
                s.sendall(b"\r\n")
                data = s.recv(1024)
                if data:
                    print(f"  Banner: {data.strip()[:200]}")
            except:
                pass
            s.close()
        except Exception:
            print(f"[CLOSED/FILTERED] {port}/tcp")


def udp_scan(target, ports, timeout=2.0):
    print(f"\n[UDP taraması (yaklaşık)] Hedef: {target}")
    for port in ports:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(timeout)
            s.sendto(b"", (target, port))
            try:
                data, _ = s.recvfrom(1024)
                print(f"[OPEN] {port}/udp — cevap alındı")
            except socket.timeout:
                print(f"[OPEN|FILTERED] {port}/udp — cevap yok (ICMP unreachable görünmüyorsa açık veya filtrelenmiş)")
            s.close()
        except Exception as e:
            print(f"[ERROR] {port}/udp — {e}")


def fallback_scan_nmap_command(cmd, outfile=None):
    # Very small parser for basic flags: -sS, -sT, -sU, -p, -sn, -sV
    tokens = cmd.split()
    flags = [t for t in tokens[1:-1] if t.startswith('-')]
    target = tokens[-1]
    ports = None
    # find -p value
    if '-p' in tokens:
        try:
            pidx = tokens.index('-p')
            ports = tokens[pidx+1]
        except:
            ports = None
    else:
        # check for -pX without space
        for t in tokens:
            if t.startswith('-p') and len(t)>2:
                ports = t[2:]
                break

    ports_list = parse_ports(ports) if ports else [22,80,443,53]

    # Decide scan type
    if '-sU' in flags:
        udp_scan(target, ports_list)
    elif '-sn' in flags:
        # use system ping as earlier
        response = os.system(f"ping -n 1 {target}" if os.name == "nt" else f"ping -c 1 {target}")
        if response == 0:
            print("✅ Host AYAKTA")
        else:
            print("❌ Host CEVAP VERMİYOR")
    else:
        # default to TCP connect
        tcp_connect_scan(target, ports_list)



def show_scan_details(key, info):
    print(f"\n== {key} ==")
    print(info['desc'])
    target = input("Hedef (örn: 192.168.1.1 veya example.com): ").strip()
    ports = None
    ask_ports = input("Port belirtmek ister misiniz? (e/h): ").lower()
    if ask_ports.startswith('e'):
        ports = input("Portlar (örn: 80,443 veya 1-65535): ").strip()
    example = build_nmap_command(info.get('flag', ''), target, ports=ports)
    print("\n[Örnek nmap komutu]")
    print(example)
    edu(f"Açıklama: {info['desc']}")
    print("\n(Not: Bu betik varsayılan olarak `nmap`'i çalıştırmaz.)")

    run_choice = input("Bu komutu çalıştırmak ister misiniz? (e/h): ").lower().strip()
    if run_choice.startswith('e'):
        run_with_output = input("Çıktıyı dosyaya kaydetmek ister misiniz? (e/h): ").lower().strip()
        out = None
        if run_with_output.startswith('e'):
            fname = input("Dosya adı (uzantı önerisi yok; örn: result.txt): ").strip()
            out = fname
        confirm_and_run(example, outfile=out)


def confirm_and_run(cmd, outfile=None):
    # Güvenlik/etik uyarısı
    print("\n!!! Yasal ve etik uyarı: Sadece izniniz olan hedeflere tarama yapın !!!")
    proceed = input("Çalıştırmak istiyorsanız 'RUN' yazın: ").strip()
    if proceed != 'RUN':
        print("Onay alınmadı — çalıştırma iptal edildi.")
        return

    # nmap var mı kontrol et
    if not shutil.which('nmap'):
        print("`nmap` sistem PATH'inde bulunamadı.")
        fb = input("Yerel (Python) fallback taraması kullanılsın mı? (e/h): ").strip().lower()
        if fb.startswith('e'):
            # Use internal Python fallback to simulate/perform scans
            fallback_scan_nmap_command(cmd, outfile=outfile)
        else:
            print("Lütfen nmap yükleyin veya PATH'i güncelleyin.")
        return

    # Çıktı formatı seçimi
    print("\nÇıktı kaydetme seçenekleri:")
    print("[1] Kaydetme (konsolda sadece göster)")
    print("[2] -oN (normal)")
    print("[3] -oX (XML)")
    print("[4] -oG (grepable)")
    print("[5] -oA (hepsi)")
    fchoice = input("Seçim (varsayılan 1): ").strip() or "1"

    final_cmd = cmd
    target = cmd.split()[-1]
    ts = datetime.now().strftime('%Y%m%d_%H%M%S')

    if fchoice == '2':
        if not outfile:
            outfile = f"learnmap_{target}_{ts}.txt"
        final_cmd = f"{cmd} -oN {outfile}"
    elif fchoice == '3':
        if not outfile:
            outfile = f"learnmap_{target}_{ts}.xml"
        final_cmd = f"{cmd} -oX {outfile}"
    elif fchoice == '4':
        if not outfile:
            outfile = f"learnmap_{target}_{ts}.gnmap"
        final_cmd = f"{cmd} -oG {outfile}"
    elif fchoice == '5':
        if not outfile:
            outfile = f"learnmap_{target}_{ts}"
        final_cmd = f"{cmd} -oA {outfile}"

    print(f"Çalıştırılıyor: {final_cmd}")
    try:
        # Stream output live and optionally save to file
        with subprocess.Popen(final_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True) as proc:
            out_f = None
            if fchoice != '1':
                # If user chose a file-based format, outfile should be set
                if outfile:
                    out_f = open(outfile, 'w', encoding='utf-8')
            try:
                for line in proc.stdout:
                    print(line, end='')
                    if out_f:
                        out_f.write(line)
                ret = proc.wait()
            finally:
                if out_f:
                    out_f.close()

        if ret == 0:
            print("\nTarama tamamlandı.")
            if fchoice != '1' and outfile:
                print(f"Çıktı kaydedildi: {outfile}")
        else:
            print(f"\nTarama kodu: {ret}")
    except Exception as e:
        print(f"Çalıştırma sırasında hata: {e}")


# =========================
# TASK MODE
# =========================
def task_mode():
    global task_mode_active, expected

    task_mode_active = True
    tasks = {
        "common_ports": "Yaygın port taraması yap",
        "ping_scan": "Host ayakta mı kontrol et",
        "slow_scan": "Yavaş tarama yap"
    }

    expected = random.choice(list(tasks.keys()))

    print("\n🎯 GÖREV MODU")
    print("Görev:", tasks[expected])
    wait()


def scan_types_menu():
    keys = list(SCANS.keys())
    while True:
        clear()
        print("-- Tarama Türleri --\n")
        for i, k in enumerate(keys, 1):
            print(f"[{i}] {k}  ({SCANS[k]['flag']})")
        print("[0] Geri")

        choice = input("Seçim: ").strip()
        if choice == "0":
            return
        try:
            idx = int(choice) - 1
            if 0 <= idx < len(keys):
                show_scan_details(keys[idx], SCANS[keys[idx]])
                wait()
        except ValueError:
            continue


def features_menu():
    keys = list(FEATURES.keys())
    while True:
        clear()
        print("-- Diğer Özellikler --\n")
        for i, k in enumerate(keys, 1):
            print(f"[{i}] {k}  ({FEATURES[k]['flag']})")
        print("[0] Geri")

        choice = input("Seçim: ").strip()
        if choice == "0":
            return
        try:
            idx = int(choice) - 1
            if 0 <= idx < len(keys):
                key = keys[idx]
                info = FEATURES[key]
                print(f"\n== {key} ==")
                print(info['desc'])
                if key == 'NSE Scripts':
                    target = input("Hedef: ")
                    script = input("Script adı veya kategorisi (örn: http-vuln*): ").strip()
                    flag = info['flag'].replace('<script>', script)
                    example = build_nmap_command(flag, target)
                else:
                    target = input("Hedef: ")
                    example = build_nmap_command(info.get('flag', ''), target)

                print("\n[Örnek nmap komutu]")
                print(example)
                edu(f"Açıklama: {info['desc']}")
                run_choice = input("Bu komutu çalıştırmak ister misiniz? (e/h): ").lower().strip()
                if run_choice.startswith('e'):
                    run_with_output = input("Çıktıyı dosyaya kaydetmek ister misiniz? (e/h): ").lower().strip()
                    out = None
                    if run_with_output.startswith('e'):
                        fname = input("Dosya adı: ").strip()
                        out = fname
                    confirm_and_run(example, outfile=out)
                else:
                    print("Çalıştırma atlandı.")
                wait()
        except ValueError:
            continue

# =========================
# MENU
# =========================
def menu():
    global EDU_MODE, LAST_ACTION

    while True:
        banner()
        print("""
    [1] Yaygın portları tara
    [2] Host ayakta mı kontrol et
    [3] Yavaş (sessiz) tarama

    [4] Eğitim modunu aç / kapat
    [5] Görev Modu
    [6] Tarama Türleri (tüm nmap scan tipleri)
    [7] Diğer Özellikler (NSE, -A, -O, çıktı formatları...)

    [0] Çıkış
    """)

        c = input("Seçim: ").strip()

        if c == "1":
            LAST_ACTION = "common_ports"
            scan_common_ports()

        elif c == "2":
            LAST_ACTION = "ping_scan"
            ping_scan()

        elif c == "3":
            LAST_ACTION = "slow_scan"
            slow_scan()

        elif c == "4":
            EDU_MODE = not EDU_MODE
            print(f"Eğitim modu: {'AÇIK' if EDU_MODE else 'KAPALI'}")
            time.sleep(1)

        elif c == "5":
            task_mode()
            continue

        elif c == "6":
            scan_types_menu()
            continue

        elif c == "7":
            features_menu()
            continue
        elif c == "8":
            categories_menu()
            continue

        elif c == "0":
            sys.exit()

        else:
            continue

        if task_mode_active:
            if LAST_ACTION == expected:
                print("\n✅ Görev başarıyla tamamlandı!")
            else:
                print("\n❌ Yanlış işlem yaptın.")
            wait()
            return

        wait()

# =========================
# MAIN
# =========================
if __name__ == "__main__":
    menu()
