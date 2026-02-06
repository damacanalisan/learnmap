#!/usr/bin/env python3
# LearnMap - Educational Nmap Learning Tool
# Purpose: Teach how Nmap works (SAFE & EDUCATIONAL)

import os
import sys
import time
import socket
import random

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
