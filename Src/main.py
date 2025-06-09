import os
import sys
import time
import socket
import requests
import json
import argparse
import concurrent.futures
import threading
import random
from datetime import datetime
from colorama import init, Fore, Back, Style
import pyfiglet
import ascii_magic
import platform
import subprocess
import re
import dns.resolver
import whois
import shodan
import nmap
import geoip2.database
from tqdm import tqdm
from bs4 import BeautifulSoup
from fake_useragent import UserAgent
from concurrent.futures import ThreadPoolExecutor, as_completed

# 🌪️ Initialization
init(autoreset=True)
ua = UserAgent()
VERSION = "3.1.7"
BANNER = pyfiglet.figlet_format("BlackTurbine", font="slant")

# 🎨 Color Scheme
class Colors:
    RED = Fore.RED + Style.BRIGHT
    GREEN = Fore.GREEN + Style.BRIGHT
    YELLOW = Fore.YELLOW + Style.BRIGHT
    BLUE = Fore.BLUE + Style.BRIGHT
    MAGENTA = Fore.MAGENTA + Style.BRIGHT
    CYAN = Fore.CYAN + Style.BRIGHT
    WHITE = Fore.WHITE + Style.BRIGHT
    RESET = Style.RESET_ALL

# 💫 Emoji Constants
class Emoji:
    ROCKET = "🚀"
    TURBINE = "🌀"
    FIRE = "🔥"
    BOMB = "💣"
    SKULL = "💀"
    GHOST = "👻"
    SPY = "🕵️"
    SCAN = "🔍"
    LOCK = "🔒"
    UNLOCK = "🔓"
    WARNING = "⚠️"
    SUCCESS = "✅"
    ERROR = "❌"
    SERVER = "🖥️"
    PLAYER = "👤"
    PING = "⏱️"
    LOADING = "⏳"
    DONE = "🎉"
    KEY = "🔑"
    SHIELD = "🛡️"
    GLOBE = "🌐"
    RADAR = "📡"
    TOOLS = "🛠️"
    DATA = "📊"
    NETWORK = "📶"
    THUNDER = "⚡"

# 🔧 Configuration
class Config:
    TIMEOUT = 7
    MAX_THREADS = 500
    SHODAN_API_KEY = "KOaNlBexuv1QbakElsWgWCYCZq8PHyYY"  # Replace with actual key
    MAX_PING = 500
    SCAN_DELAY = 0.2
    USER_AGENT = "BlackTurbine/{}".format(VERSION)
    GEOIP_DB = "GeoLite2-City.mmdb"  # Download from MaxMind

# 🌐 GeoIP Reader
try:
    geoip_reader = geoip2.database.Reader(Config.GEOIP_DB)
except:
    geoip_reader = None

# 🔥 Animation Functions
def spinning_cursor():
    while True:
        for cursor in '|/-\\':
            yield cursor

spinner = spinning_cursor()

def animate_loading(text):
    sys.stdout.write(f"\r{Colors.CYAN}{next(spinner)} {text}")
    sys.stdout.flush()

def typewriter_effect(text, delay=0.03):
    for char in text:
        sys.stdout.write(char)
        sys.stdout.flush()
        time.sleep(delay)
    print()

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def print_banner():
    clear_screen()
    print(f"{Colors.MAGENTA}{BANNER}")
    print(f"{Colors.CYAN}🌀 {Colors.WHITE}Version: {VERSION} | {Colors.YELLOW}Ultimate FiveM Server Dominance Suite")
    print(f"{Colors.CYAN}🌀 {Colors.WHITE}Developed by: {Colors.RED}Rasan Fernando {Colors.WHITE}| {Colors.GREEN}License: {Colors.YELLOW}ELITE")
    print(f"{Colors.CYAN}🌀 {Colors.WHITE}-------------------------------------------------------")

# 💣 Core Scanner Class
class BlackTurbine:
    def __init__(self):
        self.active_scans = 0
        self.total_servers_found = 0
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': Config.USER_AGENT})
        self.nm = nmap.PortScanner() if 'nmap' in sys.modules else None
        self.shodan = shodan.Shodan(Config.SHODAN_API_KEY) if Config.SHODAN_API_KEY != "YOUR_SHODAN_API_KEY" else None

    # 🛠️ Utility Methods
    def is_port_open(self, ip, port, timeout=Config.TIMEOUT):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            sock.close()
            return result == 0
        except:
            return False

    def get_geolocation(self, ip):
        if not geoip_reader:
            return None
        
        try:
            response = geoip_reader.city(ip)
            return {
                'country': response.country.name,
                'city': response.city.name,
                'latitude': response.location.latitude,
                'longitude': response.location.longitude,
                'isp': response.traits.isp if response.traits.isp else "Unknown"
            }
        except:
            return None

    def get_dns_info(self, domain):
        try:
            result = {}
            for qtype in ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA']:
                answers = dns.resolver.resolve(domain, qtype, raise_on_no_answer=False)
                result[qtype] = [str(r) for r in answers]
            return result
        except:
            return None

    def get_whois(self, domain_or_ip):
        try:
            return whois.whois(domain_or_ip)
        except:
            return None

    # 🎯 FiveM Specific Methods
    def scan_fivem_server(self, ip, port=30120, full_scan=False):
        server_info = {
            'ip': ip,
            'port': port,
            'online': False,
            'ping': -1,
            'players': 0,
            'max_players': 0,
            'hostname': "N/A",
            'version': "N/A",
            'map': "N/A",
            'gametype': "N/A",
            'resources': [],
            'vars': {},
            'geolocation': None,
            'security': {}
        }

        try:
            start_time = time.time()
            
            # Initial port check
            if not self.is_port_open(ip, port):
                return server_info
            
            # Get basic info
            info_url = f"http://{ip}:{port}/info.json"
            response = self.session.get(info_url, timeout=Config.TIMEOUT)
            
            if response.status_code == 200:
                server_info['online'] = True
                server_info['ping'] = round((time.time() - start_time) * 1000)
                data = response.json()
                
                # Basic info
                server_info.update({
                    'hostname': data.get('hostname', 'N/A'),
                    'version': data.get('version', 'N/A'),
                    'map': data.get('mapname', 'N/A'),
                    'gametype': data.get('gametype', 'N/A'),
                    'vars': data.get('vars', {})
                })
                
                # Get max players
                server_info['max_players'] = data.get('vars', {}).get('sv_maxClients', 0)
                
                # Get players
                players_url = f"http://{ip}:{port}/players.json"
                try:
                    players_response = self.session.get(players_url, timeout=Config.TIMEOUT)
                    if players_response.status_code == 200:
                        players_data = players_response.json()
                        server_info['players'] = len(players_data)
                except:
                    pass
                
                # Full scan if requested
                if full_scan:
                    # Get resources
                    resources_url = f"http://{ip}:{port}/resources.json"
                    try:
                        resources_response = self.session.get(resources_url, timeout=Config.TIMEOUT)
                        if resources_response.status_code == 200:
                            server_info['resources'] = resources_response.json()
                    except:
                        pass
                    
                    # Get geolocation
                    server_info['geolocation'] = self.get_geolocation(ip)
                    
                    # Security checks
                    server_info['security']['http_headers'] = dict(response.headers)
                    
                    # Check for common vulnerabilities
                    server_info['security']['vulnerabilities'] = self.check_vulnerabilities(ip, port)
                
                self.total_servers_found += 1
                return server_info
            
        except Exception as e:
            if full_scan:
                server_info['error'] = str(e)
        
        return server_info

    def check_vulnerabilities(self, ip, port):
        vulns = {}
        
        # Check for open ports
        vulns['open_ports'] = self.scan_ports(ip, [80, 443, 22, 3306, 5432])
        
        # Check for outdated versions
        try:
            version_url = f"http://{ip}:{port}/version.txt"
            version_resp = self.session.get(version_url, timeout=Config.TIMEOUT)
            if version_resp.status_code == 200:
                vulns['version_info'] = version_resp.text.strip()
        except:
            pass
        
        return vulns

    def scan_ports(self, ip, ports):
        results = {}
        with ThreadPoolExecutor(max_workers=Config.MAX_THREADS) as executor:
            future_to_port = {executor.submit(self.is_port_open, ip, port): port for port in ports}
            for future in concurrent.futures.as_completed(future_to_port):
                port = future_to_port[future]
                try:
                    results[port] = future.result()
                except:
                    results[port] = False
        return results

    def mass_scan(self, ip_list, port=30120, full_scan=False):
        results = []
        total = len(ip_list)
        
        with tqdm(total=total, desc=f"{Emoji.RADAR} Scanning IPs", unit="server") as pbar:
            with ThreadPoolExecutor(max_workers=Config.MAX_THREADS) as executor:
                future_to_ip = {executor.submit(self.scan_fivem_server, ip, port, full_scan): ip for ip in ip_list}
                for future in concurrent.futures.as_completed(future_to_ip):
                    ip = future_to_ip[future]
                    try:
                        result = future.result()
                        if result['online']:
                            results.append(result)
                    except:
                        pass
                    finally:
                        pbar.update(1)
        
        return results

    def scan_ip_range(self, start_ip, end_ip, port=30120, full_scan=False):
        results = []
        ip_range = self.generate_ip_range(start_ip, end_ip)
        total = len(ip_range)
        
        print(f"{Emoji.RADAR} {Colors.CYAN}Scanning {total} IPs from {start_ip} to {end_ip}...")
        
        with tqdm(total=total, desc=f"{Emoji.SCAN} Progress", unit="IP") as pbar:
            with ThreadPoolExecutor(max_workers=Config.MAX_THREADS) as executor:
                future_to_ip = {executor.submit(self.scan_fivem_server, ip, port, full_scan): ip for ip in ip_range}
                for future in concurrent.futures.as_completed(future_to_ip):
                    ip = future_to_ip[future]
                    try:
                        result = future.result()
                        if result['online']:
                            results.append(result)
                            self.display_server(result)
                    except:
                        pass
                    finally:
                        pbar.update(1)
        
        print(f"{Emoji.DONE} {Colors.GREEN}Scan completed! Found {len(results)} FiveM servers.")
        return results

    def generate_ip_range(self, start_ip, end_ip):
        start = list(map(int, start_ip.split('.')))
        end = list(map(int, end_ip.split('.')))
        ip_range = []
        
        for a in range(start[0], end[0] + 1):
            for b in range(start[1], end[1] + 1):
                for c in range(start[2], end[2] + 1):
                    for d in range(start[3], end[3] + 1):
                        ip_range.append(f"{a}.{b}.{c}.{d}")
        
        return ip_range

    def display_server(self, server, detailed=False):
        status_color = Colors.GREEN if server['online'] else Colors.RED
        ping_color = Colors.GREEN if server['ping'] < 100 else Colors.YELLOW if server['ping'] < 300 else Colors.RED
        
        print(f"\n{Emoji.SERVER} {Colors.CYAN}Server Found! {Emoji.THUNDER}")
        print(f"{Colors.BLUE}┌───────────────────────────────────────────────")
        print(f"{Colors.BLUE}│ {Colors.YELLOW}Hostname: {Colors.WHITE}{server['hostname']}")
        print(f"{Colors.BLUE}│ {Colors.YELLOW}IP:Port: {Colors.WHITE}{server['ip']}:{server['port']}")
        print(f"{Colors.BLUE}│ {Colors.YELLOW}Status: {status_color}Online {Emoji.SUCCESS}")
        print(f"{Colors.BLUE}│ {Colors.YELLOW}Ping: {ping_color}{server['ping']} ms {Emoji.PING}")
        print(f"{Colors.BLUE}│ {Colors.YELLOW}Players: {Colors.WHITE}{server['players']}/{server['max_players']} {Emoji.PLAYER}")
        
        if detailed:
            print(f"{Colors.BLUE}│ {Colors.YELLOW}Version: {Colors.WHITE}{server['version']}")
            print(f"{Colors.BLUE}│ {Colors.YELLOW}Map: {Colors.WHITE}{server['map']}")
            print(f"{Colors.BLUE}│ {Colors.YELLOW}Gametype: {Colors.WHITE}{server['gametype']}")
            
            if server['geolocation']:
                geo = server['geolocation']
                print(f"{Colors.BLUE}│ {Colors.YELLOW}Location: {Colors.WHITE}{geo.get('city', 'N/A')}, {geo.get('country', 'N/A')}")
                print(f"{Colors.BLUE}│ {Colors.YELLOW}ISP: {Colors.WHITE}{geo.get('isp', 'N/A')}")
            
            if server['resources']:
                print(f"{Colors.BLUE}│ {Colors.YELLOW}Resources: {Colors.WHITE}{len(server['resources'])} loaded")
            
            if server['vars']:
                print(f"{Colors.BLUE}│ {Colors.YELLOW}Server Vars: {Colors.WHITE}{len(server['vars'])} configured")
        
        print(f"{Colors.BLUE}└───────────────────────────────────────────────")

    def shodan_scan(self, query="FiveM", limit=100):
        if not self.shodan:
            print(f"{Emoji.ERROR} {Colors.RED}Shodan API key not configured!")
            return []
        
        try:
            print(f"{Emoji.SPY} {Colors.CYAN}Querying Shodan for '{query}'...")
            results = self.shodan.search(query, limit=limit)
            servers = []
            
            for result in results['matches']:
                if '30120' in result.get('ports', []):
                    server = self.scan_fivem_server(result['ip_str'], 30120, True)
                    if server['online']:
                        servers.append(server)
            
            print(f"{Emoji.DONE} {Colors.GREEN}Found {len(servers)} FiveM servers via Shodan.")
            return servers
        except Exception as e:
            print(f"{Emoji.ERROR} {Colors.RED}Shodan error: {str(e)}")
            return []

# 🖥️ CLI Interface
class BlackTurbineCLI:
    def __init__(self):
        self.scanner = BlackTurbine()
        self.running = True
    
    def run(self):
        while self.running:
            self.main_menu()
    
    def main_menu(self):
        print_banner()
        print(f"\n{Colors.CYAN}🌀 {Colors.WHITE}Main Menu - Select an option:")
        print(f"{Colors.GREEN}1️⃣ {Colors.WHITE}Single Server Scan {Emoji.SERVER}")
        print(f"{Colors.GREEN}2️⃣ {Colors.WHITE}IP Range Scanner {Emoji.RADAR}")
        print(f"{Colors.GREEN}3️⃣ {Colors.WHITE}Mass Scan from File {Emoji.DATA}")
        print(f"{Colors.GREEN}4️⃣ {Colors.WHITE}Shodan Integration {Emoji.SPY}")
        print(f"{Colors.GREEN}5️⃣ {Colors.WHITE}Advanced Diagnostics {Emoji.TOOLS}")
        print(f"{Colors.GREEN}6️⃣ {Colors.WHITE}Network Tools {Emoji.NETWORK}")
        print(f"{Colors.GREEN}7️⃣ {Colors.WHITE}Server Bruteforcer {Emoji.BOMB}")
        print(f"{Colors.GREEN}8️⃣ {Colors.WHITE}Settings {Emoji.SHIELD}")
        print(f"{Colors.RED}0️⃣ {Colors.WHITE}Exit {Emoji.SKULL}")
        
        choice = input(f"\n{Emoji.TURBINE} {Colors.CYAN}Enter your choice: ")
        
        if choice == '1':
            self.single_scan()
        elif choice == '2':
            self.range_scan()
        elif choice == '3':
            self.file_scan()
        elif choice == '4':
            self.shodan_search()
        elif choice == '5':
            self.advanced_diagnostics()
        elif choice == '6':
            self.network_tools()
        elif choice == '7':
            self.bruteforce_menu()
        elif choice == '8':
            self.settings_menu()
        elif choice == '0':
            self.running = False
            print(f"\n{Emoji.GHOST} {Colors.MAGENTA}BlackTurbine shutting down... Goodbye!")
        else:
            print(f"\n{Emoji.ERROR} {Colors.RED}Invalid choice!")
        
        if self.running:
            input(f"\n{Emoji.INFO} {Colors.CYAN}Press Enter to continue...")
    
    def single_scan(self):
        print_banner()
        print(f"\n{Emoji.SERVER} {Colors.CYAN}Single Server Scanner")
        ip = input(f"{Colors.YELLOW}Enter server IP: {Colors.WHITE}")
        port = input(f"{Colors.YELLOW}Enter server port (default 30120): {Colors.WHITE}") or "30120"
        full_scan = input(f"{Colors.YELLOW}Full scan? (y/n): {Colors.WHITE}").lower() == 'y'
        
        try:
            port = int(port)
            print(f"\n{Emoji.LOADING} {Colors.CYAN}Scanning server {ip}:{port}...")
            server = self.scanner.scan_fivem_server(ip, port, full_scan)
            
            if server['online']:
                self.scanner.display_server(server, full_scan)
            else:
                print(f"\n{Emoji.ERROR} {Colors.RED}Server is offline or not a FiveM server.")
        except ValueError:
            print(f"\n{Emoji.ERROR} {Colors.RED}Invalid port number!")
    
    def range_scan(self):
        print_banner()
        print(f"\n{Emoji.RADAR} {Colors.CYAN}IP Range Scanner")
        print(f"{Emoji.WARNING} {Colors.YELLOW}Note: Large ranges may take significant time!")
        
        start_ip = input(f"{Colors.YELLOW}Enter start IP (e.g., 192.168.1.1): {Colors.WHITE}")
        end_ip = input(f"{Colors.YELLOW}Enter end IP (e.g., 192.168.1.255): {Colors.WHITE}")
        port = input(f"{Colors.YELLOW}Enter port (default 30120): {Colors.WHITE}") or "30120"
        full_scan = input(f"{Colors.YELLOW}Full scan? (y/n): {Colors.WHITE}").lower() == 'y'
        
        try:
            port = int(port)
            self.scanner.scan_ip_range(start_ip, end_ip, port, full_scan)
        except ValueError:
            print(f"\n{Emoji.ERROR} {Colors.RED}Invalid port number!")
        except Exception as e:
            print(f"\n{Emoji.ERROR} {Colors.RED}Error: {str(e)}")
    
    def file_scan(self):
        print_banner()
        print(f"\n{Emoji.DATA} {Colors.CYAN}Mass Scan from File")
        file_path = input(f"{Colors.YELLOW}Enter path to file containing IPs: {Colors.WHITE}")
        port = input(f"{Colors.YELLOW}Enter port (default 30120): {Colors.WHITE}") or "30120"
        full_scan = input(f"{Colors.YELLOW}Full scan? (y/n): {Colors.WHITE}").lower() == 'y'
        
        try:
            port = int(port)
            with open(file_path, 'r') as f:
                ip_list = [line.strip() for line in f if line.strip()]
            
            print(f"\n{Emoji.LOADING} {Colors.CYAN}Found {len(ip_list)} IPs in file. Scanning...")
            results = self.scanner.mass_scan(ip_list, port, full_scan)
            
            print(f"\n{Emoji.DATA} {Colors.CYAN}Scan Results Summary:")
            print(f"{Colors.YELLOW}Total IPs scanned: {Colors.WHITE}{len(ip_list)}")
            print(f"{Colors.YELLOW}FiveM servers found: {Colors.WHITE}{len(results)}")
            print(f"{Colors.YELLOW}Success rate: {Colors.WHITE}{len(results)/len(ip_list)*100:.2f}%")
            
            if results:
                save = input(f"\n{Colors.YELLOW}Save results to file? (y/n): {Colors.WHITE}").lower() == 'y'
                if save:
                    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                    filename = f"blackturbine_scan_{timestamp}.json"
                    with open(filename, 'w') as f:
                        json.dump(results, f, indent=2)
                    print(f"{Emoji.SUCCESS} {Colors.GREEN}Results saved to {filename}")
        except FileNotFoundError:
            print(f"\n{Emoji.ERROR} {Colors.RED}File not found!")
        except ValueError:
            print(f"\n{Emoji.ERROR} {Colors.RED}Invalid port number!")
        except Exception as e:
            print(f"\n{Emoji.ERROR} {Colors.RED}Error: {str(e)}")
    
    def shodan_search(self):
        print_banner()
        print(f"\n{Emoji.SPY} {Colors.CYAN}Shodan Integration")
        if not self.scanner.shodan:
            print(f"{Emoji.ERROR} {Colors.RED}Shodan API key not configured in Config.py!")
            return
        
        query = input(f"{Colors.YELLOW}Enter Shodan search query (default 'FiveM'): {Colors.WHITE}") or "FiveM"
        limit = input(f"{Colors.YELLOW}Enter max results (default 100): {Colors.WHITE}") or "100"
        
        try:
            limit = int(limit)
            results = self.scanner.shodan_scan(query, limit)
            
            if results:
                print(f"\n{Emoji.DATA} {Colors.CYAN}Top 5 Results:")
                for i, server in enumerate(results[:5]):
                    print(f"{Colors.YELLOW}{i+1}. {Colors.WHITE}{server['hostname']} ({server['ip']}:{server['port']}) - {server['players']}/{server['max_players']} players")
                
                save = input(f"\n{Colors.YELLOW}Save all results to file? (y/n): {Colors.WHITE}").lower() == 'y'
                if save:
                    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                    filename = f"blackturbine_shodan_{timestamp}.json"
                    with open(filename, 'w') as f:
                        json.dump(results, f, indent=2)
                    print(f"{Emoji.SUCCESS} {Colors.GREEN}Results saved to {filename}")
        except ValueError:
            print(f"\n{Emoji.ERROR} {Colors.RED}Invalid number!")
        except Exception as e:
            print(f"\n{Emoji.ERROR} {Colors.RED}Error: {str(e)}")
    
    def advanced_diagnostics(self):
        print_banner()
        print(f"\n{Emoji.TOOLS} {Colors.CYAN}Advanced Diagnostics")
        ip = input(f"{Colors.YELLOW}Enter server IP: {Colors.WHITE}")
        
        print(f"\n{Emoji.LOADING} {Colors.CYAN}Running comprehensive diagnostics...")
        
        # Port scan
        print(f"\n{Emoji.SCAN} {Colors.YELLOW}Port Scan Results:")
        common_ports = [21, 22, 80, 443, 3306, 30120, 40120]
        port_results = self.scanner.scan_ports(ip, common_ports)
        for port, is_open in port_results.items():
            status = f"{Colors.GREEN}OPEN" if is_open else f"{Colors.RED}CLOSED"
            print(f"Port {port}: {status}{Colors.RESET}")
        
        # FiveM specific check
        print(f"\n{Emoji.SERVER} {Colors.YELLOW}FiveM Server Check:")
        server = self.scanner.scan_fivem_server(ip, 30120, True)
        if server['online']:
            self.scanner.display_server(server, True)
        else:
            print(f"{Emoji.ERROR} {Colors.RED}No FiveM server detected on standard port 30120")
        
        # Geolocation
        if geoip_reader:
            print(f"\n{Emoji.GLOBE} {Colors.YELLOW}Geolocation Info:")
            geo = self.scanner.get_geolocation(ip)
            if geo:
                print(f"Country: {geo.get('country', 'N/A')}")
                print(f"City: {geo.get('city', 'N/A')}")
                print(f"ISP: {geo.get('isp', 'N/A')}")
                print(f"Coordinates: {geo.get('latitude', 'N/A')}, {geo.get('longitude', 'N/A')}")
            else:
                print(f"{Emoji.ERROR} {Colors.RED}Geolocation data not available")
        
        # DNS check if it's a domain
        if re.match(r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", ip):
            print(f"\n{Emoji.NETWORK} {Colors.YELLOW}DNS Information:")
            dns_info = self.scanner.get_dns_info(ip)
            if dns_info:
                for qtype, records in dns_info.items():
                    if records:
                        print(f"{qtype}: {', '.join(records)}")
            else:
                print(f"{Emoji.ERROR} {Colors.RED}DNS lookup failed")
        
        # WHOIS if it's a domain
        if re.match(r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", ip):
            print(f"\n{Emoji.SPY} {Colors.YELLOW}WHOIS Information:")
            whois_info = self.scanner.get_whois(ip)
            if whois_info:
                print(f"Registrar: {whois_info.registrar or 'N/A'}")
                print(f"Creation Date: {whois_info.creation_date or 'N/A'}")
                print(f"Expiration Date: {whois_info.expiration_date or 'N/A'}")
                print(f"Name Servers: {', '.join(whois_info.name_servers) if whois_info.name_servers else 'N/A'}")
            else:
                print(f"{Emoji.ERROR} {Colors.RED}WHOIS lookup failed")
    
    def network_tools(self):
        print_banner()
        print(f"\n{Emoji.NETWORK} {Colors.CYAN}Network Tools")
        print(f"{Colors.GREEN}1️⃣ {Colors.WHITE}Ping Test")
        print(f"{Colors.GREEN}2️⃣ {Colors.WHITE}Traceroute")
        print(f"{Colors.GREEN}3️⃣ {Colors.WHITE}DNS Lookup")
        print(f"{Colors.GREEN}4️⃣ {Colors.WHITE}WHOIS Lookup")
        print(f"{Colors.GREEN}0️⃣ {Colors.WHITE}Back to Main Menu")
        
        choice = input(f"\n{Emoji.TURBINE} {Colors.CYAN}Enter your choice: ")
        
        if choice == '1':
            target = input(f"{Colors.YELLOW}Enter target IP/hostname: {Colors.WHITE}")
            self.run_ping(target)
        elif choice == '2':
            target = input(f"{Colors.YELLOW}Enter target IP/hostname: {Colors.WHITE}")
            self.run_traceroute(target)
        elif choice == '3':
            domain = input(f"{Colors.YELLOW}Enter domain: {Colors.WHITE}")
            self.run_dns_lookup(domain)
        elif choice == '4':
            target = input(f"{Colors.YELLOW}Enter IP/domain: {Colors.WHITE}")
            self.run_whois(target)
        elif choice == '0':
            return
        else:
            print(f"\n{Emoji.ERROR} {Colors.RED}Invalid choice!")
    
    def run_ping(self, target):
        param = '-n' if platform.system().lower() == 'windows' else '-c'
        count = '4'
        
        try:
            print(f"\n{Emoji.PING} {Colors.CYAN}Pinging {target}...")
            output = subprocess.check_output(['ping', param, count, target], stderr=subprocess.STDOUT, universal_newlines=True)
            print(output)
        except subprocess.CalledProcessError as e:
            print(f"{Emoji.ERROR} {Colors.RED}Ping failed: {e.output}")
    
    def run_traceroute(self, target):
        param = '-d' if platform.system().lower() == 'windows' else ''
        cmd = 'tracert' if platform.system().lower() == 'windows' else 'traceroute'
        
        try:
            print(f"\n{Emoji.RADAR} {Colors.CYAN}Tracing route to {target}...")
            subprocess.run([cmd, param, target])
        except FileNotFoundError:
            print(f"{Emoji.ERROR} {Colors.RED}Traceroute utility not found!")
    
    def run_dns_lookup(self, domain):
        print(f"\n{Emoji.NETWORK} {Colors.CYAN}DNS Lookup for {domain}:")
        dns_info = self.scanner.get_dns_info(domain)
        
        if dns_info:
            for qtype, records in dns_info.items():
                if records:
                    print(f"\n{Colors.YELLOW}{qtype} Records:")
                    for record in records:
                        print(f"  {Colors.WHITE}{record}")
        else:
            print(f"{Emoji.ERROR} {Colors.RED}DNS lookup failed")
    
    def run_whois(self, target):
        print(f"\n{Emoji.SPY} {Colors.CYAN}WHOIS Lookup for {target}:")
        whois_info = self.scanner.get_whois(target)
        
        if whois_info:
            print(f"\n{Colors.YELLOW}Registrar: {Colors.WHITE}{whois_info.registrar or 'N/A'}")
            print(f"{Colors.YELLOW}Creation Date: {Colors.WHITE}{whois_info.creation_date or 'N/A'}")
            print(f"{Colors.YELLOW}Expiration Date: {Colors.WHITE}{whois_info.expiration_date or 'N/A'}")
            
            if whois_info.name_servers:
                print(f"\n{Colors.YELLOW}Name Servers:")
                for ns in whois_info.name_servers:
                    print(f"  {Colors.WHITE}{ns}")
        else:
            print(f"{Emoji.ERROR} {Colors.RED}WHOIS lookup failed")
    
    def bruteforce_menu(self):
        print_banner()
        print(f"\n{Emoji.BOMB} {Colors.RED}Server Bruteforcer")
        print(f"{Emoji.WARNING} {Colors.YELLOW}Warning: This feature is for authorized penetration testing only!")
        print(f"{Colors.GREEN}1️⃣ {Colors.WHITE}Common Credentials Test")
        print(f"{Colors.GREEN}2️⃣ {Colors.WHITE}Custom Wordlist Attack")
        print(f"{Colors.GREEN}0️⃣ {Colors.WHITE}Back to Main Menu")
        
        choice = input(f"\n{Emoji.TURBINE} {Colors.CYAN}Enter your choice: ")
        
        if choice == '1':
            self.common_credentials_test()
        elif choice == '2':
            self.custom_wordlist_attack()
        elif choice == '0':
            return
        else:
            print(f"\n{Emoji.ERROR} {Colors.RED}Invalid choice!")
    
    def common_credentials_test(self):
        print(f"\n{Emoji.BOMB} {Colors.RED}Common Credentials Test")
        target = input(f"{Colors.YELLOW}Enter target IP: {Colors.WHITE}")
        port = input(f"{Colors.YELLOW}Enter port (default 30120): {Colors.WHITE}") or "30120"
        
        common_creds = [
            ('admin', 'admin'),
            ('admin', 'password'),
            ('root', 'toor'),
            ('fivem', 'fivem'),
            ('server', 'server'),
            ('user', 'user')
        ]
        
        print(f"\n{Emoji.LOADING} {Colors.CYAN}Testing common credentials...")
        
        for username, password in common_creds:
            # Implement your actual auth testing logic here
            # This is just a placeholder
            print(f"Trying {username}:{password}")
            time.sleep(0.5)
        
        print(f"\n{Emoji.ERROR} {Colors.RED}This feature is not fully implemented yet.")
    
    def custom_wordlist_attack(self):
        print(f"\n{Emoji.BOMB} {Colors.RED}Custom Wordlist Attack")
        print(f"{Emoji.ERROR} {Colors.RED}This feature is not implemented in this version.")
    
    def settings_menu(self):
        print_banner()
        print(f"\n{Emoji.SHIELD} {Colors.CYAN}Settings")
        print(f"{Colors.GREEN}1️⃣ {Colors.WHITE}Configure Shodan API Key")
        print(f"{Colors.GREEN}2️⃣ {Colors.WHITE}Set Scan Timeout (Current: {Config.TIMEOUT}s)")
        print(f"{Colors.GREEN}3️⃣ {Colors.WHITE}Set Max Threads (Current: {Config.MAX_THREADS})")
        print(f"{Colors.GREEN}0️⃣ {Colors.WHITE}Back to Main Menu")
        
        choice = input(f"\n{Emoji.TURBINE} {Colors.CYAN}Enter your choice: ")
        
        if choice == '1':
            new_key = input(f"{Colors.YELLOW}Enter Shodan API Key: {Colors.WHITE}")
            Config.SHODAN_API_KEY = new_key
            if new_key != "YOUR_SHODAN_API_KEY":
                self.scanner.shodan = shodan.Shodan(new_key)
            print(f"{Emoji.SUCCESS} {Colors.GREEN}Shodan API key updated!")
        elif choice == '2':
            try:
                new_timeout = int(input(f"{Colors.YELLOW}Enter new timeout (seconds): {Colors.WHITE}"))
                Config.TIMEOUT = new_timeout
                print(f"{Emoji.SUCCESS} {Colors.GREEN}Timeout updated to {new_timeout} seconds!")
            except ValueError:
                print(f"{Emoji.ERROR} {Colors.RED}Invalid number!")
        elif choice == '3':
            try:
                new_threads = int(input(f"{Colors.YELLOW}Enter new max threads (1-500): {Colors.WHITE}"))
                if 1 <= new_threads <= 500:
                    Config.MAX_THREADS = new_threads
                    print(f"{Emoji.SUCCESS} {Colors.GREEN}Max threads updated to {new_threads}!")
                else:
                    print(f"{Emoji.ERROR} {Colors.RED}Please enter a value between 1 and 500!")
            except ValueError:
                print(f"{Emoji.ERROR} {Colors.RED}Invalid number!")
        elif choice == '0':
            return
        else:
            print(f"\n{Emoji.ERROR} {Colors.RED}Invalid choice!")

# 🚀 Entry Point
if __name__ == "__main__":
    try:
        cli = BlackTurbineCLI()
        cli.run()
    except KeyboardInterrupt:
        print(f"\n{Emoji.SKULL} {Colors.RED}BlackTurbine terminated by user!")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Emoji.ERROR} {Colors.RED}Fatal error: {str(e)}")
        sys.exit(1)
