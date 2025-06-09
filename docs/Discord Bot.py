#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import discord
from discord.ext import commands
import os
import sys
import time
import socket
import requests
import json
import concurrent.futures
import threading
import random
from datetime import datetime
import pyfiglet
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
from discord import Embed, Color, File
import asyncio
import aiohttp
import io

# 🌪️ Initialization
intents = discord.Intents.default()
intents.message_content = True
bot = commands.Bot(command_prefix='!', intents=intents, help_command=None)
ua = UserAgent()
VERSION = "4.0.0"
BANNER = pyfiglet.figlet_format("BlackTurbine", font="slant")

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
    INFO = "ℹ️"
    GEAR = "⚙️"
    HAMMER = "🔨"
    MAG = "🔎"
    CLOCK = "🕒"
    FLAG = "🏁"

# 🔧 Configuration
class Config:
    TIMEOUT = 7
    MAX_THREADS = 100
    SHODAN_API_KEY = ""           #Must Fill This  !!!
    MAX_PING = 500
    SCAN_DELAY = 0.2
    USER_AGENT = f"BlackTurbine/{VERSION}"
    GEOIP_DB = "GeoLite2-City.mmdb"
    BOT_TOKEN = "MTM4MDMxNzE1NjUyMDEwNDA4Ng.G5cvDJ.mo2sUeu8MKi4uXFH3SB6wZSvcLwJMWd0CRbF4w"  # Replace with your bot token

# 🌐 GeoIP Reader
try:
    geoip_reader = geoip2.database.Reader(Config.GEOIP_DB)
except:
    geoip_reader = None

# 💣 Core Scanner Class
class BlackTurbine:
    def __init__(self):
        self.active_scans = 0
        self.total_servers_found = 0
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': Config.USER_AGENT})
        self.nm = nmap.PortScanner() if 'nmap' in sys.modules else None
        self.shodan = shodan.Shodan(Config.SHODAN_API_KEY) if Config.SHODAN_API_KEY != "YOUR_SHODAN_API_KEY" else None

    async def is_port_open(self, ip, port, timeout=Config.TIMEOUT):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            sock.close()
            return result == 0
        except:
            return False

    async def get_geolocation(self, ip):
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

    async def get_dns_info(self, domain):
        try:
            result = {}
            for qtype in ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA']:
                answers = dns.resolver.resolve(domain, qtype, raise_on_no_answer=False)
                result[qtype] = [str(r) for r in answers]
            return result
        except:
            return None

    async def get_whois(self, domain_or_ip):
        try:
            return whois.whois(domain_or_ip)
        except:
            return None

    async def scan_fivem_server(self, ip, port=30120, full_scan=False):
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
            
            if not await self.is_port_open(ip, port):
                return server_info
            
            info_url = f"http://{ip}:{port}/info.json"
            async with aiohttp.ClientSession() as session:
                async with session.get(info_url, timeout=aiohttp.ClientTimeout(total=Config.TIMEOUT)) as response:
                    if response.status == 200:
                        server_info['online'] = True
                        server_info['ping'] = round((time.time() - start_time) * 1000)
                        data = await response.json()
                        
                        server_info.update({
                            'hostname': data.get('hostname', 'N/A'),
                            'version': data.get('version', 'N/A'),
                            'map': data.get('mapname', 'N/A'),
                            'gametype': data.get('gametype', 'N/A'),
                            'vars': data.get('vars', {})
                        })
                        
                        server_info['max_players'] = data.get('vars', {}).get('sv_maxClients', 0)
                        
                        players_url = f"http://{ip}:{port}/players.json"
                        try:
                            async with session.get(players_url, timeout=aiohttp.ClientTimeout(total=Config.TIMEOUT)) as players_response:
                                if players_response.status == 200:
                                    players_data = await players_response.json()
                                    server_info['players'] = len(players_data)
                        except:
                            pass
                        
                        if full_scan:
                            resources_url = f"http://{ip}:{port}/resources.json"
                            try:
                                async with session.get(resources_url, timeout=aiohttp.ClientTimeout(total=Config.TIMEOUT)) as resources_response:
                                    if resources_response.status == 200:
                                        server_info['resources'] = await resources_response.json()
                            except:
                                pass
                            
                            server_info['geolocation'] = await self.get_geolocation(ip)
                            server_info['security']['http_headers'] = dict(response.headers)
                            server_info['security']['vulnerabilities'] = await self.check_vulnerabilities(ip, port)
                        
                        self.total_servers_found += 1
                        return server_info
            
        except Exception as e:
            if full_scan:
                server_info['error'] = str(e)
        
        return server_info

    async def check_vulnerabilities(self, ip, port):
        vulns = {}
        vulns['open_ports'] = await self.scan_ports(ip, [80, 443, 22, 3306, 5432])
        
        try:
            version_url = f"http://{ip}:{port}/version.txt"
            async with aiohttp.ClientSession() as session:
                async with session.get(version_url, timeout=aiohttp.ClientTimeout(total=Config.TIMEOUT)) as version_resp:
                    if version_resp.status == 200:
                        vulns['version_info'] = await version_resp.text()
        except:
            pass
        
        return vulns

    async def scan_ports(self, ip, ports):
        results = {}
        with ThreadPoolExecutor(max_workers=Config.MAX_THREADS) as executor:
            loop = asyncio.get_event_loop()
            futures = [loop.run_in_executor(executor, self.is_port_open, ip, port) for port in ports]
            for port, future in zip(ports, await asyncio.gather(*futures)):
                results[port] = future
        return results

    async def mass_scan(self, ip_list, port=30120, full_scan=False):
        results = []
        total = len(ip_list)
        
        with tqdm(total=total, desc=f"{Emoji.RADAR} Scanning IPs", unit="server") as pbar:
            with ThreadPoolExecutor(max_workers=Config.MAX_THREADS) as executor:
                loop = asyncio.get_event_loop()
                futures = [loop.run_in_executor(executor, self.scan_fivem_server, ip, port, full_scan) for ip in ip_list]
                for future in await asyncio.gather(*futures):
                    if future['online']:
                        results.append(future)
                    pbar.update(1)
        
        return results

    async def scan_ip_range(self, start_ip, end_ip, port=30120, full_scan=False):
        results = []
        ip_range = await self.generate_ip_range(start_ip, end_ip)
        total = len(ip_range)
        
        with tqdm(total=total, desc=f"{Emoji.SCAN} Progress", unit="IP") as pbar:
            with ThreadPoolExecutor(max_workers=Config.MAX_THREADS) as executor:
                loop = asyncio.get_event_loop()
                futures = [loop.run_in_executor(executor, self.scan_fivem_server, ip, port, full_scan) for ip in ip_range]
                for future in await asyncio.gather(*futures):
                    if future['online']:
                        results.append(future)
                    pbar.update(1)
        
        return results

    async def generate_ip_range(self, start_ip, end_ip):
        start = list(map(int, start_ip.split('.')))
        end = list(map(int, end_ip.split('.')))
        ip_range = []
        
        for a in range(start[0], end[0] + 1):
            for b in range(start[1], end[1] + 1):
                for c in range(start[2], end[2] + 1):
                    for d in range(start[3], end[3] + 1):
                        ip_range.append(f"{a}.{b}.{c}.{d}")
        
        return ip_range

    async def shodan_scan(self, query="FiveM", limit=100):
        if not self.shodan:
            return []
        
        try:
            results = self.shodan.search(query, limit=limit)
            servers = []
            
            for result in results['matches']:
                if '30120' in result.get('ports', []):
                    server = await self.scan_fivem_server(result['ip_str'], 30120, True)
                    if server['online']:
                        servers.append(server)
            
            return servers
        except Exception as e:
            print(f"Shodan error: {str(e)}")
            return []

scanner = BlackTurbine()

# 🎨 Discord Embed Utilities
async def create_embed(title, description="", color=Color.blue()):
    embed = Embed(
        title=f"{Emoji.TURBINE} {title}",
        description=description,
        color=color,
        timestamp=datetime.utcnow()
    )
    embed.set_footer(text=f"BlackTurbine v{VERSION} | {Emoji.SHIELD} Elite License")
    return embed

async def server_embed(server, detailed=False):
    status_color = Color.green() if server['online'] else Color.red()
    ping_color = Color.green() if server['ping'] < 100 else Color.gold() if server['ping'] < 300 else Color.red()
    
    embed = await create_embed(
        f"FiveM Server Found {Emoji.SERVER}",
        f"**{server['hostname']}**",
        status_color
    )
    
    embed.add_field(name=f"{Emoji.NETWORK} IP:Port", value=f"`{server['ip']}:{server['port']}`", inline=True)
    embed.add_field(name=f"{Emoji.PING} Ping", value=f"{server['ping']} ms", inline=True)
    embed.add_field(name=f"{Emoji.PLAYER} Players", value=f"{server['players']}/{server['max_players']}", inline=True)
    
    if detailed:
        embed.add_field(name=f"{Emoji.INFO} Version", value=server['version'], inline=True)
        embed.add_field(name=f"{Emoji.MAG} Map", value=server['map'], inline=True)
        embed.add_field(name=f"{Emoji.GAME} Gametype", value=server['gametype'], inline=True)
        
        if server['geolocation']:
            geo = server['geolocation']
            embed.add_field(
                name=f"{Emoji.GLOBE} Location", 
                value=f"{geo.get('city', 'N/A')}, {geo.get('country', 'N/A')}",
                inline=True
            )
            embed.add_field(name=f"{Emoji.SATELLITE} ISP", value=geo.get('isp', 'N/A'), inline=True)
            embed.add_field(
                name=f"{Emoji.PUSHPIN} Coordinates", 
                value=f"{geo.get('latitude', 'N/A')}, {geo.get('longitude', 'N/A')}",
                inline=True
            )
        
        if server['resources']:
            embed.add_field(
                name=f"{Emoji.TOOLS} Resources", 
                value=f"{len(server['resources'])} loaded",
                inline=False
            )
        
        if server['vars']:
            vars_str = "\n".join([f"`{k}: {v}`" for k, v in list(server['vars'].items())[:5]])
            if len(server['vars']) > 5:
                vars_str += f"\n...and {len(server['vars']) - 5} more"
            embed.add_field(name=f"{Emoji.GEAR} Server Vars", value=vars_str, inline=False)
    
    return embed

# 🤖 Discord Bot Commands
@bot.event
async def on_ready():
    print(f'{bot.user.name} has connected to Discord!')
    await bot.change_presence(activity=discord.Activity(
        type=discord.ActivityType.watching,
        name=f"!help | v{VERSION}"
    ))

@bot.command(name='help')
async def help_command(ctx):
    """Show all available commands"""
    embed = await create_embed(
        "BlackTurbine Help Menu",
        f"{Emoji.INFO} All commands start with `!` prefix\n",
        Color.gold()
    )
    
    commands = [
        ("`!scan <ip> [port]`", "Scan a single FiveM server"),
        ("`!fullscan <ip> [port]`", "Full detailed scan of a server"),
        ("`!scanrange <start_ip> <end_ip> [port]`", "Scan IP range for FiveM servers"),
        ("`!scanfile`", "Upload a file with IPs to scan (one per line)"),
        ("`!shodan [query] [limit]`", "Search Shodan for FiveM servers"),
        ("`!diagnose <ip>`", "Run advanced diagnostics on a server"),
        ("`!ping <ip/hostname>`", "Ping a server"),
        ("`!traceroute <ip/hostname>`", "Trace route to a server"),
        ("`!dns <domain>`", "DNS lookup for a domain"),
        ("`!whois <domain/ip>`", "WHOIS lookup"),
        ("`!settings`", "View current settings"),
        ("`!help`", "Show this help menu")
    ]
    
    for cmd, desc in commands:
        embed.add_field(name=cmd, value=desc, inline=False)
    
    await ctx.send(embed=embed)

@bot.command(name='scan')
async def scan_server(ctx, ip: str, port: int = 30120):
    """Scan a single FiveM server"""
    msg = await ctx.send(f"{Emoji.LOADING} Scanning server `{ip}:{port}`...")
    
    try:
        server = await scanner.scan_fivem_server(ip, port)
        if server['online']:
            embed = await server_embed(server)
            await msg.edit(content=None, embed=embed)
        else:
            await msg.edit(content=f"{Emoji.ERROR} Server is offline or not a FiveM server")
    except Exception as e:
        await msg.edit(content=f"{Emoji.ERROR} Error scanning server: {str(e)}")

@bot.command(name='fullscan')
async def full_scan(ctx, ip: str, port: int = 30120):
    """Perform a full detailed scan of a server"""
    msg = await ctx.send(f"{Emoji.LOADING} Performing full scan of `{ip}:{port}`...")
    
    try:
        server = await scanner.scan_fivem_server(ip, port, True)
        if server['online']:
            embed = await server_embed(server, True)
            
            # Add vulnerabilities if found
            if server['security'] and server['security'].get('vulnerabilities'):
                vulns = server['security']['vulnerabilities']
                vuln_text = []
                
                if vulns.get('open_ports'):
                    open_ports = [p for p, is_open in vulns['open_ports'].items() if is_open]
                    if open_ports:
                        vuln_text.append(f"🔓 Open ports: {', '.join(map(str, open_ports))}")
                
                if vulns.get('version_info'):
                    vuln_text.append(f"ℹ️ Version info: {vulns['version_info']}")
                
                if vuln_text:
                    embed.add_field(
                        name=f"{Emoji.WARNING} Potential Vulnerabilities",
                        value="\n".join(vuln_text),
                        inline=False
                    )
            
            await msg.edit(content=None, embed=embed)
        else:
            await msg.edit(content=f"{Emoji.ERROR} Server is offline or not a FiveM server")
    except Exception as e:
        await msg.edit(content=f"{Emoji.ERROR} Error scanning server: {str(e)}")

@bot.command(name='scanrange')
async def scan_range(ctx, start_ip: str, end_ip: str, port: int = 30120):
    """Scan an IP range for FiveM servers"""
    if len(start_ip.split('.')) != 4 or len(end_ip.split('.')) != 4:
        await ctx.send(f"{Emoji.ERROR} Invalid IP format. Use XXX.XXX.XXX.XXX")
        return
    
    msg = await ctx.send(f"{Emoji.RADAR} Scanning range `{start_ip}` to `{end_ip}` on port `{port}`...")
    
    try:
        results = await scanner.scan_ip_range(start_ip, end_ip, port)
        
        if not results:
            await msg.edit(content=f"{Emoji.ERROR} No FiveM servers found in the specified range")
            return
        
        # Send first 5 results immediately
        for server in results[:5]:
            embed = await server_embed(server)
            await ctx.send(embed=embed)
        
        # Save all results to file and send
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"scan_results_{timestamp}.json"
        
        with open(filename, 'w') as f:
            json.dump(results, f, indent=2)
        
        with open(filename, 'rb') as f:
            await ctx.send(
                f"{Emoji.DATA} Found {len(results)} servers. Full results:",
                file=File(f, filename)
            )
        
        os.remove(filename)
        await msg.delete()
        
    except Exception as e:
        await msg.edit(content=f"{Emoji.ERROR} Error scanning range: {str(e)}")

@bot.command(name='scanfile')
async def scan_file(ctx):
    """Scan multiple servers from an uploaded file"""
    if not ctx.message.attachments:
        await ctx.send(f"{Emoji.ERROR} Please upload a file with IPs (one per line)")
        return
    
    attachment = ctx.message.attachments[0]
    if attachment.size > 1024 * 1024:  # 1MB limit
        await ctx.send(f"{Emoji.ERROR} File too large (max 1MB)")
        return
    
    msg = await ctx.send(f"{Emoji.LOADING} Processing file...")
    
    try:
        content = (await attachment.read()).decode('utf-8')
        ip_list = [line.strip() for line in content.splitlines() if line.strip()]
        
        if not ip_list:
            await msg.edit(content=f"{Emoji.ERROR} No valid IPs found in file")
            return
        
        await msg.edit(content=f"{Emoji.RADAR} Scanning {len(ip_list)} IPs from file...")
        
        results = await scanner.mass_scan(ip_list)
        
        if not results:
            await msg.edit(content=f"{Emoji.ERROR} No FiveM servers found in the file")
            return
        
        # Send summary
        embed = await create_embed(
            "File Scan Results",
            f"**Scanned IPs:** {len(ip_list)}\n"
            f"**Servers Found:** {len(results)}\n"
            f"**Success Rate:** {len(results)/len(ip_list)*100:.2f}%",
            Color.green()
        )
        await ctx.send(embed=embed)
        
        # Send first 5 results
        for server in results[:5]:
            embed = await server_embed(server)
            await ctx.send(embed=embed)
        
        # Save all results to file
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"file_scan_{timestamp}.json"
        
        with open(filename, 'w') as f:
            json.dump(results, f, indent=2)
        
        with open(filename, 'rb') as f:
            await ctx.send(
                f"{Emoji.DATA} Full scan results:",
                file=File(f, filename)
            )
        
        os.remove(filename)
        await msg.delete()
        
    except Exception as e:
        await msg.edit(content=f"{Emoji.ERROR} Error processing file: {str(e)}")

@bot.command(name='shodan')
async def shodan_search(ctx, query: str = "FiveM", limit: int = 50):
    """Search Shodan for FiveM servers"""
    if not scanner.shodan:
        await ctx.send(f"{Emoji.ERROR} Shodan API key not configured")
        return
    
    if limit > 100:
        await ctx.send(f"{Emoji.WARNING} Limit capped at 100 for performance")
        limit = 100
    
    msg = await ctx.send(f"{Emoji.SPY} Searching Shodan for '{query}' (limit: {limit})...")
    
    try:
        results = await scanner.shodan_scan(query, limit)
        
        if not results:
            await msg.edit(content=f"{Emoji.ERROR} No FiveM servers found via Shodan")
            return
        
        # Send summary
        embed = await create_embed(
            "Shodan Search Results",
            f"**Query:** `{query}`\n"
            f"**Servers Found:** {len(results)}",
            Color.blue()
        )
        
        # Add top 5 servers to embed
        for i, server in enumerate(results[:5]):
            embed.add_field(
                name=f"{i+1}. {server['hostname']}",
                value=(
                    f"IP: `{server['ip']}:{server['port']}`\n"
                    f"Players: {server['players']}/{server['max_players']}\n"
                    f"Ping: {server['ping']}ms"
                ),
                inline=False
            )
        
        await ctx.send(embed=embed)
        
        # Save all results to file
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"shodan_results_{timestamp}.json"
        
        with open(filename, 'w') as f:
            json.dump(results, f, indent=2)
        
        with open(filename, 'rb') as f:
            await ctx.send(
                f"{Emoji.DATA} Full Shodan results:",
                file=File(f, filename)
            )
        
        os.remove(filename)
        await msg.delete()
        
    except Exception as e:
        await msg.edit(content=f"{Emoji.ERROR} Shodan error: {str(e)}")

@bot.command(name='diagnose')
async def diagnose(ctx, ip: str):
    """Run advanced diagnostics on a server"""
    msg = await ctx.send(f"{Emoji.TOOLS} Running diagnostics on `{ip}`...")
    
    try:
        # Port scan
        port_results = await scanner.scan_ports(ip, [21, 22, 80, 443, 3306, 30120, 40120])
        open_ports = [str(p) for p, is_open in port_results.items() if is_open]
        
        # FiveM scan
        server = await scanner.scan_fivem_server(ip, 30120, True)
        
        # Geolocation
        geo = await scanner.get_geolocation(ip)
        
        # Create diagnostic embed
        embed = await create_embed(
            f"Server Diagnostics {Emoji.MAG}",
            f"Target: `{ip}`",
            Color.dark_gold()
        )
        
        # Port scan results
        if open_ports:
            embed.add_field(
                name=f"{Emoji.SCAN} Open Ports",
                value=", ".join(open_ports),
                inline=False
            )
        else:
            embed.add_field(
                name=f"{Emoji.SCAN} Open Ports",
                value="No common ports open",
                inline=False
            )
        
        # FiveM server status
        if server['online']:
            embed.add_field(
                name=f"{Emoji.SERVER} FiveM Server",
                value="✅ Online",
                inline=True
            )
            embed.add_field(
                name=f"{Emoji.PLAYER} Players",
                value=f"{server['players']}/{server['max_players']}",
                inline=True
            )
            embed.add_field(
                name=f"{Emoji.PING} Ping",
                value=f"{server['ping']} ms",
                inline=True
            )
        else:
            embed.add_field(
                name=f"{Emoji.SERVER} FiveM Server",
                value="❌ Offline or not a FiveM server",
                inline=False
            )
        
        # Geolocation
        if geo:
            embed.add_field(
                name=f"{Emoji.GLOBE} Location",
                value=f"{geo.get('city', 'N/A')}, {geo.get('country', 'N/A')}",
                inline=True
            )
            embed.add_field(
                name=f"{Emoji.SATELLITE} ISP",
                value=geo.get('isp', 'N/A'),
                inline=True
            )
            embed.add_field(
                name=f"{Emoji.PUSHPIN} Coordinates",
                value=f"{geo.get('latitude', 'N/A')}, {geo.get('longitude', 'N/A')}",
                inline=True
            )
        
        # DNS info if it's a domain
        if re.match(r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", ip):
            dns_info = await scanner.get_dns_info(ip)
            if dns_info:
                dns_text = []
                for qtype, records in dns_info.items():
                    if records:
                        dns_text.append(f"**{qtype}:** {', '.join(records[:3])}{'...' if len(records) > 3 else ''}")
                
                if dns_text:
                    embed.add_field(
                        name=f"{Emoji.NETWORK} DNS Info",
                        value="\n".join(dns_text),
                        inline=False
                    )
        
        await msg.edit(content=None, embed=embed)
        
    except Exception as e:
        await msg.edit(content=f"{Emoji.ERROR} Diagnostic error: {str(e)}")

@bot.command(name='ping')
async def ping(ctx, target: str):
    """Ping a server"""
    msg = await ctx.send(f"{Emoji.PING} Pinging `{target}`...")
    
    try:
        param = '-n' if platform.system().lower() == 'windows' else '-c'
        count = '4'
        
        process = await asyncio.create_subprocess_exec(
            'ping', param, count, target,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        
        stdout, stderr = await process.communicate()
        
        if process.returncode == 0:
            output = stdout.decode('utf-8')
            await msg.edit(content=f"```\n{output[:1900]}\n```")
        else:
            await msg.edit(content=f"{Emoji.ERROR} Ping failed:\n```\n{stderr.decode('utf-8')}\n```")
    except Exception as e:
        await msg.edit(content=f"{Emoji.ERROR} Ping error: {str(e)}")

@bot.command(name='traceroute')
async def traceroute(ctx, target: str):
    """Trace route to a server"""
    msg = await ctx.send(f"{Emoji.RADAR} Tracing route to `{target}`...")
    
    try:
        cmd = 'tracert' if platform.system().lower() == 'windows' else 'traceroute'
        param = '-d' if platform.system().lower() == 'windows' else ''
        
        process = await asyncio.create_subprocess_exec(
            cmd, param, target,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        
        stdout, stderr = await process.communicate()
        
        if process.returncode == 0:
            output = stdout.decode('utf-8')
            await msg.edit(content=f"```\n{output[:1900]}\n```")
        else:
            await msg.edit(content=f"{Emoji.ERROR} Traceroute failed:\n```\n{stderr.decode('utf-8')}\n```")
    except FileNotFoundError:
        await msg.edit(content=f"{Emoji.ERROR} Traceroute utility not found")
    except Exception as e:
        await msg.edit(content=f"{Emoji.ERROR} Traceroute error: {str(e)}")

@bot.command(name='dns')
async def dns_lookup(ctx, domain: str):
    """Perform DNS lookup"""
    msg = await ctx.send(f"{Emoji.NETWORK} Looking up DNS records for `{domain}`...")
    
    try:
        dns_info = await scanner.get_dns_info(domain)
        
        if not dns_info:
            await msg.edit(content=f"{Emoji.ERROR} DNS lookup failed")
            return
        
        embed = await create_embed(
            f"DNS Lookup Results {Emoji.MAG}",
            f"Domain: `{domain}`",
            Color.blue()
        )
        
        for qtype, records in dns_info.items():
            if records:
                embed.add_field(
                    name=qtype,
                    value="\n".join(records[:5]) + ("\n..." if len(records) > 5 else ""),
                    inline=True
                )
        
        await msg.edit(content=None, embed=embed)
    except Exception as e:
        await msg.edit(content=f"{Emoji.ERROR} DNS lookup error: {str(e)}")

@bot.command(name='whois')
async def whois_lookup(ctx, target: str):
    """Perform WHOIS lookup"""
    msg = await ctx.send(f"{Emoji.SPY} Looking up WHOIS for `{target}`...")
    
    try:
        whois_info = await scanner.get_whois(target)
        
        if not whois_info:
            await msg.edit(content=f"{Emoji.ERROR} WHOIS lookup failed")
            return
        
        embed = await create_embed(
            f"WHOIS Lookup Results {Emoji.MAG}",
            f"Target: `{target}`",
            Color.blue()
        )
        
        if hasattr(whois_info, 'registrar'):
            embed.add_field(name="Registrar", value=whois_info.registrar or "N/A", inline=True)
        
        if hasattr(whois_info, 'creation_date'):
            if isinstance(whois_info.creation_date, list):
                creation_date = whois_info.creation_date[0] if whois_info.creation_date else "N/A"
            else:
                creation_date = whois_info.creation_date or "N/A"
            embed.add_field(name="Creation Date", value=str(creation_date), inline=True)
        
        if hasattr(whois_info, 'expiration_date'):
            if isinstance(whois_info.expiration_date, list):
                expiration_date = whois_info.expiration_date[0] if whois_info.expiration_date else "N/A"
            else:
                expiration_date = whois_info.expiration_date or "N/A"
            embed.add_field(name="Expiration Date", value=str(expiration_date), inline=True)
        
        if hasattr(whois_info, 'name_servers'):
            name_servers = whois_info.name_servers or []
            if name_servers:
                embed.add_field(
                    name="Name Servers",
                    value="\n".join(name_servers[:5]) + ("\n..." if len(name_servers) > 5 else ""),
                    inline=False
                )
        
        await msg.edit(content=None, embed=embed)
    except Exception as e:
        await msg.edit(content=f"{Emoji.ERROR} WHOIS lookup error: {str(e)}")

@bot.command(name='settings')
async def show_settings(ctx):
    """Show current scanner settings"""
    embed = await create_embed(
        f"Current Settings {Emoji.GEAR}",
        "",
        Color.dark_teal()
    )
    
    embed.add_field(name="Timeout", value=f"{Config.TIMEOUT}s", inline=True)
    embed.add_field(name="Max Threads", value=Config.MAX_THREADS, inline=True)
    embed.add_field(name="Shodan API", value="✅ Configured" if scanner.shodan else "❌ Not configured", inline=True)
    embed.add_field(name="GeoIP Database", value="✅ Loaded" if geoip_reader else "❌ Not loaded", inline=True)
    embed.add_field(name="User Agent", value=Config.USER_AGENT, inline=False)
    
    await ctx.send(embed=embed)

# 🚀 Start the bot
if __name__ == "__main__":
    bot.run(Config.BOT_TOKEN)
