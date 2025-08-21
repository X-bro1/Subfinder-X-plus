#!/usr/bin/env python3
import requests
import json
import argparse
import threading
import socket
import os
import re
import logging
import signal
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Set, Tuple, Optional
from dotenv import load_dotenv
from bs4 import BeautifulSoup
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, BarColumn, TimeRemainingColumn
from rich.layout import Layout
from rich.style import Style
import pyfiglet
from datetime import datetime

# === INIT RICH CONSOLE ===
console = Console()

# === CONFIGURATION === 
load_dotenv()
logging.basicConfig(level=logging.INFO, format="%(message)s")

# API Keys
SECURITYTRAILS_API_KEY = os.getenv("SECURITYTRAILS_API_KEY")
CENSYS_API_ID = os.getenv("CENSYS_API_ID")
CENSYS_API_SECRET = os.getenv("CENSYS_API_SECRET")
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

HEADERS = {"User-Agent": "Mozilla/5.0"}
DEFAULT_PORTS = [80, 443, 21, 22, 25, 8080, 8443]
socket.setdefaulttimeout(1.0)

# Global flag for graceful shutdown
shutdown_flag = False

# Global variables to store results for graceful shutdown
global_results = {
    'subs': set(),
    'per_source': {},
    'resolved': {},
    'ip_open_ports': {},
    'domain': '',
    'bruteforce_subs': set()
}

# === CREATE RESULTS FOLDER ===
def create_results_folder():
    """Create results folder if it doesn't exist"""
    if not os.path.exists("resultats"):
        os.makedirs("resultats")
        console.print("[green]✓ Created 'resultats' folder[/green]")

# === CTRL+C HANDLER ===
def signal_handler(sig, frame):
    global shutdown_flag
    if shutdown_flag:
        return  # Already shutting down
    
    console.print("\n[red]<<<<<>>>>>        Saving results and shutting down...   [/red]")
    shutdown_flag = True
    save_results_on_exit()
    sys.exit(0)

# Register signal handler
signal.signal(signal.SIGINT, signal_handler)

# === SAVE RESULTS ON EXIT ===
def save_results_on_exit():
    global global_results
    if not global_results['domain']:
        console.print("[yellow]<<<<<>>>>>     No domain scanned yet. Nothing to save.[/yellow]")
        return
    
    domain = global_results['domain']
    
    # Combine all subdomains
    all_subs = set(global_results['subs'])
    all_subs.update(global_results['bruteforce_subs'])
    
    for source_subs in global_results['per_source'].values():
        all_subs.update(source_subs)
    
    if not all_subs:
        console.print("[yellow]<<<<<>>>>>       No subdomains found to save.[/yellow]")
        return
    
    # Convert to sorted list
    subs_list = sorted(all_subs)
    
    # Create results folder
    create_results_folder()
    
    # Save raw results
    try:
        with open(f"resultats/resultat-{domain}.txt", "w", encoding="utf-8") as f:
            f.write("\n".join(subs_list))
        console.print(f"[green]📁 Raw results saved to [bold]resultats/resultat-{domain}.txt[/bold][/green]")
    except Exception as e:
        console.print(f"[red]❌ Error saving raw results: {e}[/red]")
    
    # Save HTML report
    try:
        html_content = generate_html_report(domain, subs_list, global_results['per_source'], 
                                          global_results['resolved'], global_results['ip_open_ports'])
        with open(f"resultats/rapport-{domain}.html", "w", encoding="utf-8") as f:
            f.write(html_content)
        console.print(f"[green]📁 HTML report saved to [bold]resultats/rapport-{domain}.html[/bold][/green]")
    except Exception as e:
        console.print(f"[red]❌ Error saving HTML report: {e}[/red]")
    
    # Save IPs
    if global_results['resolved']:
        try:
            save_ips_to_file(list(global_results['resolved'].values()), f"resultats/ips-{domain}.txt")
            console.print(f"[green]📁 IPs saved to [bold]resultats/ips-{domain}.txt[/bold][/green]")
        except Exception as e:
            console.print(f"[red]❌ Error saving IPs: {e}[/red]")
    
    # Afficher le message de support
    console.print("\n[bold yellow]<<<<<>>>>>         If you find this tool useful, please consider supporting its development by buying a coffee for X-Bro :   [/bold yellow]")
    console.print("[bold cyan]<<<<<>>>>>         https://ko-fi.com/xbro1         [/bold cyan]")

# === MODERN BANNER ===
def show_banner():
    banner = pyfiglet.figlet_format("SubFinder X+", font="slant")
    console.print(Panel.fit(
        f"[bold blue]{banner}[/bold blue]\n"
        f"[italic]                 Advanced Subdomain Discovery     [/italic]\n"
        f"[bold green]<<<<<>>>>>   Support the Project: https://ko-fi.com/xbro1   [/bold green]\n",
        border_style="blue",
        subtitle="[bold yellow]  Made By X-Bro  [/bold yellow]"
    ))

# === UTILITY FUNCTIONS ===
def normalize_domain(domain: str) -> str:
    try:
        return domain.encode("idna").decode("utf-8")
    except Exception:
        return domain

def clean_host(text: str) -> str:
    text = text.strip()
    if "://" in text:
        text = text.split("://", 1)[1]
    return text.split("/", 1)[0].strip()

def resolve(subdomain: str) -> Optional[str]:
    try:
        return socket.gethostbyname(subdomain)
    except:
        return None

def scan_ports(ip: str, ports: List[int] = DEFAULT_PORTS) -> List[int]:
    open_ports = []
    for port in ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1.0)
                if s.connect_ex((ip, port)) == 0:
                    open_ports.append(port)
        except:
            continue
    return open_ports

def reverse_dns_scrape(ip: str, domain: str) -> Set[str]:
    try:
        host, _, _ = socket.gethostbyaddr(ip)
        return {host} if host and host.endswith(domain) else set()
    except:
        return set()

def save_ips_to_file(ips: List[str], filename: str = "ips.txt") -> None:
    try:
        with open(filename, "w") as f:
            for ip in sorted(set(ips)):
                f.write(f"{ip.split(':')[0]}\n")
        console.print(f"[green]✓ IPs saved to {filename}[/green]")
    except Exception as e:
        console.print(f"[red]❌ Error saving IPs: {e}[/red]")

# === SOURCES ===
def from_crtsh(domain: str) -> Set[str]:
    if shutdown_flag: return set()
    try:
        r = requests.get(f"https://crt.sh/?q=%25.{domain}&output=json", timeout=15)
        data = r.json()
        return {sub.strip() for entry in data 
                for sub in entry.get("name_value", "").split("\n") 
                if sub.strip().endswith(domain)}
    except:
        return set()

def from_otx(domain: str) -> Set[str]:
    if shutdown_flag: return set()
    try:
        r = requests.get(f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns", timeout=15)
        return {entry["hostname"] for entry in r.json().get("passive_dns", []) 
                if entry.get("hostname","").endswith(domain)}
    except:
        return set()

def from_threatcrowd(domain: str) -> Set[str]:
    if shutdown_flag: return set()
    try:
        r = requests.get(f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={domain}", timeout=15)
        return set(r.json().get("subdomains", []))
    except:
        return set()

def from_anubis(domain: str) -> Set[str]:
    if shutdown_flag: return set()
    try:
        r = requests.get(f"https://jldc.me/anubis/subdomains/{domain}", timeout=15)
        return set(r.json())
    except:
        return set()

def from_hackertarget(domain: str) -> Set[str]:
    if shutdown_flag: return set()
    try:
        r = requests.get(f"https://api.hackertarget.com/hostsearch/?q={domain}", timeout=15)
        return {line.split(",")[0] for line in r.text.splitlines() 
                if line and domain in line}
    except:
        return set()

def from_bufferover(domain: str) -> Set[str]:
    if shutdown_flag: return set()
    try:
        r = requests.get(f"https://dns.bufferover.run/dns?q=.{domain}", timeout=15)
        return {parts[1] for entry in r.json().get("FDNS_A", []) or []
                if len(parts := entry.split(",")) > 1 
                and parts[1].endswith(domain)}
    except:
        return set()

def from_securitytrails(domain: str) -> Set[str]:
    if shutdown_flag: return set()
    if not SECURITYTRAILS_API_KEY:
        return set()
    try:
        r = requests.get(
            f"https://api.securitytrails.com/v1/domain/{domain}/subdomains",
            headers={"APIKEY": SECURITYTRAILS_API_KEY},
            timeout=15
        )
        return {f"{sub}.{domain}" for sub in r.json().get("subdomangs", [])}
    except:
        return set()

def from_censys(domain: str) -> Set[str]:
    if shutdown_flag: return set()
    if not (CENSYS_API_ID and CENSYS_API_SECRET):
        return set()
    try:
        r = requests.post(
            "https://search.censys.io/api/v2/hosts/search",
            auth=(CENSYS_API_ID, CENSYS_API_SECRET),
            headers={"Content-Type": "application/json"},
            json={"q": domain, "per_page": 100},
            timeout=20
        )
        return {result.get("name", "") for result in 
                r.json().get("result", {}).get("hits", []) or []
                if result.get("name","").endswith(domain)}
    except:
        return set()

def from_shodan(domain: str) -> Set[str]:
    if shutdown_flag: return set()
    if not SHODAN_API_KEY:
        return set()
    try:
        r = requests.get(f"https://api.shodan.io/dns/domain/{domain}?key={SHODAN_API_KEY}", timeout=15)
        return {f"{sub}.{domain}" for sub in r.json().get("subdomains", []) or []}
    except:
        return set()

def from_google(domain: str) -> Set[str]:
    if shutdown_flag: return set()
    subs = set()
    for start in range(0, 30, 10):
        try:
            url = f"https://www.google.com/search?q=site:*.{domain}&start={start}"
            r = requests.get(url, headers=HEADERS, timeout=10)
            soup = BeautifulSoup(r.text, "html.parser")
            subs.update(clean_host(cite.get_text()) for cite in soup.find_all("cite") 
                       if clean_host(cite.get_text()).endswith(domain))
        except:
            continue
    return subs

def from_bing(domain: str) -> Set[str]:
    if shutdown_flag: return set()
    subs = set()
    for page in range(1, 4):
        try:
            url = f"https://www.bing.com/search?q=site:*.{domain}&first={page*10}"
            r = requests.get(url, headers=HEADERS, timeout=10)
            soup = BeautifulSoup(r.text, "html.parser")
            subs.update(clean_host(cite.get_text()) for cite in soup.find_all("cite") 
                       if clean_host(cite.get_text()).endswith(domain))
        except:
            continue
    return subs

def from_urlscan(domain: str) -> Set[str]:
    if shutdown_flag: return set()
    try:
        url = f"https://urlscan.io/api/v1/search/?q=domain:{domain}"
        r = requests.get(url, headers=HEADERS, timeout=15)
        data = r.json()
        subs = set()
        for result in data.get("results", []):
            page_url = result.get("page", {}).get("url", "")
            if domain in page_url:
                subs.add(clean_host(page_url))
        return {s for s in subs if s.endswith(f".{domain}")}
    except Exception as e:
        console.print(f"[red]❌ URLScan error: {e}[/red]")
        return set()

def from_github(domain: str) -> Set[str]:
    if shutdown_flag: return set()
    subs = set()
    try:
        headers = {"Accept": "application/vnd.github.v3+json"}
        if GITHUB_TOKEN:
            headers["Authorization"] = f"token {GITHUB_TOKEN}"
        
        pattern = re.compile(
            rf"(?:(?:[a-z0-9-]+\.)+)?{re.escape(domain)}(?![a-z0-9-])", 
            re.IGNORECASE
        )
        
        url = f"https://api.github.com/search/code?q={domain}+in:file&per_page=100"
        r = requests.get(url, headers=headers, timeout=20)
        
        console.print("\n[bold white]>>>> Scanning GitHub...[/bold white]")
        
        for item in r.json().get("items", [])[:100]:
            try:
                content_url = item["html_url"].replace("github.com", "raw.githubusercontent.com").replace("/blob", "")
                content = requests.get(content_url, timeout=10).text
                matches = pattern.findall(content)
                subs.update(m.lower() for m in matches if m.endswith(domain))
            except:
                continue
        
        console.print(f"[white]• GitHub: [green]{len(subs)}[/green] subdomains found[/white]")
        return subs
    except Exception as e:
        console.print(f"[red]❌ GitHub error: {e}[/red]")
        return set()

def from_virustotal(domain: str) -> Set[str]:
    if shutdown_flag: return set()
    if not VIRUSTOTAL_API_KEY:
        return set()
    try:
        url = f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains"
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        r = requests.get(url, headers=headers, timeout=15)
        data = r.json()
        return {sub["id"] for sub in data.get("data", []) if domain in sub["id"]}
    except Exception as e:
        console.print(f"[red]❌ VirusTotal error: {e}[/red]")
        return set()

# === BRUTEFORCE ===
def bruteforce_subdomains(domain: str, wordlist_path: str, threads: int = 200) -> Set[str]:
    if shutdown_flag: return set()
    
    console.print(f"\n[bold yellow]>>>> Bruteforce (x{threads} threads)...[/bold yellow]")
    
    try:
        with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
            words = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        console.print("[red]>>>> Wordlist not found.[/red]")
        return set()

    candidates = set()
    for word in words:
        if shutdown_flag: return set()
        candidates.add(f"{word}.{domain}")

    valid = set()
    lock = threading.Lock()
    
    def check_subdomain(sub: str):
        if shutdown_flag: return
        try:
            if resolve(sub):
                with lock:
                    valid.add(sub)
        except:
            pass

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = [executor.submit(check_subdomain, sub) for sub in candidates]
        
        with Progress(
            BarColumn(complete_style="white"),
            "[progress.percentage]{task.percentage:>3.0f}%",
            TimeRemainingColumn(),
            console=console
        ) as progress:
            task = progress.add_task("[white]>>>> Checking...[/white]", total=len(futures))
            for _ in as_completed(futures):
                if shutdown_flag: 
                    executor.shutdown(wait=False, cancel_futures=True)
                    return valid
                progress.update(task, advance=1)
    
    return valid

# === MAIN SCAN FUNCTION ===
def find_subdomains(domain: str, resolve_dns: bool = False) -> Tuple[List[str], Dict[str, Set[str]], Dict[str, str], Dict[str, List[int]]]:
    domain = normalize_domain(domain)
    
    sources = [
        ("crt.sh", from_crtsh),
        ("OTX", from_otx),
        ("ThreatCrowd", from_threatcrowd),
        ("Anubis", from_anubis),
        ("HackerTarget", from_hackertarget),
        ("BufferOver", from_bufferover),
        ("SecurityTrails", from_securitytrails),
        ("Censys", from_censys),
        ("Shodan", from_shodan),
        ("Google", from_google),
        ("Bing", from_bing),
        ("VirusTotal", from_virustotal),
        ("URLScan.io", from_urlscan),
        ("GitHub", from_github),
    ]
    
    results = set()
    per_source = {name: set() for name, _ in sources}
    
    console.print("\n[bold white]>>>> Querying 14 sources...[/bold white]")
    with Progress(
        BarColumn(complete_style="white"),
        "[progress.percentage]{task.percentage:>3.0f}%",
        TimeRemainingColumn(),
        console=console
        ) as progress:
        task = progress.add_task("[white]>>>> Collecting data...[/white]", total=len(sources))
        
        for name, func in sources:
            if shutdown_flag: 
                return [], {}, {}, {}
            try:
                subs = func(domain)
                valid_subs = {s for s in subs if s.endswith(f".{domain}")}
                per_source[name] = valid_subs
                results.update(valid_subs)
                
                # Update global results incrementally
                global_results['per_source'][name] = valid_subs
                global_results['subs'].update(valid_subs)
                
                progress.update(task, advance=1, description=f"[white]>>>> Checking {name}[/white]")
                if name != "GitHub":  
                    console.print(f"[white]• {name}: [green]{len(valid_subs)}[/green] subdomains[/white]")
            except Exception as e:
                progress.update(task, advance=1, description=f"[red]>>>> Failed {name}[/red]")
                console.print(f"[red]✖ {name}: Error ({str(e)[:50]}...)[/red]")
                continue
    
    resolved = {}
    ip_open_ports = {}
    reverse_new = set()
    
    if resolve_dns and not shutdown_flag:
        console.print("\n[bold white]>>>> Resolving DNS...[/bold white]")
        with Progress(
            BarColumn(complete_style="white"),
            "[progress.percentage]{task.percentage:>3.0f}%",
            TimeRemainingColumn(),
            console=console
        ) as progress:
            task = progress.add_task("[white]Resolving IPs...[/white]", total=len(results))
            
            for sub in sorted(results):
                if shutdown_flag: 
                    return [], {}, {}, {}
                ip = resolve(sub)
                if ip:
                    resolved[sub] = ip
                progress.update(task, advance=1)
        
        # Update global results with resolved IPs
        global_results['resolved'].update(resolved)
        
        if not shutdown_flag:
            console.print("\n[bold white]>>>> Scanning ports...[/bold white]")
            unique_ips = list(set(resolved.values()))
            with Progress(
                BarColumn(complete_style="white"),
                "[progress.percentage]{task.percentage:>3.0f}%",
                TimeRemainingColumn(),
                console=console
            ) as progress:
                task = progress.add_task("[white]>>>> Scanning ports...[/white]", total=len(unique_ips))
                
                for ip in unique_ips:
                    if shutdown_flag: 
                        return [], {}, {}, {}
                    if ip not in ip_open_ports:
                        ip_open_ports[ip] = scan_ports(ip)
                    reverse_new.update(reverse_dns_scrape(ip, domain))
                    progress.update(task, advance=1)
            
            # Update global results with port scan results
            global_results['ip_open_ports'].update(ip_open_ports)
            
            if reverse_new:
                per_source["ReverseDNS"] = reverse_new
                results.update(reverse_new)
                global_results['per_source']["ReverseDNS"] = reverse_new
                global_results['subs'].update(reverse_new)
    
    return sorted(results), per_source, resolved, ip_open_ports

# === REPORT GENERATION ===
def generate_console_report(domain: str, subs: List[str], per_source: Dict[str, Set[str]], 
                          resolved: Dict[str, str], ip_open_ports: Dict[str, List[int]]) -> None:
    console.print(Panel.fit(
        f"[bold]SubFinder X+ Report for [blue]{domain}[/blue][/bold]",
        subtitle=f"[green]{len(subs)} subdomains | {len(resolved)} IPs resolved | {len(ip_open_ports)} hosts scanned[/green]",
        style="bold blue"
    ))
    
    source_table = Table(title="[bold]Source Contributions[/bold]", show_header=True, header_style="bold magenta")
    source_table.add_column("Source", style="cyan", no_wrap=True)
    source_table.add_column("Subdomains", justify="right")
    source_table.add_column("Coverage", justify="right")
    
    total = max(1, len(subs))
    for src in sorted(per_source, key=lambda x: len(per_source[x]), reverse=True):
        count = len(per_source[src])
        coverage = f"{(count / total) * 100:.1f}%"
        source_table.add_row(
            src,
            f"[green]{count}[/green]",
            f"[yellow]{coverage}[/yellow]"
        )
    
    console.print(Panel.fit(source_table))
    
    if ip_open_ports:
        port_table = Table(title="[bold]Open Ports[/bold]", show_lines=True)
        port_table.add_column("IP", style="magenta")
        port_table.add_column("Ports", style="green")
        port_table.add_column("Services", style="yellow")
        
        SERVICE_MAP = {
            80: "HTTP", 443: "HTTPS", 
            22: "SSH", 21: "FTP",
            25: "SMTP", 8080: "HTTP-Alt",
            8443: "HTTPS-Alt"
        }
        
        for ip, ports in sorted(ip_open_ports.items()):
            services = [SERVICE_MAP.get(p, str(p)) for p in sorted(ports)]
            port_table.add_row(
                ip,
                ", ".join(map(str, sorted(ports))),
                ", ".join(services)
            )
        
        console.print(Panel.fit(port_table))

def generate_html_report(domain: str, subs: List[str], per_source: Dict[str, Set[str]], 
                       resolved: Dict[str, str], ip_open_ports: Dict[str, List[int]]) -> str:
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    css = """
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 20px; color: #333; background-color: #f5f5f5; }
        .header { text-align: center; margin-bottom: 30px; padding: 20px 0; background-color: #4285f4; color: white; border-radius: 5px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
        .logo { font-size: 2.8em; font-weight: bold; margin-bottom: 5px; letter-spacing: 2px; }
        .subtitle { font-size: 1.2em; margin-bottom: 10px; }
        .version { font-size: 0.9em; color: #e0e0e0; }
        .content { background-color: white; padding: 20px; border-radius: 5px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); margin-bottom: 20px; }
        .stats { display: flex; justify-content: center; gap: 20px; margin: 20px 0; flex-wrap: wrap; }
        .stat-box { border: 1px solid #ddd; border-radius: 5px; padding: 15px; text-align: center; min-width: 150px; background-color: white; box-shadow: 0 1px 3px rgba(0,0,0,0.1); flex-grow: 1; }
        .stat-value { font-size: 1.8em; font-weight: bold; }
        .stat-label { color: #666; font-size: 0.9em; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th { background-color: #4285f4; color: white; padding: 12px 15px; text-align: left; }
        td { padding: 10px 15px; border-bottom: 1px solid #ddd; }
        tr:nth-child(even) { background-color: #f9f9f9; }
        tr:hover { background-color: #f1f1f1; }
        .source-table { margin-top: 30px; }
        .footer { margin-top: 30px; text-align: center; color: #666; font-size: 0.9em; padding: 15px; border-top: 1px solid #eee; }
        .domain-title { color: #4285f4; margin: 20px 0 10px; }
        .green { color: #0f9d58; }
        .blue { color: #4285f4; }
        .orange { color: #ff9800; }
        .red { color: #db4437; }
        .donate-section { text-align: center; margin: 30px 0; padding: 20px; background-color: #f8f9fa; border-radius: 5px; }
        .donate-button { display: inline-block; background-color: #ff5e5e; color: white; padding: 12px 24px; text-decoration: none; border-radius: 5px; font-weight: bold; margin-top: 10px; }
        .donate-button:hover { background-color: #ff3d3d; }
    </style>
    """
    
    rows = []
    for sub in sorted(subs):
        ip = resolved.get(sub, "N/A")
        ports = ", ".join(map(str, ip_open_ports.get(ip, []))) if ip != "N/A" else "N/A"
        sources = [src for src in per_source if sub in per_source[src]]
        rows.append(f"""
        <tr>
            <td>{sub}</td>
            <td>{ip}</td>
            <td>{ports}</td>
            <td>{", ".join(sources)}</td>
        </tr>
        """)
    
    source_rows = []
    for src in sorted(per_source, key=lambda x: len(per_source[x]), reverse=True):
        source_rows.append(f"""
        <tr>
            <td>{src}</td>
            <td style="text-align: right;">{len(per_source[src])}</td>
        </tr>
        """)
    
    html = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>SubFinder X+ Report - {domain}</title>
        {css}
    </head>
    <body>
        <div class="header">
            <div class="logo"> SUBFINDER X Plus </div>
            <div class="subtitle"> Subdomain Discovery Tool</div>
            <div class="version">v 3.0  Made BY X-Bro | Generated on {timestamp}</div>
        </div>
        
        <div class="content">
            <h2 class="domain-title">Scan Results for: <span class="blue">{domain}</span></h2>
            
            <div class="stats">
                <div class="stat-box">
                    <div class="stat-value green">{len(subs)}</div>
                    <div class="stat-label">Subdomains Found</div>
                </div>
                <div class="stat-box">
                    <div class="stat-value blue">{len(resolved)}</div>
                    <div class="stat-label">Resolved IPs</div>
                </div>
                <div class="stat-box">
                    <div class="stat-value orange">{len(set(resolved.values()))}</div>
                    <div class="stat-label">Unique IPs</div>
                </div>
                <div class="stat-box">
                    <div class="stat-value red">{sum(len(ports) for ports in ip_open_ports.values())}</div>
                    <div class="stat-label">Open Ports</div>
                </div>
            </div>
            
            <div class="donate-section">
                <h3>Support the Developer</h3>
                <p>If you find this tool useful, please consider supporting its development</p>
                <a href="https://ko-fi.com/xbro1" target="_blank" class="donate-button">Donate via Ko-fi</a>
            </div>
            
            <h3>Discovered Subdomains</h3>
            <table>
                <thead>
                    <tr>
                        <th>Subdomain</th>
                        <th>IP Address</th>
                        <th>Open Ports</th>
                        <th>Discovery Sources</th>
                    </tr>
                </thead>
                <tbody>
                    {"".join(rows)}
                </tbody>
            </table>
            
            <div class="source-table">
                <h3>Source Contributions</h3>
                <table>
                    <thead>
                        <tr>
                            <th>Source</th>
                            <th style="text-align: right;">Subdomains Found</th>
                        </tr>
                    </thead>
                    <tbody>
                        {"".join(source_rows)}
                    </tbody>
                </table>
            </div>
        </div>
        
        <div class="footer">
            Report generated by SubFinder X+ | Enhanced with VirusTotal, URLScan.io and GitHub Regex
        </div>
    </body>
    </html>
    """
    return html

# === MAIN FUNCTION ===
def main():
    show_banner()
    
    # Create results folder at the beginning
    create_results_folder()
    
    parser = argparse.ArgumentParser(description="SubFinder X+ - Enhanced Subdomain Discovery")
    parser.add_argument("-d", "--domain", required=True, help="Target domain")
    parser.add_argument("-r", "--resolve", action="store_true", help="Enable DNS resolution + port scan")
    parser.add_argument("-w", "--wordlist", help="Path to wordlist for bruteforce")
    parser.add_argument("-t", "--threads", type=int, default=200, help="Number of threads for bruteforce")
    parser.add_argument("--save-all", action="store_true", help="Save both HTML report and raw results")
    parser.add_argument("-o", "--output", help="Output file (.txt, .json or .html)")
    args = parser.parse_args()
    
    # Store domain in global results for graceful shutdown
    global_results['domain'] = args.domain
    
    try:
        subs, per_source, resolved, ip_open_ports = find_subdomains(args.domain, args.resolve)
        
        # Update global results
        global_results.update({
            'subs': set(subs),
            'per_source': per_source,
            'resolved': resolved,
            'ip_open_ports': ip_open_ports
        })
        
        if args.wordlist and not shutdown_flag:
            brute = bruteforce_subdomains(args.domain, args.wordlist, args.threads)
            per_source["Bruteforce"] = brute
            subs = sorted(set(subs) | brute)
            
            # Update global results with bruteforce results
            global_results['subs'].update(brute)
            global_results['per_source']["Bruteforce"] = brute
            global_results['bruteforce_subs'] = brute
            
            # Resolve bruteforced subdomains if resolve flag is set
            if args.resolve and not shutdown_flag:
                console.print("\n[bold white]>>>> Resolving bruteforced subdomains...[/bold white]")
                with Progress(
                    BarColumn(complete_style="white"),
                    "[progress.percentage]{task.percentage:>3.0f}%",
                    TimeRemainingColumn(),
                    console=console
                ) as progress:
                    task = progress.add_task("[white]Resolving IPs...[/white]", total=len(brute))
                    
                    for sub in brute:
                        if shutdown_flag: break
                        ip = resolve(sub)
                        if ip:
                            resolved[sub] = ip
                        progress.update(task, advance=1)
                
                # Update global results with resolved IPs
                global_results['resolved'].update(resolved)
        
        if not shutdown_flag:
            generate_console_report(args.domain, subs, per_source, resolved, ip_open_ports)
            
            if args.resolve and resolved:
                save_ips_to_file(list(resolved.values()), f"resultats/ips-{args.domain}.txt")
                console.print(f"[green]📁 IPs saved to [bold]resultats/ips-{args.domain}.txt[/bold][/green]")
            
            if args.save_all:
                try:
                    html_content = generate_html_report(args.domain, subs, per_source, resolved, ip_open_ports)
                    with open(f"resultats/rapport-{args.domain}.html", "w", encoding="utf-8") as f:
                        f.write(html_content)
                    
                    with open(f"resultats/resultat-{args.domain}.txt", "w", encoding="utf-8") as f:
                        f.write("\n".join(subs))
                    
                    console.print(f"\n[green]📁 HTML report saved to [bold]resultats/rapport-{args.domain}.html[/bold][/green]")
                    console.print(f"[green]📁 Raw results saved to [bold]resultats/resultat-{args.domain}.txt[/bold][/green]")
                except Exception as e:
                    console.print(f"[red]❌ Error saving files: {e}[/red]")
            elif args.output:
                try:
                    # If output path is specified, use it as is
                    if args.output.endswith(".json"):
                        payload = {
                            "domain": args.domain,
                            "subdomains": subs,
                            "resolved": resolved,
                            "ip_open_ports": ip_open_ports,
                            "sources": {k: list(v) for k, v in per_source.items()}
                        }
                        with open(args.output, "w", encoding="utf-8") as f:
                            json.dump(payload, f, indent=2, ensure_ascii=False)
                    elif args.output.endswith(".html"):
                        html_content = generate_html_report(args.domain, subs, per_source, resolved, ip_open_ports)
                        with open(args.output, "w", encoding="utf-8") as f:
                            f.write(html_content)
                    else:
                        with open(args.output, "w", encoding="utf-8") as f:
                            f.write("\n".join(subs))
                    console.print(f"\n[green]📁 Results saved to {args.output}[/green]")
                except Exception as e:
                    console.print(f"[red]❌ Error saving file: {e}[/red]")
            
            # Afficher le message de support à la fin du scan normal
            console.print("\n[bold yellow]<<<<<>>>>>         If you find this tool useful, please consider supporting its development by buying a coffee for X-Bro :    [/bold yellow]")
            console.print("[bold cyan]<<<<<>>>>>         https://ko-fi.com/xbro1         [/bold cyan]")
        else:
            console.print("[yellow]Scan interrupted by user. Results saved.[/yellow]")
                
    except KeyboardInterrupt:
        console.print("\n[red]⚠️  Interruption utilisateur détectée. Sauvegarde des résultats...[/red]")
        save_results_on_exit()
    except Exception as e:
        console.print(f"[red]❌ Erreur inattendue: {e}[/red]")
        save_results_on_exit()

if __name__ == "__main__":
    main()
