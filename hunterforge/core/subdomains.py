import requests
import tldextract
from rich.console import Console

console = Console()

def normalize_domain(domain: str) -> str:
    """
    Normalize input domain or URL to root domain.
    Example: https://sub.domain.com -> domain.com
    """
    extracted = tldextract.extract(domain)
    if extracted.suffix:
        return f"{extracted.domain}.{extracted.suffix}"
    return domain

def fetch_subdomains_from_crtsh(domain: str) -> list:
    """
    Fetch subdomains from crt.sh
    """
    url = f"https://crt.sh/?q=%25{domain}&output=json"
    headers = {"User-Agent": "Mozilla/5.0 (compatible; HunterForge/1.0)"}
    try:
        response = requests.get(url, headers=headers, timeout=30)
        if response.status_code != 200:
            console.print(f"[red][-] Failed to fetch data from crt.sh (Status {response.status_code})[/red]")
            return []
        
        text = response.text.strip()
        if not (text.startswith("[") or text.startswith("{")):
            console.print("[yellow][!] crt.sh returned non-JSON response (empty or blocked)[/yellow]")
            return []
        
        data = response.json()
        subdomains = set()
        for entry in data:
            name_value = entry.get("name_value")
            if name_value:
                for sub in name_value.split("\n"):
                    if sub.endswith(domain):
                        subdomains.add(sub.strip())
        return sorted(subdomains)
    except Exception as e:
        console.print(f"[red][-] Error fetching subdomains from crt.sh: {e}[/red]")
        return []

def fetch_subdomains_from_threatcrowd(domain: str) -> list:
    """
    Fetch subdomains from ThreatCrowd
    """
    url = f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={domain}"
    try:
        response = requests.get(url, timeout=20, verify=False)  # SSL verify disabled
        if response.status_code != 200:
            console.print(f"[red][-] Failed to fetch data from ThreatCrowd (Status {response.status_code})[/red]")
            return []
        
        data = response.json()
        return data.get("subdomains", [])
    except Exception as e:
        console.print(f"[red][-] Error fetching subdomains from ThreatCrowd: {e}[/red]")
        return []

def fetch_subdomains_from_hackertarget(domain: str) -> list:
    """
    Fetch subdomains from HackerTarget API
    """
    url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
    try:
        response = requests.get(url, timeout=15)
        if response.status_code != 200:
            console.print(f"[red][-] Failed to fetch data from HackerTarget (Status {response.status_code})[/red]")
            return []
        
        text = response.text.strip()
        if "error" in text.lower():
            console.print("[yellow][!] HackerTarget API returned error or no data[/yellow]")
            return []
        
        subdomains = set()
        for line in text.split("\n"):
            parts = line.split(",")
            if parts and parts[0].endswith(domain):
                subdomains.add(parts[0])
        
        return sorted(subdomains)
    except Exception as e:
        console.print(f"[red][-] Error fetching subdomains from HackerTarget: {e}[/red]")
        return []
