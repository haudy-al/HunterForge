import aiohttp
import asyncio
import tldextract
import aiodns
import socket
from rich.console import Console
from rich.progress import Progress

console = Console()

def normalize_domain(domain: str) -> str:
    extracted = tldextract.extract(domain)
    if extracted.suffix:
        return f"{extracted.domain}.{extracted.suffix}"
    return domain

async def fetch_crtsh(session, domain):
    url = f"https://crt.sh/?q=%25{domain}&output=json"
    try:
        async with session.get(url, timeout=30) as resp:
            if resp.status != 200:
                return []
            text = await resp.text()
            if not text.startswith("["):
                return []
            data = await resp.json()
            subs = set()
            for entry in data:
                name_value = entry.get("name_value")
                if name_value:
                    for sub in name_value.split("\n"):
                        if sub.endswith(domain):
                            subs.add(sub.strip())
            return list(subs)
    except:
        return []

async def fetch_threatcrowd(session, domain):
    url = f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={domain}"
    try:
        async with session.get(url, timeout=20, ssl=False) as resp:
            if resp.status != 200:
                return []
            data = await resp.json()
            return data.get("subdomains", [])
    except:
        return []

async def fetch_hackertarget(session, domain):
    url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
    try:
        async with session.get(url, timeout=15) as resp:
            if resp.status != 200:
                return []
            text = await resp.text()
            if "error" in text.lower():
                return []
            subs = set()
            for line in text.split("\n"):
                parts = line.split(",")
                if parts and parts[0].endswith(domain):
                    subs.add(parts[0])
            return list(subs)
    except:
        return []

async def gather_subdomains(domain):
    sources = [
        ("crt.sh", fetch_crtsh),
        ("ThreatCrowd", fetch_threatcrowd),
        ("HackerTarget", fetch_hackertarget),
    ]
    all_subdomains = set()

    async with aiohttp.ClientSession(headers={"User-Agent": "HunterForge/1.0"}) as session:
        with Progress() as progress:
            task = progress.add_task("[cyan]Fetching subdomains...", total=len(sources))
            tasks = [func(session, domain) for _, func in sources]
            results = await asyncio.gather(*tasks)
            for result in results:
                all_subdomains.update(result)
                progress.update(task, advance=1)

    return all_subdomains

async def get_asn_info(session, ip):
    """Get ASN info using ipinfo.io (no token)"""
    url = f"https://ipinfo.io/{ip}/org"
    try:
        async with session.get(url, timeout=10) as resp:
            if resp.status == 200:
                text = await resp.text()
                return text.strip()
    except:
        pass
    return "Unknown ASN"

async def brute_force_subdomains(domain, wordlist, concurrency):
    resolver = aiodns.DNSResolver()
    subdomains = {}
    try:
        with open(wordlist, "r") as f:
            words = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        console.print(f"[red][-] Wordlist not found: {wordlist}[/red]")
        return subdomains

    sem = asyncio.Semaphore(concurrency)

    async def resolve(sub):
        async with sem:
            try:
                result = await resolver.gethostbyname(sub, socket.AF_INET)
                return sub, result.addresses[0]
            except:
                return None

    tasks = [resolve(f"{word}.{domain}") for word in words]

    async with aiohttp.ClientSession() as session:
        with Progress() as progress:
            task = progress.add_task("[yellow]Brute forcing subdomains...", total=len(tasks))
            for coro in asyncio.as_completed(tasks):
                result = await coro
                if result:
                    sub, ip = result
                    asn = await get_asn_info(session, ip)
                    subdomains[sub] = (ip, asn)
                progress.update(task, advance=1)

    return subdomains
