import asyncio
import click
from rich.console import Console
from rich.panel import Panel
from rich.markdown import Markdown
from hunterforge.core.subdomains_async import (
    gather_subdomains,
    normalize_domain,
    brute_force_subdomains
)
from hunterforge.core.scanner import run_scanner

console = Console()

@click.group(
    help="""
[bold cyan]HunterForge[/bold cyan] - Advanced Bug Bounty Toolkit
Version: 1.0.4

A powerful CLI tool for bug bounty hunters:
- [green]Subdomain enumeration[/green] (passive & brute force)
- [green]IP & ASN resolution[/green]
- [green]Vulnerability scanning[/green] (XSS, Open Redirect, CORS, Security Headers)

Examples:
  [yellow]hunterforge.py recon --domain example.com[/yellow]
  [yellow]hunterforge.py recon --domain example.com --bruteforce --wordlist subdomains.txt --concurrency 200[/yellow]
  [yellow]hunterforge.py scan --url https://example.com[/yellow]
  [yellow]hunterforge.py scan --urls-file urls.txt --output results.txt[/yellow]
"""
)
def cli():
    pass

# ------------------- RECON COMMAND -------------------
@cli.command(
    help="""
[bold green]Subdomain Enumeration & Reconnaissance[/bold green]

Fetch subdomains from:
- crt.sh
- ThreatCrowd
- HackerTarget
(Optional) Brute force using a custom wordlist.
Resolve IP addresses & ASN (ISP info).

Examples:
  hunterforge.py recon --domain example.com
  hunterforge.py recon --domain example.com --bruteforce --wordlist big.txt --concurrency 200
"""
)
@click.option('--domain', required=True, help='Target domain or URL')
@click.option('--output', default=None, help='Custom output file (optional)')
@click.option('--bruteforce', is_flag=True, help='Enable brute-force subdomain enumeration')
@click.option('--wordlist', default='subdomains.txt', help='Wordlist for brute force [default: subdomains.txt]')
@click.option('--concurrency', default=100, help='Number of concurrent DNS checks [default: 100]')
def recon(domain, output, bruteforce, wordlist, concurrency):
    """
    Recon module: Passive sources + optional brute-force with ASN info
    """
    console.print(Panel.fit(f"[bold green]Starting reconnaissance on:[/bold green] {domain}"))
    root_domain = normalize_domain(domain)

    results = asyncio.run(gather_subdomains(root_domain))

    if bruteforce:
        console.print(f"[yellow][*] Starting brute-force with concurrency={concurrency}...[/yellow]")
        brute_results = asyncio.run(brute_force_subdomains(root_domain, wordlist, concurrency))
        results.update(brute_results.keys())

        console.print(f"\n[bold cyan][✓] Subdomains with IP info:[/bold cyan]\n")
        for sub, info in brute_results.items():
            ip, asn = info
            console.print(f" - {sub} [{ip}] ({asn})")

    if results:
        sorted_results = sorted(results)
        output_file = output if output else f"{root_domain}_subdomains.txt"
        with open(output_file, "w") as f:
            for sub in sorted_results:
                f.write(sub + "\n")
        console.print(f"\n[bold green][✓] Results saved to {output_file}[/bold green]")
    else:
        console.print("[red][!] No subdomains found from any source[/red]")

# ------------------- SCAN COMMAND -------------------
@cli.command(
    help="""
[bold green]Vulnerability Scanner[/bold green]

Detect:
- Reflected XSS
- Open Redirect
- CORS misconfigurations
- Missing Security Headers

Examples:
  hunterforge.py scan --url https://example.com
  hunterforge.py scan --urls-file urls.txt --output report.txt
"""
)
@click.option('--url', help='Single target URL')
@click.option('--urls-file', help='File with list of URLs')
@click.option('--output', default='scan_results.txt', help='File to save scan results [default: scan_results.txt]')
def scan(url, urls_file, output):
    """
    Vulnerability Scanner: XSS, Open Redirect, CORS, Security Headers
    """
    targets = []

    if url:
        targets.append(url)
    if urls_file:
        try:
            with open(urls_file, "r") as f:
                targets.extend([line.strip() for line in f if line.strip()])
        except FileNotFoundError:
            console.print(f"[red][-] File not found: {urls_file}[/red]")
            return

    if not targets:
        console.print("[red][!] Please provide --url or --urls-file[/red]")
        return

    console.print(Panel.fit(f"[bold cyan]Starting vulnerability scan on {len(targets)} URL(s)[/bold cyan]"))
    results = asyncio.run(run_scanner(targets))

    # Print results
    for res in results:
        console.print(f"\n[bold]{res['url']}[/bold]")
        console.print(f"  XSS: {res['xss']}")
        console.print(f"  Open Redirect: {res['redirect']}")
        console.print(f"  CORS: {res['cors']}")
        console.print(f"  Security Headers: {res['headers']}")

    # Save to file
    with open(output, "w") as f:
        for res in results:
            f.write(f"URL: {res['url']}\n")
            f.write(f"XSS: {res['xss']}\n")
            f.write(f"Open Redirect: {res['redirect']}\n")
            f.write(f"CORS: {res['cors']}\n")
            f.write(f"Security Headers: {res['headers']}\n\n")

    console.print(f"\n[bold green][✓] Scan results saved to {output}[/bold green]")

if __name__ == "__main__":
    cli()
