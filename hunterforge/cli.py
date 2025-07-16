import asyncio
import click
from rich.console import Console
from hunterforge.core.subdomains_async import (
    gather_subdomains,
    normalize_domain,
    brute_force_subdomains
)

console = Console()

@click.group()
def cli():
    """HunterForge - Bug Bounty Recon & Scanner CLI"""
    pass

@cli.command()
@click.option('--domain', required=True, help='Target domain or URL for reconnaissance')
@click.option('--output', default=None, help='Custom output file (optional)')
@click.option('--bruteforce', is_flag=True, help='Enable brute-force mode')
@click.option('--wordlist', default='subdomains.txt', help='Wordlist for brute force')
@click.option('--concurrency', default=100, help='Number of concurrent DNS checks')
def recon(domain, output, bruteforce, wordlist, concurrency):
    """
    Perform reconnaissance (async, multi-source, optional brute force + IP & ASN lookup)
    """
    root_domain = normalize_domain(domain)
    console.print(f"[bold green][+] Starting asynchronous reconnaissance on root domain:[/bold green] {root_domain}")

    results = asyncio.run(gather_subdomains(root_domain))

    if bruteforce:
        console.print(f"[yellow][*] Starting brute-force with concurrency={concurrency}...[/yellow]")
        brute_results = asyncio.run(brute_force_subdomains(root_domain, wordlist, concurrency))
        results.update(brute_results.keys())  # brute_results = {subdomain: ip}

        # Gabungkan info IP
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

if __name__ == "__main__":
    cli()
