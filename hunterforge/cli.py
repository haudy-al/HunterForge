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
def recon(domain, output, bruteforce, wordlist):
    """
    Perform reconnaissance (async, multi-source, optional brute force)
    """
    root_domain = normalize_domain(domain)
    console.print(f"[bold green][+] Starting asynchronous reconnaissance on root domain:[/bold green] {root_domain}")

    results = asyncio.run(gather_subdomains(root_domain))

    if bruteforce:
        console.print("[yellow][*] Starting brute-force subdomain enumeration...[/yellow]")
        brute_results = asyncio.run(brute_force_subdomains(root_domain, wordlist))
        results.update(brute_results)

    if results:
        sorted_results = sorted(results)
        console.print(f"\n[bold cyan][✓] Total unique subdomains: {len(sorted_results)}[/bold cyan]\n")
        for sub in sorted_results:
            console.print(f" - {sub}")

        output_file = output if output else f"{root_domain}_subdomains.txt"
        with open(output_file, "w") as f:
            for sub in sorted_results:
                f.write(sub + "\n")
        console.print(f"\n[bold green][✓] Results saved to {output_file}[/bold green]")
    else:
        console.print("[red][!] No subdomains found from any source[/red]")

if __name__ == "__main__":
    cli()
