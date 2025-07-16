from rich.console import Console
from hunterforge.cli import cli

console = Console()

logo = r"""
  
  ▗▖ ▗▖█  ▐▌▄▄▄▄     ■  ▗▞▀▚▖ ▄▄▄ ▗▄▄▄▖ ▄▄▄   ▄▄▄  ▗▞▀▚▖
  ▐▌ ▐▌▀▄▄▞▘█   █ ▗▄▟▙▄▖▐▛▀▀▘█    ▐▌   █   █ █     ▐▛▀▀▘
  ▐▛▀▜▌     █   █   ▐▌  ▝▚▄▄▖█    ▐▛▀▀▘▀▄▄▄▀ █     ▝▚▄▄▖
  ▐▌ ▐▌             ▐▌            ▐▌             ▗▄▖    
                    ▐▌                          ▐▌ ▐▌   
                                                 ▝▀▜▌   
                                                ▐▙▄▞▘   

"""

if __name__ == "__main__":
    console.print(f"[bold cyan]{logo}[/bold cyan]")
    console.print("[bold green]HunterForge v1.0.4 - Bug Bounty Toolkit[/bold green]\n")
    cli()
