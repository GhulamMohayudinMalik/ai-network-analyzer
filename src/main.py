"""
AI Network Analyzer - CLI Entry Point

Main command-line interface for network scanning and vulnerability analysis.
"""

import sys
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from src.core import get_config, setup_logger, get_logger, Config

# Initialize console for rich output
console = Console()


def print_banner():
    """Print the application banner."""
    banner_text = Text()
    banner_text.append("🛡️  ", style="bold blue")
    banner_text.append("AI Network Analyzer", style="bold white")
    banner_text.append(" v0.1.0\n", style="dim")
    banner_text.append("   Intelligent Network Security Scanner", style="italic cyan")
    
    console.print(Panel(
        banner_text,
        border_style="blue",
        padding=(0, 2)
    ))


@click.group()
@click.option(
    "--config", "-c",
    type=click.Path(exists=True, path_type=Path),
    help="Path to configuration file (YAML)"
)
@click.option(
    "--debug/--no-debug",
    default=False,
    help="Enable debug mode"
)
@click.option(
    "--quiet/--no-quiet", "-q",
    default=False,
    help="Suppress banner and non-essential output"
)
@click.pass_context
def cli(ctx: click.Context, config: Optional[Path], debug: bool, quiet: bool):
    """
    AI Network Analyzer - Intelligent Network Security Scanner
    
    Scan networks, identify vulnerabilities, and get AI-powered threat intelligence.
    
    Examples:
    
        # Scan a single host
        python -m src.main scan --target 192.168.1.1
        
        # Scan a network range
        python -m src.main scan --target 192.168.1.0/24
        
        # Generate a report
        python -m src.main report --format html --output report.html
    """
    # Initialize context
    ctx.ensure_object(dict)
    
    # Load configuration
    app_config = get_config(config)
    if debug:
        app_config.debug = True
        app_config.log_level = "DEBUG"
    
    ctx.obj["config"] = app_config
    ctx.obj["quiet"] = quiet
    
    # Setup logger
    import logging
    log_level = logging.DEBUG if debug else getattr(logging, app_config.log_level.upper())
    logger = setup_logger(level=log_level, log_to_console=not quiet)
    ctx.obj["logger"] = logger
    
    # Print banner unless quiet mode
    if not quiet:
        print_banner()


@cli.command()
@click.option(
    "--target", "-t",
    required=True,
    help="Target to scan (IP, hostname, or CIDR range)"
)
@click.option(
    "--ports", "-p",
    default=None,
    help="Ports to scan (e.g., '22,80,443' or '1-1000')"
)
@click.option(
    "--top-ports",
    type=int,
    default=None,
    help="Scan top N most common ports"
)
@click.option(
    "--scan-type", "-s",
    type=click.Choice(["tcp", "syn", "udp", "full"]),
    default="tcp",
    help="Type of scan to perform"
)
@click.option(
    "--timing", "-T",
    type=click.IntRange(0, 5),
    default=3,
    help="Timing template (0=paranoid, 5=insane)"
)
@click.option(
    "--service-detection/--no-service-detection",
    default=True,
    help="Enable service version detection"
)
@click.option(
    "--os-detection/--no-os-detection",
    default=False,
    help="Enable OS detection (requires privileges)"
)
@click.option(
    "--cve-lookup/--no-cve-lookup",
    default=True,
    help="Look up CVEs for detected services"
)
@click.option(
    "--output", "-o",
    type=click.Path(path_type=Path),
    help="Output file for results"
)
@click.option(
    "--format", "-f",
    type=click.Choice(["json", "html", "csv", "console"]),
    default="console",
    help="Output format"
)
@click.pass_context
def scan(
    ctx: click.Context,
    target: str,
    ports: Optional[str],
    top_ports: Optional[int],
    scan_type: str,
    timing: int,
    service_detection: bool,
    os_detection: bool,
    cve_lookup: bool,
    output: Optional[Path],
    format: str
):
    """
    Scan a target for open ports and vulnerabilities.
    
    Examples:
    
        # Basic scan of a host
        python -m src.main scan -t 192.168.1.1
        
        # Scan specific ports
        python -m src.main scan -t 192.168.1.1 -p 22,80,443
        
        # Fast scan of top 100 ports
        python -m src.main scan -t 192.168.1.1 --top-ports 100
        
        # Full scan with OS detection
        python -m src.main scan -t 192.168.1.0/24 -s full --os-detection
    """
    config: Config = ctx.obj["config"]
    logger = ctx.obj["logger"]
    quiet = ctx.obj.get("quiet", False)
    
    logger.info(f"Starting scan of target: {target}")
    
    console.print(f"\n[bold cyan]Scan Configuration:[/bold cyan]")
    console.print(f"  • Target: [bold]{target}[/bold]")
    console.print(f"  • Ports: {ports or 'default'}")
    console.print(f"  • Scan Type: {scan_type}")
    console.print(f"  • Timing Template: T{timing}")
    console.print(f"  • Service Detection: {'✓' if service_detection else '✗'}")
    console.print(f"  • OS Detection: {'✓' if os_detection else '✗'}")
    console.print(f"  • CVE Lookup: {'✓' if cve_lookup else '✗'}")
    
    console.print("\n[yellow]⚠️  Full port scanning will be implemented in Phase 1.3[/yellow]")
    console.print("[dim]Use 'discover' command for host discovery (Phase 1.2)[/dim]")
    
    logger.info("Scan command executed (port scanning pending Phase 1.3)")


@cli.command()
@click.option(
    "--target", "-t",
    required=True,
    help="Target to discover (IP, hostname, or CIDR range, e.g., 192.168.1.0/24)"
)
@click.option(
    "--method", "-m",
    type=click.Choice(["auto", "arp", "icmp", "tcp", "stealth"]),
    default="auto",
    help="Discovery method: auto (recommended), arp (local only), icmp (ping), tcp (SYN), stealth"
)
@click.option(
    "--timing", "-T",
    type=click.IntRange(0, 5),
    default=3,
    help="Timing template (0=paranoid, 5=insane)"
)
@click.option(
    "--tcp-ports",
    default="22,80,443",
    help="TCP ports for TCP-based discovery"
)
@click.option(
    "--resolve/--no-resolve", "-r",
    default=True,
    help="Resolve hostnames via DNS"
)
@click.option(
    "--output", "-o",
    type=click.Path(path_type=Path),
    help="Output file for results (JSON)"
)
@click.pass_context
def discover(
    ctx: click.Context,
    target: str,
    method: str,
    timing: int,
    tcp_ports: str,
    resolve: bool,
    output: Optional[Path]
):
    """
    Discover live hosts on a network.
    
    This performs host discovery without port scanning. Use this to find
    which hosts are online before running a full port scan.
    
    Examples:
    
        # Discover hosts on local network (auto-selects best method)
        python -m src.main discover -t 192.168.1.0/24
        
        # Use ARP scan (fastest, local network only)
        python -m src.main discover -t 192.168.1.0/24 -m arp
        
        # Use ICMP ping sweep
        python -m src.main discover -t 10.0.0.0/24 -m icmp
        
        # Stealth TCP scan (when ICMP is blocked)
        python -m src.main discover -t 192.168.1.0/24 -m stealth
        
        # Save results to JSON
        python -m src.main discover -t 192.168.1.0/24 -o hosts.json
    """
    import json
    from src.scanner import NetworkScanner, DiscoveryMethod
    from src.core.exceptions import NetworkScanError, InvalidTargetError
    
    config: Config = ctx.obj["config"]
    logger = ctx.obj["logger"]
    quiet = ctx.obj.get("quiet", False)
    
    # Map CLI method to DiscoveryMethod enum
    method_map = {
        "auto": DiscoveryMethod.AUTO,
        "arp": DiscoveryMethod.ARP,
        "icmp": DiscoveryMethod.ICMP_ECHO,
        "tcp": DiscoveryMethod.TCP_SYN,
        "stealth": DiscoveryMethod.TCP_SYN,
    }
    discovery_method = method_map.get(method, DiscoveryMethod.AUTO)
    
    logger.info(f"Starting host discovery on {target} using {method} method")
    
    try:
        # Initialize scanner
        scanner = NetworkScanner()
        
        # Print configuration
        if not quiet:
            console.print(f"\n[bold cyan]Discovery Configuration:[/bold cyan]")
            console.print(f"  • Target: [bold]{target}[/bold]")
            console.print(f"  • Method: {method}")
            console.print(f"  • Timing: T{timing}")
            console.print(f"  • Resolve Hostnames: {'✓' if resolve else '✗'}")
            console.print()
        
        # Run discovery
        result = scanner.discover_hosts(
            target=target,
            method=discovery_method,
            timing=timing,
            resolve_hostnames=resolve,
            tcp_ports=tcp_ports if method in ["tcp", "stealth"] else None,
            show_progress=not quiet
        )
        
        # Display results
        scanner.print_results(result)
        
        # Save to file if requested
        if output:
            output_path = Path(output)
            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(result.to_dict(), f, indent=2)
            console.print(f"\n[green]✓[/green] Results saved to: {output_path}")
            logger.info(f"Results saved to {output_path}")
        
        # Summary
        if result.hosts_up > 0:
            console.print(f"\n[green]✓ Found {result.hosts_up} live host(s)[/green]")
        else:
            console.print("\n[yellow]⚠️ No hosts found. Try a different discovery method.[/yellow]")
        
    except InvalidTargetError as e:
        console.print(f"\n[red]✗ Invalid target:[/red] {e.message}")
        logger.error(f"Invalid target: {e}")
        sys.exit(1)
        
    except NetworkScanError as e:
        console.print(f"\n[red]✗ Scan failed:[/red] {e.message}")
        if "privileges" in str(e).lower():
            console.print("[yellow]Tip: Some scan types require administrator/root privileges.[/yellow]")
        logger.error(f"Scan failed: {e}")
        sys.exit(1)
        
    except Exception as e:
        console.print(f"\n[red]✗ Unexpected error:[/red] {e}")
        logger.exception("Unexpected error during discovery")
        sys.exit(1)


@cli.command()
@click.option(
    "--input", "-i",
    type=click.Path(exists=True, path_type=Path),
    required=True,
    help="Input scan results file"
)
@click.option(
    "--format", "-f",
    type=click.Choice(["html", "pdf", "json", "csv", "md"]),
    default="html",
    help="Output report format"
)
@click.option(
    "--output", "-o",
    type=click.Path(path_type=Path),
    help="Output file path"
)
@click.pass_context
def report(ctx: click.Context, input: Path, format: str, output: Optional[Path]):
    """
    Generate a report from scan results.
    
    Examples:
    
        # Generate HTML report
        python -m src.main report -i results.json -f html -o report.html
        
        # Generate PDF report
        python -m src.main report -i results.json -f pdf -o report.pdf
    """
    config: Config = ctx.obj["config"]
    logger = ctx.obj["logger"]
    
    logger.info(f"Generating {format} report from {input}")
    
    # TODO: Implement reporting in Phase 3
    console.print(f"\n[bold cyan]Report Configuration:[/bold cyan]")
    console.print(f"  • Input: {input}")
    console.print(f"  • Format: {format}")
    console.print(f"  • Output: {output or 'auto-generated'}")
    
    console.print("\n[yellow]⚠️  Report generation will be implemented in Phase 3[/yellow]")


@cli.command()
@click.pass_context
def version(ctx: click.Context):
    """Show version information."""
    config: Config = ctx.obj["config"]
    console.print(f"AI Network Analyzer v{config.version}")


@cli.command()
@click.option(
    "--output", "-o",
    type=click.Path(path_type=Path),
    default=Path("config.yaml"),
    help="Output configuration file path"
)
@click.pass_context
def init_config(ctx: click.Context, output: Path):
    """
    Generate a default configuration file.
    
    Example:
    
        python -m src.main init-config -o my_config.yaml
    """
    config: Config = ctx.obj["config"]
    logger = ctx.obj["logger"]
    
    try:
        config.to_yaml(output)
        console.print(f"[green]✓[/green] Configuration file created: {output}")
        logger.info(f"Configuration file created: {output}")
    except ImportError as e:
        console.print(f"[red]✗[/red] {e}")
        sys.exit(1)


@cli.command()
@click.pass_context
def check(ctx: click.Context):
    """
    Check system requirements and dependencies.
    
    Verifies that all required tools (nmap, etc.) are installed
    and accessible.
    """
    import shutil
    
    console.print("\n[bold cyan]System Check:[/bold cyan]\n")
    
    # Check Python version
    py_version = sys.version_info
    py_ok = py_version >= (3, 10)
    py_status = "[green]✓[/green]" if py_ok else "[red]✗[/red]"
    console.print(f"  {py_status} Python {py_version.major}.{py_version.minor}.{py_version.micro} (3.10+ required)")
    
    # Check for nmap
    nmap_path = shutil.which("nmap")
    nmap_ok = nmap_path is not None
    nmap_status = "[green]✓[/green]" if nmap_ok else "[red]✗[/red]"
    console.print(f"  {nmap_status} nmap {'found at ' + nmap_path if nmap_ok else 'NOT FOUND'}")
    
    # Check for optional dependencies
    console.print("\n[bold cyan]Optional Dependencies:[/bold cyan]\n")
    
    optional_deps = [
        ("rich", "Beautiful console output"),
        ("yaml", "YAML configuration files"),
        ("nmap", "Nmap Python wrapper"),
        ("httpx", "HTTP client for APIs"),
        ("jinja2", "Report templates"),
    ]
    
    for dep_name, desc in optional_deps:
        try:
            __import__(dep_name)
            console.print(f"  [green]✓[/green] {dep_name}: {desc}")
        except ImportError:
            console.print(f"  [yellow]○[/yellow] {dep_name}: {desc} (not installed)")
    
    console.print()


def main():
    """Main entry point."""
    cli(obj={})


if __name__ == "__main__":
    main()
