"""OTScan CLI - Command-line interface for OT/ICS/SCADA network scanning."""

from __future__ import annotations

import sys

import click
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.table import Table

from otscan import __version__
from otscan.protocols.base import ScanMode, Severity
from otscan.scanner import OTScanner
from otscan.reporting.report import (
    generate_csv_report,
    generate_html_report,
    generate_json_report,
)

console = Console()

BANNER = r"""
   ____  ___________
  / __ \/_  __/ ___/_________ _____
 / / / / / /  \__ \/ ___/ __ `/ __ \
/ /_/ / / /  ___/ / /__/ /_/ / / / /
\____/ /_/  /____/\___/\__,_/_/ /_/
"""

SEVERITY_STYLES = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "blue",
    Severity.INFO: "dim",
}


@click.group()
@click.version_option(version=__version__, prog_name="otscan")
def main():
    """OTScan - OT/ICS/SCADA Network Security Scanner.

    Discover, identify, and assess security of industrial control systems.
    """


@main.command()
@click.argument("target")
@click.option(
    "--mode",
    type=click.Choice(["passive", "safe", "active"]),
    default="safe",
    help="Scanning mode (default: safe)",
)
@click.option("--timeout", type=float, default=5.0, help="Connection timeout in seconds")
@click.option("--workers", type=int, default=10, help="Max concurrent workers")
@click.option(
    "--protocol",
    multiple=True,
    help="Specific protocol(s) to scan (can be specified multiple times)",
)
@click.option("--output", "-o", help="Output file path")
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["json", "html", "csv"]),
    default="json",
    help="Output format (default: json)",
)
@click.option("--no-banner", is_flag=True, help="Suppress the banner")
@click.option(
    "--analyze", is_flag=True,
    help="Run AI-powered analysis on results using Anthropic Claude",
)
@click.option(
    "--api-key", envvar="ANTHROPIC_API_KEY",
    help="Anthropic API key (or set ANTHROPIC_API_KEY env var)",
)
@click.option(
    "--model", "ai_model", default=None,
    help="Claude model for analysis (default: claude-sonnet-4-6)",
)
def scan(
    target, mode, timeout, workers, protocol, output, output_format, no_banner,
    analyze, api_key, ai_model,
):
    """Scan OT/ICS/SCADA targets for devices and vulnerabilities.

    TARGET can be a single IP, CIDR range, IP range, or comma-separated list.

    \b
    Examples:
        otscan scan 192.168.1.1
        otscan scan 192.168.1.0/24 --analyze --model claude-sonnet-4-6
        otscan scan 192.168.1.1-192.168.1.50
        otscan scan 10.0.0.1 --protocol "Modbus TCP" --protocol "S7comm"
    """
    if not no_banner:
        console.print(BANNER, style="cyan")
        console.print(f"  v{__version__} - OT/ICS/SCADA Security Scanner\n", style="dim")

    scan_mode = ScanMode(mode)
    protocols = list(protocol) if protocol else None

    scanner = OTScanner(
        mode=scan_mode,
        timeout=timeout,
        max_workers=workers,
        protocols=protocols,
    )

    console.print(Panel(
        f"[bold]Target:[/bold] {target}\n"
        f"[bold]Mode:[/bold] {mode}\n"
        f"[bold]Timeout:[/bold] {timeout}s\n"
        f"[bold]Protocols:[/bold] {', '.join(p['name'] for p in scanner.list_protocols())}",
        title="Scan Configuration",
        border_style="cyan",
    ))

    # Run scan with progress bar
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("Scanning...", total=None)

        def on_progress(completed, total, current_target, error=None):
            progress.update(task, total=total, completed=completed,
                          description=f"Scanning {current_target}...")
            if error:
                console.print(f"  [red]Error scanning {current_target}: {error}[/red]")

        result = scanner.scan(target, progress_callback=on_progress)

    # Display results
    _display_summary(result)
    _display_hosts(result)
    _display_vulnerabilities(result)

    # AI-powered analysis
    if analyze:
        _run_agentic_analysis(result, api_key, ai_model)

    # Generate report
    if output:
        _generate_report(result, output, output_format)
    else:
        # Auto-generate JSON report
        default_output = f"otscan_report.{output_format}"
        _generate_report(result, default_output, output_format)


@main.command()
@click.argument("target")
@click.argument("port", type=int)
@click.argument("protocol")
@click.option("--timeout", type=float, default=5.0, help="Connection timeout in seconds")
@click.option(
    "--mode",
    type=click.Choice(["passive", "safe", "active"]),
    default="safe",
    help="Scanning mode",
)
def probe(target, port, protocol, timeout, mode):
    """Probe a single target with a specific protocol.

    \b
    Examples:
        otscan probe 192.168.1.1 502 "Modbus TCP"
        otscan probe 10.0.0.1 102 S7comm
        otscan probe 10.0.0.5 44818 EtherNet/IP
    """
    scan_mode = ScanMode(mode)
    scanner = OTScanner(mode=scan_mode, timeout=timeout)

    console.print(f"\nProbing [bold]{target}:{port}[/bold] with [cyan]{protocol}[/cyan]...\n")

    result = scanner.scan_single(target, port, protocol)
    if result is None:
        console.print(f"[red]Unknown protocol: {protocol}[/red]")
        console.print("Available protocols:")
        for p in scanner.list_protocols():
            console.print(f"  - {p['name']} (port {p['port']})")
        sys.exit(1)

    # Display result
    table = Table(title=f"Probe Result: {target}:{port}")
    table.add_column("Property", style="cyan")
    table.add_column("Value")

    table.add_row("Protocol", result.protocol)
    table.add_row("Port Open", "[green]Yes[/green]" if result.is_open else "[red]No[/red]")
    table.add_row("Identified", "[green]Yes[/green]" if result.is_identified else "[dim]No[/dim]")

    if result.device:
        table.add_row("Vendor", result.device.vendor)
        table.add_row("Model", result.device.model)
        table.add_row("Firmware", result.device.firmware)
        table.add_row("Serial", result.device.serial)
        table.add_row("Type", result.device.device_type)

    table.add_row("Scan Time", f"{result.scan_time:.2f}s")
    table.add_row("Vulnerabilities", str(len(result.vulnerabilities)))

    console.print(table)

    if result.vulnerabilities:
        console.print("\n[bold]Vulnerabilities:[/bold]")
        for vuln in result.vulnerabilities:
            style = SEVERITY_STYLES.get(vuln.severity, "white")
            console.print(f"  [{style}][{vuln.severity.value.upper()}][/{style}] {vuln.title}")
            console.print(f"    {vuln.description}", style="dim")
            if vuln.remediation:
                console.print(f"    [cyan]Fix: {vuln.remediation}[/cyan]")
            console.print()


@main.command()
@click.argument("report_file", type=click.Path(exists=True))
@click.option(
    "--api-key", envvar="ANTHROPIC_API_KEY",
    help="Anthropic API key (or set ANTHROPIC_API_KEY env var)",
)
@click.option(
    "--model", "ai_model", default=None,
    help="Claude model (default: claude-sonnet-4-6). "
    "Options: claude-opus-4-6, claude-sonnet-4-6, claude-haiku-4-5-20251001",
)
@click.option("--question", "-q", help="Ask a specific question about the results")
def analyze(report_file, api_key, ai_model, question):
    """Run AI-powered analysis on a previous scan report (JSON).

    Uses Anthropic Claude to provide risk scoring, attack path analysis,
    and prioritized remediation recommendations.

    \b
    Setup:
        export ANTHROPIC_API_KEY=sk-ant-api03-...
    \b
    Models:
        claude-opus-4-6            Most capable, deep reasoning
        claude-sonnet-4-6          Balanced speed + intelligence (default)
        claude-haiku-4-5-20251001  Fastest, lowest cost
    \b
    Examples:
        otscan analyze otscan_report.json
        otscan analyze otscan_report.json --model claude-opus-4-6
        otscan analyze otscan_report.json -q "What is the biggest risk?"
    """
    import json

    from otscan.agentic.analyzer import AgenticAnalyzer, AgenticConfig

    with open(report_file) as f:
        report_data = json.load(f)

    config = AgenticConfig(
        api_key=api_key or "",
        model=ai_model or "claude-sonnet-4-6",
    )
    if not config.api_key:
        config = AgenticConfig.from_env(model=ai_model)
    if not config.api_key:
        console.print(
            "[red]Anthropic API key required.[/red]\n"
            "Set it via: export ANTHROPIC_API_KEY=sk-ant-api03-...\n"
            "Or pass: --api-key sk-ant-api03-..."
        )
        sys.exit(1)

    analyzer = AgenticAnalyzer(config=config)

    # Convert flat report dict back to a lightweight object for the analyzer
    report_obj = _report_dict_to_obj(report_data)

    if question:
        console.print(f"\n[cyan]Asking Claude ({config.model}):[/cyan] {question}\n")
        with console.status("Thinking..."):
            answer = analyzer.ask(report_obj, question)
        console.print(Panel(answer, title="AI Analysis", border_style="cyan"))
    else:
        console.print(f"\n[cyan]Running AI analysis with {config.model}...[/cyan]")
        with console.status("Analyzing scan results..."):
            result = analyzer.analyze(report_obj)
        _display_analysis(result)


@main.command(name="list-protocols")
def list_protocols():
    """List all supported OT/ICS/SCADA protocols."""
    console.print(BANNER, style="cyan")

    table = Table(title="Supported Protocols")
    table.add_column("Protocol", style="cyan", no_wrap=True)
    table.add_column("Default Port", justify="right")
    table.add_column("Description")

    scanner = OTScanner()
    for p in scanner.list_protocols():
        table.add_row(p["name"], p["port"], p["description"])

    console.print(table)


def _display_summary(result):
    """Display scan summary."""
    s = result.summary
    console.print()

    table = Table(title="Scan Summary", show_header=False, border_style="cyan")
    table.add_column("Metric", style="bold")
    table.add_column("Value", justify="right")

    table.add_row("Targets Scanned", str(s.targets_scanned))
    table.add_row("Hosts Alive", str(s.hosts_alive))
    table.add_row("Devices Identified", str(s.devices_identified))
    table.add_row("Protocols Found", ", ".join(s.protocols_found) or "None")
    table.add_row("Duration", f"{s.scan_duration:.1f}s")
    table.add_row("", "")
    table.add_row("[bold red]Critical[/bold red]", str(s.critical_count))
    table.add_row("[red]High[/red]", str(s.high_count))
    table.add_row("[yellow]Medium[/yellow]", str(s.medium_count))
    table.add_row("[blue]Low[/blue]", str(s.low_count))
    table.add_row("[dim]Info[/dim]", str(s.info_count))
    table.add_row("[bold]Total Vulnerabilities[/bold]", f"[bold]{s.total_vulnerabilities}[/bold]")

    console.print(table)


def _display_hosts(result):
    """Display discovered hosts and devices."""
    if not result.hosts:
        console.print("\n[dim]No hosts with OT/ICS services found.[/dim]")
        return

    console.print()
    table = Table(title="Discovered Devices")
    table.add_column("IP", style="cyan")
    table.add_column("Protocol")
    table.add_column("Vendor")
    table.add_column("Model")
    table.add_column("Firmware")
    table.add_column("Type")
    table.add_column("Vulns", justify="right")

    for host in result.hosts:
        for sr in host.scan_results:
            if sr.device:
                vuln_count = len(sr.vulnerabilities)
                vuln_style = "red" if vuln_count > 0 else "green"
                table.add_row(
                    host.ip,
                    sr.device.protocol,
                    sr.device.vendor,
                    sr.device.model,
                    sr.device.firmware,
                    sr.device.device_type,
                    f"[{vuln_style}]{vuln_count}[/{vuln_style}]",
                )

    console.print(table)


def _display_vulnerabilities(result):
    """Display vulnerability findings."""
    if not result.all_vulnerabilities:
        return

    console.print()
    table = Table(title="Vulnerability Findings")
    table.add_column("Severity", no_wrap=True)
    table.add_column("Protocol")
    table.add_column("Target")
    table.add_column("Title")

    # Sort by severity (critical first)
    severity_order = {
        Severity.CRITICAL: 0,
        Severity.HIGH: 1,
        Severity.MEDIUM: 2,
        Severity.LOW: 3,
        Severity.INFO: 4,
    }
    sorted_vulns = sorted(
        result.all_vulnerabilities,
        key=lambda v: severity_order.get(v.severity, 5),
    )

    for vuln in sorted_vulns:
        style = SEVERITY_STYLES.get(vuln.severity, "white")
        table.add_row(
            f"[{style}]{vuln.severity.value.upper()}[/{style}]",
            vuln.protocol,
            f"{vuln.target}:{vuln.port}",
            vuln.title,
        )

    console.print(table)


def _generate_report(result, output_path, output_format):
    """Generate and save a report."""
    if output_format == "json":
        path = generate_json_report(result, output_path)
    elif output_format == "html":
        path = generate_html_report(result, output_path)
    elif output_format == "csv":
        path = generate_csv_report(result, output_path)
    else:
        path = generate_json_report(result, output_path)

    console.print(f"\n[green]Report saved to:[/green] {path}")


def _run_agentic_analysis(result, api_key, ai_model):
    """Run inline agentic analysis after a scan."""
    from otscan.agentic.analyzer import AgenticAnalyzer, AgenticConfig

    config = AgenticConfig(
        api_key=api_key or "",
        model=ai_model or "claude-sonnet-4-6",
    )
    if not config.api_key:
        config = AgenticConfig.from_env(model=ai_model)
    if not config.api_key:
        console.print(
            "\n[yellow]Skipping AI analysis: ANTHROPIC_API_KEY not set.[/yellow]"
        )
        return

    console.print(f"\n[cyan]Running AI analysis with {config.model}...[/cyan]")
    try:
        analyzer = AgenticAnalyzer(config=config)
        with console.status("Analyzing scan results..."):
            analysis = analyzer.analyze(result)
        _display_analysis(analysis)
    except Exception as e:
        console.print(f"\n[red]AI analysis failed: {e}[/red]")


def _display_analysis(analysis):
    """Display agentic analysis results."""
    from rich.markdown import Markdown

    console.print()
    console.print(Panel(
        f"[bold]Risk Score:[/bold] {analysis.risk_score}/10.0\n\n"
        f"{analysis.summary}",
        title="AI Security Assessment",
        border_style="cyan",
    ))

    if analysis.attack_paths:
        console.print("\n[bold cyan]Attack Paths:[/bold cyan]")
        for i, path in enumerate(analysis.attack_paths, 1):
            console.print(f"  {i}. {path}")

    if analysis.prioritized_remediations:
        console.print("\n[bold cyan]Prioritized Remediations:[/bold cyan]")
        for i, fix in enumerate(analysis.prioritized_remediations, 1):
            console.print(f"  {i}. {fix}")

    console.print(
        f"\n[dim]Model: {analysis.model_used} | "
        f"Tokens: {analysis.tokens_used}[/dim]"
    )


class _ReportObj:
    """Lightweight object to hold report data for the analyzer."""

    def __init__(self, data):
        self.scan_mode = data.get("scan_info", {}).get("mode", "safe")
        self.hosts = []
        self.all_vulnerabilities = []
        self.summary = _SummaryObj(data.get("summary", {}))

        for host_data in data.get("hosts", []):
            self.hosts.append(_HostObj(host_data))


class _SummaryObj:
    def __init__(self, data):
        self.targets_scanned = data.get("targets_scanned", 0)
        self.hosts_alive = data.get("hosts_alive", 0)
        self.devices_identified = data.get("devices_identified", 0)
        self.total_vulnerabilities = data.get("total_vulnerabilities", 0)
        sc = data.get("severity_counts", {})
        self.critical_count = sc.get("critical", 0)
        self.high_count = sc.get("high", 0)
        self.medium_count = sc.get("medium", 0)
        self.low_count = sc.get("low", 0)
        self.info_count = sc.get("info", 0)
        self.scan_duration = 0.0
        self.protocols_found = data.get("protocols_found", [])


class _HostObj:
    def __init__(self, data):
        self.ip = data.get("ip", "")
        self.hostname = data.get("hostname", "")
        self.open_ports = data.get("open_ports", [])
        self.scan_results = []
        for dev in data.get("devices", []):
            self.scan_results.append(_ScanResultObj(dev, data.get("vulnerabilities", [])))


class _ScanResultObj:
    def __init__(self, device_data, vulns_data):
        self.device = _DeviceObj(device_data) if device_data else None
        self.is_identified = bool(device_data)
        self.protocol = device_data.get("protocol", "") if device_data else ""
        self.port = 0
        self.vulnerabilities = [_VulnObj(v) for v in vulns_data]


class _DeviceObj:
    def __init__(self, data):
        self.protocol = data.get("protocol", "")
        self.vendor = data.get("vendor", "Unknown")
        self.model = data.get("model", "Unknown")
        self.firmware = data.get("firmware", "Unknown")
        self.device_type = data.get("device_type", "Unknown")


class _VulnObj:
    def __init__(self, data):
        self.title = data.get("title", "")
        self.severity = Severity(data.get("severity", "info"))
        self.protocol = data.get("protocol", "")
        self.port = data.get("port", 0)
        self.description = data.get("description", "")
        self.remediation = data.get("remediation", "")
        self.cve = data.get("cve", "")


def _report_dict_to_obj(data):
    """Convert a JSON report dict back to objects the analyzer can process."""
    return _ReportObj(data)


if __name__ == "__main__":
    main()
