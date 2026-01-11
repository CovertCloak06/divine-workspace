#!/usr/bin/env python3
"""
Divine Node Development Dashboard
Simple TUI for monitoring services and running commands
"""

import subprocess
import time
import urllib.request
from rich.console import Console
from rich.table import Table
from rich.live import Live
from rich.panel import Panel
from rich.layout import Layout


console = Console()


def check_service(url):
    """Check if a service is running."""
    try:
        urllib.request.urlopen(url, timeout=1)
        return "✅ Running"
    except Exception:
        return "❌ Down"


def get_services_status():
    """Get status of all services."""
    return {
        "PKN Server": check_service("http://localhost:8010/health"),
        "Code Academy": check_service("http://localhost:8011"),
        "PKN Mobile": check_service("http://localhost:8010/health"),
    }


def create_dashboard():
    """Create dashboard layout."""
    layout = Layout()

    # Services status table
    services = get_services_status()
    table = Table(title="🚀 Services Status")
    table.add_column("Service", style="cyan")
    table.add_column("Status", style="magenta")

    for name, status in services.items():
        table.add_row(name, status)

    # Wrap in panel
    panel = Panel(
        table,
        title="Divine Node Dashboard",
        subtitle="Press Ctrl+C to exit"
    )

    return panel


def main():
    """Run the dashboard."""
    console.print("[bold cyan]Divine Node Development Dashboard[/bold cyan]")
    console.print("[dim]Monitoring services...[/dim]\n")

    try:
        with Live(create_dashboard(), refresh_per_second=1) as live:
            while True:
                time.sleep(1)
                live.update(create_dashboard())
    except KeyboardInterrupt:
        console.print("\n[yellow]Dashboard stopped[/yellow]")


if __name__ == '__main__':
    main()
