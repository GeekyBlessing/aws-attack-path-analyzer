#!/usr/bin/env python3
"""
AWS Attack Path Analyzer
Discovers and visualizes privilege escalation paths in AWS environments.
"""

import argparse
import sys
import os
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

console = Console()

BANNER = """
╔═══════════════════════════════════════════════════════╗
║          AWS ATTACK PATH ANALYZER v1.0                ║
║     Privilege Escalation & Lateral Movement           ║
╚═══════════════════════════════════════════════════════╝
"""

def main():
    parser = argparse.ArgumentParser(
        description="AWS Attack Path Analyzer - Discovers privilege escalation paths",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py --profile default --region us-east-1
  python main.py --profile pentest --region eu-west-1 --output report.html
  python main.py --profile dev --identity arn:aws:iam::123456789012:user/devuser
        """
    )
    parser.add_argument("--profile", default="default", help="AWS profile name (default: default)")
    parser.add_argument("--region", default="us-east-1", help="AWS region (default: us-east-1)")
    parser.add_argument("--output", default="attack_paths_report.html", help="Output HTML report path")
    parser.add_argument("--identity", help="Specific IAM identity ARN to start from (optional)")
    parser.add_argument("--severity", choices=["low", "medium", "high", "critical"],
                        default="low", help="Minimum severity to include (default: low)")
    parser.add_argument("--no-report", action="store_true", help="Skip HTML report generation")
    parser.add_argument("--quiet", action="store_true", help="Suppress banner")

    args = parser.parse_args()

    if not args.quiet:
        console.print(BANNER, style="bold red")

    # Run analysis
    from modules.analyzer import AttackPathAnalyzer

    analyzer = AttackPathAnalyzer(
        profile=args.profile,
        region=args.region,
        start_identity=args.identity,
        min_severity=args.severity
    )

    results = analyzer.run()

    if not results:
        console.print("[yellow]Analysis complete. No attack paths found with current configuration.[/yellow]")
        sys.exit(0)

    # CLI report
    from modules.reporter import CLIReporter
    cli_reporter = CLIReporter(results)
    cli_reporter.print_report()

    # HTML report
    if not args.no_report:
        from modules.html_reporter import HTMLReporter
        html_reporter = HTMLReporter(results)
        output_path = html_reporter.generate(args.output)
        console.print(f"\n[bold green]✓ HTML report saved:[/bold green] {output_path}")

if __name__ == "__main__":
    main()