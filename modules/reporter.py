"""
CLI reporter - outputs findings to terminal in formatted tables.
"""

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.columns import Columns
from rich import box

console = Console()

SEVERITY_COLORS = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "cyan"
}

SEVERITY_ICONS = {
    "critical": "🔴",
    "high": "🟠",
    "medium": "🟡",
    "low": "🔵"
}


class CLIReporter:
    def __init__(self, results):
        self.results = results

    def _print_executive_summary(self):
        from modules.executive_summary import generate_executive_summary
        overall_risk = self.results.summary.get("overall_risk", {})
        exec_summary = generate_executive_summary(self.results, overall_risk)

        rating = exec_summary["overall_rating"]
        score = exec_summary["overall_score"]
        color_map = {
            "CRITICAL": "bold red",
            "HIGH": "red",
            "MEDIUM": "yellow",
            "LOW": "green"
        }
        color = color_map.get(rating, "white")

        console.print("\n")
        console.rule("[bold white]EXECUTIVE SUMMARY", style="white")
        console.print(
            f"\n  Overall Risk Rating: [{color}]{rating}[/{color}]  "
            f"[dim]Score: {score}/100[/dim]"
        )
        console.print(f"\n  [white]{exec_summary['risk_description']}[/white]")

        console.print("\n  [bold]Key Findings:[/bold]")
        for finding in exec_summary["key_findings"]:
            console.print(f"    [red]▸[/red] {finding}")

        console.print("\n  [bold]Immediate Actions Required:[/bold]")
        for i, action in enumerate(exec_summary["immediate_actions"][:5], 1):
            console.print(f"    [yellow]{i}.[/yellow] {action}")

        console.print("\n  [bold]Business Impact:[/bold]")
        for impact in exec_summary["business_impacts"][:3]:
            console.print(f"    [dim red]•[/dim red] {impact}")

    def _print_summary(self):
        summary = self.results.summary

        console.print("\n")
        console.rule("[bold red]ANALYSIS SUMMARY", style="red")

        stats = [
            Panel(f"[bold]{summary['total_identities']}[/bold]\nIdentities Scanned",
                  style="blue", padding=(1, 4)),
            Panel(f"[bold red]{summary['exploitable_paths']}[/bold red]\nExploitable Paths\n"
                  f"[dim]{summary['blocked_by_scp']} blocked by SCP[/dim]",
                  style="red", padding=(1, 4)),
            Panel(f"[bold red]{summary['severity_counts'].get('critical', 0)}[/bold red] Critical\n"
                  f"[red]{summary['severity_counts'].get('high', 0)}[/red] High\n"
                  f"[yellow]{summary['severity_counts'].get('medium', 0)}[/yellow] Medium\n"
                  f"[cyan]{summary['severity_counts'].get('low', 0)}[/cyan] Low",
                  title="Severity Breakdown", style="red", padding=(0, 4)),
            Panel(f"[bold]{summary['scp_summary']['total_scps']}[/bold] SCPs Loaded\n"
                  f"[bold]{summary['scp_summary']['total_denied_actions']}[/bold] Actions Denied\n"
                  f"[bold]{summary['scp_summary']['ou_chain_depth']}[/bold] OU Levels",
                  title="SCP Coverage", style="green", padding=(0, 4)),
            Panel(f"[bold]{summary['sensitive_resources']['secrets']}[/bold] Secrets\n"
                  f"[bold]{summary['sensitive_resources']['s3_buckets']}[/bold] S3 Buckets\n"
                  f"[bold]{summary['sensitive_resources']['ssm_params']}[/bold] SSM Params",
                  title="Sensitive Resources", style="yellow", padding=(0, 4)),
        ]
        console.print(Columns(stats))

    def _print_attack_paths(self):
        if not self.results.attack_paths:
            console.print("\n[green]✓ No attack paths found for specified severity threshold.[/green]")
            return

        console.print("\n")
        console.rule("[bold red]ATTACK PATHS", style="red")

        table = Table(
            box=box.ROUNDED,
            show_header=True,
            header_style="bold white on dark_red",
            border_style="red",
            expand=True
        )
        table.add_column("Sev", width=4, justify="center")
        table.add_column("Status", width=10, justify="center")
        table.add_column("Source Identity", style="cyan", no_wrap=False)
        table.add_column("Technique", style="yellow", width=25)
        table.add_column("Description", style="white")
        table.add_column("Permissions Used", style="dim", width=30)
        table.add_column("MITRE", width=10, justify="center")

        sorted_paths = sorted(
            self.results.attack_paths,
            key=lambda p: (
                0 if p.blocked_by_scp else 1,
                {"critical": 4, "high": 3, "medium": 2, "low": 1}.get(p.severity, 0)
            ),
            reverse=True
        )

        for path in sorted_paths:
            icon = SEVERITY_ICONS.get(path.severity, "⚪")
            color = SEVERITY_COLORS.get(path.severity, "white")
            source_short = path.source.split("/")[-1] if "/" in path.source else path.source

            if path.blocked_by_scp:
                status = "[green]BLOCKED[/green]"
                row_style = "dim"
            else:
                status = "[bold red]EXPOSED[/bold red]"
                row_style = ""

            table.add_row(
                icon,
                status,
                f"[{color}]{source_short}[/{color}]",
                f"[yellow]{path.technique}[/yellow]",
                path.description + (f"\n[dim green]↳ {path.blocking_scp}[/dim green]" if path.blocked_by_scp else "") + (f"\n[dim yellow]↳ {path.condition_explanation}[/dim yellow]" if path.condition_result == "CONDITIONAL" else ""),
                "\n".join(path.permissions_used),
                path.mitre_id,
                style=row_style
            )

        console.print(table)

    def _print_scp_coverage(self):
        summary = self.results.summary.get("scp_summary", {})
        if not summary.get("enabled"):
            return

        scps = summary.get("scps", [])
        restrictive = [s for s in scps if s["type"] == "Restrictive"]

        if not restrictive:
            console.print("\n[yellow]⚠ No restrictive SCPs found — all paths are potentially exploitable[/yellow]")
            return

        console.print("\n")
        console.rule("[bold green]SCP COVERAGE", style="green")

        table = Table(
            box=box.ROUNDED,
            show_header=True,
            header_style="bold white on dark_green",
            border_style="green",
            expand=True
        )
        table.add_column("SCP Name", style="green")
        table.add_column("Policy ID", style="dim", width=20)
        table.add_column("Target", style="cyan", width=20)
        table.add_column("Denied Actions", style="red")

        for scp in restrictive:
            denied_preview = ", ".join(scp["denied_actions"][:5])
            if len(scp["denied_actions"]) > 5:
                denied_preview += f" +{len(scp['denied_actions']) - 5} more"
            table.add_row(
                scp["name"],
                scp["id"],
                scp["target"],
                denied_preview or "[dim]none parsed[/dim]"
            )

        console.print(table)

    def _print_attack_steps(self):
        critical = [p for p in self.results.attack_paths
                    if p.severity == "critical" and not p.blocked_by_scp]
        if not critical:
            return

        console.print("\n")
        console.rule("[bold red]CRITICAL PATH DETAILS (Exploitable)", style="red")

        for i, path in enumerate(critical[:5], 1):
            console.print(f"\n[bold red]Path {i}: {path.technique}[/bold red]")
            for j, step in enumerate(path.path_steps, 1):
                console.print(f"  [dim]{j}.[/dim] {step}")

    def _print_sensitive_resources(self):
        resources = self.results.sensitive_resources

        if not any([resources["secrets"], resources["ssm_params"]]):
            return

        console.print("\n")
        console.rule("[bold yellow]SENSITIVE RESOURCES", style="yellow")

        if resources["secrets"]:
            console.print(f"\n[yellow]Secrets Manager ({len(resources['secrets'])} found):[/yellow]")
            for secret in resources["secrets"][:10]:
                console.print(f"  [red]•[/red] {secret['name']}")
                if secret.get("description"):
                    console.print(f"    [dim]{secret['description']}[/dim]")

        if resources["ssm_params"]:
            console.print(f"\n[yellow]Sensitive SSM Parameters ({len(resources['ssm_params'])} found):[/yellow]")
            for param in resources["ssm_params"][:10]:
                console.print(f"  [red]•[/red] {param['name']} [dim]({param['type']})[/dim]")

        if resources["s3_buckets"]:
            flagged = [b for b in resources["s3_buckets"] if b["flags"]]
            if flagged:
                console.print(f"\n[yellow]S3 Buckets with Issues ({len(flagged)} found):[/yellow]")
                for bucket in flagged[:10]:
                    flags_str = ", ".join(bucket["flags"])
                    console.print(f"  [red]•[/red] {bucket['name']} [dim]→ {flags_str}[/dim]")

    def _print_remediation_guidance(self):
        from modules.remediation import get_top_remediations
        remediations = get_top_remediations(self.results.attack_paths, limit=5)
        if not remediations:
            return

        console.print("\n")
        console.rule("[bold green]TOP REMEDIATIONS", style="green")

        from rich.table import Table
        from rich import box
        table = Table(
            box=box.ROUNDED,
            show_header=True,
            header_style="bold white on dark_green",
            border_style="green",
            expand=True
        )
        table.add_column("Priority", width=6, justify="center")
        table.add_column("Technique", style="yellow", width=25)
        table.add_column("Risk Score", width=10, justify="center")
        table.add_column("Effort", width=8, justify="center")
        table.add_column("Fix Summary", style="white")

        for i, rem in enumerate(remediations, 1):
            guidance = rem["guidance"]
            effort_color = {
                "Low": "green", "Medium": "yellow", "High": "red"
            }.get(guidance.get("effort", "Medium"), "white")
            first_step = guidance.get("steps", ["Review permissions"])[0]
            table.add_row(
                f"#{i}",
                rem["technique"],
                f"[red]{rem['risk_score']}[/red]",
                f"[{effort_color}]{guidance.get('effort','?')}[/{effort_color}]",
                first_step
            )
        console.print(table)

    def _print_cross_account_paths(self):
        cross = self.results.summary.get("cross_account_summary", {})
        paths = cross.get("paths", [])
        if not paths:
            return

        console.print("\n")
        console.rule("[bold magenta]CROSS-ACCOUNT ATTACK PATHS", style="magenta")

        from rich.table import Table
        from rich import box
        table = Table(
            box=box.ROUNDED,
            show_header=True,
            header_style="bold white on dark_magenta",
            border_style="magenta",
            expand=True
        )
        table.add_column("Sev", width=4, justify="center")
        table.add_column("Source Identity", style="cyan")
        table.add_column("Target Account", style="magenta")
        table.add_column("Target Role", style="yellow")
        table.add_column("Description", style="white")

        for path in paths:
            icon = "🔴" if path["severity"] == "critical" else "🟠"
            source_short = path["source"].split("/")[-1]
            table.add_row(
                icon,
                source_short,
                path["target_account"],
                path["target_role"].split("/")[-1],
                path["description"]
            )
        console.print(table)

        console.print(f"\n[magenta]Accounts reachable from {self.results.account_id}:[/magenta]")
        for acc in cross.get("accounts_reachable", []):
            console.print(f"  [red]•[/red] {acc}")

    def print_report(self):
        console.print(f"\n[dim]Account:[/dim] [bold]{self.results.account_id}[/bold]  "
                      f"[dim]Region:[/dim] [bold]{self.results.region}[/bold]  "
                      f"[dim]Scope:[/dim] [bold]{self.results.start_identity}[/bold]")

        self._print_executive_summary()
        self._print_summary()
        self._print_scp_coverage()
        self._print_attack_paths()
        self._print_attack_steps()
        self._print_remediation_guidance()
        self._print_cross_account_paths()
        self._print_sensitive_resources()
