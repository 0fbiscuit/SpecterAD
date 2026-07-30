"""Rich console renderer -- beautiful CLI output for attack paths and queries.

Provides:
- render_path: Attack path as a Rich Tree with color-coded nodes and edges
- render_query_result: Query results as a Rich Table
- render_stats: Graph statistics as a Rich Panel
- render_paths_list: Multiple paths summary table

NOTE: All strings are ASCII-safe to avoid UnicodeEncodeError on Windows
cp1252 consoles. Emojis are replaced with ASCII equivalents.
"""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.tree import Tree

from specterad.engine.queries import QueryResult
from specterad.engine.inventory import InventoryResult
from specterad.engine.dossier import DossierReport
from specterad.engine.remediation import RemediationReport
from specterad.models.graph import ADGraph
from specterad.models.path import AttackPath, PathStep
from specterad.output.formatter import (
    format_weight,
    get_node_color,
    get_risk_label,
)

# Module-level console -- can be overridden for testing
console = Console()


class ConsoleRenderer:
    """Rich-based console renderer for SpecterAD output."""

    def __init__(self, ad_graph: ADGraph, output_console: Console | None = None) -> None:
        self.ad_graph = ad_graph
        self.console = output_console or console

    def _styled_node(self, sid: str, name: str) -> str:
        """Create a Rich-styled node string with type-based coloring."""
        node_data = self.ad_graph.graph.nodes.get(sid, {})
        node_type = node_data.get("node_type", "Unknown")
        color = get_node_color(node_type)
        is_hvt = sid in self.ad_graph.high_value_targets

        if is_hvt:
            return f"[bold red]* {name}[/bold red] [dim]({node_type})[/dim]"
        return f"[{color}]{name}[/{color}] [dim]({node_type})[/dim]"

    def render_path(self, path: AttackPath) -> None:
        """Render an attack path as a Rich Tree."""
        if not path.steps:
            self.console.print("[dim]No path found.[/dim]")
            return

        risk_label, risk_color = get_risk_label(path.total_weight)

        # Header
        header = Text()
        header.append("[>] Attack Path: ", style="bold")
        header.append(path.source_name, style="bold cyan")
        header.append(" -> ", style="dim")
        header.append(path.target_name, style="bold red")

        tree = Tree(header)

        for i, step in enumerate(path.steps):
            if i == 0:
                # First node
                src_label = self._styled_node(step.source, step.source_name)
                current_branch = tree.add(src_label)

            # Edge
            edge_label = f"  --[{step.edge_type}]--  [dim](w={format_weight(step.weight)})[/dim]"
            edge_branch = current_branch.add(edge_label)

            # Target node (for every step)
            dst_label = self._styled_node(step.target, step.target_name)
            current_branch = edge_branch.add(dst_label)

        self.console.print(tree)

        # Summary line
        self.console.print(
            f"\n  Hops: [bold]{path.hop_count}[/bold] | "
            f"Weight: [bold]{format_weight(path.total_weight)}[/bold] | "
            f"Risk: [{risk_color}]{risk_label}[/{risk_color}]\n"
        )

    def render_paths_list(self, paths: list[AttackPath], title: str = "Attack Paths") -> None:
        """Render multiple paths as a summary table."""
        if not paths:
            self.console.print("[dim]No paths found.[/dim]")
            return

        table = Table(title=f"  {title}", show_lines=True, safe_box=True)
        table.add_column("#", style="dim", width=4)
        table.add_column("Source", style="cyan")
        table.add_column("Target", style="red")
        table.add_column("Hops", justify="center")
        table.add_column("Weight", justify="right")
        table.add_column("Risk", justify="center")
        table.add_column("Path Summary", max_width=60)

        for i, path in enumerate(paths, 1):
            risk_label, risk_color = get_risk_label(path.total_weight)
            edge_chain = " -> ".join(s.edge_type for s in path.steps)

            table.add_row(
                str(i),
                path.source_name,
                path.target_name,
                str(path.hop_count),
                format_weight(path.total_weight),
                f"[{risk_color}]{risk_label}[/{risk_color}]",
                edge_chain,
            )

        self.console.print(table)

    def render_query_result(self, result: QueryResult) -> None:
        """Render a query result as a Rich Table."""
        if not result.results:
            self.console.print(
                f"[dim]{result.query_name}: No results found.[/dim]"
            )
            return

        table = Table(
            title=f"  {result.query_name} ({result.count} found)",
            caption=result.description,
            show_lines=True,
            safe_box=True,
        )

        # Dynamically build columns from result keys
        if result.results:
            for key in result.results[0]:
                style = "cyan" if key == "name" else None
                table.add_column(key.replace("_", " ").title(), style=style)

        for row in result.results:
            table.add_row(*[str(v) for v in row.values()])

        self.console.print(table)

    def render_stats(self, stats: dict) -> None:
        """Render graph statistics as a Rich Panel."""
        lines: list[str] = []

        lines.append("[bold]Graph Statistics[/bold]\n")
        lines.append(
            f"  Total Nodes: [bold cyan]{stats['total_nodes']}[/bold cyan]    "
            f"Total Edges: [bold cyan]{stats['total_edges']}[/bold cyan]    "
            f"HVTs: [bold red]{stats['high_value_targets']}[/bold red]"
        )
        lines.append(f"  Domains: [bold]{', '.join(stats.get('domains', []))}[/bold]\n")

        # Nodes by type
        lines.append("  [bold]Nodes by Type:[/bold]")
        for ntype, count in sorted(stats.get("nodes_by_type", {}).items()):
            color = get_node_color(ntype)
            bar = "#" * min(count, 40)
            lines.append(f"    [{color}]{ntype:<15}[/{color}] {bar} {count}")

        # Edges by type
        lines.append("\n  [bold]Edges by Type:[/bold]")
        for etype, count in sorted(
            stats.get("edges_by_type", {}).items(),
            key=lambda x: x[1],
            reverse=True,
        ):
            bar = "=" * min(count, 30)
            lines.append(f"    {etype:<25} {bar} {count}")

        # Percentage stats (if available from InventoryEngine)
        pcts = stats.get("percentages", {})
        if pcts:
            lines.append("\n  [bold]Security Posture:[/bold]")
            for label, pct in pcts.items():
                display_label = label.replace("_", " ").title()
                lines.append(f"    {display_label:<35} {pct}")

        panel = Panel(
            "\n".join(lines),
            title="[bold]SpecterAD[/bold]",
            border_style="blue",
            padding=(1, 2),
            safe_box=True,
        )
        self.console.print(panel)

    def render_load_summary(self, stats: dict) -> None:
        """Render a compact loading summary."""
        self.console.print(
            f"\n[bold green][+][/bold green] Data loaded successfully!\n"
        )
        self.console.print(
            f"  Nodes: [bold]{stats['total_nodes']}[/bold]  |  "
            f"Edges: [bold]{stats['total_edges']}[/bold]  |  "
            f"HVTs: [bold red]{stats['high_value_targets']}[/bold red]  |  "
            f"Domains: [bold]{', '.join(stats.get('domains', []))}[/bold]\n"
        )

        # Quick breakdown
        for ntype, count in sorted(stats.get("nodes_by_type", {}).items()):
            color = get_node_color(ntype)
            self.console.print(f"    [{color}]> {ntype}s: {count}[/{color}]")
        self.console.print()

    def render_inventory(self, result: InventoryResult) -> None:
        """Render an inventory analysis result."""
        lines: list[str] = []
        lines.append(f"[bold]{result.section_name}[/bold]")
        lines.append(f"[dim]{result.description}[/dim]\n")

        data = result.data

        if "summary" in data and "buckets" in data:
            # Password age ladder
            total = data.get("total_users", 1)
            for bucket_label, count in data["summary"].items():
                pct = (count / total * 100) if total > 0 else 0
                bar = "#" * min(int(pct), 40)
                lines.append(f"  {bucket_label:<20} {bar} {count} ({pct:.1f}%)")

        elif "stale_users" in data:
            # Stale accounts
            lines.append(f"  Threshold: {data.get('threshold_days', 90)} days")
            lines.append(f"  Stale Users:     [bold red]{data['count_users']}[/bold red]")
            lines.append(f"  Stale Computers: [bold red]{data['count_computers']}[/bold red]")
            if data["stale_users"]:
                lines.append("\n  [bold]Top Stale Users:[/bold]")
                for entry in data["stale_users"][:15]:
                    lines.append(
                        f"    {entry['name']:<40} "
                        f"Last logon: {entry['last_logon_days']} days ago  "
                        f"Enabled: {entry['enabled']}"
                    )

        elif "groups" in data:
            # Privilege group membership
            for _sid, ginfo in data["groups"].items():
                lines.append(
                    f"  [bold cyan]{ginfo['group_name']}[/bold cyan] "
                    f"({ginfo['group_label']}) -- "
                    f"{ginfo['member_count']} members"
                )
                for m in ginfo["direct_and_nested_members"][:20]:
                    lines.append(f"    > {m['name']} ({m['type']})")
                if ginfo["member_count"] > 20:
                    lines.append(f"    ... and {ginfo['member_count'] - 20} more")
                lines.append("")

        elif "domains" in data:
            # Structural inventory
            lines.append(f"  Domains: {data['domain_count']}")
            for d in data["domains"]:
                lines.append(f"    > {d['name']} (Level: {d['functionallevel']})")
            lines.append(f"  Domain Controllers: {data['dc_count']}")
            for dc in data["domain_controllers"]:
                lines.append(f"    > {dc['name']}")
            lines.append(f"  Trusts: {data['trust_count']}")
            for t in data["trusts"]:
                lines.append(f"    > {t['source']} --[{t['type']}]--> {t['target']}")
            lines.append(f"  OUs: {data['ou_count']}")

        panel = Panel(
            "\n".join(lines),
            title="[bold]SpecterAD Inventory[/bold]",
            border_style="green",
            padding=(1, 2),
            safe_box=True,
        )
        self.console.print(panel)

    def render_dossier(self, report: DossierReport) -> None:
        """Render a per-node dossier report."""
        lines: list[str] = []

        # Header
        lines.append(f"[bold cyan]{report.name}[/bold cyan]")
        lines.append(f"[dim]SID: {report.sid} | Type: {report.node_type}[/dim]\n")

        # Key properties
        if report.properties:
            lines.append("[bold]Properties:[/bold]")
            for k, v in list(report.properties.items())[:15]:
                lines.append(f"  {k}: {v}")
            lines.append("")

        # Group memberships
        lines.append(f"[bold]Group Memberships ({len(report.group_memberships)}):[/bold]")
        for m in report.group_memberships[:20]:
            depth_marker = "  " * m["depth"]
            direct_tag = " [dim](direct)[/dim]" if m["is_direct"] else " [dim](nested)[/dim]"
            lines.append(f"  {depth_marker}> {m['name']}{direct_tag}")
        if len(report.group_memberships) > 20:
            lines.append(f"  ... and {len(report.group_memberships) - 20} more")
        lines.append("")

        # Inbound edges summary
        lines.append("[bold]Inbound Edges:[/bold]")
        for etype, count in sorted(report.inbound_summary.items(), key=lambda x: x[1], reverse=True):
            lines.append(f"  {etype:<25} {count}")
        lines.append("")

        # AdminTo hosts
        lines.append(f"[bold]Admin To Hosts ({len(report.admin_to_hosts)}):[/bold]")
        for host in report.admin_to_hosts[:20]:
            lines.append(f"  > {host['name']} ({host['via']})")
        if len(report.admin_to_hosts) > 20:
            lines.append(f"  ... and {len(report.admin_to_hosts) - 20} more")
        lines.append("")

        # Paths to HVT
        lines.append(f"[bold]Paths to HVTs ({len(report.paths_to_hvt)}):[/bold]")
        for path in report.paths_to_hvt:
            edge_chain = " -> ".join(s.edge_type for s in path.steps)
            lines.append(
                f"  > {path.target_name} "
                f"[dim]({path.hop_count} hops, w={path.total_weight:.2f})[/dim] "
                f"{edge_chain}"
            )

        panel = Panel(
            "\n".join(lines),
            title="[bold]SpecterAD Dossier[/bold]",
            border_style="magenta",
            padding=(1, 2),
            safe_box=True,
        )
        self.console.print(panel)

    def render_remediation(self, report: RemediationReport) -> None:
        """Render remediation analysis as a Rich Table."""
        if not report.busiest_edges:
            self.console.print("[dim]No attack paths found for remediation analysis.[/dim]")
            return

        self.console.print(
            f"\n  [bold]Remediation Analysis[/bold]\n"
            f"  Paths analyzed: [bold]{report.total_paths_analyzed}[/bold]  |  "
            f"  Unique edges: [bold]{report.total_unique_edges}[/bold]\n"
        )

        table = Table(
            title="  Busiest Edges (Choke Points)",
            show_lines=True,
            safe_box=True,
        )
        table.add_column("#", style="dim", width=4)
        table.add_column("Source", style="cyan")
        table.add_column("Edge", style="yellow")
        table.add_column("Target", style="red")
        table.add_column("Paths", justify="right")
        table.add_column("Remediation", max_width=50)

        for i, edge in enumerate(report.busiest_edges, 1):
            table.add_row(
                str(i),
                edge.source_name,
                edge.edge_type,
                edge.target_name,
                str(edge.path_count),
                edge.remediation,
            )

        self.console.print(table)
