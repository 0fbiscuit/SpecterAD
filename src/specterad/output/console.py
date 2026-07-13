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
