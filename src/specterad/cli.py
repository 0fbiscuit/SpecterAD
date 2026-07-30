"""SpecterAD CLI -- In-Memory AD Attack Path Analyzer. Developed by biscuit.

Usage:
    specterad load <path>               Load SharpHound data and show stats
    specterad path <src> <dst>          Find shortest attack path
    specterad path <src> <dst> -w       Find quietest (weighted) path
    specterad path <src> --to-da        Paths to all Domain Admins
    specterad query <name>              Run pre-built security query
    specterad stats                     Show graph statistics
    specterad export <format> -o <file> Export graph to DOT/CSV/JSON
"""

from __future__ import annotations

import logging
import sys
import time
from pathlib import Path

import click
from rich.console import Console

from specterad.engine.pathfinder import Pathfinder
from specterad.engine.queries import QueryEngine
from specterad.engine.inventory import InventoryEngine
from specterad.engine.dossier import DossierEngine
from specterad.engine.remediation import RemediationEngine
from specterad.ingestor.loader import load_sharphound_data
from specterad.ingestor.normalizer import normalize_objects
from specterad.models.graph import ADGraph, create_ad_graph
from specterad.output.console import ConsoleRenderer
from specterad.output.export import export_csv, export_dot, export_json
from specterad.output.csv_pack import export_csv_pack

console = Console()
logger = logging.getLogger("specterad")

# Module-level state for loaded graph (reused across subcommands)
_state: dict[str, Any] = {
    "ad_graph": None,
    "pathfinder": None,
    "queries": None,
    "renderer": None,
    "inventory": None,
    "dossier": None,
    "remediation": None,
}


def _load_data(data_path: str | Path) -> ADGraph:
    """Load SharpHound data and build ADGraph."""
    path = Path(data_path)
    if not path.exists():
        console.print(f"[bold red][x][/bold red] Path not found: {path}")
        sys.exit(1)

    console.print(f"[dim]Loading data from {path}...[/dim]")
    t0 = time.perf_counter()

    try:
        raw_data = load_sharphound_data(path)
        nodes = normalize_objects(raw_data)
        ad_graph = create_ad_graph(nodes)
    except Exception as exc:
        console.print(f"[bold red][x][/bold red] Failed to load data: {exc}")
        sys.exit(1)

    elapsed = time.perf_counter() - t0
    console.print(f"[dim]Loaded in {elapsed:.2f}s[/dim]")
    return ad_graph


def _ensure_loaded(data_path: str | Path | None) -> None:
    """Ensure data is loaded, prompt if needed."""
    if _state["ad_graph"] is None:
        if data_path is None:
            console.print(
                "[bold red][x][/bold red] No data loaded. "
                "Use [bold]specterad load <path>[/bold] first, "
                "or pass [bold]--data <path>[/bold]."
            )
            sys.exit(1)
        ag = _load_data(data_path)
        _state["ad_graph"] = ag
        _state["pathfinder"] = Pathfinder(ag)
        _state["queries"] = QueryEngine(ag)
        _state["renderer"] = ConsoleRenderer(ag, console)
        _state["inventory"] = InventoryEngine(ag)
        _state["dossier"] = DossierEngine(ag, _state["pathfinder"])
        _state["remediation"] = RemediationEngine(ag, _state["pathfinder"])


# ──────────────────────────────────────────────
# CLI Group
# ──────────────────────────────────────────────


@click.group()
@click.option(
    "--data", "-d",
    type=click.Path(exists=True),
    default=None,
    help="Path to SharpHound ZIP or JSON directory.",
)
@click.option(
    "--verbose", "-v",
    is_flag=True,
    default=False,
    help="Enable verbose logging.",
)
@click.pass_context
def cli(ctx: click.Context, data: str | None, verbose: bool) -> None:
    """SpecterAD -- In-Memory AD Attack Path Analyzer. Developed by biscuit.

    Lightweight CLI tool for analyzing Active Directory attack paths
    from SharpHound JSON data.
    """
    ctx.ensure_object(dict)
    ctx.obj["data_path"] = data

    if verbose:
        logging.basicConfig(
            level=logging.DEBUG,
            format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
        )
    else:
        logging.basicConfig(
            level=logging.WARNING,
            format="%(levelname)s: %(message)s",
        )

    if data:
        _ensure_loaded(data)


# ──────────────────────────────────────────────
# Commands
# ──────────────────────────────────────────────


@cli.command("load")
@click.argument("path", type=click.Path(exists=True))
@click.pass_context
def cmd_load(ctx: click.Context, path: str) -> None:
    """Load SharpHound data and display summary statistics."""
    ag = _load_data(path)
    _state["ad_graph"] = ag
    _state["pathfinder"] = Pathfinder(ag)
    _state["queries"] = QueryEngine(ag)
    _state["renderer"] = ConsoleRenderer(ag, console)
    _state["inventory"] = InventoryEngine(ag)
    _state["dossier"] = DossierEngine(ag, _state["pathfinder"])
    _state["remediation"] = RemediationEngine(ag, _state["pathfinder"])

    renderer: ConsoleRenderer = _state["renderer"]  # type: ignore
    stats = ag.summary()
    renderer.render_load_summary(stats)


@cli.command("path")
@click.argument("source")
@click.argument("target", required=False, default=None)
@click.option(
    "--weighted", "-w",
    is_flag=True,
    default=False,
    help="Use Dijkstra weighted path (quietest route).",
)
@click.option(
    "--to-da",
    is_flag=True,
    default=False,
    help="Find paths to all Domain Admins groups.",
)
@click.option(
    "--to-hvt",
    is_flag=True,
    default=False,
    help="Find paths to all High-Value Targets.",
)
@click.option(
    "--all", "show_all",
    is_flag=True,
    default=False,
    help="Show all shortest paths (not just one).",
)
@click.option(
    "--max", "max_paths",
    type=int,
    default=10,
    help="Maximum number of paths to display.",
)
@click.pass_context
def cmd_path(
    ctx: click.Context,
    source: str,
    target: str | None,
    weighted: bool,
    to_da: bool,
    to_hvt: bool,
    show_all: bool,
    max_paths: int,
) -> None:
    """Find attack paths between AD objects.

    Examples:

        specterad path "D.QUAN" "Domain Admins" -d data.zip

        specterad path "D.QUAN" "Domain Admins" -w -d data.zip

        specterad path "D.QUAN" --to-da -d data.zip

        specterad path "D.QUAN" --to-hvt -d data.zip
    """
    _ensure_loaded(ctx.obj.get("data_path"))
    pf: Pathfinder = _state["pathfinder"]  # type: ignore
    renderer: ConsoleRenderer = _state["renderer"]  # type: ignore

    try:
        if to_da:
            # Find paths to Domain Admins
            console.print(f"\n[bold]Finding paths from [cyan]{source}[/cyan] to Domain Admins...[/bold]\n")
            # Resolve DA groups
            ag: ADGraph = _state["ad_graph"]  # type: ignore
            da_paths = []
            from specterad.models.node import NodeType as NT
            for sid in ag.nodes_by_type.get(NT.GROUP, []):
                if sid.endswith("-512"):
                    try:
                        path = pf.shortest_path(source, ag.display_name(sid))
                        if path and path.steps:
                            da_paths.append(path)
                    except ValueError:
                        continue

            if da_paths:
                renderer.render_paths_list(da_paths, "Paths to Domain Admins")
                # Also render the best one in detail
                console.print()
                renderer.render_path(da_paths[0])
            else:
                console.print("[yellow]No paths to Domain Admins found.[/yellow]")

        elif to_hvt:
            # Find paths to all HVTs
            console.print(f"\n[bold]Finding paths from [cyan]{source}[/cyan] to HVTs...[/bold]\n")
            paths = pf.paths_to_hvt(source, max_targets=max_paths)
            if paths:
                renderer.render_paths_list(paths, "Paths to High-Value Targets")
            else:
                console.print("[yellow]No paths to HVTs found.[/yellow]")

        elif target is None:
            console.print("[red]Error: TARGET is required unless --to-da or --to-hvt is used.[/red]")
            sys.exit(1)

        elif show_all:
            # All shortest paths
            console.print(
                f"\n[bold]Finding all shortest paths: "
                f"[cyan]{source}[/cyan] -> [red]{target}[/red]...[/bold]\n"
            )
            paths = pf.all_shortest_paths(source, target, max_paths=max_paths)
            if paths:
                renderer.render_paths_list(paths)
                console.print()
                renderer.render_path(paths[0])
            else:
                console.print("[yellow]No paths found.[/yellow]")

        elif weighted:
            # Dijkstra weighted
            console.print(
                f"\n[bold]Finding quietest path: "
                f"[cyan]{source}[/cyan] -> [red]{target}[/red]...[/bold]\n"
            )
            path = pf.weighted_path(source, target)
            if path and path.steps:
                renderer.render_path(path)
            else:
                console.print("[yellow]No weighted path found.[/yellow]")

        else:
            # Default: shortest path
            console.print(
                f"\n[bold]Finding shortest path: "
                f"[cyan]{source}[/cyan] -> [red]{target}[/red]...[/bold]\n"
            )
            path = pf.shortest_path(source, target)
            if path and path.steps:
                renderer.render_path(path)
            else:
                console.print("[yellow]No path found.[/yellow]")

    except ValueError as exc:
        console.print(f"[bold red][x][/bold red] {exc}")
        sys.exit(1)


@cli.command("query")
@click.argument(
    "query_name",
    type=click.Choice([
        "kerberoastable", "asreproast", "unconstrained",
        "dcsync", "da-sessions", "hvt",
        "shadow-creds", "pwd-in-desc", "pwd-never-expires",
        "pwd-not-required", "priv-roast",
        "domain-trusts", "rbcd-configurable",
        "all-users", "all-groups", "all-computers", "all",
    ]),
)
@click.pass_context
def cmd_query(ctx: click.Context, query_name: str) -> None:
    """Run pre-built security queries.

    Available queries:

        kerberoastable    Users with SPNs (Kerberoasting targets)

        asreproast        Users without pre-auth (AS-REP roasting)

        unconstrained     Computers with unconstrained delegation

        dcsync            Principals with DCSync rights

        da-sessions       Computers with DA sessions

        hvt               All High-Value Targets

        shadow-creds      Principals with AddKeyCredentialLink

        pwd-in-desc       Users with passwords in description

        pwd-never-expires Users with PasswordNeverExpires

        pwd-not-required  Users with PASSWD_NOTREQD

        priv-roast        Roastable users with admin privileges

        all-users         List all users

        all-groups        List all groups

        all-computers     List all computers

        all               Run all queries
    """
    _ensure_loaded(ctx.obj.get("data_path"))
    qe: QueryEngine = _state["queries"]  # type: ignore
    renderer: ConsoleRenderer = _state["renderer"]  # type: ignore

    console.print()

    query_map = {
        "kerberoastable": qe.kerberoastable_users,
        "asreproast": qe.asrep_roastable_users,
        "unconstrained": qe.unconstrained_delegation,
        "dcsync": qe.dcsync_principals,
        "da-sessions": qe.da_sessions,
        "hvt": qe.high_value_targets,
        "shadow-creds": qe.shadow_credentials,
        "pwd-in-desc": qe.password_in_description,
        "pwd-never-expires": qe.password_never_expires,
        "pwd-not-required": qe.password_not_required,
        "priv-roast": qe.privileged_roast,
        "domain-trusts": qe.domain_trusts,
        "rbcd-configurable": qe.rbcd_configurable,
        "all-users": qe.all_users,
        "all-groups": qe.all_groups,
        "all-computers": qe.all_computers,
    }

    if query_name == "all":
        results = qe.run_all()
        for result in results:
            renderer.render_query_result(result)
            console.print()
    else:
        result = query_map[query_name]()
        renderer.render_query_result(result)

    console.print()


@cli.command("stats")
@click.pass_context
def cmd_stats(ctx: click.Context) -> None:
    """Display detailed graph statistics."""
    _ensure_loaded(ctx.obj.get("data_path"))
    inv: InventoryEngine = _state["inventory"]  # type: ignore
    renderer: ConsoleRenderer = _state["renderer"]  # type: ignore

    console.print()
    stats = inv.stats_with_percentages()
    renderer.render_stats(stats)
    console.print()


@cli.command("inventory")
@click.argument(
    "inv_type",
    type=click.Choice(["pwd-age", "stale", "groups", "structural", "all"]),
)
@click.option(
    "--days", type=int, default=90,
    help="Threshold in days for stale account detection.",
)
@click.pass_context
def cmd_inventory(ctx: click.Context, inv_type: str, days: int) -> None:
    """Run inventory analysis on loaded data.

    Available types:

        pwd-age       Password age distribution ladder

        stale         Stale/inactive accounts (configurable --days)

        groups        Privilege group membership (DA, EA, SA, Admins)

        structural    Domains, DCs, trusts, OUs

        all           Run all inventory analyses
    """
    _ensure_loaded(ctx.obj.get("data_path"))
    inv: InventoryEngine = _state["inventory"]  # type: ignore
    renderer: ConsoleRenderer = _state["renderer"]  # type: ignore

    console.print()

    inv_map = {
        "pwd-age": inv.password_age_ladder,
        "stale": lambda: inv.stale_accounts(days=days),
        "groups": inv.privilege_group_membership,
        "structural": inv.structural_inventory,
    }

    if inv_type == "all":
        results = inv.run_all()
        for result in results:
            renderer.render_inventory(result)
            console.print()
    else:
        result = inv_map[inv_type]()
        renderer.render_inventory(result)

    console.print()


@cli.command("dossier")
@click.argument("identifier")
@click.pass_context
def cmd_dossier(ctx: click.Context, identifier: str) -> None:
    """Generate a comprehensive report for a single AD object.

    IDENTIFIER can be a SID, full name, or partial name.

    Examples:

        specterad dossier D.QUAN -d data.zip

        specterad dossier ADMINISTRATOR -d data.zip

        specterad dossier S-1-5-21-1234-5678-512 -d data.zip
    """
    _ensure_loaded(ctx.obj.get("data_path"))
    dossier_eng: DossierEngine = _state["dossier"]  # type: ignore
    renderer: ConsoleRenderer = _state["renderer"]  # type: ignore

    console.print()

    try:
        report = dossier_eng.node_dossier(identifier)
        renderer.render_dossier(report)
    except ValueError as exc:
        console.print(f"[bold red][x][/bold red] {exc}")
        sys.exit(1)

    console.print()


@cli.command("remediate")
@click.option(
    "--top", type=int, default=10,
    help="Number of top choke points to display.",
)
@click.pass_context
def cmd_remediate(ctx: click.Context, top: int) -> None:
    """Analyze attack paths and recommend remediation actions.

    Identifies the busiest edges (choke points) across all attack paths
    to High-Value Targets, and provides actionable removal recommendations.

    Examples:

        specterad remediate -d data.zip

        specterad remediate --top 20 -d data.zip
    """
    _ensure_loaded(ctx.obj.get("data_path"))
    rem_eng: RemediationEngine = _state["remediation"]  # type: ignore
    renderer: ConsoleRenderer = _state["renderer"]  # type: ignore

    console.print()
    report = rem_eng.busiest_path_ranking(top_n=top)
    renderer.render_remediation(report)
    console.print()


@cli.command("export")
@click.argument(
    "format_type",
    type=click.Choice(["dot", "csv", "json", "csv-pack"]),
)
@click.option(
    "--output", "-o",
    type=click.Path(),
    default=None,
    help="Output file/directory path. Defaults to specterad_export.<format>",
)
@click.pass_context
def cmd_export(ctx: click.Context, format_type: str, output: str | None) -> None:
    """Export graph data to DOT, CSV, JSON, or CSV-pack format.

    Examples:

        specterad export dot -o graph.dot -d data.zip

        specterad export csv -o edges.csv -d data.zip

        specterad export json -o data.json -d data.zip

        specterad export csv-pack -o ./pack_output -d data.zip
    """
    _ensure_loaded(ctx.obj.get("data_path"))
    ag: ADGraph = _state["ad_graph"]  # type: ignore

    # Handle csv-pack separately (outputs a directory)
    if format_type == "csv-pack":
        if output is None:
            output = "specterad_csv_pack"
        try:
            result_dir = export_csv_pack(ag, output)
            console.print(
                f"\n[bold green][+][/bold green] CSV pack exported to "
                f"[bold]{result_dir}[/bold] (12 files)\n"
            )
        except Exception as exc:
            console.print(f"[bold red][x][/bold red] Export failed: {exc}")
            sys.exit(1)
        return

    # Default output path
    if output is None:
        output = f"specterad_export.{format_type}"

    out_path = Path(output)

    export_map = {
        "dot": export_dot,
        "csv": export_csv,
        "json": export_json,
    }

    try:
        result_path = export_map[format_type](ag, out_path)
        console.print(
            f"\n[bold green][+][/bold green] Exported to [bold]{result_path}[/bold] "
            f"({format_type.upper()} format)\n"
        )
    except Exception as exc:
        console.print(f"[bold red][x][/bold red] Export failed: {exc}")
        sys.exit(1)


def main() -> None:
    """Entry point for the CLI."""
    cli()


if __name__ == "__main__":
    main()
