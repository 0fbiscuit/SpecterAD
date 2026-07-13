"""Export module — DOT (Graphviz), CSV, and JSON export for attack paths.

Supports three formats:
- DOT: Graphviz graph description for visual rendering
- CSV: Tabular edge list for Excel/SIEM import
- JSON: Structured data for automation pipelines
"""

from __future__ import annotations

import csv
import json
import logging
from io import StringIO
from pathlib import Path
from typing import Any

from specterad.models.graph import ADGraph
from specterad.models.path import AttackPath
from specterad.output.formatter import get_node_color

logger = logging.getLogger(__name__)


def export_dot(
    ad_graph: ADGraph,
    output_path: Path | str,
    paths: list[AttackPath] | None = None,
) -> Path:
    """Export graph or specific paths to Graphviz DOT format.

    If paths are provided, only the subgraph containing those paths
    is exported. Otherwise, the entire graph is exported.

    Args:
        ad_graph: The ADGraph to export.
        output_path: Output file path.
        paths: Optional list of AttackPaths to highlight.

    Returns:
        The output file path.
    """
    output_path = Path(output_path)
    lines: list[str] = []

    lines.append("digraph SpecterAD {")
    lines.append('  rankdir=LR;')
    lines.append('  node [shape=box, style="rounded,filled", fontname="Consolas"];')
    lines.append('  edge [fontname="Consolas", fontsize=10];')
    lines.append("")

    # Color map for DOT
    dot_colors: dict[str, str] = {
        "User": "#2ecc71",
        "Computer": "#f39c12",
        "Group": "#3498db",
        "Domain": "#9b59b6",
        "OU": "#1abc9c",
        "GPO": "#1abc9c",
        "CertTemplate": "#e74c3c",
        "Container": "#95a5a6",
    }

    if paths:
        # Export only path subgraph
        path_nodes: set[str] = set()
        path_edges: set[tuple[str, str]] = set()
        for path in paths:
            for step in path.steps:
                path_nodes.add(step.source)
                path_nodes.add(step.target)
                path_edges.add((step.source, step.target))

        # Nodes
        for sid in path_nodes:
            node_data = ad_graph.graph.nodes.get(sid, {})
            name = ad_graph.display_name(sid)
            ntype = node_data.get("node_type", "Unknown")
            color = dot_colors.get(ntype, "#bdc3c7")
            is_hvt = sid in ad_graph.high_value_targets
            style = "bold" if is_hvt else "filled"
            penwidth = "3" if is_hvt else "1"

            safe_name = name.replace('"', '\\"')
            lines.append(
                f'  "{sid}" [label="{safe_name}\\n({ntype})", '
                f'fillcolor="{color}", penwidth={penwidth}, style="{style},rounded,filled"];'
            )

        lines.append("")

        # Edges — collect edge types from path steps
        path_edge_types: dict[tuple[str, str], str] = {}
        for path in paths:
            for step in path.steps:
                path_edge_types[(step.source, step.target)] = step.edge_type

        for (src, dst), etype in path_edge_types.items():
            lines.append(f'  "{src}" -> "{dst}" [label="{etype}", color="#e74c3c", penwidth=2];')

    else:
        # Export entire graph
        for sid in ad_graph.graph.nodes:
            node_data = ad_graph.graph.nodes[sid]
            name = ad_graph.display_name(sid)
            ntype = node_data.get("node_type", "Unknown")
            color = dot_colors.get(ntype, "#bdc3c7")
            safe_name = name.replace('"', '\\"')
            lines.append(
                f'  "{sid}" [label="{safe_name}\\n({ntype})", fillcolor="{color}"];'
            )

        lines.append("")

        for src, dst, data in ad_graph.graph.edges(data=True):
            etype = data.get("edge_type", "")
            lines.append(f'  "{src}" -> "{dst}" [label="{etype}"];')

    lines.append("}")

    output_path.write_text("\n".join(lines), encoding="utf-8")
    logger.info("Exported DOT graph to %s", output_path)
    return output_path


def export_csv(
    ad_graph: ADGraph,
    output_path: Path | str,
    paths: list[AttackPath] | None = None,
) -> Path:
    """Export edges to CSV format.

    If paths are provided, only path edges are exported.
    Otherwise, all graph edges are exported.

    CSV columns: source_sid, source_name, edge_type, target_sid, target_name, weight

    Args:
        ad_graph: The ADGraph to export.
        output_path: Output file path.
        paths: Optional list of AttackPaths.

    Returns:
        The output file path.
    """
    output_path = Path(output_path)

    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            "source_sid", "source_name", "edge_type",
            "target_sid", "target_name", "weight",
        ])

        if paths:
            for path in paths:
                for step in path.steps:
                    writer.writerow([
                        step.source, step.source_name, step.edge_type,
                        step.target, step.target_name, f"{step.weight:.4f}",
                    ])
        else:
            for src, dst, data in ad_graph.graph.edges(data=True):
                etype = data.get("edge_type", "Unknown")
                writer.writerow([
                    src,
                    ad_graph.display_name(src),
                    etype,
                    dst,
                    ad_graph.display_name(dst),
                    "",
                ])

    logger.info("Exported CSV to %s", output_path)
    return output_path


def export_json(
    ad_graph: ADGraph,
    output_path: Path | str,
    paths: list[AttackPath] | None = None,
) -> Path:
    """Export paths or graph to structured JSON.

    If paths are provided, exports path details.
    Otherwise, exports graph summary with nodes and edges.

    Args:
        ad_graph: The ADGraph to export.
        output_path: Output file path.
        paths: Optional list of AttackPaths.

    Returns:
        The output file path.
    """
    output_path = Path(output_path)

    if paths:
        data: dict[str, Any] = {
            "type": "attack_paths",
            "count": len(paths),
            "paths": [],
        }
        for path in paths:
            path_data = {
                "source": path.source,
                "source_name": path.source_name,
                "target": path.target,
                "target_name": path.target_name,
                "hop_count": path.hop_count,
                "total_weight": round(path.total_weight, 4),
                "steps": [
                    {
                        "source": s.source,
                        "source_name": s.source_name,
                        "edge_type": s.edge_type,
                        "target": s.target,
                        "target_name": s.target_name,
                        "weight": round(s.weight, 4),
                    }
                    for s in path.steps
                ],
            }
            data["paths"].append(path_data)
    else:
        stats = ad_graph.summary()
        data = {
            "type": "graph_export",
            "summary": stats,
            "nodes": [
                {
                    "sid": sid,
                    "name": ad_graph.display_name(sid),
                    "node_type": ad_graph.graph.nodes[sid].get("node_type", "Unknown"),
                    "high_value": sid in ad_graph.high_value_targets,
                }
                for sid in ad_graph.graph.nodes
            ],
            "edges": [
                {
                    "source": src,
                    "target": dst,
                    "edge_type": d.get("edge_type", "Unknown"),
                }
                for src, dst, d in ad_graph.graph.edges(data=True)
            ],
        }

    output_path.write_text(
        json.dumps(data, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    logger.info("Exported JSON to %s", output_path)
    return output_path
