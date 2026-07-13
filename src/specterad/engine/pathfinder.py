"""Pathfinder — attack path analysis algorithms.

Provides:
- shortest_path: BFS-based shortest path (unweighted, fewest hops)
- all_shortest_paths: All equally-short paths between two nodes
- weighted_path: Dijkstra-based "quietest" path (minimizes risk weight)
- paths_to_hvt: Shortest paths from a source to ALL high-value targets

All methods accept human-readable names (resolved via ADGraph.resolve())
and return AttackPath objects with human-readable display names.
"""

from __future__ import annotations

import logging
from pathlib import Path as FilePath

import networkx as nx

from specterad.engine.weights import EdgeWeight, get_edge_weight, load_weights
from specterad.models.edge import TRAVERSABLE_EDGES, EdgeType
from specterad.models.graph import ADGraph
from specterad.models.path import AttackPath, PathStep

logger = logging.getLogger(__name__)


class Pathfinder:
    """Attack path analysis engine operating on an ADGraph.

    Filters edges to only use TRAVERSABLE_EDGES for pathfinding.
    Non-traversable edges (Contains, GPLink, DCFor) are excluded.
    """

    def __init__(
        self,
        ad_graph: ADGraph,
        weights_path: FilePath | str | None = None,
    ) -> None:
        """Initialize the pathfinder.

        Args:
            ad_graph: The enriched AD graph from Phase 2.
            weights_path: Optional path to custom edge_weights.yaml.
        """
        self.ad_graph = ad_graph
        self._graph = ad_graph.graph

        # Load weights
        self._weights, self._formula = load_weights(weights_path)

        # Build a traversable-only subgraph view for pathfinding
        self._traversable_view = nx.subgraph_view(
            self._graph,
            filter_edge=self._is_traversable_edge,
        )

        logger.info(
            "Pathfinder initialized: %d traversable edges",
            self._traversable_view.number_of_edges(),
        )

    def _is_traversable_edge(self, u: str, v: str) -> bool:
        """Edge filter: only allow traversable edge types."""
        edge_data = self._graph[u][v]
        edge_type_str = edge_data.get("edge_type", "")
        try:
            return EdgeType(edge_type_str) in TRAVERSABLE_EDGES
        except ValueError:
            return False

    def _resolve_or_raise(self, identifier: str) -> str:
        """Resolve a name/SID or raise ValueError."""
        sid = self.ad_graph.resolve(identifier)
        if sid is None:
            raise ValueError(f"Cannot resolve identifier: '{identifier}'")
        return sid

    def _build_path(self, node_list: list[str]) -> AttackPath:
        """Convert a list of node SIDs into an AttackPath with steps."""
        if len(node_list) < 2:
            return AttackPath(steps=[], total_weight=0.0, hop_count=0)

        steps: list[PathStep] = []
        total_weight = 0.0

        for i in range(len(node_list) - 1):
            src_sid = node_list[i]
            dst_sid = node_list[i + 1]

            edge_data = self._graph[src_sid][dst_sid]
            edge_type_str = edge_data.get("edge_type", "Unknown")

            weight = get_edge_weight(
                edge_type_str, self._weights, self._formula
            )

            step = PathStep(
                source=src_sid,
                source_name=self.ad_graph.display_name(src_sid),
                edge_type=edge_type_str,
                target=dst_sid,
                target_name=self.ad_graph.display_name(dst_sid),
                weight=weight,
            )
            steps.append(step)
            total_weight += weight

        return AttackPath(
            steps=steps,
            total_weight=total_weight,
            hop_count=len(steps),
        )

    def _dijkstra_weight_func(self, u: str, v: str, data: dict) -> float:
        """Weight function for Dijkstra — returns composite edge weight."""
        edge_type_str = data.get("edge_type", "")
        return get_edge_weight(edge_type_str, self._weights, self._formula)

    # ──────────────────────────────────────────
    # Public API
    # ──────────────────────────────────────────

    def shortest_path(
        self,
        source: str,
        target: str,
    ) -> AttackPath | None:
        """Find the shortest attack path (fewest hops, BFS).

        Args:
            source: Source name or SID (e.g. "D.QUAN" or "S-1-5-21-...")
            target: Target name or SID (e.g. "Domain Admins")

        Returns:
            AttackPath if a path exists, None otherwise.
        """
        src_sid = self._resolve_or_raise(source)
        dst_sid = self._resolve_or_raise(target)

        try:
            node_list = nx.shortest_path(
                self._traversable_view, src_sid, dst_sid
            )
            return self._build_path(node_list)
        except nx.NetworkXNoPath:
            logger.debug("No path from %s to %s", source, target)
            return None
        except nx.NodeNotFound as exc:
            logger.warning("Node not found in graph: %s", exc)
            return None

    def all_shortest_paths(
        self,
        source: str,
        target: str,
        max_paths: int = 10,
    ) -> list[AttackPath]:
        """Find all equally-short attack paths (BFS).

        Args:
            source: Source name or SID.
            target: Target name or SID.
            max_paths: Maximum number of paths to return.

        Returns:
            List of AttackPath objects, sorted by hop count.
        """
        src_sid = self._resolve_or_raise(source)
        dst_sid = self._resolve_or_raise(target)

        try:
            paths: list[AttackPath] = []
            for i, node_list in enumerate(
                nx.all_shortest_paths(self._traversable_view, src_sid, dst_sid)
            ):
                if i >= max_paths:
                    break
                paths.append(self._build_path(node_list))
            return paths
        except nx.NetworkXNoPath:
            return []
        except nx.NodeNotFound:
            return []

    def weighted_path(
        self,
        source: str,
        target: str,
    ) -> AttackPath | None:
        """Find the "quietest" attack path (Dijkstra, minimizes risk weight).

        Uses the composite weight from edge_weights.yaml to prefer
        stealthier, more reliable attack steps.

        Args:
            source: Source name or SID.
            target: Target name or SID.

        Returns:
            AttackPath with minimal total weight, or None if no path.
        """
        src_sid = self._resolve_or_raise(source)
        dst_sid = self._resolve_or_raise(target)

        try:
            node_list = nx.dijkstra_path(
                self._traversable_view,
                src_sid,
                dst_sid,
                weight=self._dijkstra_weight_func,
            )
            return self._build_path(node_list)
        except nx.NetworkXNoPath:
            logger.debug("No weighted path from %s to %s", source, target)
            return None
        except nx.NodeNotFound:
            return None

    def paths_to_hvt(
        self,
        source: str,
        max_targets: int = 20,
    ) -> list[AttackPath]:
        """Find shortest paths from source to ALL high-value targets.

        Args:
            source: Source name or SID.
            max_targets: Maximum number of HVT paths to return.

        Returns:
            List of AttackPath objects, sorted by hop count (ascending).
        """
        src_sid = self._resolve_or_raise(source)
        paths: list[AttackPath] = []

        for hvt_sid in self.ad_graph.high_value_targets:
            if hvt_sid == src_sid:
                continue

            try:
                node_list = nx.shortest_path(
                    self._traversable_view, src_sid, hvt_sid
                )
                path = self._build_path(node_list)
                paths.append(path)
            except (nx.NetworkXNoPath, nx.NodeNotFound):
                continue

        # Sort by hop count, then by total weight
        paths.sort(key=lambda p: (p.hop_count, p.total_weight))
        return paths[:max_targets]

    def has_path(self, source: str, target: str) -> bool:
        """Check if any attack path exists between two nodes.

        Args:
            source: Source name or SID.
            target: Target name or SID.

        Returns:
            True if a traversable path exists.
        """
        src_sid = self._resolve_or_raise(source)
        dst_sid = self._resolve_or_raise(target)
        return nx.has_path(self._traversable_view, src_sid, dst_sid)
