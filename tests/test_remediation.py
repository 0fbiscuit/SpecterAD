"""Unit tests for Phase 6: Path Remediation Engine."""

from __future__ import annotations

import networkx as nx
import pytest

from specterad.engine.remediation import RemediationEngine
from specterad.engine.pathfinder import Pathfinder
from specterad.models.edge import EdgeType
from specterad.models.graph import ADGraph
from specterad.models.node import ADNode, NodeType

@pytest.fixture
def remediation_engine() -> RemediationEngine:
    graph = nx.DiGraph()
    # A graph with a choke point: C1 and C2 both path to HVT1 via U1
    graph.add_node("C1", node_type=NodeType.COMPUTER.value, name="COMP1")
    graph.add_node("C2", node_type=NodeType.COMPUTER.value, name="COMP2")
    graph.add_node("U1", node_type=NodeType.USER.value, name="USER1")
    graph.add_node("HVT1", node_type=NodeType.GROUP.value, name="DOMAIN ADMINS", high_value=True)
    
    # Edges
    graph.add_edge("C1", "U1", edge_type=EdgeType.HAS_SESSION.value)
    graph.add_edge("C2", "U1", edge_type=EdgeType.HAS_SESSION.value)
    # The choke point
    graph.add_edge("U1", "HVT1", edge_type=EdgeType.MEMBER_OF.value)
    
    nodes = {
        "C1": ADNode("C1", NodeType.COMPUTER, "COMP1"),
        "C2": ADNode("C2", NodeType.COMPUTER, "COMP2"),
        "U1": ADNode("U1", NodeType.USER, "USER1"),
        "HVT1": ADNode("HVT1", NodeType.GROUP, "DOMAIN ADMINS"),
    }
    
    ad_graph = ADGraph(graph=graph)
    for sid, node in nodes.items():
        ad_graph.name_to_sid[node.name.upper()] = sid
        ad_graph.sid_to_name[sid] = node.name
        ad_graph.nodes_by_type.setdefault(node.node_type, []).append(sid)
    # Mock finding HVTs
    ad_graph.high_value_targets = {"HVT1"}
    
    pathfinder = Pathfinder(ad_graph)
    return RemediationEngine(ad_graph, pathfinder)

def test_busiest_path_ranking(remediation_engine: RemediationEngine) -> None:
    """Test finding choke points across attack paths."""
    report = remediation_engine.busiest_path_ranking(top_n=5)
    
    # 3 paths (C1->HVT1, C2->HVT1, U1->HVT1)
    assert report.total_paths_analyzed == 3
    
    # The U1 -> HVT1 edge should be the busiest (count=3)
    busiest = report.busiest_edges[0]
    assert busiest.source_sid == "U1"
    assert busiest.target_sid == "HVT1"
    assert busiest.edge_type == EdgeType.MEMBER_OF.value
    assert busiest.path_count == 3
