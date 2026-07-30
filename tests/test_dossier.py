"""Unit tests for Phase 5: Compromise Dossier Engine."""

from __future__ import annotations

import networkx as nx
import pytest

from specterad.engine.dossier import DossierEngine
from specterad.engine.pathfinder import Pathfinder
from specterad.models.edge import EdgeType
from specterad.models.graph import ADGraph
from specterad.models.node import ADNode, NodeType

@pytest.fixture
def dossier_engine() -> DossierEngine:
    graph = nx.DiGraph()
    graph.add_node("U1", node_type=NodeType.USER.value, name="USER1")
    graph.add_node("G1", node_type=NodeType.GROUP.value, name="GROUP1")
    graph.add_node("C1", node_type=NodeType.COMPUTER.value, name="COMP1")
    graph.add_node("C2", node_type=NodeType.COMPUTER.value, name="COMP2")
    
    # Membership chain: U1 -> G1
    graph.add_edge("U1", "G1", edge_type=EdgeType.MEMBER_OF.value)
    
    # Inbound edge: C1 -> U1
    graph.add_edge("C1", "U1", edge_type=EdgeType.HAS_SESSION.value)
    
    # AdminTo edge: G1 -> C2
    graph.add_edge("G1", "C2", edge_type=EdgeType.ADMIN_TO.value)
    
    nodes = {
        "U1": ADNode("U1", NodeType.USER, "USER1", {"sid": "U1"}),
        "G1": ADNode("G1", NodeType.GROUP, "GROUP1", {"sid": "G1"}),
        "C1": ADNode("C1", NodeType.COMPUTER, "COMP1", {"sid": "C1"}),
        "C2": ADNode("C2", NodeType.COMPUTER, "COMP2", {"sid": "C2"}),
    }
    
    ad_graph = ADGraph(graph=graph)
    for sid, node in nodes.items():
        ad_graph.name_to_sid[node.name.upper()] = sid
        ad_graph.sid_to_name[sid] = node.name
        ad_graph.nodes_by_type.setdefault(node.node_type, []).append(sid)
        
    pathfinder = Pathfinder(ad_graph)
    return DossierEngine(ad_graph, pathfinder)

def test_node_dossier(dossier_engine: DossierEngine) -> None:
    """Test generating a full node dossier report."""
    report = dossier_engine.node_dossier("USER1")
    
    assert report.sid == "U1"
    assert report.name == "USER1"
    
    # Memberships
    assert len(report.group_memberships) == 1
    assert report.group_memberships[0]["sid"] == "G1"
    
    # Inbound edges
    assert EdgeType.HAS_SESSION.value in report.inbound_edges
    assert report.inbound_edges[EdgeType.HAS_SESSION.value][0]["sid"] == "C1"
    
    # Bulk AdminTo
    assert len(report.admin_to_hosts) == 1
    assert report.admin_to_hosts[0]["sid"] == "C2"
    assert report.admin_to_hosts[0]["via"].startswith("via")
