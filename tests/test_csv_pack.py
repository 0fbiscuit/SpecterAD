"""Unit tests for Phase 7: PlumHound CSV Pack Export."""

from __future__ import annotations

from pathlib import Path

import networkx as nx
import pytest

from specterad.output.csv_pack import export_csv_pack
from specterad.models.edge import EdgeType
from specterad.models.graph import ADGraph
from specterad.models.node import ADNode, NodeType

@pytest.fixture
def mock_graph() -> ADGraph:
    graph = nx.DiGraph()
    graph.add_node("D1", node_type=NodeType.DOMAIN.value, name="LAB.LOCAL")
    graph.add_node("U1", node_type=NodeType.USER.value, name="USER1")
    graph.add_node("C1", node_type=NodeType.COMPUTER.value, name="COMP1")
    
    graph.add_edge("U1", "C1", edge_type=EdgeType.ADMIN_TO.value)
    
    nodes = {
        "D1": ADNode("D1", NodeType.DOMAIN, "LAB.LOCAL", {"functionallevel": "Windows 2016"}),
        "U1": ADNode("U1", NodeType.USER, "USER1", {"hasspn": True}),
        "C1": ADNode("C1", NodeType.COMPUTER, "COMP1"),
    }
    
    ad_graph = ADGraph(graph=graph)
    for sid, node in nodes.items():
        ad_graph.name_to_sid[node.name.upper()] = sid
        ad_graph.sid_to_name[sid] = node.name
        ad_graph.nodes_by_type.setdefault(node.node_type, []).append(sid)
    return ad_graph

def test_export_csv_pack(mock_graph: ADGraph, tmp_path: Path) -> None:
    """Test generating 12 CSV files for the pack."""
    out_dir = tmp_path / "pack"
    
    result_dir = export_csv_pack(mock_graph, out_dir)
    
    assert result_dir.exists()
    assert result_dir.is_dir()
    
    csv_files = list(result_dir.glob("*.csv"))
    # Should generate 12 files
    assert len(csv_files) == 12
    
    # Check that 01_domains exists and has content
    domain_csv = result_dir / "01_domains.csv"
    assert domain_csv.exists()
    content = domain_csv.read_text()
    assert "LAB.LOCAL" in content
    
    # Check that 10_bulk_admin_to_hosts exists and has content
    admin_csv = result_dir / "10_bulk_admin_to_hosts.csv"
    assert admin_csv.exists()
    content = admin_csv.read_text()
    assert "USER1" in content
