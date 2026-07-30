"""Unit tests for Phase 8: Azure / Entra Skeleton."""

from __future__ import annotations

import networkx as nx
import pytest

from specterad.engine.azure_queries import AzureQueryEngine
from specterad.models.edge import EdgeType
from specterad.models.graph import ADGraph
from specterad.models.node import ADNode, NodeType

@pytest.fixture
def azure_engine() -> AzureQueryEngine:
    graph = nx.DiGraph()
    
    # Add nodes
    graph.add_node("U1", node_type=NodeType.AZ_USER.value, name="AZ Admin")
    graph.add_node("T1", node_type=NodeType.AZ_TENANT.value, name="Tenant")
    graph.add_node("VM1", node_type=NodeType.AZ_VM.value, name="Prod VM")
    
    # Edges
    graph.add_edge("U1", "T1", edge_type=EdgeType.AZ_GLOBAL_ADMIN.value)
    graph.add_edge("U1", "VM1", edge_type=EdgeType.AZ_VM_CONTRIBUTOR.value)
    
    nodes = {
        "U1": ADNode("U1", NodeType.AZ_USER, "AZ Admin"),
        "T1": ADNode("T1", NodeType.AZ_TENANT, "Tenant"),
        "VM1": ADNode("VM1", NodeType.AZ_VM, "Prod VM"),
    }
    
    ad_graph = ADGraph(graph=graph)
    for sid, node in nodes.items():
        ad_graph.name_to_sid[node.name.upper()] = sid
        ad_graph.sid_to_name[sid] = node.name
        ad_graph.nodes_by_type.setdefault(node.node_type, []).append(sid)
    return AzureQueryEngine(ad_graph)

def test_azure_global_admins(azure_engine: AzureQueryEngine) -> None:
    """Test Global Admin query."""
    result = azure_engine.global_admins()
    assert result.count == 1
    assert result.results[0]["principal_sid"] == "U1"
    assert result.results[0]["tenant_sid"] == "T1"

def test_azure_vm_admin_access(azure_engine: AzureQueryEngine) -> None:
    """Test VM access query."""
    result = azure_engine.vm_admin_access()
    assert result.count == 1
    assert result.results[0]["principal_sid"] == "U1"
    assert result.results[0]["vm_sid"] == "VM1"

def test_azure_summary(azure_engine: AzureQueryEngine) -> None:
    """Test Azure summary generation."""
    summary = azure_engine.azure_summary()
    assert summary["_total_azure_nodes"] == 3
    assert summary[NodeType.AZ_USER.value] == 1
    assert summary[NodeType.AZ_TENANT.value] == 1
    assert summary[NodeType.AZ_VM.value] == 1
