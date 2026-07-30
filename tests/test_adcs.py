"""Unit tests for Phase 4: ADCS Edge Derivation."""

from __future__ import annotations

import networkx as nx
import pytest

from specterad.graph.post_process import derive_adcs_edges
from specterad.models.edge import EdgeType
from specterad.models.node import ADNode, NodeType

def test_derive_adcs_edges() -> None:
    """Test derivation of ESC1-7 edges from certtemplates."""
    graph = nx.DiGraph()
    
    # Add principals
    graph.add_node("S-1-5-21-1111-2222-3333-1001", node_type=NodeType.USER)
    graph.add_node("S-1-5-21-1111-2222-3333-1002", node_type=NodeType.USER)
    graph.add_node("S-1-5-21-1111-2222-3333-512", node_type=NodeType.GROUP)
    
    # Add CT nodes
    nodes: dict[str, ADNode] = {
        "S-1-5-21-1111-2222-3333-1001": ADNode(
            object_id="S-1-5-21-1111-2222-3333-1001",
            node_type=NodeType.USER,
            name="D.QUAN@LAB.LOCAL"
        ),
        "S-1-5-21-1111-2222-3333-512": ADNode(
            object_id="S-1-5-21-1111-2222-3333-512",
            node_type=NodeType.GROUP,
            name="DOMAIN ADMINS@LAB.LOCAL"
        ),
        "CT-ESC1": ADNode(
            object_id="CT-ESC1",
            node_type=NodeType.CERTTEMPLATE,
            name="ESC1_TEMPLATE",
            properties={"enrolleesuppliessubject": True, "ekus": ["1.3.6.1.5.5.7.3.2"]},
            aces=[{"PrincipalSID": "S-1-5-21-1111-2222-3333-1001", "RightName": "Enroll"}]
        ),
        "CT-ESC2": ADNode(
            object_id="CT-ESC2",
            node_type=NodeType.CERTTEMPLATE,
            name="ESC2_TEMPLATE",
            properties={"enrolleesuppliessubject": False, "ekus": ["2.5.29.37.0"]},
            aces=[{"PrincipalSID": "S-1-5-21-1111-2222-3333-1001", "RightName": "Enroll"}]
        ),
        "CA-ESC57": ADNode(
            object_id="CA-ESC57",
            node_type=NodeType.CERTTEMPLATE,
            name="VULN-CA-5-7",
            properties={"type": "enterpriseca", "sanflag": False},
            aces=[
                {"PrincipalSID": "S-1-5-21-1111-2222-3333-1001", "RightName": "WriteOwner"},
                {"PrincipalSID": "S-1-5-21-1111-2222-3333-512", "RightName": "ManageCA"},
                {"PrincipalSID": "S-1-5-21-1111-2222-3333-512", "RightName": "ManageCertificates"}
            ]
        )
    }
    
    for sid, node in nodes.items():
        graph.add_node(sid, node_type=node.node_type)
            
    count = derive_adcs_edges(graph, nodes)
    
    edges = list(graph.edges(data=True))
    assert count > 0
    
    has_esc1 = any(e[2].get("edge_type") == EdgeType.ADCSESC1.value for e in edges)
    has_esc2 = any(e[2].get("edge_type") == EdgeType.ADCSESC2.value for e in edges)
    has_esc5 = any(e[2].get("edge_type") == EdgeType.ADCSESC5.value for e in edges)
    has_esc7 = any(e[2].get("edge_type") == EdgeType.ADCSESC7.value for e in edges)
    
    assert has_esc1
    assert has_esc2
    assert has_esc5
    assert has_esc7

def test_derive_adcs_esc6() -> None:
    """Test ESC6 logic in isolation to prevent edge overwrites."""
    graph = nx.DiGraph()
    graph.add_node("S-1-5-21-1111-2222-3333-1002", node_type=NodeType.USER)
    
    nodes = {
        "S-1-5-21-1111-2222-3333-1002": ADNode(
            object_id="S-1-5-21-1111-2222-3333-1002",
            node_type=NodeType.USER,
            name="ATTACKER2@LAB.LOCAL"
        ),
        "CA-ESC6": ADNode(
            object_id="CA-ESC6",
            node_type=NodeType.CERTTEMPLATE,
            name="VULN-CA-6",
            properties={"type": "enterpriseca", "sanflag": True},
            aces=[]
        ),
        "CT-ESC6-Target": ADNode(
            object_id="CT-ESC6-Target",
            node_type=NodeType.CERTTEMPLATE,
            name="ESC6_TEMPLATE",
            properties={"enrolleesuppliessubject": False, "ekus": []},
            aces=[{"PrincipalSID": "S-1-5-21-1111-2222-3333-1002", "RightName": "Enroll"}]
        )
    }
    for sid, node in nodes.items():
        graph.add_node(sid, node_type=node.node_type)
        
    count = derive_adcs_edges(graph, nodes)
    assert count > 0
    edges = list(graph.edges(data=True))
    assert any(e[2].get("edge_type") == EdgeType.ADCSESC6.value for e in edges)
