"""Unit tests for Phase 2: Graph Construction.

Tests cover:
- Edge registry: EdgeType enum, traversability, ACE mapping
- Graph builder: nodes, ACE edges, MemberOf, AdminTo, HasSession
- Post-processor: DCSync composite, ADCS ESC1/3/4, HVT marking
- ADGraph wrapper: reverse lookup, resolve, display_name, summary
- Integration: full pipeline from fixtures → ADGraph
"""

from __future__ import annotations

from pathlib import Path

import networkx as nx
import pytest

from specterad.graph.builder import build_graph
from specterad.graph.post_process import (
    derive_adcs_edges,
    derive_dcsync_edges,
    mark_high_value_targets,
    post_process_graph,
)
from specterad.ingestor.loader import load_sharphound_data
from specterad.ingestor.normalizer import normalize_objects
from specterad.models.edge import ACE_RIGHT_TO_EDGE, TRAVERSABLE_EDGES, EdgeType
from specterad.models.graph import ADGraph, create_ad_graph
from specterad.models.node import ADNode, NodeType


# ──────────────────────────────────────────────
# Helpers: build nodes dict for testing
# ──────────────────────────────────────────────


def _make_node(
    sid: str,
    name: str,
    node_type: NodeType,
    properties: dict | None = None,
    aces: list | None = None,
    extra_relations: dict | None = None,
) -> ADNode:
    return ADNode(
        object_id=sid,
        node_type=node_type,
        name=name,
        properties=properties or {},
        aces=aces or [],
        extra_relations=extra_relations or {},
    )


def _make_test_nodes() -> dict[str, ADNode]:
    """Build a minimal AD graph for testing.

    Structure:
        Users: D.QUAN (1001), ADMINISTRATOR (500), SVC_SQL (1005)
        Groups: DOMAIN ADMINS (512), IT_SUPPORT (1100)
        Computers: DC01 (2001)
        Domain: LAB.LOCAL (4444)

    Relationships:
        ADMINISTRATOR -[MemberOf]-> DOMAIN ADMINS
        D.QUAN -[MemberOf]-> IT_SUPPORT
        IT_SUPPORT -[GenericAll]-> DC01 (via ACE)
        DOMAIN ADMINS -[AdminTo]-> DC01 (via LocalAdmins)
    """
    return {
        "S-1-5-21-1111-2222-3333-1001": _make_node(
            "S-1-5-21-1111-2222-3333-1001", "D.QUAN@LAB.LOCAL", NodeType.USER,
            properties={"domain": "LAB.LOCAL", "hasspn": False},
        ),
        "S-1-5-21-1111-2222-3333-500": _make_node(
            "S-1-5-21-1111-2222-3333-500", "ADMINISTRATOR@LAB.LOCAL", NodeType.USER,
            properties={"domain": "LAB.LOCAL", "hasspn": False},
        ),
        "S-1-5-21-1111-2222-3333-1005": _make_node(
            "S-1-5-21-1111-2222-3333-1005", "SVC_SQL@LAB.LOCAL", NodeType.USER,
            properties={"domain": "LAB.LOCAL", "hasspn": True},
        ),
        "S-1-5-21-1111-2222-3333-512": _make_node(
            "S-1-5-21-1111-2222-3333-512", "DOMAIN ADMINS@LAB.LOCAL", NodeType.GROUP,
            extra_relations={
                "Members": [
                    {"ObjectIdentifier": "S-1-5-21-1111-2222-3333-500", "ObjectType": "User"},
                ],
            },
        ),
        "S-1-5-21-1111-2222-3333-1100": _make_node(
            "S-1-5-21-1111-2222-3333-1100", "IT_SUPPORT@LAB.LOCAL", NodeType.GROUP,
            extra_relations={
                "Members": [
                    {"ObjectIdentifier": "S-1-5-21-1111-2222-3333-1001", "ObjectType": "User"},
                ],
            },
        ),
        "S-1-5-21-1111-2222-3333-2001": _make_node(
            "S-1-5-21-1111-2222-3333-2001", "DC01.LAB.LOCAL", NodeType.COMPUTER,
            properties={"domain": "LAB.LOCAL"},
            aces=[
                {
                    "PrincipalSID": "S-1-5-21-1111-2222-3333-1100",
                    "PrincipalType": "Group",
                    "RightName": "GenericAll",
                    "IsInherited": False,
                },
            ],
            extra_relations={
                "LocalAdmins": [
                    {"ObjectIdentifier": "S-1-5-21-1111-2222-3333-512", "ObjectType": "Group"},
                ],
            },
        ),
        "S-1-5-21-1111-2222-3333-4444": _make_node(
            "S-1-5-21-1111-2222-3333-4444", "LAB.LOCAL", NodeType.DOMAIN,
            properties={"name": "LAB.LOCAL", "functionallevel": "2016"},
        ),
    }


# ──────────────────────────────────────────────
# Edge Registry Tests
# ──────────────────────────────────────────────


class TestEdgeRegistry:
    """Tests for EdgeType enum, traversability, and ACE mapping."""

    def test_traversable_excludes_structural(self) -> None:
        """Non-traversable edges should not be in TRAVERSABLE_EDGES."""
        assert EdgeType.GP_LINK not in TRAVERSABLE_EDGES
        assert EdgeType.CONTAINS not in TRAVERSABLE_EDGES
        assert EdgeType.DC_FOR not in TRAVERSABLE_EDGES

    def test_traversable_includes_attack_edges(self) -> None:
        """Key attack edges should be traversable."""
        assert EdgeType.GENERIC_ALL in TRAVERSABLE_EDGES
        assert EdgeType.ADMIN_TO in TRAVERSABLE_EDGES
        assert EdgeType.HAS_SESSION in TRAVERSABLE_EDGES
        assert EdgeType.MEMBER_OF in TRAVERSABLE_EDGES
        assert EdgeType.DCSYNC in TRAVERSABLE_EDGES
        assert EdgeType.ADCSESC1 in TRAVERSABLE_EDGES

    def test_ace_right_mapping(self) -> None:
        """Common ACE RightNames should map to correct EdgeTypes."""
        assert ACE_RIGHT_TO_EDGE["GenericAll"] == EdgeType.GENERIC_ALL
        assert ACE_RIGHT_TO_EDGE["WriteDacl"] == EdgeType.WRITE_DACL
        assert ACE_RIGHT_TO_EDGE["ForceChangePassword"] == EdgeType.FORCE_CHANGE_PASSWORD
        assert ACE_RIGHT_TO_EDGE["AddMember"] == EdgeType.ADD_MEMBER

    def test_edge_type_is_str_enum(self) -> None:
        """EdgeType should be usable as string for graph attribute storage."""
        assert EdgeType.GENERIC_ALL.value == "GenericAll"
        assert EdgeType.ADMIN_TO.value == "AdminTo"


# ──────────────────────────────────────────────
# Graph Builder Tests
# ──────────────────────────────────────────────


class TestBuildNodes:
    """Tests for adding ADNodes as graph nodes."""

    def test_build_nodes_count(self) -> None:
        """All ADNodes should be added as graph nodes."""
        nodes = _make_test_nodes()
        graph = build_graph(nodes)
        assert graph.number_of_nodes() == 7

    def test_node_attributes(self) -> None:
        """Graph nodes should carry name and node_type attributes."""
        nodes = _make_test_nodes()
        graph = build_graph(nodes)

        sid = "S-1-5-21-1111-2222-3333-1001"
        assert graph.nodes[sid]["name"] == "D.QUAN@LAB.LOCAL"
        assert graph.nodes[sid]["node_type"] == "User"

    def test_node_properties_stored(self) -> None:
        """Serializable properties should be on graph node."""
        nodes = _make_test_nodes()
        graph = build_graph(nodes)

        sid = "S-1-5-21-1111-2222-3333-1005"
        assert graph.nodes[sid]["hasspn"] is True


class TestBuildEdgesFromAces:
    """Tests for ACE-based edge construction."""

    def test_ace_edge_created(self) -> None:
        """GenericAll ACE on DC01 should create IT_SUPPORT → DC01 edge."""
        nodes = _make_test_nodes()
        graph = build_graph(nodes)

        src = "S-1-5-21-1111-2222-3333-1100"  # IT_SUPPORT
        dst = "S-1-5-21-1111-2222-3333-2001"  # DC01
        assert graph.has_edge(src, dst)
        assert graph[src][dst]["edge_type"] == "GenericAll"

    def test_unknown_right_name_skipped(self) -> None:
        """ACEs with unknown RightName should not create edges."""
        nodes = {
            "SID-A": _make_node("SID-A", "A", NodeType.USER),
            "SID-B": _make_node(
                "SID-B", "B", NodeType.COMPUTER,
                aces=[{
                    "PrincipalSID": "SID-A",
                    "RightName": "SomeUnknownRight",
                }],
            ),
        }
        graph = build_graph(nodes)
        assert not graph.has_edge("SID-A", "SID-B")

    def test_dangling_principal_skipped(self) -> None:
        """ACEs referencing non-existent principals should be skipped."""
        nodes = {
            "SID-B": _make_node(
                "SID-B", "B", NodeType.COMPUTER,
                aces=[{
                    "PrincipalSID": "SID-NONEXISTENT",
                    "RightName": "GenericAll",
                }],
            ),
        }
        graph = build_graph(nodes)
        assert graph.number_of_edges() == 0


class TestMemberOfEdges:
    """Tests for MemberOf edge construction (direct only, NO flattening)."""

    def test_direct_memberof_created(self) -> None:
        """ADMINISTRATOR → DOMAIN ADMINS MemberOf edge should exist."""
        nodes = _make_test_nodes()
        graph = build_graph(nodes)

        src = "S-1-5-21-1111-2222-3333-500"   # ADMINISTRATOR
        dst = "S-1-5-21-1111-2222-3333-512"    # DOMAIN ADMINS
        assert graph.has_edge(src, dst)
        assert graph[src][dst]["edge_type"] == "MemberOf"

    def test_dquan_memberof_it_support(self) -> None:
        """D.QUAN → IT_SUPPORT MemberOf edge should exist."""
        nodes = _make_test_nodes()
        graph = build_graph(nodes)

        src = "S-1-5-21-1111-2222-3333-1001"   # D.QUAN
        dst = "S-1-5-21-1111-2222-3333-1100"    # IT_SUPPORT
        assert graph.has_edge(src, dst)
        assert graph[src][dst]["edge_type"] == "MemberOf"

    def test_no_transitive_memberof(self) -> None:
        """Nested group chains should NOT be flattened.

        Even though D.QUAN is in IT_SUPPORT, there should be NO direct
        edge from D.QUAN to any group that IT_SUPPORT might be a member of.
        """
        nodes = _make_test_nodes()
        # Add nested group: IT_SUPPORT -[MemberOf]-> DOMAIN ADMINS
        nodes["S-1-5-21-1111-2222-3333-512"].extra_relations["Members"].append(
            {"ObjectIdentifier": "S-1-5-21-1111-2222-3333-1100", "ObjectType": "Group"}
        )
        graph = build_graph(nodes)

        # D.QUAN should NOT have a direct MemberOf edge to DOMAIN ADMINS
        dquan = "S-1-5-21-1111-2222-3333-1001"
        da = "S-1-5-21-1111-2222-3333-512"
        assert not graph.has_edge(dquan, da)

        # But IT_SUPPORT → DOMAIN ADMINS should exist
        it_support = "S-1-5-21-1111-2222-3333-1100"
        assert graph.has_edge(it_support, da)


class TestAdminToEdges:
    """Tests for AdminTo edge construction."""

    def test_admin_to_created(self) -> None:
        """DOMAIN ADMINS -[AdminTo]-> DC01 from LocalAdmins."""
        nodes = _make_test_nodes()
        graph = build_graph(nodes)

        src = "S-1-5-21-1111-2222-3333-512"    # DOMAIN ADMINS
        dst = "S-1-5-21-1111-2222-3333-2001"   # DC01
        assert graph.has_edge(src, dst)
        assert graph[src][dst]["edge_type"] == "AdminTo"


class TestSessionEdges:
    """Tests for HasSession edge construction."""

    def test_has_session_created(self) -> None:
        """HasSession should create Computer → User edge."""
        nodes = {
            "COMP-1": _make_node(
                "COMP-1", "WS01.LAB.LOCAL", NodeType.COMPUTER,
                extra_relations={
                    "Sessions": [
                        {"ObjectIdentifier": "USER-1", "ObjectType": "User"},
                    ],
                },
            ),
            "USER-1": _make_node("USER-1", "ADMIN@LAB.LOCAL", NodeType.USER),
        }
        graph = build_graph(nodes)

        # Direction: Computer → User (user creds are on that computer)
        assert graph.has_edge("COMP-1", "USER-1")
        assert graph["COMP-1"]["USER-1"]["edge_type"] == "HasSession"


# ──────────────────────────────────────────────
# Post-Processor Tests
# ──────────────────────────────────────────────


class TestDCSyncComposite:
    """Tests for DCSync composite edge derivation."""

    def test_dcsync_from_both_rights(self) -> None:
        """Principal with GetChanges + GetChangesAll on Domain → DCSync edge."""
        nodes = {
            "DOMAIN-SID": _make_node(
                "DOMAIN-SID", "LAB.LOCAL", NodeType.DOMAIN,
                aces=[
                    {"PrincipalSID": "ATTACKER-SID", "RightName": "GetChanges"},
                    {"PrincipalSID": "ATTACKER-SID", "RightName": "GetChangesAll"},
                ],
            ),
            "ATTACKER-SID": _make_node(
                "ATTACKER-SID", "EVIL@LAB.LOCAL", NodeType.USER,
            ),
        }
        graph = build_graph(nodes)
        derive_dcsync_edges(graph, nodes)

        assert graph.has_edge("ATTACKER-SID", "DOMAIN-SID")
        assert graph["ATTACKER-SID"]["DOMAIN-SID"]["edge_type"] == "DCSync"

    def test_no_dcsync_with_only_one_right(self) -> None:
        """GetChanges alone should NOT create DCSync edge."""
        nodes = {
            "DOMAIN-SID": _make_node(
                "DOMAIN-SID", "LAB.LOCAL", NodeType.DOMAIN,
                aces=[
                    {"PrincipalSID": "PARTIAL-SID", "RightName": "GetChanges"},
                ],
            ),
            "PARTIAL-SID": _make_node(
                "PARTIAL-SID", "PARTIAL@LAB.LOCAL", NodeType.USER,
            ),
        }
        graph = build_graph(nodes)
        count = derive_dcsync_edges(graph, nodes)

        assert count == 0
        assert not graph.has_edge("PARTIAL-SID", "DOMAIN-SID")


class TestADCSEdges:
    """Tests for ADCS ESC1/3/4 composite edge derivation."""

    def test_esc1_all_conditions_met(self) -> None:
        """ESC1: Enroll + Client Auth EKU + EnrolleeSuppliesSubject → ADCSESC1."""
        nodes = {
            "CT-SID": _make_node(
                "CT-SID", "VulnTemplate", NodeType.CERTTEMPLATE,
                properties={
                    "enrolleesuppliessubject": True,
                    "ekus": ["1.3.6.1.5.5.7.3.2"],  # Client Auth
                },
                aces=[
                    {"PrincipalSID": "USER-SID", "RightName": "Enroll"},
                ],
            ),
            "USER-SID": _make_node("USER-SID", "ATTACKER@LAB.LOCAL", NodeType.USER),
        }
        graph = build_graph(nodes)
        count = derive_adcs_edges(graph, nodes)

        assert count >= 1
        assert graph.has_edge("USER-SID", "CT-SID")
        # Check that at least one edge has ADCSESC1 type
        edge_data = graph["USER-SID"]["CT-SID"]
        assert edge_data["edge_type"] == "ADCSESC1"

    def test_esc1_missing_enrollee_supplies_subject(self) -> None:
        """ESC1 should NOT fire without enrolleesuppliessubject=True."""
        nodes = {
            "CT-SID": _make_node(
                "CT-SID", "SafeTemplate", NodeType.CERTTEMPLATE,
                properties={
                    "enrolleesuppliessubject": False,
                    "ekus": ["1.3.6.1.5.5.7.3.2"],
                },
                aces=[
                    {"PrincipalSID": "USER-SID", "RightName": "Enroll"},
                ],
            ),
            "USER-SID": _make_node("USER-SID", "USER@LAB.LOCAL", NodeType.USER),
        }
        graph = build_graph(nodes)
        count = derive_adcs_edges(graph, nodes)

        # No ADCSESC1 edge should exist
        has_esc1 = False
        for _, _, data in graph.edges(data=True):
            if data.get("edge_type") == "ADCSESC1":
                has_esc1 = True
        assert not has_esc1

    def test_esc4_write_on_certtemplate(self) -> None:
        """ESC4: WriteDacl on CertTemplate → ADCSESC4 edge."""
        nodes = {
            "CT-SID": _make_node(
                "CT-SID", "Template", NodeType.CERTTEMPLATE,
                properties={"ekus": []},
                aces=[
                    {"PrincipalSID": "USER-SID", "RightName": "WriteDacl"},
                ],
            ),
            "USER-SID": _make_node("USER-SID", "ATTACKER@LAB.LOCAL", NodeType.USER),
        }
        graph = build_graph(nodes)
        count = derive_adcs_edges(graph, nodes)

        assert count >= 1
        found_esc4 = any(
            data.get("edge_type") == "ADCSESC4"
            for _, _, data in graph.edges(data=True)
        )
        assert found_esc4


class TestHighValueTargets:
    """Tests for HVT marking."""

    def test_domain_admins_marked(self) -> None:
        """Group with SID ending in -512 should be marked as HVT."""
        nodes = _make_test_nodes()
        graph = build_graph(nodes)
        hvts = mark_high_value_targets(graph, nodes)

        assert "S-1-5-21-1111-2222-3333-512" in hvts

    def test_hvt_attribute_set(self) -> None:
        """HVT nodes should have high_value=True attribute."""
        nodes = _make_test_nodes()
        graph = build_graph(nodes)
        mark_high_value_targets(graph, nodes)

        da_sid = "S-1-5-21-1111-2222-3333-512"
        assert graph.nodes[da_sid].get("high_value") is True

    def test_regular_user_not_hvt(self) -> None:
        """Regular users should NOT be marked as HVT."""
        nodes = _make_test_nodes()
        graph = build_graph(nodes)
        hvts = mark_high_value_targets(graph, nodes)

        assert "S-1-5-21-1111-2222-3333-1001" not in hvts  # D.QUAN


# ──────────────────────────────────────────────
# ADGraph Wrapper Tests
# ──────────────────────────────────────────────


class TestADGraphWrapper:
    """Tests for ADGraph creation and lookup methods."""

    def test_create_ad_graph(self) -> None:
        """create_ad_graph should return a fully populated ADGraph."""
        nodes = _make_test_nodes()
        ag = create_ad_graph(nodes)

        assert isinstance(ag, ADGraph)
        assert ag.graph.number_of_nodes() == 7
        assert len(ag.high_value_targets) > 0

    def test_nodes_by_type(self) -> None:
        """nodes_by_type should correctly categorize SIDs."""
        nodes = _make_test_nodes()
        ag = create_ad_graph(nodes)

        assert len(ag.nodes_by_type[NodeType.USER]) == 3
        assert len(ag.nodes_by_type[NodeType.GROUP]) == 2
        assert len(ag.nodes_by_type[NodeType.COMPUTER]) == 1
        assert len(ag.nodes_by_type[NodeType.DOMAIN]) == 1

    def test_domain_sids_map(self) -> None:
        """domain_sids should map domain name to domain SID."""
        nodes = _make_test_nodes()
        ag = create_ad_graph(nodes)

        assert "LAB.LOCAL" in ag.domain_sids
        assert ag.domain_sids["LAB.LOCAL"] == "S-1-5-21-1111-2222-3333-4444"


class TestReverseLookup:
    """Tests for resolve() and display_name() methods."""

    def test_resolve_by_exact_sid(self) -> None:
        """resolve() with exact SID should return the SID."""
        nodes = _make_test_nodes()
        ag = create_ad_graph(nodes)

        result = ag.resolve("S-1-5-21-1111-2222-3333-1001")
        assert result == "S-1-5-21-1111-2222-3333-1001"

    def test_resolve_by_full_name(self) -> None:
        """resolve() with full name should return correct SID."""
        nodes = _make_test_nodes()
        ag = create_ad_graph(nodes)

        result = ag.resolve("D.QUAN@LAB.LOCAL")
        assert result == "S-1-5-21-1111-2222-3333-1001"

    def test_resolve_case_insensitive(self) -> None:
        """resolve() should be case-insensitive."""
        nodes = _make_test_nodes()
        ag = create_ad_graph(nodes)

        result = ag.resolve("d.quan@lab.local")
        assert result == "S-1-5-21-1111-2222-3333-1001"

    def test_resolve_partial_name(self) -> None:
        """resolve() with short name should match."""
        nodes = _make_test_nodes()
        ag = create_ad_graph(nodes)

        result = ag.resolve("D.QUAN")
        assert result == "S-1-5-21-1111-2222-3333-1001"

    def test_resolve_domain_admins(self) -> None:
        """resolve() with 'Domain Admins' should find the DA group."""
        nodes = _make_test_nodes()
        ag = create_ad_graph(nodes)

        result = ag.resolve("Domain Admins")
        assert result == "S-1-5-21-1111-2222-3333-512"

    def test_resolve_nonexistent(self) -> None:
        """resolve() with unknown identifier should return None."""
        nodes = _make_test_nodes()
        ag = create_ad_graph(nodes)

        result = ag.resolve("NONEXISTENT_USER")
        assert result is None

    def test_display_name(self) -> None:
        """display_name() should return human-readable name."""
        nodes = _make_test_nodes()
        ag = create_ad_graph(nodes)

        name = ag.display_name("S-1-5-21-1111-2222-3333-1001")
        assert name == "D.QUAN@LAB.LOCAL"

    def test_display_name_fallback(self) -> None:
        """display_name() with unknown SID should return SID itself."""
        nodes = _make_test_nodes()
        ag = create_ad_graph(nodes)

        name = ag.display_name("S-1-5-UNKNOWN")
        assert name == "S-1-5-UNKNOWN"


class TestGraphSummary:
    """Tests for ADGraph.summary() method."""

    def test_summary_structure(self) -> None:
        """summary() should return dict with expected keys."""
        nodes = _make_test_nodes()
        ag = create_ad_graph(nodes)
        stats = ag.summary()

        assert "total_nodes" in stats
        assert "total_edges" in stats
        assert "nodes_by_type" in stats
        assert "edges_by_type" in stats
        assert "high_value_targets" in stats
        assert "domains" in stats

    def test_summary_counts(self) -> None:
        """summary() counts should match actual graph."""
        nodes = _make_test_nodes()
        ag = create_ad_graph(nodes)
        stats = ag.summary()

        assert stats["total_nodes"] == 7
        assert stats["total_edges"] == ag.graph.number_of_edges()
        assert stats["nodes_by_type"]["User"] == 3
        assert stats["nodes_by_type"]["Group"] == 2
        assert stats["nodes_by_type"]["Computer"] == 1
        assert stats["nodes_by_type"]["Domain"] == 1


# ──────────────────────────────────────────────
# Integration: Full Pipeline from Fixtures
# ──────────────────────────────────────────────


class TestFullPipelineIntegration:
    """Integration tests: fixtures → ingestor → graph → ADGraph."""

    def test_fixture_to_adgraph(self, fixtures_dir: Path) -> None:
        """Full pipeline from fixture JSON files to ADGraph."""
        raw_data = load_sharphound_data(fixtures_dir)
        nodes = normalize_objects(raw_data)
        ag = create_ad_graph(nodes)

        # 19 nodes from fixtures (7 AD + 5 certtemplates + 7 azusers)
        assert ag.graph.number_of_nodes() == 19
        assert ag.graph.number_of_edges() > 0

        # MemberOf edges should exist
        assert ag.graph.has_edge(
            "S-1-5-21-1111-2222-3333-500",   # ADMINISTRATOR
            "S-1-5-21-1111-2222-3333-512",    # DOMAIN ADMINS
        )
        assert ag.graph.has_edge(
            "S-1-5-21-1111-2222-3333-1001",  # D.QUAN
            "S-1-5-21-1111-2222-3333-1100",  # IT_SUPPORT
        )

        # AdminTo edge
        assert ag.graph.has_edge(
            "S-1-5-21-1111-2222-3333-512",   # DOMAIN ADMINS
            "S-1-5-21-1111-2222-3333-2001",  # DC01
        )

        # GenericAll ACE edge
        assert ag.graph.has_edge(
            "S-1-5-21-1111-2222-3333-1100",  # IT_SUPPORT
            "S-1-5-21-1111-2222-3333-2001",  # DC01
        )

        # HVT marking
        assert "S-1-5-21-1111-2222-3333-512" in ag.high_value_targets

        # Reverse lookup works
        assert ag.resolve("D.QUAN") == "S-1-5-21-1111-2222-3333-1001"
        assert ag.display_name("S-1-5-21-1111-2222-3333-512") == "DOMAIN ADMINS@LAB.LOCAL"

    def test_fixture_from_zip(self, sample_zip: Path) -> None:
        """Full pipeline from ZIP → ADGraph."""
        raw_data = load_sharphound_data(sample_zip)
        nodes = normalize_objects(raw_data)
        ag = create_ad_graph(nodes)

        assert ag.graph.number_of_nodes() == 19
        assert len(ag.high_value_targets) > 0
        assert ag.resolve("ADMINISTRATOR") == "S-1-5-21-1111-2222-3333-500"
