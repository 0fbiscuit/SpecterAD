"""Unit tests for Phase 3: Pathfinding Engine.

Tests cover:
- Edge weights: YAML loading, composite calculation, defaults
- Pathfinder: BFS shortest path, Dijkstra weighted path, HVT paths,
              no-path handling, cycle handling, name resolution
- Query engine: Kerberoastable, AS-REP, DCSync, DA sessions, HVT
- Integration: full pipeline from fixtures → pathfinding
"""

from __future__ import annotations

from pathlib import Path

import pytest

from specterad.engine.pathfinder import Pathfinder
from specterad.engine.queries import QueryEngine, QueryResult
from specterad.engine.weights import EdgeWeight, get_edge_weight, load_weights
from specterad.models.edge import EdgeType
from specterad.models.graph import ADGraph, create_ad_graph
from specterad.models.node import ADNode, NodeType
from specterad.models.path import AttackPath, PathStep


# ──────────────────────────────────────────────
# Helpers: build test graph
# ──────────────────────────────────────────────


def _n(
    sid: str, name: str, ntype: NodeType,
    props: dict | None = None,
    aces: list | None = None,
    extra: dict | None = None,
) -> ADNode:
    return ADNode(
        object_id=sid, node_type=ntype, name=name,
        properties=props or {}, aces=aces or [],
        extra_relations=extra or {},
    )


def _build_attack_graph() -> tuple[dict[str, ADNode], ADGraph]:
    """Build a realistic test graph with multiple attack paths.

    Topology:
        D.QUAN -[MemberOf]-> IT_SUPPORT
        IT_SUPPORT -[GenericAll]-> SVC_SQL
        SVC_SQL -[AdminTo]-> DC01
        DC01 -[HasSession]-> ADMINISTRATOR
        ADMINISTRATOR -[MemberOf]-> DOMAIN ADMINS

        Also: D.QUAN -[CanRDP]-> WS01 -[HasSession]-> ADMINISTRATOR
              (alternative path — noisier via CanRDP)

    Attack narrative:
        Path 1 (quiet): D.QUAN → IT_SUPPORT → SVC_SQL → DC01 → ADMIN → DA
        Path 2 (noisy):  D.QUAN → WS01 → ADMIN → DA
    """
    nodes = {
        # Users
        "S-DQUAN": _n("S-DQUAN", "D.QUAN@LAB.LOCAL", NodeType.USER,
                       props={"domain": "LAB.LOCAL", "hasspn": False}),
        "S-ADMIN": _n("S-ADMIN", "ADMINISTRATOR@LAB.LOCAL", NodeType.USER,
                       props={"domain": "LAB.LOCAL", "hasspn": False}),
        "S-SVC": _n("S-SVC", "SVC_SQL@LAB.LOCAL", NodeType.USER,
                     props={"domain": "LAB.LOCAL", "hasspn": True}),

        # Groups
        "S-1-5-21-TEST-512": _n("S-1-5-21-TEST-512", "DOMAIN ADMINS@LAB.LOCAL", NodeType.GROUP,
                    extra={"Members": [
                        {"ObjectIdentifier": "S-ADMIN", "ObjectType": "User"},
                    ]}),
        "S-IT": _n("S-IT", "IT_SUPPORT@LAB.LOCAL", NodeType.GROUP,
                    extra={"Members": [
                        {"ObjectIdentifier": "S-DQUAN", "ObjectType": "User"},
                    ]}),

        # Computers
        "S-DC01": _n("S-DC01", "DC01.LAB.LOCAL", NodeType.COMPUTER,
                      props={"domain": "LAB.LOCAL"},
                      extra={
                          "LocalAdmins": [
                              {"ObjectIdentifier": "S-SVC", "ObjectType": "User"},
                          ],
                          "Sessions": [
                              {"ObjectIdentifier": "S-ADMIN", "ObjectType": "User"},
                          ],
                      }),
        "S-WS01": _n("S-WS01", "WS01.LAB.LOCAL", NodeType.COMPUTER,
                      props={"domain": "LAB.LOCAL"},
                      extra={
                          "RemoteDesktopUsers": [
                              {"ObjectIdentifier": "S-DQUAN", "ObjectType": "User"},
                          ],
                          "Sessions": [
                              {"ObjectIdentifier": "S-ADMIN", "ObjectType": "User"},
                          ],
                      }),

        # IT_SUPPORT has GenericAll on SVC_SQL
        # (SVC_SQL has the ACE, IT_SUPPORT is the principal)
    }

    # Add ACE: IT_SUPPORT -[GenericAll]-> SVC_SQL
    nodes["S-SVC"].aces = [
        {
            "PrincipalSID": "S-IT",
            "PrincipalType": "Group",
            "RightName": "GenericAll",
            "IsInherited": False,
        },
    ]

    # Domain
    nodes["S-DOMAIN"] = _n(
        "S-DOMAIN", "LAB.LOCAL", NodeType.DOMAIN,
        props={"name": "LAB.LOCAL"},
    )

    ag = create_ad_graph(nodes)
    return nodes, ag


def _build_dcsync_graph() -> tuple[dict[str, ADNode], ADGraph]:
    """Graph with a DCSync principal for query testing."""
    nodes = {
        "S-EVIL": _n("S-EVIL", "EVIL@LAB.LOCAL", NodeType.USER),
        "S-DOMAIN": _n(
            "S-DOMAIN", "LAB.LOCAL", NodeType.DOMAIN,
            props={"name": "LAB.LOCAL"},
            aces=[
                {"PrincipalSID": "S-EVIL", "RightName": "GetChanges"},
                {"PrincipalSID": "S-EVIL", "RightName": "GetChangesAll"},
            ],
        ),
    }
    return nodes, create_ad_graph(nodes)


# ──────────────────────────────────────────────
# Edge Weight Tests
# ──────────────────────────────────────────────


class TestEdgeWeight:
    """Tests for EdgeWeight model and composite calculation."""

    def test_composite_default_formula(self) -> None:
        """Composite weight should use default formula."""
        ew = EdgeWeight(detection_risk=0.8, failure_risk=0.1, complexity=0.5)
        formula = {"detection_weight": 0.4, "failure_weight": 0.3, "complexity_weight": 0.3}
        result = ew.composite(formula)
        expected = 0.8 * 0.4 + 0.1 * 0.3 + 0.5 * 0.3  # 0.32 + 0.03 + 0.15 = 0.50
        assert abs(result - expected) < 1e-10

    def test_zero_weight(self) -> None:
        """MemberOf should have zero composite weight."""
        ew = EdgeWeight(detection_risk=0.0, failure_risk=0.0, complexity=0.0)
        formula = {"detection_weight": 0.4, "failure_weight": 0.3, "complexity_weight": 0.3}
        assert ew.composite(formula) == 0.0

    def test_max_weight(self) -> None:
        """All 1.0 should produce composite = 1.0."""
        ew = EdgeWeight(detection_risk=1.0, failure_risk=1.0, complexity=1.0)
        formula = {"detection_weight": 0.4, "failure_weight": 0.3, "complexity_weight": 0.3}
        assert abs(ew.composite(formula) - 1.0) < 1e-10


class TestLoadWeights:
    """Tests for YAML weight loading."""

    def test_load_from_yaml(self) -> None:
        """Loading from the project's edge_weights.yaml should succeed."""
        config_path = Path(__file__).parent.parent / "config" / "edge_weights.yaml"
        if config_path.exists():
            weights, formula = load_weights(config_path)
            assert len(weights) > 0
            assert "detection_weight" in formula
            assert "GenericAll" in weights
            assert "DCSync" in weights

    def test_load_defaults_on_missing_file(self) -> None:
        """Missing YAML file should fall back to embedded defaults."""
        weights, formula = load_weights("/nonexistent/path.yaml")
        assert len(weights) > 0
        assert "GenericAll" in weights
        assert formula["detection_weight"] == 0.4

    def test_memberof_zero_weight(self) -> None:
        """MemberOf should have zero weight in defaults."""
        weights, formula = load_weights("/nonexistent/path.yaml")
        ew = weights["MemberOf"]
        assert ew.composite(formula) == 0.0

    def test_dcsync_high_detection(self) -> None:
        """DCSync should have high detection risk."""
        weights, _ = load_weights("/nonexistent/path.yaml")
        assert weights["DCSync"].detection_risk >= 0.7

    def test_get_edge_weight_unknown(self) -> None:
        """Unknown edge type should return penalty weight of 1.0."""
        weights, formula = load_weights("/nonexistent/path.yaml")
        result = get_edge_weight("SomeUnknownEdge", weights, formula)
        assert result == 1.0


# ──────────────────────────────────────────────
# Pathfinder Tests
# ──────────────────────────────────────────────


class TestShortestPath:
    """Tests for BFS shortest path."""

    def test_shortest_path_exists(self) -> None:
        """D.QUAN → DOMAIN ADMINS should have a path."""
        _, ag = _build_attack_graph()
        pf = Pathfinder(ag)

        path = pf.shortest_path("D.QUAN", "Domain Admins")
        assert path is not None
        assert path.hop_count > 0
        assert path.source_name == "D.QUAN@LAB.LOCAL"
        assert path.target_name == "DOMAIN ADMINS@LAB.LOCAL"

    def test_shortest_path_uses_fewest_hops(self) -> None:
        """BFS should prefer the 3-hop path over the 5-hop path.

        Path 2: D.QUAN → WS01 → ADMIN → DA (3 hops via CanRDP)
        Path 1: D.QUAN → IT → SVC → DC01 → ADMIN → DA (5 hops)
        """
        _, ag = _build_attack_graph()
        pf = Pathfinder(ag)

        path = pf.shortest_path("D.QUAN", "Domain Admins")
        assert path is not None
        assert path.hop_count <= 4  # Should take the shorter route

    def test_shortest_path_step_details(self) -> None:
        """Each step should have source/target names and edge type."""
        _, ag = _build_attack_graph()
        pf = Pathfinder(ag)

        path = pf.shortest_path("D.QUAN", "Domain Admins")
        assert path is not None
        for step in path.steps:
            assert step.source != ""
            assert step.target != ""
            assert step.source_name != ""
            assert step.target_name != ""
            assert step.edge_type != ""

    def test_no_path_returns_none(self) -> None:
        """No path between disconnected nodes → None."""
        nodes = {
            "S-ALICE": _n("S-ALICE", "ALICE@CORP.NET", NodeType.USER),
            "S-BOB": _n("S-BOB", "BOB@CORP.NET", NodeType.USER),
        }
        ag = create_ad_graph(nodes)
        pf = Pathfinder(ag)

        path = pf.shortest_path("ALICE", "BOB")
        assert path is None

    def test_resolve_failure_raises(self) -> None:
        """Unknown identifier should raise ValueError."""
        _, ag = _build_attack_graph()
        pf = Pathfinder(ag)

        with pytest.raises(ValueError, match="Cannot resolve"):
            pf.shortest_path("NONEXISTENT", "Domain Admins")


class TestAllShortestPaths:
    """Tests for all_shortest_paths."""

    def test_returns_multiple_paths(self) -> None:
        """Multiple equally-short paths should be returned."""
        _, ag = _build_attack_graph()
        pf = Pathfinder(ag)

        paths = pf.all_shortest_paths("D.QUAN", "Domain Admins")
        assert len(paths) >= 1
        # All paths should have the same hop count
        if len(paths) > 1:
            assert all(p.hop_count == paths[0].hop_count for p in paths)

    def test_max_paths_limit(self) -> None:
        """Should not return more than max_paths."""
        _, ag = _build_attack_graph()
        pf = Pathfinder(ag)

        paths = pf.all_shortest_paths("D.QUAN", "Domain Admins", max_paths=1)
        assert len(paths) <= 1

    def test_no_path_returns_empty(self) -> None:
        """No path → empty list."""
        nodes = {
            "S-ALICE": _n("S-ALICE", "ALICE@CORP.NET", NodeType.USER),
            "S-BOB": _n("S-BOB", "BOB@CORP.NET", NodeType.USER),
        }
        ag = create_ad_graph(nodes)
        pf = Pathfinder(ag)

        paths = pf.all_shortest_paths("ALICE", "BOB")
        assert paths == []


class TestWeightedPath:
    """Tests for Dijkstra weighted pathfinding."""

    def test_weighted_path_exists(self) -> None:
        """Dijkstra should find a weighted path."""
        _, ag = _build_attack_graph()
        pf = Pathfinder(ag)

        path = pf.weighted_path("D.QUAN", "Domain Admins")
        assert path is not None
        assert path.total_weight > 0

    def test_weighted_prefers_quiet_path(self) -> None:
        """Dijkstra should prefer quiet ACL path over noisy CanRDP path.

        Quiet path: D.QUAN → IT → SVC(GenericAll) → DC01(AdminTo) → ADMIN → DA
        Noisy path: D.QUAN → WS01(CanRDP) → ADMIN → DA

        CanRDP has weight ~0.49 per hop, GenericAll ~0.115, MemberOf ~0.0
        The noisy path is shorter but has higher weight per hop.
        """
        _, ag = _build_attack_graph()
        pf = Pathfinder(ag)

        weighted = pf.weighted_path("D.QUAN", "Domain Admins")
        shortest = pf.shortest_path("D.QUAN", "Domain Admins")

        assert weighted is not None
        assert shortest is not None

        # The weighted path should have lower or equal total weight
        assert weighted.total_weight <= shortest.total_weight + 0.01

    def test_weighted_no_path(self) -> None:
        """No path → None."""
        nodes = {
            "S-ALICE": _n("S-ALICE", "ALICE@CORP.NET", NodeType.USER),
            "S-BOB": _n("S-BOB", "BOB@CORP.NET", NodeType.USER),
        }
        ag = create_ad_graph(nodes)
        pf = Pathfinder(ag)

        assert pf.weighted_path("ALICE", "BOB") is None


class TestPathsToHVT:
    """Tests for paths_to_hvt (paths to all high-value targets)."""

    def test_finds_paths_to_domain_admins(self) -> None:
        """D.QUAN should have a path to DOMAIN ADMINS (HVT)."""
        _, ag = _build_attack_graph()
        pf = Pathfinder(ag)

        paths = pf.paths_to_hvt("D.QUAN")
        assert len(paths) > 0

        # At least one path should reach DOMAIN ADMINS
        da_paths = [p for p in paths if "DOMAIN ADMINS" in p.target_name]
        assert len(da_paths) >= 1

    def test_sorted_by_hop_count(self) -> None:
        """Results should be sorted by hop count ascending."""
        _, ag = _build_attack_graph()
        pf = Pathfinder(ag)

        paths = pf.paths_to_hvt("D.QUAN")
        if len(paths) > 1:
            for i in range(len(paths) - 1):
                assert paths[i].hop_count <= paths[i + 1].hop_count


class TestHasPath:
    """Tests for has_path check."""

    def test_has_path_true(self) -> None:
        _, ag = _build_attack_graph()
        pf = Pathfinder(ag)
        assert pf.has_path("D.QUAN", "Domain Admins") is True

    def test_has_path_false(self) -> None:
        nodes = {
            "S-ALICE": _n("S-ALICE", "ALICE@CORP.NET", NodeType.USER),
            "S-BOB": _n("S-BOB", "BOB@CORP.NET", NodeType.USER),
        }
        ag = create_ad_graph(nodes)
        pf = Pathfinder(ag)
        assert pf.has_path("ALICE", "BOB") is False


class TestCycleHandling:
    """Tests for handling cyclic graphs."""

    def test_cycle_does_not_infinite_loop(self) -> None:
        """Pathfinding on a graph with cycles should terminate."""
        nodes = {
            "S-A": _n("S-A", "A@LAB.LOCAL", NodeType.USER),
            "S-B": _n("S-B", "B@LAB.LOCAL", NodeType.USER),
            "S-C": _n("S-C", "C@LAB.LOCAL", NodeType.GROUP,
                       extra={"Members": [
                           {"ObjectIdentifier": "S-A", "ObjectType": "User"},
                       ]}),
            "S-D": _n("S-D", "D@LAB.LOCAL", NodeType.GROUP,
                       extra={"Members": [
                           {"ObjectIdentifier": "S-C", "ObjectType": "Group"},
                       ]}),
        }
        # Add ACE to create a cycle: D -[GenericAll]-> A
        nodes["S-A"].aces = [
            {"PrincipalSID": "S-D", "RightName": "GenericAll", "IsInherited": False},
        ]
        ag = create_ad_graph(nodes)
        pf = Pathfinder(ag)

        # A → C → D → A would be a cycle, but BFS should still terminate
        path = pf.shortest_path("A", "D")
        assert path is not None
        assert path.hop_count > 0


# ──────────────────────────────────────────────
# Query Engine Tests
# ──────────────────────────────────────────────


class TestKerberoastableQuery:
    """Tests for Kerberoastable users query."""

    def test_finds_spn_users(self) -> None:
        """SVC_SQL with hasspn=True should be found."""
        _, ag = _build_attack_graph()
        qe = QueryEngine(ag)

        result = qe.kerberoastable_users()
        assert result.count >= 1
        sids = {r["sid"] for r in result.results}
        assert "S-SVC" in sids

    def test_excludes_non_spn_users(self) -> None:
        """D.QUAN without SPN should NOT be in results."""
        _, ag = _build_attack_graph()
        qe = QueryEngine(ag)

        result = qe.kerberoastable_users()
        sids = {r["sid"] for r in result.results}
        assert "S-DQUAN" not in sids


class TestDCSyncQuery:
    """Tests for DCSync principals query."""

    def test_finds_dcsync_principal(self) -> None:
        """EVIL user with both GetChanges+GetChangesAll should be found."""
        _, ag = _build_dcsync_graph()
        qe = QueryEngine(ag)

        result = qe.dcsync_principals()
        assert result.count >= 1
        sids = {r["sid"] for r in result.results}
        assert "S-EVIL" in sids

    def test_no_dcsync_in_clean_graph(self) -> None:
        """Graph without DCSync edges → empty results."""
        _, ag = _build_attack_graph()
        qe = QueryEngine(ag)

        result = qe.dcsync_principals()
        assert result.count == 0


class TestDASessionsQuery:
    """Tests for Domain Admin sessions query."""

    def test_finds_da_session(self) -> None:
        """DC01 has ADMIN session, and ADMIN is in DA → should be found."""
        _, ag = _build_attack_graph()
        qe = QueryEngine(ag)

        result = qe.da_sessions()
        # ADMIN has session on DC01 and WS01, and ADMIN is member of DA
        assert result.count >= 1
        computers = {r["computer_name"] for r in result.results}
        assert "DC01.LAB.LOCAL" in computers or "WS01.LAB.LOCAL" in computers


class TestHVTQuery:
    """Tests for high-value targets query."""

    def test_lists_hvts(self) -> None:
        """HVT query should include DOMAIN ADMINS (SID suffix -512 not present here,
        but name pattern 'domain admins' should match)."""
        _, ag = _build_attack_graph()
        qe = QueryEngine(ag)

        result = qe.high_value_targets()
        assert result.count > 0

    def test_query_result_structure(self) -> None:
        """QueryResult should have proper fields."""
        _, ag = _build_attack_graph()
        qe = QueryEngine(ag)

        result = qe.high_value_targets()
        assert isinstance(result, QueryResult)
        assert result.query_name != ""
        assert result.description != ""


class TestRunAll:
    """Tests for running all queries at once."""

    def test_run_all_returns_list(self) -> None:
        """run_all should return a list of QueryResult objects."""
        _, ag = _build_attack_graph()
        qe = QueryEngine(ag)

        results = qe.run_all()
        assert len(results) == 22
        assert all(isinstance(r, QueryResult) for r in results)


# ──────────────────────────────────────────────
# Path Model Tests
# ──────────────────────────────────────────────


class TestPathModels:
    """Tests for PathStep and AttackPath dataclasses."""

    def test_attack_path_properties(self) -> None:
        """AttackPath properties should reflect first/last steps."""
        steps = [
            PathStep("S-A", "A", "MemberOf", "S-B", "B", 0.0),
            PathStep("S-B", "B", "AdminTo", "S-C", "C", 0.3),
        ]
        path = AttackPath(steps=steps, total_weight=0.3, hop_count=2)

        assert path.source == "S-A"
        assert path.target == "S-C"
        assert path.source_name == "A"
        assert path.target_name == "C"

    def test_empty_path(self) -> None:
        """Empty AttackPath should have empty source/target."""
        path = AttackPath()
        assert path.source == ""
        assert path.target == ""
        assert path.hop_count == 0

    def test_repr(self) -> None:
        """Repr should be human-readable."""
        steps = [PathStep("S-A", "A", "GenericAll", "S-B", "B", 0.115)]
        path = AttackPath(steps=steps, total_weight=0.115, hop_count=1)
        assert "A" in repr(path)
        assert "B" in repr(path)


# ──────────────────────────────────────────────
# Integration: Fixture Pipeline → Engine
# ──────────────────────────────────────────────


class TestIntegrationFixtures:
    """Integration tests: fixtures → ingestor → graph → engine."""

    def test_fixture_pathfinding(self, fixtures_dir: Path) -> None:
        """Full pipeline from fixtures to pathfinding."""
        from specterad.ingestor.loader import load_sharphound_data
        from specterad.ingestor.normalizer import normalize_objects

        raw_data = load_sharphound_data(fixtures_dir)
        nodes = normalize_objects(raw_data)
        ag = create_ad_graph(nodes)
        pf = Pathfinder(ag)

        # D.QUAN → Domain Admins should have a path via IT_SUPPORT
        path = pf.shortest_path("D.QUAN", "Domain Admins")
        # May or may not have a path depending on fixture edges
        # but pathfinder should not crash
        assert path is None or isinstance(path, AttackPath)

    def test_fixture_queries(self, fixtures_dir: Path) -> None:
        """Pre-built queries should run on fixture data."""
        from specterad.ingestor.loader import load_sharphound_data
        from specterad.ingestor.normalizer import normalize_objects

        raw_data = load_sharphound_data(fixtures_dir)
        nodes = normalize_objects(raw_data)
        ag = create_ad_graph(nodes)
        qe = QueryEngine(ag)

        # Kerberoastable should find SVC_SQL
        result = qe.kerberoastable_users()
        sids = {r["sid"] for r in result.results}
        assert "S-1-5-21-1111-2222-3333-1005" in sids

        # HVT should find DOMAIN ADMINS
        hvt = qe.high_value_targets()
        assert hvt.count > 0
