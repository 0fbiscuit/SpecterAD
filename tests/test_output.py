"""Unit tests for Phase 4: CLI & Visualization.

Tests cover:
- Formatter: risk labels, node colors, edge icons
- Console renderer: path rendering, query rendering, stats rendering
- Export: DOT syntax, CSV structure, JSON structure
- CLI: Click runner tests for load, path, query, stats, export, help
"""

from __future__ import annotations

import csv
import json
from io import StringIO
from pathlib import Path

import pytest
from click.testing import CliRunner
from rich.console import Console

from specterad.cli import cli, _state
from specterad.engine.pathfinder import Pathfinder
from specterad.engine.queries import QueryEngine, QueryResult
from specterad.models.graph import ADGraph, create_ad_graph
from specterad.models.node import ADNode, NodeType
from specterad.models.path import AttackPath, PathStep
from specterad.output.console import ConsoleRenderer
from specterad.output.export import export_csv, export_dot, export_json
from specterad.output.formatter import (
    format_weight,
    get_node_color,
    get_risk_label,
)


# ──────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────


def _n(
    sid: str, name: str, ntype: NodeType,
    props: dict | None = None,
    aces: list | None = None,
    extra: dict | None = None,
) -> ADNode:
    return ADNode(
        object_id=sid, node_type=ntype, name=name,
        properties=props or {}, aces=aces or {},
        extra_relations=extra or {},
    )


def _build_test_graph() -> ADGraph:
    """Build a small ADGraph for output testing."""
    nodes = {
        "S-DQUAN": _n("S-DQUAN", "D.QUAN@LAB.LOCAL", NodeType.USER,
                       props={"domain": "LAB.LOCAL", "hasspn": False}),
        "S-ADMIN": _n("S-ADMIN", "ADMINISTRATOR@LAB.LOCAL", NodeType.USER,
                       props={"domain": "LAB.LOCAL"}),
        "S-SVC": _n("S-SVC", "SVC_SQL@LAB.LOCAL", NodeType.USER,
                     props={"domain": "LAB.LOCAL", "hasspn": True}),
        "S-1-5-21-TEST-512": _n(
            "S-1-5-21-TEST-512", "DOMAIN ADMINS@LAB.LOCAL", NodeType.GROUP,
            extra={"Members": [
                {"ObjectIdentifier": "S-ADMIN", "ObjectType": "User"},
            ]},
        ),
        "S-IT": _n("S-IT", "IT_SUPPORT@LAB.LOCAL", NodeType.GROUP,
                    extra={"Members": [
                        {"ObjectIdentifier": "S-DQUAN", "ObjectType": "User"},
                    ]}),
        "S-DC01": _n("S-DC01", "DC01.LAB.LOCAL", NodeType.COMPUTER,
                      props={"domain": "LAB.LOCAL"},
                      extra={
                          "Sessions": [
                              {"ObjectIdentifier": "S-ADMIN", "ObjectType": "User"},
                          ],
                      }),
        "S-DOMAIN": _n("S-DOMAIN", "LAB.LOCAL", NodeType.DOMAIN,
                        props={"name": "LAB.LOCAL"}),
    }
    # ACE: IT_SUPPORT -> SVC_SQL
    nodes["S-SVC"].aces = [
        {"PrincipalSID": "S-IT", "RightName": "GenericAll", "IsInherited": False},
    ]
    return create_ad_graph(nodes)


def _sample_path() -> AttackPath:
    """Create a sample AttackPath for rendering tests."""
    return AttackPath(
        steps=[
            PathStep("S-DQUAN", "D.QUAN@LAB.LOCAL", "MemberOf",
                     "S-IT", "IT_SUPPORT@LAB.LOCAL", 0.0),
            PathStep("S-IT", "IT_SUPPORT@LAB.LOCAL", "GenericAll",
                     "S-SVC", "SVC_SQL@LAB.LOCAL", 0.115),
            PathStep("S-SVC", "SVC_SQL@LAB.LOCAL", "AdminTo",
                     "S-DC01", "DC01.LAB.LOCAL", 0.31),
        ],
        total_weight=0.425,
        hop_count=3,
    )


# ──────────────────────────────────────────────
# Formatter Tests
# ──────────────────────────────────────────────


class TestFormatter:
    """Tests for output formatting utilities."""

    def test_risk_label_low(self) -> None:
        label, color = get_risk_label(0.10)
        assert label == "LOW"
        assert color == "green"

    def test_risk_label_medium(self) -> None:
        label, _ = get_risk_label(0.25)
        assert label == "MEDIUM"

    def test_risk_label_high(self) -> None:
        label, _ = get_risk_label(0.50)
        assert label == "HIGH"

    def test_risk_label_critical(self) -> None:
        label, _ = get_risk_label(0.80)
        assert label == "CRITICAL"

    def test_node_color_user(self) -> None:
        assert get_node_color("User") == "green"

    def test_node_color_computer(self) -> None:
        assert get_node_color("Computer") == "yellow"

    def test_node_color_unknown(self) -> None:
        assert get_node_color("SomethingWeird") == "white"

    def test_format_weight(self) -> None:
        assert format_weight(0.123456) == "0.123"
        assert format_weight(0.0) == "0.000"
        assert format_weight(1.0) == "1.000"


# ──────────────────────────────────────────────
# Console Renderer Tests
# ──────────────────────────────────────────────


class TestConsoleRenderer:
    """Tests for Rich console renderer."""

    def _capture_output(self, ag: ADGraph) -> tuple[ConsoleRenderer, Console, StringIO]:
        """Create a renderer that captures output."""
        buffer = StringIO()
        test_console = Console(file=buffer, force_terminal=True, width=120)
        renderer = ConsoleRenderer(ag, test_console)
        return renderer, test_console, buffer

    def test_render_path_produces_output(self) -> None:
        """render_path should produce non-empty output."""
        ag = _build_test_graph()
        renderer, _, buffer = self._capture_output(ag)

        path = _sample_path()
        renderer.render_path(path)

        output = buffer.getvalue()
        assert len(output) > 0
        assert "D.QUAN" in output
        assert "MemberOf" in output

    def test_render_empty_path(self) -> None:
        """Empty path should show 'No path found'."""
        ag = _build_test_graph()
        renderer, _, buffer = self._capture_output(ag)

        renderer.render_path(AttackPath())
        output = buffer.getvalue()
        assert "No path found" in output

    def test_render_query_result(self) -> None:
        """Query result should be rendered as table."""
        ag = _build_test_graph()
        renderer, _, buffer = self._capture_output(ag)

        result = QueryResult(
            query_name="Test Query",
            description="A test",
            results=[{"sid": "S-1", "name": "TEST"}],
            count=1,
        )
        renderer.render_query_result(result)
        output = buffer.getvalue()
        assert "Test Query" in output
        assert "1 found" in output

    def test_render_empty_query(self) -> None:
        """Empty query should show 'No results found'."""
        ag = _build_test_graph()
        renderer, _, buffer = self._capture_output(ag)

        result = QueryResult(
            query_name="Empty", description="", results=[], count=0,
        )
        renderer.render_query_result(result)
        output = buffer.getvalue()
        assert "No results found" in output

    def test_render_stats(self) -> None:
        """Stats rendering should include node and edge counts."""
        ag = _build_test_graph()
        renderer, _, buffer = self._capture_output(ag)

        stats = ag.summary()
        renderer.render_stats(stats)
        output = buffer.getvalue()
        assert "Graph Statistics" in output
        assert "Total Nodes" in output

    def test_render_load_summary(self) -> None:
        """Load summary should show success message."""
        ag = _build_test_graph()
        renderer, _, buffer = self._capture_output(ag)

        stats = ag.summary()
        renderer.render_load_summary(stats)
        output = buffer.getvalue()
        assert "loaded successfully" in output

    def test_render_paths_list(self) -> None:
        """Multiple paths should be rendered as table."""
        ag = _build_test_graph()
        renderer, _, buffer = self._capture_output(ag)

        paths = [_sample_path(), _sample_path()]
        renderer.render_paths_list(paths)
        output = buffer.getvalue()
        assert "Attack Paths" in output


# ──────────────────────────────────────────────
# Export Tests
# ──────────────────────────────────────────────


class TestExportDOT:
    """Tests for DOT (Graphviz) export."""

    def test_dot_valid_syntax(self, tmp_path: Path) -> None:
        """Exported DOT should have valid digraph structure."""
        ag = _build_test_graph()
        out = tmp_path / "test.dot"
        export_dot(ag, out)

        content = out.read_text(encoding="utf-8")
        assert content.startswith("digraph SpecterAD")
        assert content.strip().endswith("}")
        assert "rankdir=LR" in content

    def test_dot_contains_nodes(self, tmp_path: Path) -> None:
        """DOT should contain all graph nodes."""
        ag = _build_test_graph()
        out = tmp_path / "test.dot"
        export_dot(ag, out)

        content = out.read_text(encoding="utf-8")
        assert "D.QUAN@LAB.LOCAL" in content
        assert "DC01.LAB.LOCAL" in content

    def test_dot_contains_edges(self, tmp_path: Path) -> None:
        """DOT should contain edges."""
        ag = _build_test_graph()
        out = tmp_path / "test.dot"
        export_dot(ag, out)

        content = out.read_text(encoding="utf-8")
        assert "->" in content

    def test_dot_path_mode(self, tmp_path: Path) -> None:
        """DOT export with paths should highlight path edges."""
        ag = _build_test_graph()
        out = tmp_path / "test_path.dot"
        paths = [_sample_path()]
        export_dot(ag, out, paths=paths)

        content = out.read_text(encoding="utf-8")
        assert "penwidth=2" in content  # Highlighted path edges
        assert "MemberOf" in content


class TestExportCSV:
    """Tests for CSV export."""

    def test_csv_has_headers(self, tmp_path: Path) -> None:
        """CSV should have standard headers."""
        ag = _build_test_graph()
        out = tmp_path / "test.csv"
        export_csv(ag, out)

        with open(out, newline="", encoding="utf-8") as f:
            reader = csv.reader(f)
            headers = next(reader)

        assert "source_sid" in headers
        assert "source_name" in headers
        assert "edge_type" in headers
        assert "target_sid" in headers

    def test_csv_has_data_rows(self, tmp_path: Path) -> None:
        """CSV should have data rows for edges."""
        ag = _build_test_graph()
        out = tmp_path / "test.csv"
        export_csv(ag, out)

        with open(out, newline="", encoding="utf-8") as f:
            reader = csv.reader(f)
            rows = list(reader)

        assert len(rows) > 1  # Header + at least 1 data row

    def test_csv_path_mode(self, tmp_path: Path) -> None:
        """CSV with paths should export path edges."""
        ag = _build_test_graph()
        out = tmp_path / "paths.csv"
        paths = [_sample_path()]
        export_csv(ag, out, paths=paths)

        with open(out, newline="", encoding="utf-8") as f:
            reader = csv.reader(f)
            rows = list(reader)

        # Header + 3 edges from sample path
        assert len(rows) == 4


class TestExportJSON:
    """Tests for JSON export."""

    def test_json_graph_structure(self, tmp_path: Path) -> None:
        """JSON graph export should have nodes and edges."""
        ag = _build_test_graph()
        out = tmp_path / "test.json"
        export_json(ag, out)

        data = json.loads(out.read_text(encoding="utf-8"))
        assert data["type"] == "graph_export"
        assert "summary" in data
        assert "nodes" in data
        assert "edges" in data
        assert len(data["nodes"]) > 0

    def test_json_path_structure(self, tmp_path: Path) -> None:
        """JSON path export should have path details."""
        ag = _build_test_graph()
        out = tmp_path / "paths.json"
        paths = [_sample_path()]
        export_json(ag, out, paths=paths)

        data = json.loads(out.read_text(encoding="utf-8"))
        assert data["type"] == "attack_paths"
        assert data["count"] == 1
        assert len(data["paths"]) == 1
        assert data["paths"][0]["hop_count"] == 3

    def test_json_valid_format(self, tmp_path: Path) -> None:
        """JSON should be valid and parseable."""
        ag = _build_test_graph()
        out = tmp_path / "test.json"
        export_json(ag, out)

        # Should not raise
        data = json.loads(out.read_text(encoding="utf-8"))
        assert isinstance(data, dict)


# ──────────────────────────────────────────────
# CLI Tests (Click CliRunner)
# ──────────────────────────────────────────────


class TestCLI:
    """Tests for Click CLI commands."""

    @pytest.fixture(autouse=True)
    def _reset_state(self) -> None:
        """Reset CLI state between tests."""
        _state["ad_graph"] = None
        _state["pathfinder"] = None
        _state["queries"] = None
        _state["renderer"] = None

    def test_help(self) -> None:
        """--help should show usage info."""
        runner = CliRunner()
        result = runner.invoke(cli, ["--help"])
        assert result.exit_code == 0
        assert "SpecterAD" in result.output
        assert "load" in result.output
        assert "path" in result.output
        assert "query" in result.output

    def test_load_command(self, fixtures_dir: Path) -> None:
        """load command should succeed with fixture data."""
        runner = CliRunner()
        result = runner.invoke(cli, ["load", str(fixtures_dir)])
        assert result.exit_code == 0
        assert "loaded successfully" in result.output

    def test_load_nonexistent_path(self) -> None:
        """load with bad path should fail."""
        runner = CliRunner()
        result = runner.invoke(cli, ["load", "/nonexistent/path"])
        assert result.exit_code != 0

    def test_stats_command(self, fixtures_dir: Path) -> None:
        """stats command should show statistics."""
        runner = CliRunner()
        result = runner.invoke(cli, ["--data", str(fixtures_dir), "stats"])
        assert result.exit_code == 0
        assert "Graph Statistics" in result.output

    def test_query_kerberoastable(self, fixtures_dir: Path) -> None:
        """query kerberoastable should work."""
        runner = CliRunner()
        result = runner.invoke(
            cli, ["--data", str(fixtures_dir), "query", "kerberoastable"]
        )
        assert result.exit_code == 0
        assert "Kerberoastable" in result.output

    def test_query_all(self, fixtures_dir: Path) -> None:
        """query all should run all queries."""
        runner = CliRunner()
        result = runner.invoke(
            cli, ["--data", str(fixtures_dir), "query", "all"]
        )
        assert result.exit_code == 0

    def test_path_command(self, fixtures_dir: Path) -> None:
        """path command should not crash."""
        runner = CliRunner()
        result = runner.invoke(
            cli, ["--data", str(fixtures_dir), "path", "D.QUAN", "Domain Admins"]
        )
        # May find path or not — just verify no crash
        assert result.exit_code == 0

    def test_path_to_hvt(self, fixtures_dir: Path) -> None:
        """path --to-hvt should not crash."""
        runner = CliRunner()
        result = runner.invoke(
            cli, ["--data", str(fixtures_dir), "path", "D.QUAN", "--to-hvt"]
        )
        assert result.exit_code == 0

    def test_export_json(self, fixtures_dir: Path, tmp_path: Path) -> None:
        """export json should create a file."""
        out_file = tmp_path / "export.json"
        runner = CliRunner()
        result = runner.invoke(
            cli, ["--data", str(fixtures_dir), "export", "json", "-o", str(out_file)]
        )
        assert result.exit_code == 0
        assert out_file.exists()

        data = json.loads(out_file.read_text(encoding="utf-8"))
        assert data["type"] == "graph_export"

    def test_export_csv(self, fixtures_dir: Path, tmp_path: Path) -> None:
        """export csv should create a valid CSV."""
        out_file = tmp_path / "export.csv"
        runner = CliRunner()
        result = runner.invoke(
            cli, ["--data", str(fixtures_dir), "export", "csv", "-o", str(out_file)]
        )
        assert result.exit_code == 0
        assert out_file.exists()

    def test_export_dot(self, fixtures_dir: Path, tmp_path: Path) -> None:
        """export dot should create valid DOT."""
        out_file = tmp_path / "export.dot"
        runner = CliRunner()
        result = runner.invoke(
            cli, ["--data", str(fixtures_dir), "export", "dot", "-o", str(out_file)]
        )
        assert result.exit_code == 0
        assert out_file.exists()
        content = out_file.read_text(encoding="utf-8")
        assert "digraph" in content

    def test_query_help(self) -> None:
        """query --help should list available queries."""
        runner = CliRunner()
        result = runner.invoke(cli, ["query", "--help"])
        assert result.exit_code == 0
        assert "kerberoastable" in result.output
        assert "dcsync" in result.output

    def test_path_no_target_no_flag(self, fixtures_dir: Path) -> None:
        """path without target or --to-da should error."""
        runner = CliRunner()
        result = runner.invoke(
            cli, ["--data", str(fixtures_dir), "path", "D.QUAN"]
        )
        # Should fail or show error message
        assert result.exit_code != 0 or "required" in result.output.lower() or "Error" in result.output
