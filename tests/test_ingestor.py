"""Unit tests for Phase 1: Data Ingestion.

Tests cover:
- Loader: ZIP and directory discovery
- Parser: orjson bulk parse, ijson streaming, error handling
- Normalizer: ADNode creation, deleted filtering, timestamp normalization,
  extra relations extraction, reverse lookup readiness
"""

from __future__ import annotations

import json
import zipfile
from pathlib import Path

import pytest

from specterad.ingestor import IngestionError
from specterad.ingestor.loader import (
    discover_json_files,
    load_sharphound_data,
)
from specterad.ingestor.parser import parse_json_file
from specterad.ingestor.normalizer import (
    normalize_objects,
    normalize_single_object,
)
from specterad.models.node import ADNode, NodeType


# ──────────────────────────────────────────────
# Loader Tests
# ──────────────────────────────────────────────


class TestDiscoverJsonInZip:
    """Tests for loading JSON from a SharpHound ZIP."""

    def test_load_zip_discovers_all_files(self, sample_zip: Path) -> None:
        """ZIP with 6 JSON files should yield 6 tuples."""
        results = list(discover_json_files(sample_zip))
        assert len(results) == 6
        filenames = {r[0] for r in results}
        assert "users.json" in filenames
        assert "computers.json" in filenames
        assert "groups.json" in filenames
        assert "domains.json" in filenames
        assert "certtemplates.json" in filenames
        assert "azusers.json" in filenames

    def test_load_zip_returns_bytes(self, sample_zip: Path) -> None:
        """Each yielded item should contain raw bytes."""
        for filename, raw_bytes, file_size in discover_json_files(sample_zip):
            assert isinstance(raw_bytes, bytes)
            assert len(raw_bytes) > 0
            assert file_size > 0

    def test_load_zip_invalid(self, tmp_path: Path) -> None:
        """A non-ZIP file should raise IngestionError."""
        bad_file = tmp_path / "fake.zip"
        bad_file.write_text("not a zip")
        with pytest.raises(IngestionError, match="Invalid ZIP"):
            list(discover_json_files(bad_file))

    def test_load_zip_empty(self, tmp_path: Path) -> None:
        """ZIP with no JSON should raise IngestionError."""
        zip_path = tmp_path / "empty.zip"
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("readme.txt", "no json here")
        with pytest.raises(IngestionError, match="No JSON"):
            list(discover_json_files(zip_path))


class TestDiscoverJsonInDir:
    """Tests for loading JSON from a directory."""

    def test_load_dir(self, fixtures_dir: Path) -> None:
        """Fixture directory should yield all .json files."""
        results = list(discover_json_files(fixtures_dir))
        assert len(results) == 6

    def test_load_dir_empty(self, tmp_path: Path) -> None:
        """Empty directory should raise IngestionError."""
        with pytest.raises(IngestionError, match="No JSON"):
            list(discover_json_files(tmp_path))

    def test_load_nonexistent(self) -> None:
        """Non-existent path should raise IngestionError."""
        with pytest.raises(IngestionError, match="does not exist"):
            list(discover_json_files("/nonexistent/path"))

    def test_load_invalid_source_type(self, tmp_path: Path) -> None:
        """A non-ZIP file (not a dir) should raise IngestionError."""
        txt_file = tmp_path / "data.txt"
        txt_file.write_text("not json")
        with pytest.raises(IngestionError, match="must be a .zip"):
            list(discover_json_files(txt_file))


# ──────────────────────────────────────────────
# Parser Tests
# ──────────────────────────────────────────────


class TestParserBulk:
    """Tests for orjson bulk parsing (files < threshold)."""

    def test_parse_users(self, users_json_bytes: bytes) -> None:
        """Parse users.json → meta_type='users', 3 objects."""
        meta_type, objects = parse_json_file(
            users_json_bytes, len(users_json_bytes)
        )
        assert meta_type == "users"
        assert len(objects) == 3

    def test_parse_computers(self, computers_json_bytes: bytes) -> None:
        """Parse computers.json → meta_type='computers', 1 object."""
        meta_type, objects = parse_json_file(
            computers_json_bytes, len(computers_json_bytes)
        )
        assert meta_type == "computers"
        assert len(objects) == 1

    def test_parse_groups(self, groups_json_bytes: bytes) -> None:
        """Parse groups.json → meta_type='groups', 2 objects."""
        meta_type, objects = parse_json_file(
            groups_json_bytes, len(groups_json_bytes)
        )
        assert meta_type == "groups"
        assert len(objects) == 2

    def test_parse_domains(self, domains_json_bytes: bytes) -> None:
        """Parse domains.json → meta_type='domains', 1 object."""
        meta_type, objects = parse_json_file(
            domains_json_bytes, len(domains_json_bytes)
        )
        assert meta_type == "domains"
        assert len(objects) == 1

    def test_parse_preserves_object_structure(
        self, users_json_bytes: bytes
    ) -> None:
        """Parsed objects should retain ObjectIdentifier and Properties."""
        _, objects = parse_json_file(users_json_bytes, len(users_json_bytes))
        first = objects[0]
        assert "ObjectIdentifier" in first
        assert "Properties" in first
        assert first["ObjectIdentifier"] == "S-1-5-21-1111-2222-3333-1001"
        assert first["Properties"]["name"] == "D.QUAN@LAB.LOCAL"


class TestParserStreaming:
    """Tests for ijson streaming parsing (files >= threshold)."""

    def test_streaming_produces_same_result(
        self, users_json_bytes: bytes
    ) -> None:
        """Streaming should produce identical objects as bulk parse."""
        # Force streaming by setting threshold to 0 MB
        meta_type, objects = parse_json_file(
            users_json_bytes, len(users_json_bytes), stream_threshold_mb=0
        )
        assert meta_type == "users"
        assert len(objects) == 3
        assert objects[0]["ObjectIdentifier"] == "S-1-5-21-1111-2222-3333-1001"

    def test_streaming_computers(self, computers_json_bytes: bytes) -> None:
        """Streaming parse of computers.json."""
        meta_type, objects = parse_json_file(
            computers_json_bytes, len(computers_json_bytes), stream_threshold_mb=0
        )
        assert meta_type == "computers"
        assert len(objects) == 1
        assert "Aces" in objects[0]


class TestParserErrors:
    """Tests for parser error handling."""

    def test_invalid_json(self, invalid_json_bytes: bytes) -> None:
        """Invalid JSON should raise IngestionError."""
        with pytest.raises(IngestionError, match="Invalid JSON"):
            parse_json_file(invalid_json_bytes, len(invalid_json_bytes))

    def test_missing_meta(self, no_meta_json_bytes: bytes) -> None:
        """JSON without meta block should raise IngestionError."""
        with pytest.raises(IngestionError, match="meta"):
            parse_json_file(no_meta_json_bytes, len(no_meta_json_bytes))

    def test_invalid_json_streaming(self, invalid_json_bytes: bytes) -> None:
        """Invalid JSON in streaming mode should also raise."""
        with pytest.raises(IngestionError):
            parse_json_file(
                invalid_json_bytes, len(invalid_json_bytes), stream_threshold_mb=0
            )


# ──────────────────────────────────────────────
# Normalizer Tests
# ──────────────────────────────────────────────


class TestNormalizeSingleObject:
    """Tests for normalizing individual raw objects to ADNode."""

    def test_normalize_user(self) -> None:
        """A basic user dict → ADNode with correct fields."""
        raw = {
            "ObjectIdentifier": "S-1-5-21-1111-2222-3333-1001",
            "Properties": {
                "name": "D.QUAN@LAB.LOCAL",
                "domain": "LAB.LOCAL",
                "hasspn": False,
            },
        }
        node = normalize_single_object(raw, NodeType.USER)
        assert node is not None
        assert node.object_id == "S-1-5-21-1111-2222-3333-1001"
        assert node.node_type == NodeType.USER
        assert node.name == "D.QUAN@LAB.LOCAL"
        assert node.properties["domain"] == "LAB.LOCAL"
        assert node.aces == []

    def test_normalize_computer_with_aces(self) -> None:
        """Computer with ACEs should preserve them in the node."""
        raw = {
            "ObjectIdentifier": "S-1-5-21-1111-2222-3333-2001",
            "Properties": {"name": "DC01.LAB.LOCAL", "domain": "LAB.LOCAL"},
            "Aces": [
                {
                    "PrincipalSID": "S-1-5-21-1111-2222-3333-1100",
                    "PrincipalType": "Group",
                    "RightName": "GenericAll",
                    "IsInherited": False,
                }
            ],
        }
        node = normalize_single_object(raw, NodeType.COMPUTER)
        assert node is not None
        assert len(node.aces) == 1
        assert node.aces[0]["RightName"] == "GenericAll"

    def test_normalize_preserves_local_admins(self) -> None:
        """LocalAdmins.Results should be extracted to extra_relations."""
        raw = {
            "ObjectIdentifier": "S-1-5-21-1111-2222-3333-2001",
            "Properties": {"name": "DC01.LAB.LOCAL"},
            "LocalAdmins": {
                "Results": [
                    {
                        "ObjectIdentifier": "S-1-5-21-1111-2222-3333-512",
                        "ObjectType": "Group",
                    }
                ]
            },
        }
        node = normalize_single_object(raw, NodeType.COMPUTER)
        assert node is not None
        assert "LocalAdmins" in node.extra_relations
        assert len(node.extra_relations["LocalAdmins"]) == 1

    def test_normalize_preserves_members(self) -> None:
        """Group Members list should be in extra_relations."""
        raw = {
            "ObjectIdentifier": "S-1-5-21-1111-2222-3333-512",
            "Properties": {"name": "DOMAIN ADMINS@LAB.LOCAL"},
            "Members": [
                {
                    "ObjectIdentifier": "S-1-5-21-1111-2222-3333-500",
                    "ObjectType": "User",
                }
            ],
        }
        node = normalize_single_object(raw, NodeType.GROUP)
        assert node is not None
        assert "Members" in node.extra_relations
        assert len(node.extra_relations["Members"]) == 1

    def test_skip_deleted_object(self) -> None:
        """Objects with IsDeleted=True should return None."""
        raw = {
            "ObjectIdentifier": "S-1-5-21-1111-2222-3333-9999",
            "IsDeleted": True,
            "Properties": {"name": "DELETED@LAB.LOCAL"},
        }
        node = normalize_single_object(raw, NodeType.USER)
        assert node is None

    def test_keep_non_deleted_object(self) -> None:
        """Objects with IsDeleted=False should be processed normally."""
        raw = {
            "ObjectIdentifier": "S-1-5-21-1111-2222-3333-8888",
            "IsDeleted": False,
            "Properties": {"name": "ACTIVE@LAB.LOCAL"},
        }
        node = normalize_single_object(raw, NodeType.USER)
        assert node is not None
        assert node.name == "ACTIVE@LAB.LOCAL"

    def test_missing_object_identifier(self) -> None:
        """Object without ObjectIdentifier should raise IngestionError."""
        raw = {"Properties": {"name": "NO_SID@LAB.LOCAL"}}
        with pytest.raises(IngestionError, match="ObjectIdentifier"):
            normalize_single_object(raw, NodeType.USER)

    def test_sid_uppercased(self) -> None:
        """SIDs should be normalized to uppercase."""
        raw = {
            "ObjectIdentifier": "s-1-5-21-lower-case-sid",
            "Properties": {"name": "TEST@LAB.LOCAL"},
        }
        node = normalize_single_object(raw, NodeType.USER)
        assert node is not None
        assert node.object_id == "S-1-5-21-LOWER-CASE-SID"

    def test_missing_name_fallback(self) -> None:
        """If Properties.name is missing, fall back to ObjectIdentifier."""
        raw = {
            "ObjectIdentifier": "S-1-5-21-1111-2222-3333-7777",
            "Properties": {"domain": "LAB.LOCAL"},
        }
        node = normalize_single_object(raw, NodeType.USER)
        assert node is not None
        assert node.name == "S-1-5-21-1111-2222-3333-7777"


class TestNormalizeObjects:
    """Tests for the bulk normalize_objects pipeline."""

    def test_full_pipeline(self, fixtures_dir: Path) -> None:
        """End-to-end: load → parse → normalize all fixture data."""
        raw_data = load_sharphound_data(fixtures_dir)
        nodes = normalize_objects(raw_data)

        # We expect 3 users + 1 computer + 2 groups + 1 domain + 5 certtemplates + 7 azusers = 19 nodes
        assert len(nodes) == 19

        # Verify specific nodes exist by SID
        assert "S-1-5-21-1111-2222-3333-1001" in nodes  # D.QUAN
        assert "S-1-5-21-1111-2222-3333-500" in nodes   # ADMINISTRATOR
        assert "S-1-5-21-1111-2222-3333-1005" in nodes   # SVC_SQL
        assert "S-1-5-21-1111-2222-3333-2001" in nodes   # DC01
        assert "S-1-5-21-1111-2222-3333-512" in nodes    # DOMAIN ADMINS
        assert "S-1-5-21-1111-2222-3333-1100" in nodes   # IT_SUPPORT
        assert "S-1-5-21-1111-2222-3333-4444" in nodes   # LAB.LOCAL domain

    def test_node_types_correct(self, fixtures_dir: Path) -> None:
        """Each node should have the correct NodeType."""
        raw_data = load_sharphound_data(fixtures_dir)
        nodes = normalize_objects(raw_data)

        assert nodes["S-1-5-21-1111-2222-3333-1001"].node_type == NodeType.USER
        assert nodes["S-1-5-21-1111-2222-3333-2001"].node_type == NodeType.COMPUTER
        assert nodes["S-1-5-21-1111-2222-3333-512"].node_type == NodeType.GROUP
        assert nodes["S-1-5-21-1111-2222-3333-4444"].node_type == NodeType.DOMAIN

    def test_skip_deleted_in_pipeline(self) -> None:
        """Deleted objects should be excluded from the final result."""
        raw_data = {
            "users": [
                {
                    "ObjectIdentifier": "S-1-5-21-DELETED",
                    "IsDeleted": True,
                    "Properties": {"name": "GONE@LAB.LOCAL"},
                },
                {
                    "ObjectIdentifier": "S-1-5-21-ACTIVE",
                    "Properties": {"name": "HERE@LAB.LOCAL"},
                },
            ]
        }
        nodes = normalize_objects(raw_data)
        assert len(nodes) == 1
        assert "S-1-5-21-ACTIVE" in nodes
        assert "S-1-5-21-DELETED" not in nodes

    def test_unknown_meta_type_skipped(self) -> None:
        """Unknown meta.type should be skipped with a warning."""
        raw_data = {
            "unknown_type": [
                {"ObjectIdentifier": "S-1-5-test", "Properties": {"name": "X"}}
            ]
        }
        nodes = normalize_objects(raw_data)
        assert len(nodes) == 0

    def test_kerberoastable_property(self, fixtures_dir: Path) -> None:
        """SVC_SQL should have hasspn=True for Kerberoasting detection."""
        raw_data = load_sharphound_data(fixtures_dir)
        nodes = normalize_objects(raw_data)
        svc_sql = nodes["S-1-5-21-1111-2222-3333-1005"]
        assert svc_sql.properties.get("hasspn") is True

    def test_computer_has_aces_and_local_admins(
        self, fixtures_dir: Path
    ) -> None:
        """DC01 should have both Aces and LocalAdmins preserved."""
        raw_data = load_sharphound_data(fixtures_dir)
        nodes = normalize_objects(raw_data)
        dc01 = nodes["S-1-5-21-1111-2222-3333-2001"]

        # ACEs from computers.json
        assert len(dc01.aces) == 1
        assert dc01.aces[0]["RightName"] == "GenericAll"

        # LocalAdmins from extra_relations
        assert "LocalAdmins" in dc01.extra_relations
        assert len(dc01.extra_relations["LocalAdmins"]) == 1

    def test_group_has_members(self, fixtures_dir: Path) -> None:
        """DOMAIN ADMINS should have Members in extra_relations."""
        raw_data = load_sharphound_data(fixtures_dir)
        nodes = normalize_objects(raw_data)
        da = nodes["S-1-5-21-1111-2222-3333-512"]

        assert "Members" in da.extra_relations
        assert len(da.extra_relations["Members"]) == 1
        assert (
            da.extra_relations["Members"][0]["ObjectIdentifier"]
            == "S-1-5-21-1111-2222-3333-500"
        )


# ──────────────────────────────────────────────
# Integration: Full Load Pipeline
# ──────────────────────────────────────────────


class TestFullLoadPipeline:
    """Integration tests: ZIP → parse → normalize."""

    def test_load_from_zip(self, sample_zip: Path) -> None:
        """Full pipeline from ZIP file → dict of ADNodes."""
        raw_data = load_sharphound_data(sample_zip)
        nodes = normalize_objects(raw_data)
        assert len(nodes) == 19

    def test_load_from_directory(self, fixtures_dir: Path) -> None:
        """Full pipeline from directory → dict of ADNodes."""
        raw_data = load_sharphound_data(fixtures_dir)
        nodes = normalize_objects(raw_data)
        assert len(nodes) == 19

    def test_zip_and_dir_produce_same_results(
        self, sample_zip: Path, fixtures_dir: Path
    ) -> None:
        """ZIP and directory loading should produce identical nodes."""
        zip_data = load_sharphound_data(sample_zip)
        dir_data = load_sharphound_data(fixtures_dir)

        zip_nodes = normalize_objects(zip_data)
        dir_nodes = normalize_objects(dir_data)

        assert set(zip_nodes.keys()) == set(dir_nodes.keys())
        for sid in zip_nodes:
            assert zip_nodes[sid].name == dir_nodes[sid].name
            assert zip_nodes[sid].node_type == dir_nodes[sid].node_type
