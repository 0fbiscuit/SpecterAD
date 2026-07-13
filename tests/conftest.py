"""Shared pytest fixtures for SpecterAD tests."""

from __future__ import annotations

import json
import zipfile
from io import BytesIO
from pathlib import Path

import pytest

# Path to test fixture files
FIXTURES_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture
def fixtures_dir() -> Path:
    """Return path to the fixtures directory."""
    return FIXTURES_DIR


@pytest.fixture
def users_json_bytes() -> bytes:
    """Raw bytes of the users.json fixture."""
    return (FIXTURES_DIR / "users.json").read_bytes()


@pytest.fixture
def computers_json_bytes() -> bytes:
    """Raw bytes of the computers.json fixture."""
    return (FIXTURES_DIR / "computers.json").read_bytes()


@pytest.fixture
def groups_json_bytes() -> bytes:
    """Raw bytes of the groups.json fixture."""
    return (FIXTURES_DIR / "groups.json").read_bytes()


@pytest.fixture
def domains_json_bytes() -> bytes:
    """Raw bytes of the domains.json fixture."""
    return (FIXTURES_DIR / "domains.json").read_bytes()


@pytest.fixture
def sample_zip(tmp_path: Path) -> Path:
    """Create a temporary SharpHound-style ZIP with all fixture JSONs.

    Returns the path to the created ZIP file.
    """
    zip_path = tmp_path / "sharphound_lab.zip"
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for json_file in FIXTURES_DIR.glob("*.json"):
            zf.write(json_file, json_file.name)
    return zip_path


@pytest.fixture
def invalid_json_bytes() -> bytes:
    """Bytes containing invalid JSON."""
    return b"{ this is not valid json !!!"


@pytest.fixture
def no_meta_json_bytes() -> bytes:
    """Valid JSON but missing the meta block."""
    return json.dumps({"data": [{"ObjectIdentifier": "S-1-5-21-test"}]}).encode()


@pytest.fixture
def deleted_object_json_bytes() -> bytes:
    """JSON with a deleted object that should be skipped."""
    return json.dumps({
        "data": [
            {
                "ObjectIdentifier": "S-1-5-21-1111-2222-3333-9999",
                "IsDeleted": True,
                "Properties": {"name": "DELETED_USER@LAB.LOCAL"},
            },
            {
                "ObjectIdentifier": "S-1-5-21-1111-2222-3333-8888",
                "IsDeleted": False,
                "Properties": {"name": "ACTIVE_USER@LAB.LOCAL"},
            },
        ],
        "meta": {"type": "users", "count": 2, "methods": 0},
    }).encode()
