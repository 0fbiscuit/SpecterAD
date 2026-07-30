"""PlumHound CSV Pack — multi-file structured CSV export.

Generates a directory of 12 CSV files covering key security findings,
mirroring the PlumHound community pack output format.
"""

from __future__ import annotations

import csv
import logging
from pathlib import Path
from typing import Any

from specterad.engine.queries import QueryEngine
from specterad.engine.inventory import InventoryEngine
from specterad.models.edge import EdgeType
from specterad.models.graph import ADGraph
from specterad.models.node import NodeType

logger = logging.getLogger(__name__)


def _write_csv(path: Path, headers: list[str], rows: list[dict[str, Any]]) -> int:
    """Write a CSV file from a list of dicts. Returns row count."""
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=headers, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow(row)
    return len(rows)


def export_csv_pack(
    ad_graph: ADGraph,
    output_dir: Path | str,
) -> Path:
    """Export a PlumHound-style CSV pack to a directory.

    Creates 12 CSV files covering key AD security findings.

    Args:
        ad_graph: The loaded ADGraph instance.
        output_dir: Directory to write CSV files into.

    Returns:
        Path to the output directory.
    """
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    graph = ad_graph.graph
    qe = QueryEngine(ad_graph)
    inv = InventoryEngine(ad_graph)

    # ── 01: Domains ──
    domains = []
    for sid in ad_graph.nodes_by_type.get(NodeType.DOMAIN, []):
        nd = graph.nodes.get(sid, {})
        domains.append({
            "sid": sid,
            "name": ad_graph.display_name(sid),
            "functionallevel": nd.get("functionallevel", "Unknown"),
        })
    _write_csv(
        output_dir / "01_domains.csv",
        ["sid", "name", "functionallevel"],
        domains,
    )

    # ── 02: Domain Admins ──
    priv = inv.privilege_group_membership()
    da_members = []
    for _sid, ginfo in priv.data.get("groups", {}).items():
        for m in ginfo.get("direct_and_nested_members", []):
            da_members.append({
                "group": ginfo["group_name"],
                "group_label": ginfo["group_label"],
                "member_sid": m["sid"],
                "member_name": m["name"],
                "member_type": m["type"],
            })
    _write_csv(
        output_dir / "02_domain_admins.csv",
        ["group", "group_label", "member_sid", "member_name", "member_type"],
        da_members,
    )

    # ── 03: Kerberoastable ──
    kerb = qe.kerberoastable_users()
    _write_csv(
        output_dir / "03_kerberoastable.csv",
        ["sid", "name", "node_type", "hasspn", "admincount", "enabled", "lastlogon", "is_privileged"],
        kerb.results,
    )

    # ── 04: AS-REP Roastable ──
    asrep = qe.asrep_roastable_users()
    _write_csv(
        output_dir / "04_asreproastable.csv",
        ["sid", "name", "node_type", "dontreqpreauth", "admincount", "enabled", "lastlogon", "is_privileged"],
        asrep.results,
    )

    # ── 05: LAPS Readers ──
    laps_readers = []
    for src, dst, data in graph.edges(data=True):
        if data.get("edge_type") == EdgeType.READ_LAPS_PASSWORD.value:
            laps_readers.append({
                "principal_sid": src,
                "principal_name": ad_graph.display_name(src),
                "target_sid": dst,
                "target_name": ad_graph.display_name(dst),
            })
    _write_csv(
        output_dir / "05_laps_readers.csv",
        ["principal_sid", "principal_name", "target_sid", "target_name"],
        laps_readers,
    )

    # ── 06: Everyone/Authenticated Users edges ──
    _EVERYONE_PATTERNS = frozenset({
        "S-1-1-0",       # Everyone
        "S-1-5-11",      # Authenticated Users
        "S-1-5-32-545",  # Users (Builtin)
    })
    everyone_edges = []
    for src, dst, data in graph.edges(data=True):
        src_upper = src.upper()
        if any(src_upper.endswith(p) or src_upper == p for p in _EVERYONE_PATTERNS):
            everyone_edges.append({
                "source_sid": src,
                "source_name": ad_graph.display_name(src),
                "edge_type": data.get("edge_type", "Unknown"),
                "target_sid": dst,
                "target_name": ad_graph.display_name(dst),
            })
    _write_csv(
        output_dir / "06_everyone_edges.csv",
        ["source_sid", "source_name", "edge_type", "target_sid", "target_name"],
        everyone_edges,
    )

    # ── 07: Over-privileged edges ──
    _OVERPRIV_TYPES = frozenset({
        EdgeType.GENERIC_ALL.value,
        EdgeType.WRITE_DACL.value,
        EdgeType.WRITE_OWNER.value,
    })
    overpriv = []
    for src, dst, data in graph.edges(data=True):
        if data.get("edge_type") in _OVERPRIV_TYPES:
            overpriv.append({
                "source_sid": src,
                "source_name": ad_graph.display_name(src),
                "edge_type": data.get("edge_type"),
                "target_sid": dst,
                "target_name": ad_graph.display_name(dst),
            })
    _write_csv(
        output_dir / "07_overpriv_edges.csv",
        ["source_sid", "source_name", "edge_type", "target_sid", "target_name"],
        overpriv,
    )

    # ── 08: Computer AdminTo Computer ──
    comp_sids = set(ad_graph.nodes_by_type.get(NodeType.COMPUTER, []))
    c2c_admin = []
    for src, dst, data in graph.edges(data=True):
        if (
            data.get("edge_type") == EdgeType.ADMIN_TO.value
            and src in comp_sids
            and dst in comp_sids
        ):
            c2c_admin.append({
                "source_sid": src,
                "source_name": ad_graph.display_name(src),
                "target_sid": dst,
                "target_name": ad_graph.display_name(dst),
            })
    _write_csv(
        output_dir / "08_computer_admin_to_computer.csv",
        ["source_sid", "source_name", "target_sid", "target_name"],
        c2c_admin,
    )

    # ── 09: Dual-privilege local admins (DA + AdminTo) ──
    da_member_sids: set[str] = set()
    for _sid, ginfo in priv.data.get("groups", {}).items():
        if ginfo["group_label"] == "Domain Admins":
            for m in ginfo["direct_and_nested_members"]:
                da_member_sids.add(m["sid"])
    dual_priv = []
    for da_sid in da_member_sids:
        for succ in graph.successors(da_sid):
            edge_data = graph[da_sid][succ]
            if edge_data.get("edge_type") == EdgeType.ADMIN_TO.value:
                dual_priv.append({
                    "user_sid": da_sid,
                    "user_name": ad_graph.display_name(da_sid),
                    "computer_sid": succ,
                    "computer_name": ad_graph.display_name(succ),
                })
    _write_csv(
        output_dir / "09_dual_priv_local_admin.csv",
        ["user_sid", "user_name", "computer_sid", "computer_name"],
        dual_priv,
    )

    # ── 10: Bulk AdminTo hosts ──
    admin_to_all = []
    for src, dst, data in graph.edges(data=True):
        if data.get("edge_type") == EdgeType.ADMIN_TO.value:
            admin_to_all.append({
                "admin_sid": src,
                "admin_name": ad_graph.display_name(src),
                "computer_sid": dst,
                "computer_name": ad_graph.display_name(dst),
            })
    _write_csv(
        output_dir / "10_bulk_admin_to_hosts.csv",
        ["admin_sid", "admin_name", "computer_sid", "computer_name"],
        admin_to_all,
    )

    # ── 11: Unconstrained delegation ──
    uncon = qe.unconstrained_delegation()
    _write_csv(
        output_dir / "11_unconstrained.csv",
        ["sid", "name", "node_type", "is_dc", "risk"],
        uncon.results,
    )

    # ── 12: DCSync principals ──
    dcsync = qe.dcsync_principals()
    _write_csv(
        output_dir / "12_dcsync.csv",
        ["sid", "name", "target_domain", "edge_type"],
        dcsync.results,
    )

    logger.info("Exported CSV pack to %s (12 files)", output_dir)
    return output_dir
