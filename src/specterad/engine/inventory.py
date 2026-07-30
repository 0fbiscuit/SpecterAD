"""Inventory engine — password age, stale accounts, privilege groups, structural data.

Provides deeper analysis beyond simple queries:
- Password age ladders (grouped by age buckets)
- Stale/inactive accounts (no logon > N days)
- Privilege group membership (direct + nested via BFS)
- Structural inventory (domains, DCs, trusts, OUs)
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

import networkx as nx

from specterad.models.edge import EdgeType
from specterad.models.graph import ADGraph
from specterad.models.node import NodeType

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class InventoryResult:
    """Result of an inventory analysis."""

    section_name: str
    description: str
    data: dict[str, Any]


class InventoryEngine:
    """Deep inventory analysis engine operating on an ADGraph."""

    def __init__(self, ad_graph: ADGraph) -> None:
        self.ad_graph = ad_graph
        self._graph = ad_graph.graph

    def _parse_iso_age_days(self, iso_str: str | None) -> int | None:
        """Parse an ISO 8601 timestamp and return age in days from now."""
        if not iso_str or not isinstance(iso_str, str):
            return None
        try:
            dt = datetime.fromisoformat(iso_str)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            delta = datetime.now(timezone.utc) - dt
            return max(0, delta.days)
        except (ValueError, TypeError):
            return None

    def _get_all_members_bfs(self, group_sid: str) -> set[str]:
        """BFS backwards on MemberOf edges to find all direct + nested members."""
        members: set[str] = set()
        queue = [group_sid]
        visited: set[str] = {group_sid}

        while queue:
            current = queue.pop(0)
            for pred in self._graph.predecessors(current):
                edge_data = self._graph[pred][current]
                if edge_data.get("edge_type") == EdgeType.MEMBER_OF.value:
                    if pred not in visited:
                        visited.add(pred)
                        members.add(pred)
                        # If the member is a group, continue BFS for nested
                        pred_data = self._graph.nodes.get(pred, {})
                        if pred_data.get("node_type") == NodeType.GROUP.value:
                            queue.append(pred)

        return members

    def password_age_ladder(
        self,
        thresholds: list[int] | None = None,
    ) -> InventoryResult:
        """Analyze password age distribution across all users.

        Groups users into buckets based on how old their password is.
        """
        if thresholds is None:
            thresholds = [30, 90, 180, 365]

        buckets: dict[str, list[dict[str, Any]]] = {
            "never_set": [],
        }
        # Build bucket labels
        labels = []
        for i, t in enumerate(thresholds):
            if i == 0:
                labels.append(f"< {t}d")
            else:
                labels.append(f"{thresholds[i-1]}-{t}d")
        labels.append(f"> {thresholds[-1]}d")
        for label in labels:
            buckets[label] = []

        for sid in self.ad_graph.nodes_by_type.get(NodeType.USER, []):
            node_data = self._graph.nodes.get(sid, {})
            pwd_last_set = node_data.get("pwdlastset")
            name = self.ad_graph.display_name(sid)

            age_days = self._parse_iso_age_days(pwd_last_set)
            entry = {"sid": sid, "name": name, "age_days": age_days}

            if age_days is None:
                buckets["never_set"].append(entry)
                continue

            placed = False
            for i, t in enumerate(thresholds):
                if age_days < t:
                    if i == 0:
                        buckets[f"< {t}d"].append(entry)
                    else:
                        buckets[f"{thresholds[i-1]}-{t}d"].append(entry)
                    placed = True
                    break

            if not placed:
                buckets[f"> {thresholds[-1]}d"].append(entry)

        summary = {label: len(items) for label, items in buckets.items()}

        return InventoryResult(
            section_name="Password Age Ladder",
            description="Password age distribution across all user accounts",
            data={"buckets": buckets, "summary": summary, "total_users": sum(summary.values())},
        )

    def stale_accounts(self, days: int = 90) -> InventoryResult:
        """Find accounts that haven't logged in for N days or have never logged in."""
        stale_users: list[dict[str, Any]] = []
        stale_computers: list[dict[str, Any]] = []

        for node_type, result_list in [
            (NodeType.USER, stale_users),
            (NodeType.COMPUTER, stale_computers),
        ]:
            for sid in self.ad_graph.nodes_by_type.get(node_type, []):
                node_data = self._graph.nodes.get(sid, {})
                lastlogon = node_data.get("lastlogontimestamp", node_data.get("lastlogon"))
                age_days = self._parse_iso_age_days(lastlogon)
                enabled = node_data.get("enabled", True)

                if age_days is None or age_days >= days:
                    result_list.append({
                        "sid": sid,
                        "name": self.ad_graph.display_name(sid),
                        "last_logon_days": age_days if age_days is not None else "Never",
                        "enabled": enabled,
                    })

        return InventoryResult(
            section_name="Stale Accounts",
            description=f"Accounts with no logon in {days}+ days or never logged in",
            data={
                "stale_users": stale_users,
                "stale_computers": stale_computers,
                "count_users": len(stale_users),
                "count_computers": len(stale_computers),
                "threshold_days": days,
            },
        )

    def privilege_group_membership(self) -> InventoryResult:
        """Enumerate direct + nested members of all privilege groups (DA, EA, SA, Administrators)."""
        _PRIV_RIDS = {
            "-512": "Domain Admins",
            "-519": "Enterprise Admins",
            "-544": "Administrators",
            "-518": "Schema Admins",
        }

        groups: dict[str, dict[str, Any]] = {}

        for sid in self.ad_graph.nodes_by_type.get(NodeType.GROUP, []):
            for rid_suffix, group_label in _PRIV_RIDS.items():
                if sid.endswith(rid_suffix):
                    members = self._get_all_members_bfs(sid)
                    member_details = []
                    for m_sid in sorted(members):
                        m_data = self._graph.nodes.get(m_sid, {})
                        member_details.append({
                            "sid": m_sid,
                            "name": self.ad_graph.display_name(m_sid),
                            "type": m_data.get("node_type", "Unknown"),
                        })
                    groups[sid] = {
                        "group_name": self.ad_graph.display_name(sid),
                        "group_label": group_label,
                        "direct_and_nested_members": member_details,
                        "member_count": len(member_details),
                    }
                    break

        return InventoryResult(
            section_name="Privilege Group Membership",
            description="Direct + nested members of high-privilege groups",
            data={"groups": groups, "total_groups": len(groups)},
        )

    def structural_inventory(self) -> InventoryResult:
        """Inventory of domains, DCs, trusts, and OUs."""
        # Domains
        domains = []
        for sid in self.ad_graph.nodes_by_type.get(NodeType.DOMAIN, []):
            node_data = self._graph.nodes.get(sid, {})
            domains.append({
                "sid": sid,
                "name": self.ad_graph.display_name(sid),
                "functionallevel": node_data.get("functionallevel", "Unknown"),
            })

        # Domain Controllers
        dcs = []
        for sid in self.ad_graph.nodes_by_type.get(NodeType.COMPUTER, []):
            node_data = self._graph.nodes.get(sid, {})
            if node_data.get("isdc", False):
                dcs.append({
                    "sid": sid,
                    "name": self.ad_graph.display_name(sid),
                })

        # Trusts (from Domain.Trusts relation)
        trusts: list[dict[str, Any]] = []
        for sid in self.ad_graph.nodes_by_type.get(NodeType.DOMAIN, []):
            # Check for TrustedBy edges
            for succ in self._graph.successors(sid):
                edge_data = self._graph[sid][succ]
                etype = edge_data.get("edge_type", "")
                if "Trust" in etype or etype == "TrustedBy":
                    trusts.append({
                        "source": self.ad_graph.display_name(sid),
                        "target": self.ad_graph.display_name(succ),
                        "type": etype,
                    })

        # OUs
        ou_count = len(self.ad_graph.nodes_by_type.get(NodeType.OU, []))

        return InventoryResult(
            section_name="Structural Inventory",
            description="Domains, Domain Controllers, Trusts, and OUs",
            data={
                "domains": domains,
                "domain_controllers": dcs,
                "trusts": trusts,
                "ou_count": ou_count,
                "domain_count": len(domains),
                "dc_count": len(dcs),
                "trust_count": len(trusts),
            },
        )

    def stats_with_percentages(self) -> dict[str, Any]:
        """Enhanced stats with percentage breakdowns."""
        stats = self.ad_graph.summary()
        total_users = len(self.ad_graph.nodes_by_type.get(NodeType.USER, []))
        total_computers = len(self.ad_graph.nodes_by_type.get(NodeType.COMPUTER, []))

        # Count properties
        kerb_count = 0
        asrep_count = 0
        pwd_never_count = 0
        enabled_count = 0
        unconstrained_count = 0

        for sid in self.ad_graph.nodes_by_type.get(NodeType.USER, []):
            nd = self._graph.nodes.get(sid, {})
            if nd.get("hasspn"):
                kerb_count += 1
            if nd.get("dontreqpreauth"):
                asrep_count += 1
            if nd.get("pwdneverexpires"):
                pwd_never_count += 1
            if nd.get("enabled", True):
                enabled_count += 1

        for sid in self.ad_graph.nodes_by_type.get(NodeType.COMPUTER, []):
            nd = self._graph.nodes.get(sid, {})
            if nd.get("unconstraineddelegation"):
                unconstrained_count += 1

        def _pct(part: int, total: int) -> str:
            if total == 0:
                return "0.0%"
            return f"{(part / total) * 100:.1f}%"

        stats["percentages"] = {
            "users_kerberoastable": _pct(kerb_count, total_users),
            "users_asreproastable": _pct(asrep_count, total_users),
            "users_pwd_never_expires": _pct(pwd_never_count, total_users),
            "users_enabled": _pct(enabled_count, total_users),
            "computers_unconstrained": _pct(unconstrained_count, total_computers),
        }
        stats["raw_counts"] = {
            "kerberoastable": kerb_count,
            "asreproastable": asrep_count,
            "pwd_never_expires": pwd_never_count,
            "enabled_users": enabled_count,
            "unconstrained": unconstrained_count,
        }

        return stats

    def run_all(self) -> list[InventoryResult]:
        """Run all inventory analyses."""
        return [
            self.password_age_ladder(),
            self.stale_accounts(),
            self.privilege_group_membership(),
            self.structural_inventory(),
        ]
