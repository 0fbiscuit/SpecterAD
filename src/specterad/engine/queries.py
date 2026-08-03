"""Pre-built security queries for common AD attack patterns.

Provides quick-access queries that security analysts commonly need:
- Kerberoastable users (hasspn=true)
- AS-REP Roastable users (dontreqpreauth=true)
- Unconstrained delegation computers
- DCSync principals
- Domain Admin sessions
- Shadow credentials (AddKeyCredentialLink)
- Password in description
- PasswordNeverExpires / PasswordNotRequired
- Privileged roast (roastable + admin)
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import Any

import networkx as nx

from specterad.models.edge import EdgeType
from specterad.models.graph import ADGraph
from specterad.models.node import NodeType

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class QueryResult:
    """Result of a pre-built query.

    Attributes:
        query_name: Human-readable name of the query.
        description: What this query finds.
        results: List of result dicts with details for each finding.
        count: Total number of findings.
    """

    query_name: str
    description: str
    results: list[dict[str, Any]]
    count: int


class QueryEngine:
    """Pre-built query templates for common AD security analysis."""

    def __init__(self, ad_graph: ADGraph) -> None:
        self.ad_graph = ad_graph
        self._graph = ad_graph.graph

    def _get_nodes_with_property(
        self,
        node_type: NodeType,
        property_name: str,
        expected_value: Any = True,
    ) -> list[dict[str, Any]]:
        """Find nodes of a given type where a property matches expected value."""
        results: list[dict[str, Any]] = []
        sids = self.ad_graph.nodes_by_type.get(node_type, [])

        for sid in sids:
            node_data = self._graph.nodes.get(sid, {})
            if node_data.get(property_name) == expected_value:
                results.append({
                    "sid": sid,
                    "name": self.ad_graph.display_name(sid),
                    "node_type": node_type.value,
                    property_name: expected_value,
                })

        return results

    def _enrich_roast_result(self, result: dict[str, Any]) -> dict[str, Any]:
        """Enrich a roastable user result with AdminCount/lastlogon/enabled tags."""
        sid = result["sid"]
        node_data = self._graph.nodes.get(sid, {})
        result["admincount"] = bool(node_data.get("admincount", False))
        result["enabled"] = bool(node_data.get("enabled", True))
        result["lastlogon"] = node_data.get("lastlogontimestamp", node_data.get("lastlogon", "N/A"))

        # Check if user is a member of DA/EA (direct MemberOf check)
        is_priv = False
        for succ in self._graph.successors(sid):
            edge_data = self._graph[sid][succ]
            if edge_data.get("edge_type") == EdgeType.MEMBER_OF.value:
                if succ.endswith("-512") or succ.endswith("-519"):
                    is_priv = True
                    break
        result["is_privileged"] = is_priv
        return result

    def kerberoastable_users(self) -> QueryResult:
        """Find users with SPNs set (vulnerable to Kerberoasting).

        Attack: Request TGS ticket for SPN → offline crack the hash.
        Results enriched with AdminCount, lastlogon, enabled, is_privileged tags.
        """
        results = self._get_nodes_with_property(
            NodeType.USER, "hasspn", True
        )
        results = [self._enrich_roast_result(r) for r in results]

        return QueryResult(
            query_name="Kerberoastable Users",
            description="Users with SPNs set — vulnerable to offline TGS ticket cracking",
            results=results,
            count=len(results),
        )

    def asrep_roastable_users(self) -> QueryResult:
        """Find users that don't require Kerberos pre-authentication.

        Attack: Request AS-REP without password → offline crack the hash.
        Results enriched with AdminCount, lastlogon, enabled, is_privileged tags.
        """
        results = self._get_nodes_with_property(
            NodeType.USER, "dontreqpreauth", True
        )
        results = [self._enrich_roast_result(r) for r in results]

        return QueryResult(
            query_name="AS-REP Roastable Users",
            description="Users not requiring Kerberos pre-auth — vulnerable to AS-REP offline cracking",
            results=results,
            count=len(results),
        )

    def unconstrained_delegation(self) -> QueryResult:
        """Find computers with unconstrained delegation enabled.

        Attack: Any user authenticating to this machine will have their
        TGT cached, allowing impersonation.

        Results split by is_dc flag to distinguish DCs (expected) from
        non-DC computers (high risk).
        """
        results: list[dict[str, Any]] = []
        for sid in self.ad_graph.nodes_by_type.get(NodeType.COMPUTER, []):
            node_data = self._graph.nodes.get(sid, {})
            if node_data.get("unconstraineddelegation"):
                is_dc = bool(node_data.get("isdc", False))
                results.append({
                    "sid": sid,
                    "name": self.ad_graph.display_name(sid),
                    "node_type": "Computer",
                    "is_dc": is_dc,
                    "risk": "Expected" if is_dc else "HIGH",
                })

        return QueryResult(
            query_name="Unconstrained Delegation",
            description="Computers that cache TGTs — non-DC entries are high risk",
            results=results,
            count=len(results),
        )

    def dcsync_principals(self) -> QueryResult:
        """Find principals that have DCSync rights on any domain.

        Looks for edges of type DCSync from any node to a Domain node.
        """
        results: list[dict[str, Any]] = []
        domain_sids = self.ad_graph.nodes_by_type.get(NodeType.DOMAIN, [])

        for domain_sid in domain_sids:
            # Find all predecessors with DCSync edges to this domain
            for pred in self._graph.predecessors(domain_sid):
                edge_data = self._graph[pred][domain_sid]
                if edge_data.get("edge_type") == EdgeType.DCSYNC.value:
                    results.append({
                        "sid": pred,
                        "name": self.ad_graph.display_name(pred),
                        "target_domain": self.ad_graph.display_name(domain_sid),
                        "edge_type": "DCSync",
                    })

        return QueryResult(
            query_name="DCSync Principals",
            description="Principals with replication rights (GetChanges + GetChangesAll) on domain",
            results=results,
            count=len(results),
        )

    def da_sessions(self) -> QueryResult:
        """Find computers where Domain Admin has an active session.

        Attack: Compromise the computer → dump DA credentials from memory.
        """
        results: list[dict[str, Any]] = []

        # Get all DA group SIDs (RID -512)
        da_sids: set[str] = set()
        for sid in self.ad_graph.nodes_by_type.get(NodeType.GROUP, []):
            if sid.endswith("-512"):
                da_sids.add(sid)

        # Get direct members of DA groups
        da_members: set[str] = set()
        for da_sid in da_sids:
            for pred in self._graph.predecessors(da_sid):
                edge_data = self._graph[pred][da_sid]
                if edge_data.get("edge_type") == EdgeType.MEMBER_OF.value:
                    da_members.add(pred)

        # Find HasSession edges: Computer → DA_User
        for comp_sid in self.ad_graph.nodes_by_type.get(NodeType.COMPUTER, []):
            for successor in self._graph.successors(comp_sid):
                edge_data = self._graph[comp_sid][successor]
                if (
                    edge_data.get("edge_type") == EdgeType.HAS_SESSION.value
                    and successor in da_members
                ):
                    results.append({
                        "computer_sid": comp_sid,
                        "computer_name": self.ad_graph.display_name(comp_sid),
                        "user_sid": successor,
                        "user_name": self.ad_graph.display_name(successor),
                    })

        return QueryResult(
            query_name="Domain Admin Sessions",
            description="Computers with active Domain Admin sessions — credential dump targets",
            results=results,
            count=len(results),
        )

    def high_value_targets(self) -> QueryResult:
        """List all identified High-Value Targets."""
        results: list[dict[str, Any]] = []

        for sid in sorted(self.ad_graph.high_value_targets):
            node_data = self._graph.nodes.get(sid, {})
            results.append({
                "sid": sid,
                "name": self.ad_graph.display_name(sid),
                "node_type": node_data.get("node_type", "Unknown"),
            })

        return QueryResult(
            query_name="High-Value Targets",
            description="All identified high-value targets (DA, EA, DC, Schema Admins, etc.)",
            results=results,
            count=len(results),
        )

    def all_users(self) -> QueryResult:
        """List all users in the graph."""
        results = []
        for sid in sorted(self.ad_graph.nodes_by_type.get(NodeType.USER, [])):
            results.append({
                "sid": sid,
                "name": self.ad_graph.display_name(sid),
                "node_type": "User",
            })
        return QueryResult(
            query_name="All Users",
            description="All user objects identified in the graph",
            results=results,
            count=len(results),
        )

    def all_groups(self) -> QueryResult:
        """List all groups in the graph."""
        results = []
        for sid in sorted(self.ad_graph.nodes_by_type.get(NodeType.GROUP, [])):
            results.append({
                "sid": sid,
                "name": self.ad_graph.display_name(sid),
                "node_type": "Group",
            })
        return QueryResult(
            query_name="All Groups",
            description="All group objects identified in the graph",
            results=results,
            count=len(results),
        )

    def all_computers(self) -> QueryResult:
        """List all computers in the graph."""
        results = []
        for sid in sorted(self.ad_graph.nodes_by_type.get(NodeType.COMPUTER, [])):
            results.append({
                "sid": sid,
                "name": self.ad_graph.display_name(sid),
                "node_type": "Computer",
            })
        return QueryResult(
            query_name="All Computers",
            description="All computer objects identified in the graph",
            results=results,
            count=len(results),
        )

    def shadow_credentials(self) -> QueryResult:
        """Find principals that can set shadow credentials (AddKeyCredentialLink).

        Attack: Write msDS-KeyCredentialLink → obtain TGT as target.
        """
        results: list[dict[str, Any]] = []
        for src, dst, data in self._graph.edges(data=True):
            if data.get("edge_type") == EdgeType.ADD_KEY_CREDENTIAL_LINK.value:
                dst_data = self._graph.nodes.get(dst, {})
                dst_type = dst_data.get("node_type", "Unknown")
                if dst_type in (NodeType.USER.value, NodeType.COMPUTER.value):
                    results.append({
                        "principal_sid": src,
                        "principal_name": self.ad_graph.display_name(src),
                        "target_sid": dst,
                        "target_name": self.ad_graph.display_name(dst),
                        "target_type": dst_type,
                    })

        return QueryResult(
            query_name="Shadow Credentials",
            description="Principals that can write msDS-KeyCredentialLink — PKINIT abuse",
            results=results,
            count=len(results),
        )

    def password_in_description(self) -> QueryResult:
        """Find users with potential passwords in their description field.

        Scans the 'description' property for common password-related keywords.
        """
        _PWD_PATTERN = re.compile(
            r"(pass|pwd|p@ss|credential|secret|wachtwoord|motdepasse)",
            re.IGNORECASE,
        )
        results: list[dict[str, Any]] = []
        for sid in self.ad_graph.nodes_by_type.get(NodeType.USER, []):
            node_data = self._graph.nodes.get(sid, {})
            desc = node_data.get("description", "")
            if desc and isinstance(desc, str) and _PWD_PATTERN.search(desc):
                results.append({
                    "sid": sid,
                    "name": self.ad_graph.display_name(sid),
                    "description": desc[:120],
                })

        return QueryResult(
            query_name="Password in Description",
            description="Users with password-related keywords in description field",
            results=results,
            count=len(results),
        )

    def password_never_expires(self) -> QueryResult:
        """Find users with PasswordNeverExpires flag set."""
        results = self._get_nodes_with_property(
            NodeType.USER, "pwdneverexpires", True
        )
        return QueryResult(
            query_name="Password Never Expires",
            description="Users whose passwords never expire — stale credential risk",
            results=results,
            count=len(results),
        )

    def password_not_required(self) -> QueryResult:
        """Find users with PASSWD_NOTREQD flag set."""
        results = self._get_nodes_with_property(
            NodeType.USER, "passwordnotreqd", True
        )
        return QueryResult(
            query_name="Password Not Required",
            description="Users that can have an empty password",
            results=results,
            count=len(results),
        )

    def privileged_roast(self) -> QueryResult:
        """Find roastable users that are also privileged.

        Combines Kerberoastable/AS-REP roastable with DA/EA membership
        or AdminCount=True. High-priority targets.
        """
        results: list[dict[str, Any]] = []
        seen: set[str] = set()

        for query_fn in (self.kerberoastable_users, self.asrep_roastable_users):
            qr = query_fn()
            for r in qr.results:
                sid = r["sid"]
                if sid in seen:
                    continue
                seen.add(sid)
                if r.get("is_privileged") or r.get("admincount"):
                    results.append({
                        "sid": sid,
                        "name": r["name"],
                        "attack": qr.query_name,
                        "admincount": r.get("admincount", False),
                        "is_privileged": r.get("is_privileged", False),
                    })

        return QueryResult(
            query_name="Privileged Roast",
            description="Roastable users with admin privileges — highest priority targets",
            results=results,
            count=len(results),
        )
    def domain_trusts(self) -> QueryResult:
        """List all domain trust relationships.

        Shows trust direction, type, and transitivity from TrustedBy edges.
        """
        results: list[dict[str, Any]] = []
        seen: set[tuple[str, str]] = set()

        for src, dst, data in self._graph.edges(data=True):
            if data.get("edge_type") == EdgeType.TRUSTED_BY.value:
                pair = (src, dst)
                if pair in seen:
                    continue
                seen.add(pair)
                results.append({
                    "source_domain": self.ad_graph.display_name(src),
                    "target_domain": self.ad_graph.display_name(dst),
                    "trust_type": data.get("trust_type", "Unknown"),
                    "trust_direction": data.get("trust_direction", "N/A"),
                    "is_transitive": data.get("is_transitive", False),
                })

        return QueryResult(
            query_name="Domain Trusts",
            description="All domain trust relationships and their properties",
            results=results,
            count=len(results),
        )

    def rbcd_configurable(self) -> QueryResult:
        """Find computers where RBCD can be configured by a principal.

        Shows principals that have GenericWrite/WriteAccountRestrictions/GenericAll
        on a Computer, enabling msDS-AllowedToActOnBehalfOfOtherIdentity writes.
        """
        results: list[dict[str, Any]] = []

        for comp_sid in self.ad_graph.nodes_by_type.get(NodeType.COMPUTER, []):
            node_data = self._graph.nodes.get(comp_sid, {})
            configurers = node_data.get("rbcd_configurable_by", [])
            for principal_sid in configurers:
                results.append({
                    "principal_sid": principal_sid,
                    "principal_name": self.ad_graph.display_name(principal_sid),
                    "target_sid": comp_sid,
                    "target_name": self.ad_graph.display_name(comp_sid),
                })

        return QueryResult(
            query_name="RBCD Configurable",
            description="Principals that can configure Resource-Based Constrained Delegation",
            results=results,
            count=len(results),
        )

    def constrained_delegation(self) -> QueryResult:
        """Find computers/users with constrained delegation configured.

        Attack: Protocol transition → impersonate any user to the
        services listed in msDS-AllowedToDelegateTo.
        """
        results: list[dict[str, Any]] = []
        for node_type in (NodeType.COMPUTER, NodeType.USER):
            for sid in self.ad_graph.nodes_by_type.get(node_type, []):
                node_data = self._graph.nodes.get(sid, {})
                targets = node_data.get("allowedtodelegate", [])
                if targets:
                    results.append({
                        "sid": sid,
                        "name": self.ad_graph.display_name(sid),
                        "node_type": node_type.value,
                        "delegate_to": targets if isinstance(targets, list) else [targets],
                    })

        return QueryResult(
            query_name="Constrained Delegation",
            description="Accounts with constrained delegation — can impersonate users to specific services",
            results=results,
            count=len(results),
        )

    def trusted_to_auth_for_delegation(self) -> QueryResult:
        """Find accounts with TrustedToAuthForDelegation (S4U2Self abuse).

        Attack: Protocol transition allows S4U2Self → obtain forwardable
        TGS as any user without their password.
        """
        results: list[dict[str, Any]] = []
        for node_type in (NodeType.COMPUTER, NodeType.USER):
            for sid in self.ad_graph.nodes_by_type.get(node_type, []):
                node_data = self._graph.nodes.get(sid, {})
                if node_data.get("trustedtoauth", False):
                    results.append({
                        "sid": sid,
                        "name": self.ad_graph.display_name(sid),
                        "node_type": node_type.value,
                    })

        return QueryResult(
            query_name="Trusted To Auth For Delegation",
            description="Accounts with protocol transition enabled — S4U2Self abuse risk",
            results=results,
            count=len(results),
        )

    def laps_computers(self) -> QueryResult:
        """Find computers with LAPS enabled or disabled.

        LAPS-enabled computers rotate local admin passwords automatically.
        Computers WITHOUT LAPS are higher risk for credential reuse.
        """
        with_laps: list[dict[str, Any]] = []
        without_laps: list[dict[str, Any]] = []
        for sid in self.ad_graph.nodes_by_type.get(NodeType.COMPUTER, []):
            node_data = self._graph.nodes.get(sid, {})
            has_laps = bool(node_data.get("haslaps", False))
            entry = {
                "sid": sid,
                "name": self.ad_graph.display_name(sid),
                "haslaps": has_laps,
            }
            if has_laps:
                with_laps.append(entry)
            else:
                without_laps.append(entry)

        # Return computers WITHOUT LAPS as primary findings (higher risk)
        results = without_laps + with_laps
        return QueryResult(
            query_name="LAPS Status",
            description=f"Computer LAPS status — {len(without_laps)} without LAPS (risk), {len(with_laps)} with LAPS",
            results=results,
            count=len(results),
        )

    def gmsa_accounts(self) -> QueryResult:
        """Find Group Managed Service Accounts (gMSA).

        gMSA passwords can be read by authorized principals via
        ReadGMSAPassword edges.
        """
        results: list[dict[str, Any]] = []
        for sid in self.ad_graph.nodes_by_type.get(NodeType.USER, []):
            node_data = self._graph.nodes.get(sid, {})
            name = self.ad_graph.display_name(sid)
            # gMSA objects typically have gmsa-related properties or
            # end with $ like computer accounts
            if node_data.get("gmsa", False) or node_data.get("isgmsa", False):
                results.append({
                    "sid": sid,
                    "name": name,
                    "node_type": "User",
                })

        return QueryResult(
            query_name="gMSA Accounts",
            description="Group Managed Service Accounts — check ReadGMSAPassword edges for readers",
            results=results,
            count=len(results),
        )

    def smartcard_not_required(self) -> QueryResult:
        """Find users where smart card logon is NOT required.

        Users without SMARTCARD_REQUIRED can authenticate with passwords,
        which may be weaker than certificate-based authentication.
        """
        results: list[dict[str, Any]] = []
        for sid in self.ad_graph.nodes_by_type.get(NodeType.USER, []):
            node_data = self._graph.nodes.get(sid, {})
            # smartcardlogonrequired is False or missing = not required
            if not node_data.get("smartcardlogonrequired", False):
                if node_data.get("enabled", True):
                    results.append({
                        "sid": sid,
                        "name": self.ad_graph.display_name(sid),
                        "enabled": True,
                    })

        return QueryResult(
            query_name="Smartcard Not Required",
            description="Enabled users that do NOT require smartcard logon",
            results=results,
            count=len(results),
        )

    def sensitive_not_delegated(self) -> QueryResult:
        """Find privileged users NOT marked as 'sensitive and cannot be delegated'.

        Best practice: privileged accounts (admincount=1) should have the
        NOT_DELEGATED flag set to prevent delegation abuse.
        """
        results: list[dict[str, Any]] = []
        for sid in self.ad_graph.nodes_by_type.get(NodeType.USER, []):
            node_data = self._graph.nodes.get(sid, {})
            if node_data.get("admincount", False):
                is_sensitive = node_data.get("sensitive", False)
                if not is_sensitive:
                    results.append({
                        "sid": sid,
                        "name": self.ad_graph.display_name(sid),
                        "admincount": True,
                        "sensitive": False,
                    })

        return QueryResult(
            query_name="Sensitive Not Delegated",
            description="Privileged users (admincount=1) without NOT_DELEGATED flag — delegation abuse risk",
            results=results,
            count=len(results),
        )

    def run_all(self) -> list[QueryResult]:
        """Run all pre-built queries and return results."""
        return [
            self.kerberoastable_users(),
            self.asrep_roastable_users(),
            self.unconstrained_delegation(),
            self.constrained_delegation(),
            self.trusted_to_auth_for_delegation(),
            self.dcsync_principals(),
            self.da_sessions(),
            self.high_value_targets(),
            self.shadow_credentials(),
            self.password_in_description(),
            self.password_never_expires(),
            self.password_not_required(),
            self.privileged_roast(),
            self.laps_computers(),
            self.gmsa_accounts(),
            self.smartcard_not_required(),
            self.sensitive_not_delegated(),
            self.domain_trusts(),
            self.rbcd_configurable(),
            self.all_users(),
            self.all_groups(),
            self.all_computers(),
        ]
