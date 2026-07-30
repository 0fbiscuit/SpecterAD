"""Azure / Entra ID query engine — skeleton security queries for Azure objects.

Provides pre-built queries for Azure AD attack path analysis.
These queries scan the graph for Azure-specific risks:
- Global Admin enumeration
- Privileged Role Admin assignments
- Service Principal abuse paths
- Key Vault access analysis
- VM access analysis

NOTE: This is a SKELETON implementation. Full query results depend
on having AzureHound JSON data loaded. Without Azure data, all queries
return empty results gracefully.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

import networkx as nx

from specterad.engine.queries import QueryResult
from specterad.models.edge import EdgeType
from specterad.models.graph import ADGraph
from specterad.models.node import NodeType

logger = logging.getLogger(__name__)


class AzureQueryEngine:
    """Pre-built security queries for Azure / Entra ID objects."""

    def __init__(self, ad_graph: ADGraph) -> None:
        self.ad_graph = ad_graph
        self._graph = ad_graph.graph

    def _has_azure_data(self) -> bool:
        """Check if Azure nodes exist in the graph."""
        _AZ_TYPES = {
            NodeType.AZ_TENANT, NodeType.AZ_USER, NodeType.AZ_GROUP,
            NodeType.AZ_APP, NodeType.AZ_SERVICE_PRINCIPAL,
        }
        for az_type in _AZ_TYPES:
            if self.ad_graph.nodes_by_type.get(az_type):
                return True
        return False

    def global_admins(self) -> QueryResult:
        """Find all Azure Global Administrators.

        Global Admins have full control over the tenant — highest privilege role.
        """
        results: list[dict[str, Any]] = []

        for src, dst, data in self._graph.edges(data=True):
            if data.get("edge_type") == EdgeType.AZ_GLOBAL_ADMIN.value:
                results.append({
                    "principal_sid": src,
                    "principal_name": self.ad_graph.display_name(src),
                    "tenant_sid": dst,
                    "tenant_name": self.ad_graph.display_name(dst),
                })

        return QueryResult(
            query_name="Azure Global Admins",
            description="Principals with Global Administrator role in Azure/Entra ID",
            results=results,
            count=len(results),
        )

    def privileged_role_admins(self) -> QueryResult:
        """Find principals with Privileged Role Administrator access.

        Can assign any role to any user — nearly equivalent to Global Admin.
        """
        results: list[dict[str, Any]] = []

        for src, dst, data in self._graph.edges(data=True):
            if data.get("edge_type") == EdgeType.AZ_PRIVILEGED_ROLE_ADMIN.value:
                results.append({
                    "principal_sid": src,
                    "principal_name": self.ad_graph.display_name(src),
                    "target_sid": dst,
                    "target_name": self.ad_graph.display_name(dst),
                })

        return QueryResult(
            query_name="Azure Privileged Role Admins",
            description="Principals that can assign any role — near Global Admin equivalence",
            results=results,
            count=len(results),
        )

    def service_principal_owners(self) -> QueryResult:
        """Find ownership relationships on Service Principals.

        Owning a Service Principal allows credential rotation and abuse.
        """
        results: list[dict[str, Any]] = []

        sp_sids = self.ad_graph.nodes_by_type.get(
            NodeType.AZ_SERVICE_PRINCIPAL, []
        )
        for sp_sid in sp_sids:
            for pred in self._graph.predecessors(sp_sid):
                edge_data = self._graph[pred][sp_sid]
                if edge_data.get("edge_type") == EdgeType.AZ_OWNER.value:
                    results.append({
                        "owner_sid": pred,
                        "owner_name": self.ad_graph.display_name(pred),
                        "sp_sid": sp_sid,
                        "sp_name": self.ad_graph.display_name(sp_sid),
                    })

        return QueryResult(
            query_name="Service Principal Owners",
            description="Principals that own Service Principals — can rotate credentials",
            results=results,
            count=len(results),
        )

    def key_vault_access(self) -> QueryResult:
        """Find principals with access to Azure Key Vaults.

        Key Vault access can expose secrets, certificates, and keys.
        """
        results: list[dict[str, Any]] = []

        kv_sids = self.ad_graph.nodes_by_type.get(NodeType.AZ_KEY_VAULT, [])
        for kv_sid in kv_sids:
            for pred in self._graph.predecessors(kv_sid):
                edge_data = self._graph[pred][kv_sid]
                etype = edge_data.get("edge_type", "")
                if etype in (
                    EdgeType.AZ_KEY_VAULT_CONTRIBUTOR.value,
                    EdgeType.AZ_OWNER.value,
                    EdgeType.AZ_CONTRIBUTOR.value,
                ):
                    results.append({
                        "principal_sid": pred,
                        "principal_name": self.ad_graph.display_name(pred),
                        "keyvault_sid": kv_sid,
                        "keyvault_name": self.ad_graph.display_name(kv_sid),
                        "access_type": etype,
                    })

        return QueryResult(
            query_name="Key Vault Access",
            description="Principals with access to Azure Key Vaults — potential secret exposure",
            results=results,
            count=len(results),
        )

    def vm_admin_access(self) -> QueryResult:
        """Find principals with admin login or contributor access to VMs.

        VM access enables command execution and potential lateral movement.
        """
        results: list[dict[str, Any]] = []

        vm_sids = self.ad_graph.nodes_by_type.get(NodeType.AZ_VM, [])
        for vm_sid in vm_sids:
            for pred in self._graph.predecessors(vm_sid):
                edge_data = self._graph[pred][vm_sid]
                etype = edge_data.get("edge_type", "")
                if etype in (
                    EdgeType.AZ_VM_ADMIN_LOGIN.value,
                    EdgeType.AZ_VM_CONTRIBUTOR.value,
                    EdgeType.AZ_EXEC_COMMAND.value,
                ):
                    results.append({
                        "principal_sid": pred,
                        "principal_name": self.ad_graph.display_name(pred),
                        "vm_sid": vm_sid,
                        "vm_name": self.ad_graph.display_name(vm_sid),
                        "access_type": etype,
                    })

        return QueryResult(
            query_name="VM Admin Access",
            description="Principals with admin/contributor/exec access to Azure VMs",
            results=results,
            count=len(results),
        )

    def azure_summary(self) -> dict[str, int]:
        """Return a summary of Azure objects and edges in the graph."""
        _AZ_NODE_TYPES = {
            NodeType.AZ_TENANT, NodeType.AZ_USER, NodeType.AZ_GROUP,
            NodeType.AZ_APP, NodeType.AZ_SERVICE_PRINCIPAL,
            NodeType.AZ_SUBSCRIPTION, NodeType.AZ_RESOURCE_GROUP,
            NodeType.AZ_VM, NodeType.AZ_KEY_VAULT, NodeType.AZ_DEVICE,
            NodeType.AZ_MANAGEMENT_GROUP, NodeType.AZ_ROLE,
        }

        summary: dict[str, int] = {}
        total = 0
        for nt in _AZ_NODE_TYPES:
            count = len(self.ad_graph.nodes_by_type.get(nt, []))
            if count > 0:
                summary[nt.value] = count
                total += count

        summary["_total_azure_nodes"] = total
        return summary

    def run_all(self) -> list[QueryResult]:
        """Run all Azure queries. Returns empty results if no Azure data."""
        if not self._has_azure_data():
            logger.info(
                "No Azure/Entra data in graph — Azure queries skipped. "
                "Load AzureHound JSON to enable Azure analysis."
            )
            return []

        return [
            self.global_admins(),
            self.privileged_role_admins(),
            self.service_principal_owners(),
            self.key_vault_access(),
            self.vm_admin_access(),
        ]
