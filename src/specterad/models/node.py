"""AD and Azure node models — NodeType enum and ADNode dataclass."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class NodeType(str, Enum):
    """Types of Active Directory objects supported by SharpHound."""

    USER = "User"
    COMPUTER = "Computer"
    GROUP = "Group"
    DOMAIN = "Domain"
    OU = "OU"
    GPO = "GPO"
    CERTTEMPLATE = "CertTemplate"
    CONTAINER = "Container"

    # ── Azure / Entra ID ──
    AZ_TENANT = "AZTenant"
    AZ_USER = "AZUser"
    AZ_GROUP = "AZGroup"
    AZ_APP = "AZApp"
    AZ_SERVICE_PRINCIPAL = "AZServicePrincipal"
    AZ_SUBSCRIPTION = "AZSubscription"
    AZ_RESOURCE_GROUP = "AZResourceGroup"
    AZ_VM = "AZVM"
    AZ_KEY_VAULT = "AZKeyVault"
    AZ_DEVICE = "AZDevice"
    AZ_MANAGEMENT_GROUP = "AZManagementGroup"
    AZ_ROLE = "AZRole"


# Map from SharpHound meta.type (lowercase) → NodeType
META_TYPE_MAP: dict[str, NodeType] = {
    "users": NodeType.USER,
    "computers": NodeType.COMPUTER,
    "groups": NodeType.GROUP,
    "domains": NodeType.DOMAIN,
    "ous": NodeType.OU,
    "gpos": NodeType.GPO,
    "certtemplates": NodeType.CERTTEMPLATE,
    "containers": NodeType.CONTAINER,
    # Azure / Entra ID types (AzureHound meta.type)
    "aztenants": NodeType.AZ_TENANT,
    "azusers": NodeType.AZ_USER,
    "azgroups": NodeType.AZ_GROUP,
    "azapps": NodeType.AZ_APP,
    "azserviceprincipals": NodeType.AZ_SERVICE_PRINCIPAL,
    "azsubscriptions": NodeType.AZ_SUBSCRIPTION,
    "azresourcegroups": NodeType.AZ_RESOURCE_GROUP,
    "azvms": NodeType.AZ_VM,
    "azkeyvaults": NodeType.AZ_KEY_VAULT,
    "azdevices": NodeType.AZ_DEVICE,
    "azmanagementgroups": NodeType.AZ_MANAGEMENT_GROUP,
    "azroles": NodeType.AZ_ROLE,
}


@dataclass(slots=True)
class ADNode:
    """Represents a single Active Directory object parsed from SharpHound JSON.

    Attributes:
        object_id: Unique identifier — SID for AD objects, ObjectID for Azure.
        node_type: The classification of this AD object.
        name: Display name (e.g. "D.QUAN@LAB.LOCAL").
        properties: Raw properties dict from SharpHound JSON.
        aces: Raw ACE (Access Control Entry) list — used in Phase 2 for edges.
        extra_relations: Additional relationship data (Members, LocalAdmins,
            Sessions, etc.) preserved from SharpHound JSON for Phase 2.
    """

    object_id: str
    node_type: NodeType
    name: str
    properties: dict[str, Any] = field(default_factory=dict)
    aces: list[dict[str, Any]] = field(default_factory=list)
    extra_relations: dict[str, Any] = field(default_factory=dict)

    def __repr__(self) -> str:
        return f"ADNode({self.node_type.value}:{self.name})"
