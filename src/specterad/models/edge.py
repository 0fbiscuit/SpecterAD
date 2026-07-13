"""AD edge models — EdgeType enum, traversability classification, and ACE mapping."""

from __future__ import annotations

from enum import Enum


class EdgeType(str, Enum):
    """All edge types recognized by SpecterAD.

    Edges are classified as either *traversable* (usable by pathfinding
    algorithms to model attack steps) or *non-traversable* (structural
    relationships displayed for context but not treated as attack moves).
    """

    # ── Traversable: ACL / Permission-based ──
    GENERIC_ALL = "GenericAll"
    GENERIC_WRITE = "GenericWrite"
    WRITE_DACL = "WriteDacl"
    WRITE_OWNER = "WriteOwner"
    OWNS = "Owns"
    ALL_EXTENDED_RIGHTS = "AllExtendedRights"
    FORCE_CHANGE_PASSWORD = "ForceChangePassword"
    ADD_MEMBER = "AddMember"
    ADD_SELF = "AddSelf"
    ADD_KEY_CREDENTIAL_LINK = "AddKeyCredentialLink"
    WRITE_SPN = "WriteSPN"
    WRITE_ACCOUNT_RESTRICTIONS = "WriteAccountRestrictions"

    # ── Traversable: Execution / Lateral Movement ──
    ADMIN_TO = "AdminTo"
    CAN_RDP = "CanRDP"
    CAN_PS_REMOTE = "CanPSRemote"
    EXECUTE_DCOM = "ExecuteDCOM"
    SQL_ADMIN = "SQLAdmin"

    # ── Traversable: Delegation ──
    ALLOWED_TO_DELEGATE = "AllowedToDelegate"
    ALLOWED_TO_ACT = "AllowedToAct"

    # ── Traversable: Credential Access ──
    HAS_SESSION = "HasSession"
    READ_LAPS_PASSWORD = "ReadLAPSPassword"
    READ_GMSA_PASSWORD = "ReadGMSAPassword"
    DCSYNC = "DCSync"
    DUMP_SMSA_PASSWORD = "DumpSMSAPassword"
    HAS_SID_HISTORY = "HasSIDHistory"

    # ── Traversable: Group Membership ──
    MEMBER_OF = "MemberOf"

    # ── Traversable: ADCS (MVP: ESC1, ESC3, ESC4) ──
    ADCSESC1 = "ADCSESC1"
    ADCSESC3 = "ADCSESC3"
    ADCSESC4 = "ADCSESC4"
    GOLDEN_CERT = "GoldenCert"
    MANAGE_CA = "ManageCA"
    MANAGE_CERTIFICATES = "ManageCertificates"

    # ── Non-Traversable: Structural ──
    GP_LINK = "GPLink"
    CONTAINS = "Contains"
    DC_FOR = "DCFor"


# Edges the pathfinding engine can walk through for attack path analysis.
TRAVERSABLE_EDGES: frozenset[EdgeType] = frozenset(EdgeType) - frozenset({
    EdgeType.GP_LINK,
    EdgeType.CONTAINS,
    EdgeType.DC_FOR,
})


# ── Mapping: SharpHound ACE RightName → EdgeType ──
# When processing Aces[].RightName from SharpHound JSON, this maps
# the string value to the corresponding EdgeType.
ACE_RIGHT_TO_EDGE: dict[str, EdgeType] = {
    "GenericAll": EdgeType.GENERIC_ALL,
    "GenericWrite": EdgeType.GENERIC_WRITE,
    "WriteDacl": EdgeType.WRITE_DACL,
    "WriteOwner": EdgeType.WRITE_OWNER,
    "Owns": EdgeType.OWNS,
    "AllExtendedRights": EdgeType.ALL_EXTENDED_RIGHTS,
    "ForceChangePassword": EdgeType.FORCE_CHANGE_PASSWORD,
    "AddMember": EdgeType.ADD_MEMBER,
    "AddSelf": EdgeType.ADD_SELF,
    "AddKeyCredentialLink": EdgeType.ADD_KEY_CREDENTIAL_LINK,
    "WriteSPN": EdgeType.WRITE_SPN,
    "WriteAccountRestrictions": EdgeType.WRITE_ACCOUNT_RESTRICTIONS,
    "ReadLAPSPassword": EdgeType.READ_LAPS_PASSWORD,
    "ReadGMSAPassword": EdgeType.READ_GMSA_PASSWORD,
    "User-Force-Change-Password": EdgeType.FORCE_CHANGE_PASSWORD,
    "Member": EdgeType.ADD_MEMBER,
    "ManageCA": EdgeType.MANAGE_CA,
    "ManageCertificates": EdgeType.MANAGE_CERTIFICATES,
    # NOTE: GetChanges / GetChangesAll are NOT mapped here.
    # DCSync is a composite edge requiring BOTH rights on a Domain object.
    # It is derived exclusively by post_process.derive_dcsync_edges().
}
