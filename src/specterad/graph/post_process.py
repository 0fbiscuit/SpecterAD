"""Post-processor — derive composite edges and mark high-value targets.

Composite edges are edges that cannot be directly mapped from a single ACE
but require combining multiple conditions:

- DCSync: requires both GetChanges AND GetChangesAll on the Domain object.
- ADCS ESC1: CertTemplate with Enroll + client auth EKU + enrollee supplies subject.
- ADCS ESC3: CertTemplate with enrollment agent EKU.
- ADCS ESC4: Principal has WriteDacl/WriteOwner/GenericAll on a CertTemplate.

High-Value Targets (HVT): Domain Admins, Enterprise Admins, Administrators,
Domain Controllers, and any group with SID ending in well-known RIDs.
"""

from __future__ import annotations

import logging

import networkx as nx

from specterad.models.edge import EdgeType
from specterad.models.node import ADNode, NodeType

logger = logging.getLogger(__name__)

# Well-known SID suffixes for high-value groups
_HVT_RID_SUFFIXES: frozenset[str] = frozenset({
    "-512",   # Domain Admins
    "-519",   # Enterprise Admins
    "-544",   # Administrators (Builtin)
    "-516",   # Domain Controllers
    "-518",   # Schema Admins
    "-498",   # Enterprise Domain Controllers
    "-521",   # Read-only Domain Controllers
})

# Well-known group name patterns (case-insensitive match)
_HVT_NAME_PATTERNS: frozenset[str] = frozenset({
    "domain admins",
    "enterprise admins",
    "administrators",
    "domain controllers",
    "schema admins",
})


def derive_dcsync_edges(
    graph: nx.DiGraph,
    nodes: dict[str, ADNode],
) -> int:
    """Derive DCSync composite edges.

    DCSync requires a principal to have BOTH:
    - GetChanges (DS-Replication-Get-Changes)
    - GetChangesAll (DS-Replication-Get-Changes-All)
    on a Domain object.

    We scan all Domain nodes' ACEs, group by PrincipalSID, and create
    a DCSync edge only when both rights are present.
    """
    count = 0
    domain_sids = [
        sid for sid, node in nodes.items()
        if node.node_type == NodeType.DOMAIN
    ]

    for domain_sid in domain_sids:
        domain_node = nodes[domain_sid]

        # Group ACE rights by principal
        principal_rights: dict[str, set[str]] = {}
        for ace in domain_node.aces:
            psid = ace.get("PrincipalSID", "").strip().upper()
            right = ace.get("RightName", "")
            if psid and right:
                principal_rights.setdefault(psid, set()).add(right)

        # Check for GetChanges + GetChangesAll combination
        for psid, rights in principal_rights.items():
            has_get_changes = "GetChanges" in rights
            has_get_changes_all = "GetChangesAll" in rights

            if has_get_changes and has_get_changes_all:
                if psid in graph and domain_sid in graph:
                    graph.add_edge(
                        psid,
                        domain_sid,
                        edge_type=EdgeType.DCSYNC.value,
                    )
                    count += 1
                    logger.debug(
                        "DCSync edge: %s -> %s", psid, domain_sid
                    )

    logger.info("Derived %d DCSync composite edges", count)
    return count


def derive_adcs_edges(
    graph: nx.DiGraph,
    nodes: dict[str, ADNode],
) -> int:
    """Derive ADCS attack path edges (ESC1-7 + skeleton ESC8/9/13).

    Scans CertTemplate and EnterpriseCA nodes and their ACEs to create
    composite edges representing certificate abuse attack paths.

    ESC1: Enroll + Client Auth EKU + Enrollee Supplies Subject
    ESC2: Enroll + Any Purpose / No EKU (SubCA) — no enrollee-supplies-subject required
    ESC3: Enroll + Enrollment Agent EKU
    ESC4: WriteDacl/WriteOwner/GenericAll on CertTemplate
    ESC5: WriteDacl/WriteOwner on CA server object
    ESC6: CA has EDITF_ATTRIBUTESUBJECTALTNAME2 flag → any cert can have SAN
    ESC7: ManageCA + ManageCertificates on same CA → approve pending requests
    ESC8/9/13: Skeleton — log warning if not enough data
    """
    count = 0

    # ── Collect CertTemplate nodes ──
    cert_templates = {
        sid: node for sid, node in nodes.items()
        if node.node_type == NodeType.CERTTEMPLATE
    }

    # ── Collect EnterpriseCA nodes ──
    enterprise_cas = {
        sid: node for sid, node in nodes.items()
        if node.node_type == NodeType.CERTTEMPLATE
        and node.properties.get("type", "").lower() == "enterpriseca"
    }
    # Also try to find CA nodes from any node with "CA" in properties
    for sid, node in nodes.items():
        props = node.properties
        if props.get("caname") or props.get("certificateauthority"):
            enterprise_cas[sid] = node

    if not cert_templates and not enterprise_cas:
        logger.debug("No CertTemplate/CA nodes found — skipping ADCS post-processing")
        return 0

    # ── Process CertTemplate nodes for ESC1/2/3/4 ──
    for ct_sid, ct_node in cert_templates.items():
        props = ct_node.properties

        enrollee_supplies_subject = props.get("enrolleesuppliessubject", False)

        ekus = props.get("ekus", [])
        client_auth_oids = {
            "1.3.6.1.5.5.7.3.2",      # Client Authentication
            "1.3.6.1.4.1.311.20.2.2",  # Smart Card Logon
            "2.5.29.37.0",             # Any Purpose
        }
        any_purpose_oid = "2.5.29.37.0"
        enrollment_agent_oid = "1.3.6.1.4.1.311.20.2.1"

        has_client_auth = (
            not ekus  # No EKUs = SubCA = any purpose
            or any(eku in client_auth_oids for eku in ekus)
        )
        has_any_purpose = (
            not ekus  # SubCA
            or any_purpose_oid in ekus
        )

        for ace in ct_node.aces:
            psid = ace.get("PrincipalSID", "").strip().upper()
            right = ace.get("RightName", "")

            if not psid or psid not in graph or ct_sid not in graph:
                continue

            is_enroll = right in ("Enroll", "GenericAll", "AllExtendedRights")

            # ── ESC1: Enroll + Client Auth + Enrollee Supplies Subject ──
            if is_enroll and enrollee_supplies_subject and has_client_auth:
                graph.add_edge(
                    psid, ct_sid,
                    edge_type=EdgeType.ADCSESC1.value,
                )
                count += 1

            # ── ESC2: Enroll + Any Purpose/No EKU (no enrollee-supplies-subject needed) ──
            if is_enroll and has_any_purpose and not enrollee_supplies_subject:
                graph.add_edge(
                    psid, ct_sid,
                    edge_type=EdgeType.ADCSESC2.value,
                )
                count += 1

            # ── ESC3: Enrollment Agent EKU ──
            if is_enroll and enrollment_agent_oid in ekus:
                graph.add_edge(
                    psid, ct_sid,
                    edge_type=EdgeType.ADCSESC3.value,
                )
                count += 1

            # ── ESC4: Write privileges on CertTemplate ──
            if right in ("WriteDacl", "WriteOwner", "GenericAll"):
                graph.add_edge(
                    psid, ct_sid,
                    edge_type=EdgeType.ADCSESC4.value,
                )
                count += 1

    # ── Process CA objects for ESC5/6/7 ──
    for ca_sid, ca_node in enterprise_cas.items():
        ca_props = ca_node.properties

        # Group ACE rights by principal for ESC7 (needs ManageCA + ManageCertificates)
        principal_ca_rights: dict[str, set[str]] = {}

        for ace in ca_node.aces:
            psid = ace.get("PrincipalSID", "").strip().upper()
            right = ace.get("RightName", "")
            if not psid or psid not in graph or ca_sid not in graph:
                continue

            principal_ca_rights.setdefault(psid, set()).add(right)

            # ── ESC5: WriteDacl/WriteOwner on CA server ──
            if right in ("WriteDacl", "WriteOwner"):
                graph.add_edge(
                    psid, ca_sid,
                    edge_type=EdgeType.ADCSESC5.value,
                )
                count += 1

        # ── ESC6: CA has EDITF_ATTRIBUTESUBJECTALTNAME2 flag ──
        san_flag = ca_props.get("sanflag") or ca_props.get("certificatenameflag", 0)
        # EDITF_ATTRIBUTESUBJECTALTNAME2 = 0x00040000 = flag bit in editflags
        edit_flags = ca_props.get("editflags", 0)
        has_san_edit = False
        if isinstance(edit_flags, int) and (edit_flags & 0x00040000):
            has_san_edit = True
        elif isinstance(san_flag, bool) and san_flag:
            has_san_edit = True

        if has_san_edit:
            # ESC6 means ANY enrolled principal can add SAN — tag the CA node
            graph.nodes[ca_sid]["esc6_vulnerable"] = True
            logger.info(
                "ESC6: CA %s has EDITF_ATTRIBUTESUBJECTALTNAME2 enabled",
                ca_sid,
            )
            # Create ESC6 edges from anyone with Enroll to cert templates under this CA
            for ct_sid, ct_node in cert_templates.items():
                for ace in ct_node.aces:
                    psid = ace.get("PrincipalSID", "").strip().upper()
                    right = ace.get("RightName", "")
                    if not psid or psid not in graph:
                        continue
                    if right in ("Enroll", "GenericAll", "AllExtendedRights"):
                        graph.add_edge(
                            psid, ct_sid,
                            edge_type=EdgeType.ADCSESC6.value,
                        )
                        count += 1

        # ── ESC7: ManageCA + ManageCertificates on same CA ──
        for psid, rights in principal_ca_rights.items():
            if "ManageCA" in rights and "ManageCertificates" in rights:
                graph.add_edge(
                    psid, ca_sid,
                    edge_type=EdgeType.ADCSESC7.value,
                )
                count += 1
                logger.debug("ESC7 edge: %s -> %s", psid, ca_sid)

    # ── ESC8/9/13 Skeleton — require data not in standard SharpHound ──
    _esc_skeleton_warned = False
    for ca_sid, ca_node in enterprise_cas.items():
        ca_props = ca_node.properties
        # ESC8 requires HTTP enrollment (Web Enrollment) data
        # ESC9 requires CT_FLAG_NO_SECURITY_EXTENSION check
        # ESC13 requires issuance policy OID mapping
        if not _esc_skeleton_warned:
            logger.debug(
                "ESC8/9/13: Skipped — requires AzureHound/Certify data "
                "not available in standard SharpHound collection"
            )
            _esc_skeleton_warned = True

    logger.info("Derived %d ADCS edges (ESC1-7)", count)
    return count


def derive_rbcd_can_configure(
    graph: nx.DiGraph,
    nodes: dict[str, ADNode],
) -> int:
    """Derive CanConfigureRBCD composite edges.

    If a principal has GenericWrite, WriteAccountRestrictions, or GenericAll
    on a Computer, they can write msDS-AllowedToActOnBehalfOfOtherIdentity,
    which enables Resource-Based Constrained Delegation abuse.

    Edge: Principal -[CanConfigureRBCD]-> Computer
    """
    _RBCD_RIGHTS = frozenset({
        EdgeType.GENERIC_WRITE.value,
        EdgeType.WRITE_ACCOUNT_RESTRICTIONS.value,
        EdgeType.GENERIC_ALL.value,
    })

    count = 0
    computer_sids = [
        sid for sid, node in nodes.items()
        if node.node_type == NodeType.COMPUTER
    ]

    for comp_sid in computer_sids:
        for pred in list(graph.predecessors(comp_sid)):
            edge_data = graph[pred][comp_sid]
            if edge_data.get("edge_type") in _RBCD_RIGHTS:
                # Don't add duplicate
                existing_edges = [
                    d for _, _, d in graph.edges(pred, data=True)
                    if d.get("edge_type") == EdgeType.CAN_CONFIGURE_RBCD.value
                    and _ == pred
                ]
                # Check if CanConfigureRBCD already exists to this target
                has_rbcd = False
                if graph.has_edge(pred, comp_sid):
                    # MultiDiGraph check — but we use DiGraph so check edge_type
                    for succ in graph.successors(pred):
                        if succ == comp_sid:
                            e = graph[pred][succ]
                            if e.get("edge_type") == EdgeType.CAN_CONFIGURE_RBCD.value:
                                has_rbcd = True
                                break

                if not has_rbcd:
                    # We can't add a second edge in DiGraph between same pair,
                    # so tag the existing edge instead
                    graph.nodes[comp_sid].setdefault("rbcd_configurable_by", [])
                    graph.nodes[comp_sid]["rbcd_configurable_by"].append(pred)
                    count += 1
                    logger.debug(
                        "RBCD configurable: %s can configure RBCD on %s",
                        pred, comp_sid,
                    )

    logger.info("Identified %d RBCD-configurable relationships", count)
    return count


def suppress_generic_write_noise(
    graph: nx.DiGraph,
    nodes: dict[str, ADNode],
) -> int:
    """Tag noisy Computer→Computer GenericWrite edges.

    In AD, computers often have GenericWrite on other computers due to
    normal AD operations. These edges clutter attack path analysis.

    Tags edges with noise=True (does NOT delete them) so queries and
    renderers can optionally filter them out.
    """
    count = 0
    computer_sids = set(
        sid for sid, node in nodes.items()
        if node.node_type == NodeType.COMPUTER
    )

    for src in computer_sids:
        for dst in list(graph.successors(src)):
            if dst not in computer_sids:
                continue
            edge_data = graph[src][dst]
            if edge_data.get("edge_type") == EdgeType.GENERIC_WRITE.value:
                edge_data["noise"] = True
                count += 1

    logger.info("Tagged %d noisy Computer->Computer GenericWrite edges", count)
    return count


def mark_high_value_targets(
    graph: nx.DiGraph,
    nodes: dict[str, ADNode],
) -> set[str]:
    """Identify and mark High-Value Targets in the graph.

    HVTs are nodes that represent critical assets an attacker would
    target: Domain Admins, Enterprise Admins, Domain Controllers, etc.

    Returns:
        Set of SIDs that are high-value targets.
    """
    hvt_sids: set[str] = set()

    for sid, node in nodes.items():
        is_hvt = False

        # Check by SID suffix (well-known RIDs)
        for suffix in _HVT_RID_SUFFIXES:
            if sid.endswith(suffix):
                is_hvt = True
                break

        # Check by name pattern
        if not is_hvt and node.name:
            name_lower = node.name.lower().split("@")[0]
            if name_lower in _HVT_NAME_PATTERNS:
                is_hvt = True

        # Domain Controllers (computers that are DCs)
        if not is_hvt and node.node_type == NodeType.COMPUTER:
            if node.properties.get("isdc", False):
                is_hvt = True
            elif "OU=DOMAIN CONTROLLERS" in node.properties.get("distinguishedname", "").upper():
                is_hvt = True

        if is_hvt and sid in graph:
            graph.nodes[sid]["high_value"] = True
            hvt_sids.add(sid)

    logger.info("Marked %d high-value targets", len(hvt_sids))
    return hvt_sids


def post_process_graph(
    graph: nx.DiGraph,
    nodes: dict[str, ADNode],
) -> set[str]:
    """Run all post-processing steps on the graph.

    1. Derive DCSync composite edges
    2. Derive ADCS ESC1/ESC3/ESC4 edges
    3. Derive RBCD can-configure relationships
    4. Suppress GenericWrite noise (Computer→Computer)
    5. Mark high-value targets

    Args:
        graph: The nx.DiGraph built by build_graph().
        nodes: The original ADNode dict for property access.

    Returns:
        Set of SIDs that are high-value targets.
    """
    derive_dcsync_edges(graph, nodes)
    derive_adcs_edges(graph, nodes)
    derive_rbcd_can_configure(graph, nodes)
    suppress_generic_write_noise(graph, nodes)
    hvt_sids = mark_high_value_targets(graph, nodes)
    return hvt_sids
