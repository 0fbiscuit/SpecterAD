"""Path formatting utilities — risk labels, color coding, edge icons."""

from __future__ import annotations

from specterad.models.node import NodeType

# ── Color coding for node types (Rich markup) ──
NODE_COLORS: dict[str, str] = {
    NodeType.USER.value: "green",
    NodeType.COMPUTER.value: "yellow",
    NodeType.GROUP.value: "blue",
    NodeType.DOMAIN.value: "magenta",
    NodeType.OU.value: "cyan",
    NodeType.GPO.value: "cyan",
    NodeType.CERTTEMPLATE.value: "red",
    NodeType.CONTAINER.value: "dim",
}

# ── Risk level classification ──
RISK_THRESHOLDS: list[tuple[float, str, str]] = [
    (0.15, "LOW", "green"),
    (0.35, "MEDIUM", "yellow"),
    (0.60, "HIGH", "red"),
    (float("inf"), "CRITICAL", "bold red"),
]

def get_risk_label(weight: float) -> tuple[str, str]:
    """Get risk level label and color for a given weight.

    Returns:
        (label, color) tuple e.g. ("MEDIUM", "yellow")
    """
    for threshold, label, color in RISK_THRESHOLDS:
        if weight < threshold:
            return label, color
    return "CRITICAL", "bold red"


def get_node_color(node_type: str) -> str:
    """Get Rich color for a node type."""
    return NODE_COLORS.get(node_type, "white")


def format_weight(weight: float) -> str:
    """Format a weight value with fixed precision."""
    return f"{weight:.3f}"
