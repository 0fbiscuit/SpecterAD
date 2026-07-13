"""Edge weights — risk-based weight model with YAML loader.

Each edge type has three risk dimensions:
- detection_risk: How likely the action triggers security alerts (0=silent, 1=noisy)
- failure_risk: How likely the action fails (0=reliable, 1=unreliable)
- complexity: Skill/tooling required (0=trivial, 1=expert-level)

These combine into a single composite weight via a configurable formula.
Dijkstra uses composite weights to find the "quietest" attack path.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from specterad.models.edge import EdgeType

logger = logging.getLogger(__name__)

# Default config file location (relative to project root)
_DEFAULT_CONFIG_PATH = Path(__file__).parent.parent.parent.parent / "config" / "edge_weights.yaml"


@dataclass(slots=True)
class EdgeWeight:
    """Risk-based weight for a single edge type."""

    detection_risk: float  # 0.0 (silent) → 1.0 (noisy)
    failure_risk: float    # 0.0 (reliable) → 1.0 (unreliable)
    complexity: float      # 0.0 (trivial) → 1.0 (expert-level)

    def composite(self, formula: dict[str, float]) -> float:
        """Calculate the combined weight using the formula.

        Args:
            formula: Dict with keys 'detection_weight', 'failure_weight',
                     'complexity_weight' — coefficients that sum to 1.0.

        Returns:
            Weighted sum of all three dimensions.
        """
        return (
            self.detection_risk * formula.get("detection_weight", 0.4)
            + self.failure_risk * formula.get("failure_weight", 0.3)
            + self.complexity * formula.get("complexity_weight", 0.3)
        )


# ── Hardcoded defaults ──
# Used as fallback when YAML config is not available.
_DEFAULT_FORMULA: dict[str, float] = {
    "detection_weight": 0.4,
    "failure_weight": 0.3,
    "complexity_weight": 0.3,
}

_DEFAULT_WEIGHTS: dict[str, dict[str, float]] = {
    "GenericAll":           {"detection": 0.1,  "failure": 0.05, "complexity": 0.2},
    "GenericWrite":         {"detection": 0.15, "failure": 0.05, "complexity": 0.2},
    "WriteDacl":            {"detection": 0.2,  "failure": 0.05, "complexity": 0.3},
    "WriteOwner":           {"detection": 0.2,  "failure": 0.05, "complexity": 0.3},
    "Owns":                 {"detection": 0.05, "failure": 0.02, "complexity": 0.1},
    "AllExtendedRights":    {"detection": 0.15, "failure": 0.05, "complexity": 0.2},
    "ForceChangePassword":  {"detection": 0.2,  "failure": 0.1,  "complexity": 0.1},
    "AddMember":            {"detection": 0.1,  "failure": 0.05, "complexity": 0.1},
    "AddSelf":              {"detection": 0.1,  "failure": 0.05, "complexity": 0.1},
    "AddKeyCredentialLink": {"detection": 0.3,  "failure": 0.1,  "complexity": 0.4},
    "WriteSPN":             {"detection": 0.15, "failure": 0.05, "complexity": 0.2},
    "WriteAccountRestrictions": {"detection": 0.2, "failure": 0.1, "complexity": 0.3},
    "AdminTo":              {"detection": 0.4,  "failure": 0.2,  "complexity": 0.3},
    "CanRDP":               {"detection": 0.7,  "failure": 0.4,  "complexity": 0.3},
    "CanPSRemote":          {"detection": 0.5,  "failure": 0.3,  "complexity": 0.3},
    "ExecuteDCOM":          {"detection": 0.5,  "failure": 0.3,  "complexity": 0.4},
    "SQLAdmin":             {"detection": 0.4,  "failure": 0.3,  "complexity": 0.4},
    "AllowedToDelegate":    {"detection": 0.3,  "failure": 0.2,  "complexity": 0.5},
    "AllowedToAct":         {"detection": 0.3,  "failure": 0.2,  "complexity": 0.5},
    "HasSession":           {"detection": 0.5,  "failure": 0.3,  "complexity": 0.4},
    "ReadLAPSPassword":     {"detection": 0.2,  "failure": 0.05, "complexity": 0.2},
    "ReadGMSAPassword":     {"detection": 0.15, "failure": 0.05, "complexity": 0.2},
    "DCSync":               {"detection": 0.8,  "failure": 0.1,  "complexity": 0.5},
    "DumpSMSAPassword":     {"detection": 0.3,  "failure": 0.15, "complexity": 0.3},
    "HasSIDHistory":        {"detection": 0.05, "failure": 0.02, "complexity": 0.1},
    "MemberOf":             {"detection": 0.0,  "failure": 0.0,  "complexity": 0.0},
    "ADCSESC1":             {"detection": 0.3,  "failure": 0.15, "complexity": 0.5},
    "ADCSESC3":             {"detection": 0.35, "failure": 0.2,  "complexity": 0.5},
    "ADCSESC4":             {"detection": 0.3,  "failure": 0.1,  "complexity": 0.6},
    "GoldenCert":           {"detection": 0.7,  "failure": 0.2,  "complexity": 0.7},
    "ManageCA":             {"detection": 0.4,  "failure": 0.1,  "complexity": 0.5},
    "ManageCertificates":   {"detection": 0.4,  "failure": 0.1,  "complexity": 0.5},
    "GPLink":               {"detection": 0.0,  "failure": 0.0,  "complexity": 0.0},
    "Contains":             {"detection": 0.0,  "failure": 0.0,  "complexity": 0.0},
    "DCFor":                {"detection": 0.0,  "failure": 0.0,  "complexity": 0.0},
}


def _parse_weight_entry(entry: dict[str, float]) -> EdgeWeight:
    """Parse a single weight entry from YAML or defaults."""
    return EdgeWeight(
        detection_risk=entry.get("detection", 0.5),
        failure_risk=entry.get("failure", 0.5),
        complexity=entry.get("complexity", 0.5),
    )


def load_weights(
    path: Path | str | None = None,
) -> tuple[dict[str, EdgeWeight], dict[str, float]]:
    """Load edge weights and formula from YAML config.

    Falls back to embedded defaults if the file doesn't exist.

    Args:
        path: Path to edge_weights.yaml. If None, uses the default location.

    Returns:
        Tuple of (weights_dict, formula_dict):
        - weights_dict: {EdgeType.value → EdgeWeight}
        - formula_dict: coefficient dict for composite calculation
    """
    config: dict[str, Any] | None = None

    if path is not None:
        config_path = Path(path)
    else:
        config_path = _DEFAULT_CONFIG_PATH

    if config_path.exists():
        try:
            with open(config_path, "r", encoding="utf-8") as f:
                config = yaml.safe_load(f)
            logger.info("Loaded edge weights from %s", config_path)
        except Exception as exc:
            logger.warning(
                "Failed to load %s, using defaults: %s", config_path, exc
            )

    if config and isinstance(config, dict):
        raw_weights = config.get("weights", _DEFAULT_WEIGHTS)
        formula = config.get("formula", _DEFAULT_FORMULA)
    else:
        raw_weights = _DEFAULT_WEIGHTS
        formula = _DEFAULT_FORMULA

    weights: dict[str, EdgeWeight] = {}
    for edge_name, entry in raw_weights.items():
        weights[edge_name] = _parse_weight_entry(entry)

    logger.debug("Loaded %d edge weight entries", len(weights))
    return weights, formula


def get_edge_weight(
    edge_type_value: str,
    weights: dict[str, EdgeWeight],
    formula: dict[str, float],
) -> float:
    """Get the composite weight for an edge type.

    Args:
        edge_type_value: The EdgeType.value string (e.g. "GenericAll").
        weights: Weights dict from load_weights().
        formula: Formula dict from load_weights().

    Returns:
        The composite weight, or a default penalty of 1.0 if unknown.
    """
    ew = weights.get(edge_type_value)
    if ew is None:
        logger.debug("No weight for edge type '%s', using penalty 1.0", edge_type_value)
        return 1.0
    return ew.composite(formula)
