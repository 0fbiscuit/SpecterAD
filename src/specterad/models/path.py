"""Path models — PathStep and AttackPath dataclasses for pathfinding results."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(slots=True)
class PathStep:
    """A single hop in an attack path.

    Represents: source -[edge_type]-> target with associated weight.
    """

    source: str           # SID of the source node
    source_name: str      # Display name of source
    edge_type: str        # EdgeType.value string
    target: str           # SID of the target node
    target_name: str      # Display name of target
    weight: float = 0.0   # Composite weight of this edge


@dataclass(slots=True)
class AttackPath:
    """A complete attack path from source to destination.

    Contains an ordered list of PathSteps and aggregate metrics.
    """

    steps: list[PathStep] = field(default_factory=list)
    total_weight: float = 0.0
    hop_count: int = 0

    @property
    def source(self) -> str:
        """SID of the path's starting node."""
        return self.steps[0].source if self.steps else ""

    @property
    def target(self) -> str:
        """SID of the path's final destination node."""
        return self.steps[-1].target if self.steps else ""

    @property
    def source_name(self) -> str:
        return self.steps[0].source_name if self.steps else ""

    @property
    def target_name(self) -> str:
        return self.steps[-1].target_name if self.steps else ""

    def __repr__(self) -> str:
        if not self.steps:
            return "AttackPath(empty)"
        return (
            f"AttackPath({self.source_name} → {self.target_name}, "
            f"{self.hop_count} hops, weight={self.total_weight:.3f})"
        )
