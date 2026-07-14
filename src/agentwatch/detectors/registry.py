"""Registry for managing and running detectors."""

from __future__ import annotations

from typing import TYPE_CHECKING

from .base import Category, Detector, Warning
from .health import get_all_health_detectors
from .security import get_all_security_detectors

if TYPE_CHECKING:
    from agentwatch.parser.models import ActionBuffer


class DetectorRegistry:
    """Registry for managing and running detectors."""
    
    def __init__(
        self,
        include_health: bool = True,
        include_security: bool = False,
    ):
        self.detectors: list[Detector] = []
        
        if include_health:
            self.detectors.extend(get_all_health_detectors())
        
        if include_security:
            self.detectors.extend(get_all_security_detectors())
    
    def add_detector(self, detector: Detector) -> None:
        """Add a custom detector to the registry."""
        self.detectors.append(detector)
    
    def remove_detector(self, name: str) -> bool:
        """Remove a detector by name."""
        for i, d in enumerate(self.detectors):
            if d.name == name:
                self.detectors.pop(i)
                return True
        return False
    
    def get_detector(self, name: str) -> Detector | None:
        """Get a detector by name."""
        for d in self.detectors:
            if d.name == name:
                return d
        return None
    
    def check_all(self, buffer: "ActionBuffer") -> list[Warning]:
        """Run all detectors and collect warnings."""
        warnings = []
        
        for detector in self.detectors:
            try:
                warning = detector.check(buffer)
                if warning:
                    warnings.append(warning)
            except Exception:
                # Don't let one detector crash everything
                pass
        
        # Sort by severity (critical first)
        severity_order = {
            "critical": 0,
            "high": 1,
            "medium": 2,
            "low": 3,
        }
        warnings.sort(key=lambda w: severity_order.get(w.severity.value, 4))
        
        return warnings
    
    def check_health(self, buffer: "ActionBuffer") -> list[Warning]:
        """Run only health detectors."""
        warnings = []
        
        for detector in self.detectors:
            if not detector.is_security_detector:
                try:
                    warning = detector.check(buffer)
                    if warning:
                        warnings.append(warning)
                except Exception:
                    pass
        
        return warnings
    
    def check_security(self, buffer: "ActionBuffer") -> list[Warning]:
        """Run only security detectors."""
        warnings = []
        
        for detector in self.detectors:
            if detector.is_security_detector:
                try:
                    warning = detector.check(buffer)
                    if warning:
                        warnings.append(warning)
                except Exception:
                    pass
        
        return warnings
    
    @property
    def health_detectors(self) -> list[Detector]:
        """Get all health detectors."""
        return [d for d in self.detectors if not d.is_security_detector]
    
    @property
    def security_detectors(self) -> list[Detector]:
        """Get all security detectors."""
        return [d for d in self.detectors if d.is_security_detector]
    
    def list_detectors(self) -> dict[str, list[str]]:
        """List all registered detectors by category."""
        result: dict[str, list[str]] = {}
        
        for detector in self.detectors:
            cat = detector.category.value
            if cat not in result:
                result[cat] = []
            result[cat].append(f"{detector.name}: {detector.description}")
        
        return result


def create_registry(
    mode: str = "health",
    custom_detectors: list[Detector] | None = None,
) -> DetectorRegistry:
    """
    Create a detector registry for a specific mode.
    
    Args:
        mode: "health", "security", or "all"
        custom_detectors: Optional list of custom detectors to add
    
    Returns:
        Configured DetectorRegistry
    """
    if mode == "health":
        registry = DetectorRegistry(include_health=True, include_security=False)
    elif mode == "security":
        registry = DetectorRegistry(include_health=False, include_security=True)
    elif mode == "all":
        registry = DetectorRegistry(include_health=True, include_security=True)
    else:
        raise ValueError(f"Unknown mode: {mode}")
    
    if custom_detectors:
        for detector in custom_detectors:
            registry.add_detector(detector)
    
    return registry
