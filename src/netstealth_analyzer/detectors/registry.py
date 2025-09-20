"""
Detector registry for managing and discovering detectors.

This module provides a centralized registry for all detectors,
supporting both built-in and plugin detectors with async capabilities.
"""

from typing import Any, Dict, List, Optional, Set, Type
from dataclasses import dataclass, field
from datetime import datetime, timezone

from .base import IDetector, DetectionContext, DetectionResult
from ..models.enums import IssueCategory
from ..core.events import EventBus


@dataclass
class DetectorInfo:
    """Information about a registered detector."""
    
    name: str
    version: str
    description: str
    categories: List[IssueCategory]
    detector_class: Type[IDetector]
    is_enabled: bool = True
    priority: int = 100  # Lower numbers = higher priority
    metadata: Dict[str, Any] = field(default_factory=dict)
    registered_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class DetectorRegistry:
    """
    Registry for managing detectors.
    
    Provides detector discovery, instantiation, and execution management
    with support for async operations and event-driven notifications.
    """
    
    def __init__(self, event_bus: Optional[EventBus] = None):
        """
        Initialize detector registry.
        
        Args:
            event_bus: Optional event bus for notifications
        """
        self.event_bus = event_bus
        self._detectors: Dict[str, DetectorInfo] = {}
        self._categories_map: Dict[IssueCategory, List[str]] = {}
        
        # Auto-register built-in detectors
        self._register_builtin_detectors()
    
    def register_detector(
        self,
        detector_class: Type[IDetector],
        priority: int = 100,
        enabled: bool = True,
        metadata: Optional[Dict[str, Any]] = None
    ) -> bool:
        """
        Register a detector class.
        
        Args:
            detector_class: Detector class to register
            priority: Priority level (lower = higher priority)
            enabled: Whether detector is enabled by default
            metadata: Additional metadata
            
        Returns:
            True if registered successfully, False if already exists
        """
        # Create temporary instance to get metadata
        temp_instance = detector_class()
        name = temp_instance.name
        
        if name in self._detectors:
            return False
        
        # Create detector info
        info = DetectorInfo(
            name=name,
            version=temp_instance.version,
            description=temp_instance.description,
            categories=temp_instance.categories,
            detector_class=detector_class,
            is_enabled=enabled,
            priority=priority,
            metadata=metadata or {}
        )
        
        # Register detector
        self._detectors[name] = info
        
        # Update categories mapping
        for category in info.categories:
            if category not in self._categories_map:
                self._categories_map[category] = []
            self._categories_map[category].append(name)
        
        # Emit registration event
        self._emit_event("detector_registered", {
            "detector_name": name,
            "categories": [c.value for c in info.categories]
        })
        
        return True
    
    def unregister_detector(self, detector_name: str) -> bool:
        """
        Unregister a detector.
        
        Args:
            detector_name: Name of detector to unregister
            
        Returns:
            True if unregistered successfully, False if not found
        """
        if detector_name not in self._detectors:
            return False
        
        info = self._detectors[detector_name]
        
        # Remove from categories mapping
        for category in info.categories:
            if category in self._categories_map:
                self._categories_map[category] = [
                    name for name in self._categories_map[category] 
                    if name != detector_name
                ]
                if not self._categories_map[category]:
                    del self._categories_map[category]
        
        # Remove detector
        del self._detectors[detector_name]
        
        # Emit unregistration event
        self._emit_event("detector_unregistered", {
            "detector_name": detector_name
        })
        
        return True
    
    def get_detector_info(self, detector_name: str) -> Optional[DetectorInfo]:
        """Get information about a registered detector."""
        return self._detectors.get(detector_name)
    
    def list_detectors(
        self, 
        enabled_only: bool = False,
        category: Optional[IssueCategory] = None
    ) -> List[DetectorInfo]:
        """
        List registered detectors.
        
        Args:
            enabled_only: Only return enabled detectors
            category: Only return detectors for specific category
            
        Returns:
            List of detector information
        """
        detectors = list(self._detectors.values())
        
        if enabled_only:
            detectors = [d for d in detectors if d.is_enabled]
        
        if category:
            detectors = [d for d in detectors if category in d.categories]
        
        # Sort by priority (lower numbers first)
        detectors.sort(key=lambda d: d.priority)
        
        return detectors
    
    def get_detectors_for_category(self, category: IssueCategory) -> List[str]:
        """Get detector names that handle a specific category."""
        return self._categories_map.get(category, [])
    
    def enable_detector(self, detector_name: str) -> bool:
        """Enable a detector."""
        if detector_name not in self._detectors:
            return False
        
        self._detectors[detector_name].is_enabled = True
        self._emit_event("detector_enabled", {"detector_name": detector_name})
        return True
    
    def disable_detector(self, detector_name: str) -> bool:
        """Disable a detector."""
        if detector_name not in self._detectors:
            return False
        
        self._detectors[detector_name].is_enabled = False
        self._emit_event("detector_disabled", {"detector_name": detector_name})
        return True
    
    def create_detector(self, detector_name: str) -> Optional[IDetector]:
        """
        Create an instance of a registered detector.
        
        Args:
            detector_name: Name of detector to create
            
        Returns:
            Detector instance or None if not found/disabled
        """
        info = self._detectors.get(detector_name)
        if not info or not info.is_enabled:
            return None
        
        try:
            return info.detector_class(event_bus=self.event_bus)
        except Exception as e:
            self._emit_event("detector_creation_failed", {
                "detector_name": detector_name,
                "error": str(e)
            })
            return None
    
    async def run_detector(
        self,
        detector_name: str,
        context: DetectionContext
    ) -> Optional[DetectionResult]:
        """
        Run a specific detector.
        
        Args:
            detector_name: Name of detector to run
            context: Detection context
            
        Returns:
            Detection result or None if detector not available
        """
        detector = self.create_detector(detector_name)
        if not detector:
            return None
        
        try:
            # Validate context
            if not await detector.validate_context(context):
                return DetectionResult(
                    detector_name=detector.name,
                    detector_version=detector.version,
                    execution_time_ms=0,
                    issues_found=[],
                    detection_rules_applied=[],
                    statistics={},
                    errors=[{"error": "Invalid context for detector"}]
                )
            
            # Run detection
            self._emit_event("detector_started", {"detector_name": detector_name})
            result = await detector.detect(context)
            self._emit_event("detector_completed", {
                "detector_name": detector_name,
                "issues_found": len(result.issues_found)
            })
            
            return result
            
        except Exception as e:
            self._emit_event("detector_failed", {
                "detector_name": detector_name,
                "error": str(e)
            })
            
            return DetectionResult(
                detector_name=detector.name,
                detector_version=detector.version,
                execution_time_ms=0,
                issues_found=[],
                detection_rules_applied=[],
                statistics={},
                errors=[{"error": str(e)}]
            )
    
    async def run_detectors_for_category(
        self,
        category: IssueCategory,
        context: DetectionContext
    ) -> List[DetectionResult]:
        """
        Run all enabled detectors for a specific category.
        
        Args:
            category: Issue category to detect
            context: Detection context
            
        Returns:
            List of detection results
        """
        detector_names = self.get_detectors_for_category(category)
        results = []
        
        for detector_name in detector_names:
            if self._detectors[detector_name].is_enabled:
                result = await self.run_detector(detector_name, context)
                if result:
                    results.append(result)
        
        return results
    
    async def run_all_detectors(
        self,
        context: DetectionContext,
        enabled_only: bool = True
    ) -> List[DetectionResult]:
        """
        Run all detectors.
        
        Args:
            context: Detection context
            enabled_only: Only run enabled detectors
            
        Returns:
            List of detection results
        """
        detectors = self.list_detectors(enabled_only=enabled_only)
        results = []
        
        for detector_info in detectors:
            result = await self.run_detector(detector_info.name, context)
            if result:
                results.append(result)
        
        return results
    
    def get_registry_stats(self) -> Dict[str, Any]:
        """Get registry statistics."""
        enabled_count = len([d for d in self._detectors.values() if d.is_enabled])
        
        category_counts = {}
        for category, detector_names in self._categories_map.items():
            enabled_for_category = len([
                name for name in detector_names 
                if self._detectors[name].is_enabled
            ])
            category_counts[category.value] = {
                'total': len(detector_names),
                'enabled': enabled_for_category
            }
        
        return {
            'total_detectors': len(self._detectors),
            'enabled_detectors': enabled_count,
            'disabled_detectors': len(self._detectors) - enabled_count,
            'categories_covered': len(self._categories_map),
            'category_breakdown': category_counts
        }
    
    def _register_builtin_detectors(self) -> None:
        """Register built-in detectors."""
        # Import and register built-in detectors
        from .tls import TlsDetector
        from .proxy import ProxyDetector
        from .browser import BrowserDetector
        from .network import NetworkDetector
        
        self.register_detector(TlsDetector, priority=10)
        self.register_detector(ProxyDetector, priority=20)
        self.register_detector(BrowserDetector, priority=30)
        self.register_detector(NetworkDetector, priority=40)
    
    def _emit_event(self, event_type: str, data: Any = None) -> None:
        """Emit event if event bus is available."""
        if self.event_bus:
            # Create a task for the async emit to avoid unawaited coroutine warning
            import asyncio
            try:
                # Try to get the running loop (modern approach)
                try:
                    loop = asyncio.get_running_loop()
                    # If we're in an async context, create a task
                    asyncio.create_task(self.event_bus.emit(event_type, data))
                except RuntimeError:
                    # No running loop, try to create a new one
                    try:
                        asyncio.run(self.event_bus.emit(event_type, data))
                    except RuntimeError:
                        # Can't create event loop, skip event emission
                        pass
            except Exception:
                # Any other error, skip event emission
                pass


# Global registry instance
_global_registry: Optional[DetectorRegistry] = None


def get_global_registry() -> DetectorRegistry:
    """Get the global detector registry instance."""
    global _global_registry
    if _global_registry is None:
        _global_registry = DetectorRegistry()
    return _global_registry


def set_global_registry(registry: DetectorRegistry) -> None:
    """Set the global detector registry instance."""
    global _global_registry
    _global_registry = registry
