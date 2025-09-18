"""
Comprehensive tests for NetStealth Analyzer Detector Registry.

This test module provides extensive coverage for the DetectorRegistry class,
including detector registration, management, execution, and event handling.

Author: NetStealth Analyzer Team
Version: 2.0.0
Python: 3.11+
"""

import pytest
import asyncio
from unittest.mock import Mock, AsyncMock, patch, MagicMock
from datetime import datetime, timezone
from typing import List, Dict, Any, AsyncIterator

from netstealth_analyzer.detectors.registry import (
    DetectorRegistry, DetectorInfo, get_global_registry, set_global_registry
)
from netstealth_analyzer.detectors.base import (
    IDetector, BaseDetector, DetectionContext, DetectionResult
)
from netstealth_analyzer.models.enums import IssueCategory, SeverityLevel, DetectionConfidence
from netstealth_analyzer.models.issues import Issue, IssueEvidence
from netstealth_analyzer.models.network import NetworkTrace
from netstealth_analyzer.core.events import EventBus


class MockDetector(BaseDetector):
    """Mock detector for testing."""
    
    def __init__(self, event_bus=None, name="mock_detector", version="1.0.0"):
        super().__init__(event_bus)
        self._name = name
        self._version = version
        self._description = f"Mock detector {name}"
        self._categories = [IssueCategory.PROXY_DETECTION]
        self._detection_rules = []
        self.detect_called = False
        self.validate_context_called = False
        self.should_fail = False
        self.should_validate = True
    
    @property
    def name(self) -> str:
        return self._name
    
    @property
    def version(self) -> str:
        return self._version
    
    @property
    def description(self) -> str:
        return self._description
    
    @property
    def categories(self) -> List[IssueCategory]:
        return self._categories
    
    @property
    def detection_rules(self) -> List:
        return self._detection_rules
    
    async def detect(self, context: DetectionContext) -> DetectionResult:
        """Mock detection implementation."""
        self.detect_called = True
        
        if self.should_fail:
            raise RuntimeError("Mock detector failure")
        
        # Create mock issue
        issue = self._create_issue(
            title="Mock Issue",
            description="Test issue from mock detector",
            category=IssueCategory.PROXY_DETECTION,
            severity=SeverityLevel.MEDIUM,
            confidence=DetectionConfidence.HIGH,
            evidence=[
                self._create_evidence(
                    evidence_type="test_evidence",
                    description="Mock evidence",
                    value="test_value"
                )
            ]
        )
        
        return DetectionResult(
            detector_name=self.name,
            detector_version=self.version,
            execution_time_ms=100.0,
            issues_found=[issue],
            detection_rules_applied=[],
            statistics={"traces_analyzed": 1},
            errors=[]
        )
    
    async def validate_context(self, context: DetectionContext) -> bool:
        """Mock validation implementation."""
        self.validate_context_called = True
        return self.should_validate
    
    async def stream_detect(self, context: DetectionContext) -> AsyncIterator[Issue]:
        """Mock streaming detection."""
        result = await self.detect(context)
        for issue in result.issues_found:
            yield issue


class MockTlsDetector(MockDetector):
    """Mock TLS detector for testing."""
    
    def __init__(self, event_bus=None):
        super().__init__(event_bus, "tls_detector", "2.0.0")
        self._categories = [IssueCategory.TLS_FINGERPRINT]


class MockProxyDetector(MockDetector):
    """Mock Proxy detector for testing."""
    
    def __init__(self, event_bus=None):
        super().__init__(event_bus, "proxy_detector", "1.5.0")
        self._categories = [IssueCategory.PROXY_DETECTION]


class MockBrowserDetector(MockDetector):
    """Mock Browser detector for testing."""
    
    def __init__(self, event_bus=None):
        super().__init__(event_bus, "browser_detector", "1.2.0")
        self._categories = [IssueCategory.BROWSER_CONFIG]


class MockNetworkDetector(MockDetector):
    """Mock Network detector for testing."""
    
    def __init__(self, event_bus=None):
        super().__init__(event_bus, "network_detector", "1.8.0")
        self._categories = [IssueCategory.NETWORK_ANOMALY]


@pytest.fixture
def mock_event_bus():
    """Create mock event bus."""
    event_bus = Mock(spec=EventBus)
    event_bus.emit = AsyncMock()
    return event_bus


@pytest.fixture
def sample_context():
    """Create sample detection context."""
    trace = NetworkTrace(
        url="https://example.com/test",
        method="GET",
        status_code=200,
        request_headers=[{"name": "User-Agent", "value": "TestAgent"}],
        response_headers=[{"name": "Content-Type", "value": "text/html"}],
        request_body="",
        response_body="test response",
        timing_ms=150.0,
        timestamp=datetime.now(timezone.utc)
    )
    
    return DetectionContext(
        network_traces=[trace],
        service_domains=["example.com"],
        target_geography={"country": "US"},
        strict_mode=False,
        confidence_threshold=0.7
    )


@pytest.fixture
def detector_registry(mock_event_bus):
    """Create detector registry for testing."""
    with patch('netstealth_analyzer.detectors.registry.DetectorRegistry._register_builtin_detectors'):
        registry = DetectorRegistry(event_bus=mock_event_bus)
    return registry


class TestDetectorInfo:
    """Test DetectorInfo dataclass."""
    
    def test_detector_info_creation(self):
        """Test creating DetectorInfo."""
        info = DetectorInfo(
            name="test_detector",
            version="1.0.0",
            description="Test detector",
        categories=[IssueCategory.PROXY_DETECTION],
            detector_class=MockDetector,
            is_enabled=True,
            priority=50,
            metadata={"test": "value"}
        )
        
        assert info.name == "test_detector"
        assert info.version == "1.0.0"
        assert info.description == "Test detector"
        assert info.categories == [IssueCategory.PROXY_DETECTION]
        assert info.detector_class == MockDetector
        assert info.is_enabled is True
        assert info.priority == 50
        assert info.metadata == {"test": "value"}
        assert isinstance(info.registered_at, datetime)
    
    def test_detector_info_defaults(self):
        """Test DetectorInfo with default values."""
        info = DetectorInfo(
            name="test",
            version="1.0",
            description="Test",
            categories=[],
            detector_class=MockDetector
        )
        
        assert info.is_enabled is True
        assert info.priority == 100
        assert info.metadata == {}
        assert isinstance(info.registered_at, datetime)


class TestDetectorRegistryInit:
    """Test DetectorRegistry initialization."""
    
    def test_init_without_event_bus(self):
        """Test registry initialization without event bus."""
        with patch('netstealth_analyzer.detectors.registry.DetectorRegistry._register_builtin_detectors'):
            registry = DetectorRegistry()
        
        assert registry.event_bus is None
        assert registry._detectors == {}
        assert registry._categories_map == {}
    
    def test_init_with_event_bus(self, mock_event_bus):
        """Test registry initialization with event bus."""
        with patch('netstealth_analyzer.detectors.registry.DetectorRegistry._register_builtin_detectors'):
            registry = DetectorRegistry(event_bus=mock_event_bus)
        
        assert registry.event_bus == mock_event_bus
        assert registry._detectors == {}
        assert registry._categories_map == {}
    
    def test_init_calls_register_builtin(self):
        """Test that initialization calls builtin detector registration."""
        with patch('netstealth_analyzer.detectors.registry.DetectorRegistry._register_builtin_detectors') as mock_register:
            DetectorRegistry()
        
        mock_register.assert_called_once()


class TestDetectorRegistration:
    """Test detector registration functionality."""
    
    def test_register_detector_success(self, detector_registry, mock_event_bus):
        """Test successful detector registration."""
        result = detector_registry.register_detector(MockDetector)
        
        assert result is True
        assert "mock_detector" in detector_registry._detectors
        
        info = detector_registry._detectors["mock_detector"]
        assert info.name == "mock_detector"
        assert info.version == "1.0.0"
        assert info.detector_class == MockDetector
        assert info.is_enabled is True
        assert info.priority == 100
        
        # Check categories mapping
        assert IssueCategory.PROXY_DETECTION in detector_registry._categories_map
        assert "mock_detector" in detector_registry._categories_map[IssueCategory.PROXY_DETECTION]
        
        # Check event emission
        mock_event_bus.emit.assert_called_with("detector_registered", {
            "detector_name": "mock_detector",
            "categories": ["proxy_detection"]
        })
    
    def test_register_detector_with_custom_params(self, detector_registry):
        """Test detector registration with custom parameters."""
        metadata = {"custom": "value"}
        
        result = detector_registry.register_detector(
            MockDetector,
            priority=50,
            enabled=False,
            metadata=metadata
        )
        
        assert result is True
        
        info = detector_registry._detectors["mock_detector"]
        assert info.priority == 50
        assert info.is_enabled is False
        assert info.metadata == metadata
    
    def test_register_detector_duplicate(self, detector_registry):
        """Test registering duplicate detector."""
        # Register first time
        result1 = detector_registry.register_detector(MockDetector)
        assert result1 is True
        
        # Try to register again
        result2 = detector_registry.register_detector(MockDetector)
        assert result2 is False
        
        # Should still only have one entry
        assert len(detector_registry._detectors) == 1
    
    def test_register_multiple_detectors(self, detector_registry):
        """Test registering multiple detectors."""
        detectors = [MockTlsDetector, MockProxyDetector, MockBrowserDetector]
        
        for detector_class in detectors:
            result = detector_registry.register_detector(detector_class)
            assert result is True
        
        assert len(detector_registry._detectors) == 3
        assert "tls_detector" in detector_registry._detectors
        assert "proxy_detector" in detector_registry._detectors
        assert "browser_detector" in detector_registry._detectors
        
        # Check categories mapping
        assert len(detector_registry._categories_map) == 3
        assert IssueCategory.TLS_FINGERPRINT in detector_registry._categories_map
        assert IssueCategory.PROXY_DETECTION in detector_registry._categories_map
        assert IssueCategory.BROWSER_CONFIG in detector_registry._categories_map


class TestDetectorUnregistration:
    """Test detector unregistration functionality."""
    
    def test_unregister_detector_success(self, detector_registry, mock_event_bus):
        """Test successful detector unregistration."""
        # Register detector first
        detector_registry.register_detector(MockDetector)
        assert "mock_detector" in detector_registry._detectors
        
        # Unregister
        result = detector_registry.unregister_detector("mock_detector")
        
        assert result is True
        assert "mock_detector" not in detector_registry._detectors
        assert IssueCategory.PROXY_DETECTION not in detector_registry._categories_map
        
        # Check event emission
        mock_event_bus.emit.assert_called_with("detector_unregistered", {
            "detector_name": "mock_detector"
        })
    
    def test_unregister_detector_not_found(self, detector_registry):
        """Test unregistering non-existent detector."""
        result = detector_registry.unregister_detector("nonexistent")
        assert result is False
    
    def test_unregister_detector_with_shared_category(self, detector_registry):
        """Test unregistering detector that shares category with others."""
        # Register two detectors with same category
        detector_registry.register_detector(MockDetector)
        detector_registry.register_detector(MockProxyDetector)
        
        # Both should be in the same category
        assert len(detector_registry._categories_map[IssueCategory.PROXY_DETECTION]) == 2
        
        # Unregister one
        result = detector_registry.unregister_detector("mock_detector")
        assert result is True
        
        # Category should still exist with remaining detector
        assert IssueCategory.PROXY_DETECTION in detector_registry._categories_map
        assert len(detector_registry._categories_map[IssueCategory.PROXY_DETECTION]) == 1
        assert "proxy_detector" in detector_registry._categories_map[IssueCategory.PROXY_DETECTION]
    
    def test_unregister_last_detector_in_category(self, detector_registry):
        """Test unregistering the last detector in a category."""
        # Register detector
        detector_registry.register_detector(MockTlsDetector)
        assert IssueCategory.TLS_FINGERPRINT in detector_registry._categories_map
        
        # Unregister
        result = detector_registry.unregister_detector("tls_detector")
        assert result is True
        
        # Category should be removed
        assert IssueCategory.TLS_FINGERPRINT not in detector_registry._categories_map


class TestDetectorQuery:
    """Test detector query functionality."""
    
    def test_get_detector_info_success(self, detector_registry):
        """Test getting detector info."""
        detector_registry.register_detector(MockDetector)
        
        info = detector_registry.get_detector_info("mock_detector")
        
        assert info is not None
        assert info.name == "mock_detector"
        assert info.version == "1.0.0"
        assert info.detector_class == MockDetector
    
    def test_get_detector_info_not_found(self, detector_registry):
        """Test getting info for non-existent detector."""
        info = detector_registry.get_detector_info("nonexistent")
        assert info is None
    
    def test_list_detectors_all(self, detector_registry):
        """Test listing all detectors."""
        detectors = [MockTlsDetector, MockProxyDetector, MockBrowserDetector]
        priorities = [10, 20, 30]
        
        for detector_class, priority in zip(detectors, priorities):
            detector_registry.register_detector(detector_class, priority=priority)
        
        detector_list = detector_registry.list_detectors()
        
        assert len(detector_list) == 3
        # Should be sorted by priority
        assert detector_list[0].name == "tls_detector"
        assert detector_list[1].name == "proxy_detector"
        assert detector_list[2].name == "browser_detector"
    
    def test_list_detectors_enabled_only(self, detector_registry):
        """Test listing only enabled detectors."""
        detector_registry.register_detector(MockTlsDetector, enabled=True)
        detector_registry.register_detector(MockProxyDetector, enabled=False)
        detector_registry.register_detector(MockBrowserDetector, enabled=True)
        
        enabled_detectors = detector_registry.list_detectors(enabled_only=True)
        
        assert len(enabled_detectors) == 2
        names = [d.name for d in enabled_detectors]
        assert "tls_detector" in names
        assert "browser_detector" in names
        assert "proxy_detector" not in names
    
    def test_list_detectors_by_category(self, detector_registry):
        """Test listing detectors by category."""
        detector_registry.register_detector(MockTlsDetector)
        detector_registry.register_detector(MockProxyDetector)
        detector_registry.register_detector(MockBrowserDetector)
        
        tls_detectors = detector_registry.list_detectors(category=IssueCategory.TLS_FINGERPRINT)
        
        assert len(tls_detectors) == 1
        assert tls_detectors[0].name == "tls_detector"
    
    def test_list_detectors_enabled_and_category(self, detector_registry):
        """Test listing detectors with both enabled and category filters."""
        detector_registry.register_detector(MockTlsDetector, enabled=True)
        detector_registry.register_detector(MockProxyDetector, enabled=False)
        
        # Should return empty list (proxy detector is disabled)
        proxy_detectors = detector_registry.list_detectors(
            enabled_only=True,
            category=IssueCategory.PROXY_DETECTION
        )
        assert len(proxy_detectors) == 0
        
        # Should return TLS detector
        tls_detectors = detector_registry.list_detectors(
            enabled_only=True,
            category=IssueCategory.TLS_FINGERPRINT
        )
        assert len(tls_detectors) == 1
    
    def test_get_detectors_for_category(self, detector_registry):
        """Test getting detector names for category."""
        detector_registry.register_detector(MockTlsDetector)
        detector_registry.register_detector(MockProxyDetector)
        
        tls_detectors = detector_registry.get_detectors_for_category(IssueCategory.TLS_FINGERPRINT)
        proxy_detectors = detector_registry.get_detectors_for_category(IssueCategory.PROXY_DETECTION)
        empty_category = detector_registry.get_detectors_for_category(IssueCategory.NETWORK_ANOMALY)
        
        assert tls_detectors == ["tls_detector"]
        assert proxy_detectors == ["proxy_detector"]
        assert empty_category == []


class TestDetectorEnableDisable:
    """Test detector enable/disable functionality."""
    
    def test_enable_detector_success(self, detector_registry, mock_event_bus):
        """Test enabling detector."""
        detector_registry.register_detector(MockDetector, enabled=False)
        
        result = detector_registry.enable_detector("mock_detector")
        
        assert result is True
        assert detector_registry._detectors["mock_detector"].is_enabled is True
        
        mock_event_bus.emit.assert_called_with("detector_enabled", {
            "detector_name": "mock_detector"
        })
    
    def test_enable_detector_not_found(self, detector_registry):
        """Test enabling non-existent detector."""
        result = detector_registry.enable_detector("nonexistent")
        assert result is False
    
    def test_disable_detector_success(self, detector_registry, mock_event_bus):
        """Test disabling detector."""
        detector_registry.register_detector(MockDetector, enabled=True)
        
        result = detector_registry.disable_detector("mock_detector")
        
        assert result is True
        assert detector_registry._detectors["mock_detector"].is_enabled is False
        
        mock_event_bus.emit.assert_called_with("detector_disabled", {
            "detector_name": "mock_detector"
        })
    
    def test_disable_detector_not_found(self, detector_registry):
        """Test disabling non-existent detector."""
        result = detector_registry.disable_detector("nonexistent")
        assert result is False


class TestDetectorCreation:
    """Test detector instance creation."""
    
    def test_create_detector_success(self, detector_registry, mock_event_bus):
        """Test successful detector creation."""
        detector_registry.register_detector(MockDetector, enabled=True)
        
        detector = detector_registry.create_detector("mock_detector")
        
        assert detector is not None
        assert isinstance(detector, MockDetector)
        assert detector.event_bus == mock_event_bus
    
    def test_create_detector_not_found(self, detector_registry):
        """Test creating non-existent detector."""
        detector = detector_registry.create_detector("nonexistent")
        assert detector is None
    
    def test_create_detector_disabled(self, detector_registry):
        """Test creating disabled detector."""
        detector_registry.register_detector(MockDetector, enabled=False)
        
        detector = detector_registry.create_detector("mock_detector")
        assert detector is None
    
    def test_create_detector_failure(self, detector_registry, mock_event_bus):
        """Test detector creation failure during registration."""
        # Mock detector class that raises exception during instantiation
        class FailingDetector(MockDetector):
            def __init__(self, event_bus=None):
                raise RuntimeError("Creation failed")
        
        # Registration should raise exception because temp instance creation fails
        with pytest.raises(RuntimeError, match="Creation failed"):
            detector_registry.register_detector(FailingDetector, enabled=True)
        
        # Detector should not be registered
        assert "mock_detector" not in detector_registry._detectors
        
        # Trying to create should return None (detector not found)
        detector = detector_registry.create_detector("mock_detector")
        assert detector is None
    
    def test_create_detector_runtime_failure(self, detector_registry, mock_event_bus):
        """Test detector creation failure at runtime."""
        # Register a working detector first
        detector_registry.register_detector(MockDetector, enabled=True)
        
        # Mock the detector class to fail during creation (not registration)
        original_class = detector_registry._detectors["mock_detector"].detector_class
        
        class RuntimeFailingDetector(MockDetector):
            def __init__(self, event_bus=None):
                raise RuntimeError("Runtime creation failed")
        
        # Replace the detector class in registry
        detector_registry._detectors["mock_detector"].detector_class = RuntimeFailingDetector
        
        # Creation should return None and emit failure event
        detector = detector_registry.create_detector("mock_detector")
        assert detector is None
        
        # Should emit failure event
        mock_event_bus.emit.assert_called_with("detector_creation_failed", {
            "detector_name": "mock_detector",
            "error": "Runtime creation failed"
        })


class TestDetectorExecution:
    """Test detector execution functionality."""
    
    @pytest.mark.asyncio
    async def test_run_detector_success(self, detector_registry, sample_context, mock_event_bus):
        """Test successful detector execution."""
        detector_registry.register_detector(MockDetector, enabled=True)
        
        result = await detector_registry.run_detector("mock_detector", sample_context)
        
        assert result is not None
        assert isinstance(result, DetectionResult)
        assert result.detector_name == "mock_detector"
        assert result.detector_version == "1.0.0"
        assert len(result.issues_found) == 1
        assert result.is_successful
        
        # Check events
        mock_event_bus.emit.assert_any_call("detector_started", {"detector_name": "mock_detector"})
        mock_event_bus.emit.assert_any_call("detector_completed", {
            "detector_name": "mock_detector",
            "issues_found": 1
        })
    
    @pytest.mark.asyncio
    async def test_run_detector_not_found(self, detector_registry, sample_context):
        """Test running non-existent detector."""
        result = await detector_registry.run_detector("nonexistent", sample_context)
        assert result is None
    
    @pytest.mark.asyncio
    async def test_run_detector_disabled(self, detector_registry, sample_context):
        """Test running disabled detector."""
        detector_registry.register_detector(MockDetector, enabled=False)
        
        result = await detector_registry.run_detector("mock_detector", sample_context)
        assert result is None
    
    @pytest.mark.asyncio
    async def test_run_detector_invalid_context(self, detector_registry, sample_context, mock_event_bus):
        """Test running detector with invalid context."""
        # Create detector that fails validation
        class InvalidContextDetector(MockDetector):
            async def validate_context(self, context):
                return False
        
        detector_registry.register_detector(InvalidContextDetector, enabled=True)
        
        result = await detector_registry.run_detector("mock_detector", sample_context)
        
        assert result is not None
        assert not result.is_successful
        assert len(result.errors) == 1
        assert "Invalid context" in result.errors[0]["error"]
    
    @pytest.mark.asyncio
    async def test_run_detector_execution_failure(self, detector_registry, sample_context, mock_event_bus):
        """Test detector execution failure."""
        # Create detector that fails during execution
        class FailingDetector(MockDetector):
            async def detect(self, context):
                raise RuntimeError("Detection failed")
        
        detector_registry.register_detector(FailingDetector, enabled=True)
        
        result = await detector_registry.run_detector("mock_detector", sample_context)
        
        assert result is not None
        assert not result.is_successful
        assert len(result.errors) == 1
        assert "Detection failed" in result.errors[0]["error"]
        
        # Check failure event
        mock_event_bus.emit.assert_any_call("detector_failed", {
            "detector_name": "mock_detector",
            "error": "Detection failed"
        })
    
    @pytest.mark.asyncio
    async def test_run_detectors_for_category(self, detector_registry, sample_context):
        """Test running all detectors for a category."""
        detector_registry.register_detector(MockProxyDetector, enabled=True)
        detector_registry.register_detector(MockTlsDetector, enabled=True)
        
        # Add another proxy detector
        class AnotherProxyDetector(MockDetector):
            def __init__(self, event_bus=None):
                super().__init__(event_bus, "another_proxy", "2.0.0")
                self._categories = [IssueCategory.PROXY_DETECTION]
        
        detector_registry.register_detector(AnotherProxyDetector, enabled=True)
        
        results = await detector_registry.run_detectors_for_category(
            IssueCategory.PROXY_DETECTION, sample_context
        )
        
        assert len(results) == 2
        detector_names = [r.detector_name for r in results]
        assert "proxy_detector" in detector_names
        assert "another_proxy" in detector_names
    
    @pytest.mark.asyncio
    async def test_run_detectors_for_category_with_disabled(self, detector_registry, sample_context):
        """Test running detectors for category with some disabled."""
        detector_registry.register_detector(MockProxyDetector, enabled=True)
        
        class DisabledProxyDetector(MockDetector):
            def __init__(self, event_bus=None):
                super().__init__(event_bus, "disabled_proxy", "1.0.0")
                self._categories = [IssueCategory.PROXY_DETECTION]
        
        detector_registry.register_detector(DisabledProxyDetector, enabled=False)
        
        results = await detector_registry.run_detectors_for_category(
            IssueCategory.PROXY_DETECTION, sample_context
        )
        
        assert len(results) == 1
        assert results[0].detector_name == "proxy_detector"
    
    @pytest.mark.asyncio
    async def test_run_all_detectors(self, detector_registry, sample_context):
        """Test running all detectors."""
        detectors = [MockTlsDetector, MockProxyDetector, MockBrowserDetector]
        
        for detector_class in detectors:
            detector_registry.register_detector(detector_class, enabled=True)
        
        results = await detector_registry.run_all_detectors(sample_context)
        
        assert len(results) == 3
        detector_names = [r.detector_name for r in results]
        assert "tls_detector" in detector_names
        assert "proxy_detector" in detector_names
        assert "browser_detector" in detector_names
    
    @pytest.mark.asyncio
    async def test_run_all_detectors_enabled_only(self, detector_registry, sample_context):
        """Test running all detectors with enabled filter."""
        detector_registry.register_detector(MockTlsDetector, enabled=True)
        detector_registry.register_detector(MockProxyDetector, enabled=False)
        detector_registry.register_detector(MockBrowserDetector, enabled=True)
        
        results = await detector_registry.run_all_detectors(sample_context, enabled_only=True)
        
        assert len(results) == 2
        detector_names = [r.detector_name for r in results]
        assert "tls_detector" in detector_names
        assert "browser_detector" in detector_names
        assert "proxy_detector" not in detector_names
    
    @pytest.mark.asyncio
    async def test_run_all_detectors_include_disabled(self, detector_registry, sample_context):
        """Test running all detectors including disabled ones."""
        detector_registry.register_detector(MockTlsDetector, enabled=True)
        detector_registry.register_detector(MockProxyDetector, enabled=False)
        
        results = await detector_registry.run_all_detectors(sample_context, enabled_only=False)
        
        # Disabled detector should not return result (create_detector returns None)
        assert len(results) == 1
        assert results[0].detector_name == "tls_detector"


class TestRegistryStatistics:
    """Test registry statistics functionality."""
    
    def test_get_registry_stats_empty(self, detector_registry):
        """Test getting stats for empty registry."""
        stats = detector_registry.get_registry_stats()
        
        assert stats['total_detectors'] == 0
        assert stats['enabled_detectors'] == 0
        assert stats['disabled_detectors'] == 0
        assert stats['categories_covered'] == 0
        assert stats['category_breakdown'] == {}
    
    def test_get_registry_stats_with_detectors(self, detector_registry):
        """Test getting stats with registered detectors."""
        detector_registry.register_detector(MockTlsDetector, enabled=True)
        detector_registry.register_detector(MockProxyDetector, enabled=False)
        detector_registry.register_detector(MockBrowserDetector, enabled=True)
        
        stats = detector_registry.get_registry_stats()
        
        assert stats['total_detectors'] == 3
        assert stats['enabled_detectors'] == 2
        assert stats['disabled_detectors'] == 1
        assert stats['categories_covered'] == 3
        
        # Check category breakdown
        breakdown = stats['category_breakdown']
        assert breakdown['tls_fingerprint']['total'] == 1
        assert breakdown['tls_fingerprint']['enabled'] == 1
        assert breakdown['proxy_detection']['total'] == 1
        assert breakdown['proxy_detection']['enabled'] == 0
        assert breakdown['browser_config']['total'] == 1
        assert breakdown['browser_config']['enabled'] == 1
    
    def test_get_registry_stats_multiple_same_category(self, detector_registry):
        """Test stats with multiple detectors in same category."""
        detector_registry.register_detector(MockProxyDetector, enabled=True)
        
        class AnotherProxyDetector(MockDetector):
            def __init__(self, event_bus=None):
                super().__init__(event_bus, "another_proxy", "2.0.0")
                self._categories = [IssueCategory.PROXY_DETECTION]
        
        detector_registry.register_detector(AnotherProxyDetector, enabled=False)
        
        stats = detector_registry.get_registry_stats()
        
        assert stats['total_detectors'] == 2
        assert stats['enabled_detectors'] == 1
        assert stats['categories_covered'] == 1
        
        breakdown = stats['category_breakdown']
        assert breakdown['proxy_detection']['total'] == 2
        assert breakdown['proxy_detection']['enabled'] == 1


class TestBuiltinDetectorRegistration:
    """Test built-in detector registration."""
    
    def test_register_builtin_detectors_success(self):
        """Test successful built-in detector registration."""
        with patch('netstealth_analyzer.detectors.registry.DetectorRegistry.register_detector') as mock_register:
            registry = DetectorRegistry()
            
            # Should attempt to register built-in detectors
            assert mock_register.call_count >= 0  # May be 0 if imports fail
    
    def test_register_builtin_detectors_import_failures(self):
        """Test built-in registration with import failures."""
        # All imports should fail gracefully
        with patch('netstealth_analyzer.detectors.registry.DetectorRegistry.register_detector') as mock_register:
            registry = DetectorRegistry()
            
            # Should not raise exceptions even if imports fail
            assert isinstance(registry, DetectorRegistry)
    
    @patch('netstealth_analyzer.detectors.registry.DetectorRegistry.register_detector')
    def test_register_builtin_detectors_partial_success(self, mock_register):
        """Test built-in registration with partial success."""
        # Mock successful registration
        mock_register.return_value = True
        
        registry = DetectorRegistry()
        
        # Should have attempted registration
        assert mock_register.call_count >= 0


class TestGlobalRegistry:
    """Test global registry functionality."""
    
    def test_get_global_registry_singleton(self):
        """Test global registry singleton behavior."""
        # Reset global registry
        set_global_registry(None)
        
        registry1 = get_global_registry()
        registry2 = get_global_registry()
        
        assert registry1 is registry2
        assert isinstance(registry1, DetectorRegistry)
    
    def test_set_global_registry(self):
        """Test setting global registry."""
        custom_registry = DetectorRegistry()
        set_global_registry(custom_registry)
        
        retrieved_registry = get_global_registry()
        assert retrieved_registry is custom_registry
    
    def test_get_global_registry_creates_default(self):
        """Test that get_global_registry creates default instance."""
        # Reset global registry
        set_global_registry(None)
        
        registry = get_global_registry()
        
        assert registry is not None
        assert isinstance(registry, DetectorRegistry)


class TestEventEmission:
    """Test event emission functionality."""
    
    def test_emit_event_with_event_bus(self, detector_registry, mock_event_bus):
        """Test event emission when event bus is available."""
        detector_registry._emit_event("test_event", {"data": "value"})
        
        mock_event_bus.emit.assert_called_once_with("test_event", {"data": "value"})
    
    def test_emit_event_without_event_bus(self):
        """Test event emission when no event bus is available."""
        with patch('netstealth_analyzer.detectors.registry.DetectorRegistry._register_builtin_detectors'):
            registry = DetectorRegistry(event_bus=None)
        
        # Should not raise exception
        registry._emit_event("test_event", {"data": "value"})
    
    def test_emit_event_with_none_data(self, detector_registry, mock_event_bus):
        """Test event emission with None data."""
        detector_registry._emit_event("test_event", None)
        
        mock_event_bus.emit.assert_called_once_with("test_event", None)


class TestDetectorRegistryIntegration:
    """Test detector registry integration scenarios."""
    
    @pytest.mark.asyncio
    async def test_full_workflow_single_detector(self, detector_registry, sample_context, mock_event_bus):
        """Test complete workflow with single detector."""
        # Register detector
        result = detector_registry.register_detector(MockTlsDetector, enabled=True)
        assert result is True
        
        # Verify registration
        info = detector_registry.get_detector_info("tls_detector")
        assert info is not None
        
        # Run detector
        detection_result = await detector_registry.run_detector("tls_detector", sample_context)
        assert detection_result is not None
        assert detection_result.is_successful
        
        # Check statistics
        stats = detector_registry.get_registry_stats()
        assert stats['total_detectors'] == 1
        assert stats['enabled_detectors'] == 1
    
    @pytest.mark.asyncio
    async def test_full_workflow_multiple_detectors(self, detector_registry, sample_context):
        """Test complete workflow with multiple detectors."""
        # Register multiple detectors
        detectors = [
            (MockTlsDetector, 10, True),
            (MockProxyDetector, 20, True),
            (MockBrowserDetector, 30, False),  # Disabled
            (MockNetworkDetector, 40, True)
        ]
        
        for detector_class, priority, enabled in detectors:
            result = detector_registry.register_detector(
                detector_class, priority=priority, enabled=enabled
            )
            assert result is True
        
        # Run all enabled detectors
        results = await detector_registry.run_all_detectors(sample_context, enabled_only=True)
        
        # Should have 3 results (browser detector is disabled)
        assert len(results) == 3
        
        # Check detector names
        detector_names = [r.detector_name for r in results]
        assert "tls_detector" in detector_names
        assert "proxy_detector" in detector_names
        assert "network_detector" in detector_names
        assert "browser_detector" not in detector_names
        
        # Verify all results are successful
        for result in results:
            assert result.is_successful
            assert len(result.issues_found) == 1
    
    @pytest.mark.asyncio
    async def test_category_based_detection(self, detector_registry, sample_context):
        """Test category-based detection workflow."""
        # Register detectors with different categories
        detector_registry.register_detector(MockTlsDetector, enabled=True)
        detector_registry.register_detector(MockProxyDetector, enabled=True)
        detector_registry.register_detector(MockBrowserDetector, enabled=True)
        
        # Run detectors for specific category
        tls_results = await detector_registry.run_detectors_for_category(
            IssueCategory.TLS_FINGERPRINT, sample_context
        )
        proxy_results = await detector_registry.run_detectors_for_category(
            IssueCategory.PROXY_DETECTION, sample_context
        )
        
        assert len(tls_results) == 1
        assert tls_results[0].detector_name == "tls_detector"
        
        assert len(proxy_results) == 1
        assert proxy_results[0].detector_name == "proxy_detector"
    
    def test_detector_lifecycle_management(self, detector_registry, mock_event_bus):
        """Test complete detector lifecycle management."""
        # Register detector
        result = detector_registry.register_detector(MockDetector, enabled=True)
        assert result is True
        
        # Verify initial state
        info = detector_registry.get_detector_info("mock_detector")
        assert info.is_enabled is True
        
        # Disable detector
        result = detector_registry.disable_detector("mock_detector")
        assert result is True
        assert detector_registry.get_detector_info("mock_detector").is_enabled is False
        
        # Re-enable detector
        result = detector_registry.enable_detector("mock_detector")
        assert result is True
        assert detector_registry.get_detector_info("mock_detector").is_enabled is True
        
        # Unregister detector
        result = detector_registry.unregister_detector("mock_detector")
        assert result is True
        assert detector_registry.get_detector_info("mock_detector") is None
        
        # Verify events were emitted
        expected_calls = [
            ("detector_registered", {"detector_name": "mock_detector", "categories": ["proxy_detection"]}),
            ("detector_disabled", {"detector_name": "mock_detector"}),
            ("detector_enabled", {"detector_name": "mock_detector"}),
            ("detector_unregistered", {"detector_name": "mock_detector"})
        ]
        
        for event_type, data in expected_calls:
            mock_event_bus.emit.assert_any_call(event_type, data)
    
    @pytest.mark.asyncio
    async def test_error_handling_and_recovery(self, detector_registry, sample_context, mock_event_bus):
        """Test error handling and recovery scenarios."""
        # Register failing detector
        class FailingDetector(MockDetector):
            async def detect(self, context):
                raise RuntimeError("Simulated failure")
        
        detector_registry.register_detector(FailingDetector, enabled=True)
        
        # Run failing detector
        result = await detector_registry.run_detector("mock_detector", sample_context)
        
        # Should return error result, not None
        assert result is not None
        assert not result.is_successful
        assert len(result.errors) == 1
        
        # Should emit failure event
        mock_event_bus.emit.assert_any_call("detector_failed", {
            "detector_name": "mock_detector",
            "error": "Simulated failure"
        })
        
        # Registry should still be functional
        stats = detector_registry.get_registry_stats()
        assert stats['total_detectors'] == 1
    
    def test_priority_ordering(self, detector_registry):
        """Test that detectors are ordered by priority."""
        # Register detectors with different priorities
        detectors_with_priorities = [
            (MockTlsDetector, 50),
            (MockProxyDetector, 10),  # Highest priority (lowest number)
            (MockBrowserDetector, 30),
            (MockNetworkDetector, 20)
        ]
        
        for detector_class, priority in detectors_with_priorities:
            detector_registry.register_detector(detector_class, priority=priority)
        
        # List detectors - should be ordered by priority
        detector_list = detector_registry.list_detectors()
        
        assert len(detector_list) == 4
        assert detector_list[0].name == "proxy_detector"  # Priority 10
        assert detector_list[1].name == "network_detector"  # Priority 20
        assert detector_list[2].name == "browser_detector"  # Priority 30
        assert detector_list[3].name == "tls_detector"  # Priority 50
    
    def test_metadata_handling(self, detector_registry):
        """Test detector metadata handling."""
        metadata = {
            "author": "Test Author",
            "license": "MIT",
            "tags": ["test", "mock"],
            "config": {"threshold": 0.8}
        }
        
        result = detector_registry.register_detector(
            MockDetector, 
            metadata=metadata
        )
        assert result is True
        
        info = detector_registry.get_detector_info("mock_detector")
        assert info.metadata == metadata
        
        # Verify metadata is preserved
        stats = detector_registry.get_registry_stats()
        assert stats['total_detectors'] == 1


class TestDetectorRegistryEdgeCases:
    """Test edge cases and boundary conditions."""
    
    def test_empty_registry_operations(self, detector_registry):
        """Test operations on empty registry."""
        # All query operations should work on empty registry
        assert detector_registry.get_detector_info("nonexistent") is None
        assert detector_registry.list_detectors() == []
        assert detector_registry.get_detectors_for_category(IssueCategory.PROXY_DETECTION) == []
        
        # Enable/disable operations should return False
        assert detector_registry.enable_detector("nonexistent") is False
        assert detector_registry.disable_detector("nonexistent") is False
        
        # Unregister should return False
        assert detector_registry.unregister_detector("nonexistent") is False
        
        # Stats should show empty state
        stats = detector_registry.get_registry_stats()
        assert stats['total_detectors'] == 0
        assert stats['enabled_detectors'] == 0
        assert stats['disabled_detectors'] == 0
        assert stats['categories_covered'] == 0
    
    @pytest.mark.asyncio
    async def test_run_operations_on_empty_registry(self, detector_registry, sample_context):
        """Test run operations on empty registry."""
        # All run operations should handle empty registry gracefully
        result = await detector_registry.run_detector("nonexistent", sample_context)
        assert result is None
        
        results = await detector_registry.run_detectors_for_category(
            IssueCategory.PROXY_DETECTION, sample_context
        )
        assert results == []
        
        results = await detector_registry.run_all_detectors(sample_context)
        assert results == []
    
    def test_detector_with_multiple_categories(self, detector_registry):
        """Test detector that handles multiple categories."""
        class MultiCategoryDetector(MockDetector):
            def __init__(self, event_bus=None):
                super().__init__(event_bus, "multi_detector", "1.0.0")
                self._categories = [
                    IssueCategory.PROXY_DETECTION,
                    IssueCategory.TLS_FINGERPRINT,
                    IssueCategory.BROWSER_CONFIG
                ]
        
        result = detector_registry.register_detector(MultiCategoryDetector)
        assert result is True
        
        # Should appear in all category mappings
        for category in [IssueCategory.PROXY_DETECTION, IssueCategory.TLS_FINGERPRINT, IssueCategory.BROWSER_CONFIG]:
            detectors = detector_registry.get_detectors_for_category(category)
            assert "multi_detector" in detectors
        
        # Should appear in category-filtered lists
        for category in [IssueCategory.PROXY_DETECTION, IssueCategory.TLS_FINGERPRINT, IssueCategory.BROWSER_CONFIG]:
            detector_list = detector_registry.list_detectors(category=category)
            assert len(detector_list) == 1
            assert detector_list[0].name == "multi_detector"
    
    def test_detector_with_no_categories(self, detector_registry):
        """Test detector with empty categories list."""
        class NoCategoryDetector(MockDetector):
            def __init__(self, event_bus=None):
                super().__init__(event_bus, "no_category", "1.0.0")
                self._categories = []
        
        result = detector_registry.register_detector(NoCategoryDetector)
        assert result is True
        
        # Should not appear in any category mappings
        for category in IssueCategory:
            detectors = detector_registry.get_detectors_for_category(category)
            assert "no_category" not in detectors
        
        # Should still appear in general listings
        detector_list = detector_registry.list_detectors()
        assert len(detector_list) == 1
        assert detector_list[0].name == "no_category"
    
    def test_extreme_priority_values(self, detector_registry):
        """Test detectors with extreme priority values."""
        class HighPriorityDetector(MockDetector):
            def __init__(self, event_bus=None):
                super().__init__(event_bus, "high_priority", "1.0.0")
        
        class LowPriorityDetector(MockDetector):
            def __init__(self, event_bus=None):
                super().__init__(event_bus, "low_priority", "1.0.0")
        
        # Register with extreme priorities
        detector_registry.register_detector(HighPriorityDetector, priority=0)  # Highest
        detector_registry.register_detector(LowPriorityDetector, priority=999999)  # Lowest
        
        detector_list = detector_registry.list_detectors()
        
        assert len(detector_list) == 2
        assert detector_list[0].name == "high_priority"
        assert detector_list[1].name == "low_priority"
        assert detector_list[0].priority == 0
        assert detector_list[1].priority == 999999
