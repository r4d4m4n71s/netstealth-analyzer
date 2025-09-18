"""
Integration test configuration and fixtures for NetStealth Analyzer.

Provides shared fixtures and utilities for cross-component integration testing.
"""

import pytest
import asyncio
import tempfile
import shutil
from pathlib import Path
from typing import Dict, Any, List
from unittest.mock import Mock, AsyncMock

from src.netstealth_analyzer.config import ConfigurationManager
from src.netstealth_analyzer.core.events import EventBus
from src.netstealth_analyzer.core.errors import ErrorHandler, get_error_handler
from src.netstealth_analyzer.plugins.registry import PluginRegistry
from src.netstealth_analyzer.plugins.loader import PluginLoader
from src.netstealth_analyzer.plugins.sandbox import PluginSandbox
from src.netstealth_analyzer.models.network import NetworkTrace, HttpRequest, HttpResponse
from src.netstealth_analyzer.models.issues import Issue, IssueCategory, SeverityLevel
from src.netstealth_analyzer.models.results import AnalysisResult


@pytest.fixture(scope="session")
def event_loop():
    """Create an instance of the default event loop for the test session."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
async def event_bus():
    """Create a fresh EventBus for testing."""
    bus = EventBus()
    yield bus
    # EventBus doesn't need explicit shutdown in tests


@pytest.fixture
def error_handler():
    """Create a fresh ErrorHandler for testing."""
    handler = ErrorHandler()
    yield handler
    handler.clear_history()


@pytest.fixture
def config_manager():
    """Create a ConfigurationManager for testing."""
    return ConfigurationManager()


@pytest.fixture
async def plugin_registry():
    """Create a PluginRegistry for testing."""
    registry = PluginRegistry()
    yield registry
    await registry.cleanup_all_plugins()


@pytest.fixture
def plugin_sandbox():
    """Create a PluginSandbox for testing."""
    return PluginSandbox(
        max_memory_mb=50,  # Smaller limits for testing
        max_execution_time=5.0,
        max_cpu_time=2.0
    )


@pytest.fixture
def plugin_loader(plugin_registry):
    """Create a PluginLoader for testing."""
    return PluginLoader(plugin_registry)


@pytest.fixture
def temp_plugin_dir():
    """Create a temporary directory for plugin files."""
    temp_dir = tempfile.mkdtemp()
    yield Path(temp_dir)
    shutil.rmtree(temp_dir)


@pytest.fixture
def sample_network_trace():
    """Create a sample NetworkTrace for testing."""
    from src.netstealth_analyzer.models.network import NetworkHop
    from src.netstealth_analyzer.models.enums import RiskLevel
    from datetime import datetime, timezone
    
    # Create a simple network trace with one hop
    hop = NetworkHop(
        hop_number=1,
        actor="test-client",
        actor_name="Test Client",
        actor_category="client",
        incoming_ip="192.168.1.100",
        outgoing_ip="93.184.216.34",  # example.com IP
        risk_level=RiskLevel.SAFE,
        timestamp=datetime.now(timezone.utc)
    )
    
    trace = NetworkTrace(
        trace_id="test-trace-001",
        hops=[hop],
        total_hops=1,
        overall_risk_level=RiskLevel.SAFE
    )
    
    return trace


@pytest.fixture
def sample_issues():
    """Create sample issues for testing."""
    from src.netstealth_analyzer.models.issues import IssueEvidence
    
    return [
        Issue(
            id="issue-001",
            category=IssueCategory.FINGERPRINTING,
            severity=SeverityLevel.HIGH,
            title="User-Agent Fingerprinting",
            description="Unique user agent detected",
            confidence=0.8,
            impact_score=75,
            evidence=[
                IssueEvidence(
                    type="header",
                    description="Unique user agent detected",
                    raw_data={"user_agent": "test-client"},
                    confidence=0.8
                )
            ]
        ),
        Issue(
            id="issue-002",
            category=IssueCategory.TRACKING,
            severity=SeverityLevel.MEDIUM,
            title="Cookie Tracking",
            description="Tracking cookie detected",
            confidence=0.9,
            impact_score=50,
            evidence=[
                IssueEvidence(
                    type="cookie",
                    description="Tracking cookie detected",
                    raw_data={"cookie": "track_id=12345"},
                    confidence=0.9
                )
            ]
        )
    ]


@pytest.fixture
def sample_analysis_result(sample_network_trace, sample_issues):
    """Create a sample AnalysisResult for testing."""
    return AnalysisResult(
        traces=[sample_network_trace],
        issues=sample_issues,
        analysis_id="test-analysis-001",
        timestamp=1234567892.0
    )


@pytest.fixture
def integration_config():
    """Create a test configuration for integration tests."""
    return {
        "analysis": {
            "timeout": 30.0,
            "max_traces": 1000,
            "parallel_processing": True
        },
        "plugins": {
            "directory": "/tmp/test_plugins",
            "auto_load": True,
            "sandbox": {
                "enabled": True,
                "memory_limit_mb": 100,
                "execution_timeout": 10.0
            }
        },
        "reporting": {
            "format": "json",
            "include_evidence": True,
            "severity_filter": "medium"
        },
        "logging": {
            "level": "INFO",
            "file": "/tmp/netstealth_test.log"
        }
    }


@pytest.fixture
def mock_plugin_code():
    """Sample plugin code for testing."""
    return '''
from src.netstealth_analyzer.plugins.base import IPlugin, PluginMetadata, PluginType
from src.netstealth_analyzer.models.issues import Issue, IssueType, IssueSeverity

class IntegrationTestPlugin(IPlugin):
    def __init__(self, config=None):
        super().__init__(config)
        self._metadata = PluginMetadata(
            name="integration_test_plugin",
            version="1.0.0",
            plugin_type=PluginType.DETECTOR,
            description="Plugin for integration testing"
        )
    
    @property
    def metadata(self):
        return self._metadata
    
    async def detect(self, traces):
        """Detect test issues in network traces."""
        issues = []
        for trace in traces:
            # NetworkTrace has trace_id and hops, not request.url
            if "test" in trace.trace_id:
                issue = Issue(
                    id=f"test-issue-{trace.trace_id}",
                    type=IssueType.FINGERPRINTING,
                    severity=IssueSeverity.LOW,
                    title="Test Detection",
                    description="Test issue detected by integration plugin",
                    evidence={"trace_id": trace.trace_id},
                    source=self.name
                )
                issues.append(issue)
        return issues
'''


class IntegrationTestHelper:
    """Helper class for integration test utilities."""
    
    @staticmethod
    def create_plugin_file(directory: Path, filename: str, content: str) -> Path:
        """Create a plugin file in the specified directory."""
        plugin_path = directory / filename
        plugin_path.write_text(content)
        return plugin_path
    
    @staticmethod
    def create_config_file(directory: Path, config: Dict[str, Any]) -> Path:
        """Create a configuration file."""
        import json
        config_path = directory / "test_config.json"
        config_path.write_text(json.dumps(config, indent=2))
        return config_path
    
    @staticmethod
    async def wait_for_event(event_bus: EventBus, event_type: str, timeout: float = 5.0):
        """Wait for a specific event to be emitted."""
        received_event = None
        
        async def event_handler(event_data):
            nonlocal received_event
            received_event = event_data
        
        # Subscribe to event
        await event_bus.subscribe(event_type, event_handler)
        
        # Wait for event with timeout
        start_time = asyncio.get_event_loop().time()
        while received_event is None:
            await asyncio.sleep(0.01)
            if asyncio.get_event_loop().time() - start_time > timeout:
                break
        
        # Unsubscribe
        await event_bus.unsubscribe(event_type, event_handler)
        
        return received_event


@pytest.fixture
def integration_helper():
    """Provide integration test helper utilities."""
    return IntegrationTestHelper()
