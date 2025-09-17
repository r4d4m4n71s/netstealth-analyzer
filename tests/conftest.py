"""
Pytest configuration and shared fixtures for NetStealth Analyzer tests.

This module provides common test fixtures, configuration, and utilities
for testing the NetStealth Analyzer v2.0 with Python 3.13 compatibility.
"""

import asyncio
import pytest
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional
from datetime import datetime, timezone

from src.netstealth_analyzer.core.events import EventBus
from src.netstealth_analyzer.models.enums import SeverityLevel, IssueCategory, LogFormat
from src.netstealth_analyzer.models.issues import Issue, IssueEvidence
from src.netstealth_analyzer.models.network import NetworkTrace, HttpRequest, HttpResponse
from src.netstealth_analyzer.plugins.registry import PluginRegistry
from src.netstealth_analyzer.plugins.base import PluginMetadata, PluginType


@pytest.fixture(scope="session")
def event_loop():
    """Create an instance of the default event loop for the test session."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
def event_bus():
    """Create a fresh EventBus instance for testing."""
    return EventBus()


@pytest.fixture
def plugin_registry():
    """Create a fresh PluginRegistry instance for testing."""
    return PluginRegistry()


@pytest.fixture
def sample_issue():
    """Create a sample Issue for testing."""
    evidence = IssueEvidence(
        type="header",
        description="Proxy header detected",
        raw_data="X-Forwarded-For: 192.168.1.1",
        confidence=0.9,
        metadata={"header_name": "X-Forwarded-For"}
    )
    
    return Issue(
        title="Proxy Detection Issue",
        description="Test issue for proxy detection",
        category=IssueCategory.PROXY_DETECTION,
        severity=SeverityLevel.HIGH,
        confidence=0.85,
        impact_score=75,
        evidence=[evidence]
    )


@pytest.fixture
def sample_network_trace():
    """Create a sample NetworkTrace for testing."""
    request = HttpRequest(
        method="GET",
        url="https://example.com/api/test",
        headers=[
            {"name": "User-Agent", "value": "Mozilla/5.0"},
            {"name": "X-Forwarded-For", "value": "192.168.1.1"}
        ],
        body="",
        timestamp=datetime.now(timezone.utc)
    )
    
    response = HttpResponse(
        status_code=200,
        status_text="OK",
        headers=[
            {"name": "Content-Type", "value": "application/json"},
            {"name": "Server", "value": "nginx/1.18.0"}
        ],
        body='{"status": "success"}',
        timestamp=datetime.now(timezone.utc)
    )
    
    return NetworkTrace(
        id="trace-001",
        request=request,
        response=response,
        source_file="test.har",
        metadata={"test": True}
    )


@pytest.fixture
def sample_plugin_metadata():
    """Create sample plugin metadata for testing."""
    return PluginMetadata(
        name="test_plugin",
        version="1.0.0",
        plugin_type=PluginType.DETECTOR,
        description="Test plugin for unit testing",
        author="Test Author",
        supported_categories=["proxy_leak", "tls_fingerprint"],
        config_schema={
            "threshold": {"type": float, "required": False, "default": 0.7},
            "enabled": {"type": bool, "required": False, "default": True}
        },
        default_config={"threshold": 0.7, "enabled": True}
    )


@pytest.fixture
def temp_directory():
    """Create a temporary directory for testing."""
    with tempfile.TemporaryDirectory() as temp_dir:
        yield Path(temp_dir)


@pytest.fixture
def sample_har_content():
    """Sample HAR file content for testing."""
    return '''
    {
        "log": {
            "version": "1.2",
            "creator": {
                "name": "Test Creator",
                "version": "1.0"
            },
            "entries": [
                {
                    "startedDateTime": "2023-01-01T00:00:00.000Z",
                    "request": {
                        "method": "GET",
                        "url": "https://example.com/test",
                        "headers": [
                            {"name": "User-Agent", "value": "Mozilla/5.0"},
                            {"name": "X-Forwarded-For", "value": "192.168.1.1"}
                        ],
                        "postData": {"text": ""}
                    },
                    "response": {
                        "status": 200,
                        "statusText": "OK",
                        "headers": [
                            {"name": "Content-Type", "value": "application/json"}
                        ],
                        "content": {"text": "{\\"status\\": \\"success\\"}"}
                    }
                }
            ]
        }
    }
    '''


@pytest.fixture
def sample_mitmproxy_content():
    """Sample mitmproxy log content for testing."""
    return '''
    [
        {
            "version": [8, 1, 1],
            "request": {
                "method": "GET",
                "scheme": "https",
                "host": "example.com",
                "port": 443,
                "path": "/test",
                "headers": [
                    ["user-agent", "Mozilla/5.0"],
                    ["x-forwarded-for", "192.168.1.1"]
                ],
                "content": ""
            },
            "response": {
                "status_code": 200,
                "reason": "OK",
                "headers": [
                    ["content-type", "application/json"]
                ],
                "content": "{\\"status\\": \\"success\\"}"
            }
        }
    ]
    '''


@pytest.fixture
async def sample_log_files(temp_directory, sample_har_content, sample_mitmproxy_content):
    """Create sample log files for testing."""
    har_file = temp_directory / "test.har"
    mitmproxy_file = temp_directory / "test.mitm"
    
    har_file.write_text(sample_har_content)
    mitmproxy_file.write_text(sample_mitmproxy_content)
    
    return {
        "har": har_file,
        "mitmproxy": mitmproxy_file
    }


@pytest.fixture
def mock_detection_context():
    """Create a mock detection context for testing."""
    from src.netstealth_analyzer.detectors.base import DetectionContext
    
    return DetectionContext(
        traces=[],
        service_domains=["example.com"],
        target_geography="US",
        configuration={"threshold": 0.7}
    )


# Async test utilities
def pytest_configure(config):
    """Configure pytest for async testing."""
    config.addinivalue_line(
        "markers", "asyncio: mark test as async"
    )


# Custom assertions for testing
def assert_issue_valid(issue: Issue):
    """Assert that an issue is valid."""
    assert issue.id is not None
    assert issue.title is not None
    assert issue.description is not None
    assert isinstance(issue.category, IssueCategory)
    assert isinstance(issue.severity, SeverityLevel)
    assert 0.0 <= issue.confidence <= 1.0
    assert isinstance(issue.evidence, list)
    assert isinstance(issue.remediation_suggestions, list)


def assert_network_trace_valid(trace: NetworkTrace):
    """Assert that a network trace is valid."""
    assert trace.id is not None
    assert trace.request is not None
    assert trace.request.method is not None
    assert trace.request.url is not None
    assert isinstance(trace.request.headers, list)
    assert trace.source_file is not None


# Test data generators
def generate_test_issues(count: int = 5) -> List[Issue]:
    """Generate a list of test issues."""
    issues = []
    categories = list(IssueCategory)
    severities = list(SeverityLevel)
    
    for i in range(count):
        evidence = IssueEvidence(
            type="test",
            description=f"Test evidence {i}",
            raw_data=f"test_data_{i}",
            confidence=0.8,
            metadata={"index": i}
        )
        
        issue = Issue(
            title=f"Test Issue {i}",
            description=f"Test issue description {i}",
            category=categories[i % len(categories)],
            severity=severities[i % len(severities)],
            confidence=0.5 + (i * 0.1) % 0.5,
            impact_score=50 + (i * 10) % 50,
            evidence=[evidence]
        )
        issues.append(issue)
    
    return issues


def generate_test_traces(count: int = 3) -> List[NetworkTrace]:
    """Generate a list of test network traces."""
    traces = []
    
    for i in range(count):
        request = HttpRequest(
            method="GET" if i % 2 == 0 else "POST",
            url=f"https://example{i}.com/api/test",
            headers=[
                {"name": "User-Agent", "value": f"TestAgent/{i}"},
                {"name": "X-Test-Header", "value": f"test-value-{i}"}
            ],
            body=f"test body {i}" if i % 2 == 1 else "",
            timestamp=datetime.now(timezone.utc)
        )
        
        response = HttpResponse(
            status_code=200 if i % 3 != 2 else 404,
            status_text="OK" if i % 3 != 2 else "Not Found",
            headers=[
                {"name": "Content-Type", "value": "application/json"},
                {"name": "X-Response-Id", "value": f"resp-{i}"}
            ],
            body=f'{{"id": {i}, "status": "success"}}',
            timestamp=datetime.now(timezone.utc)
        )
        
        trace = NetworkTrace(
            id=f"trace-{i:03d}",
            request=request,
            response=response,
            source_file=f"test{i}.har",
            metadata={"test_index": i}
        )
        traces.append(trace)
    
    return traces
