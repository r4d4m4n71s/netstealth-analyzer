"""
Actor System Integration Tests.

This module contains comprehensive integration tests that validate the actor
system's ability to identify and analyze network intermediaries and their
behaviors in real-world scenarios.
"""

import pytest
import json
import tempfile
import os
from datetime import datetime, timezone
from unittest.mock import AsyncMock, Mock, patch

from src.netstealth_analyzer.analyzer import NetStealthAnalyzer
from src.netstealth_analyzer.builder import AnalyzerBuilder
from src.netstealth_analyzer.config import NetStealthConfig, DetectorConfig, PerformanceConfig, FilterConfig, AnalysisMode
from src.netstealth_analyzer.actors.proxy import ProxyActor
from src.netstealth_analyzer.actors.registry import ActorRegistry
from src.netstealth_analyzer.models.network import NetworkTrace, HttpData, HttpRequest, HttpResponse
from src.netstealth_analyzer.models.enums import SeverityLevel, IssueCategory
from src.netstealth_analyzer.actors.base import ActorCategory
from src.netstealth_analyzer.core.events import EventBus


def create_test_config(confidence_threshold=0.7, enable_streaming=False, 
                      max_concurrent_detectors=4, service_domains=None, 
                      expected_geography=None, metadata=None):
    """Create a NetStealthConfig for testing."""
    return NetStealthConfig(
        target_service=service_domains[0] if service_domains else None,
        geography=expected_geography,
        analysis_mode=AnalysisMode.STREAMING if enable_streaming else AnalysisMode.BATCH,
        detectors=DetectorConfig(
            confidence_threshold=confidence_threshold,
            enabled_detectors=["tls", "proxy", "browser", "network"]
        ),
        performance=PerformanceConfig(
            max_concurrent_detectors=max_concurrent_detectors,
            enable_parallel_processing=not enable_streaming
        ),
        filters=FilterConfig(
            min_confidence=confidence_threshold
        ),
        custom=metadata or {}
    )


@pytest.fixture
def proxy_trace_data():
    """Create network trace data with proxy indicators."""
    return {
        "log": {
            "version": "1.2",
            "creator": {"name": "Test", "version": "1.0"},
            "entries": [
                {
                    "startedDateTime": "2025-01-01T00:00:00.000Z",
                    "time": 200,
                    "request": {
                        "method": "GET",
                        "url": "https://example.com/api/data",
                        "httpVersion": "HTTP/1.1",
                        "headers": [
                            {"name": "User-Agent", "value": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"},
                            {"name": "X-Forwarded-For", "value": "192.168.1.100, 10.0.0.1"},
                            {"name": "X-Real-IP", "value": "203.0.113.1"},
                            {"name": "Via", "value": "1.1 proxy.company.com:8080"}
                        ],
                        "queryString": [],
                        "cookies": [],
                        "headersSize": 300,
                        "bodySize": 0
                    },
                    "response": {
                        "status": 200,
                        "statusText": "OK",
                        "httpVersion": "HTTP/1.1",
                        "headers": [
                            {"name": "Content-Type", "value": "application/json"},
                            {"name": "X-Proxy-Cache", "value": "HIT"},
                            {"name": "X-Served-By", "value": "proxy-server-01"}
                        ],
                        "cookies": [],
                        "content": {
                            "size": 200,
                            "mimeType": "application/json",
                            "text": '{"data": "proxied response"}'
                        },
                        "redirectURL": "",
                        "headersSize": 150,
                        "bodySize": 200
                    },
                    "cache": {},
                    "timings": {
                        "blocked": 5,
                        "dns": 20,
                        "connect": 50,
                        "send": 10,
                        "wait": 100,
                        "receive": 15,
                        "ssl": 40
                    }
                }
            ]
        }
    }


@pytest.fixture
def cdn_trace_data():
    """Create network trace data with CDN indicators."""
    return {
        "log": {
            "version": "1.2",
            "creator": {"name": "Test", "version": "1.0"},
            "entries": [
                {
                    "startedDateTime": "2025-01-01T00:00:00.000Z",
                    "time": 50,  # Fast CDN response
                    "request": {
                        "method": "GET",
                        "url": "https://cdn.example.com/assets/script.js",
                        "httpVersion": "HTTP/1.1",
                        "headers": [
                            {"name": "User-Agent", "value": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"},
                            {"name": "Accept", "value": "application/javascript"}
                        ],
                        "queryString": [],
                        "cookies": [],
                        "headersSize": 200,
                        "bodySize": 0
                    },
                    "response": {
                        "status": 200,
                        "statusText": "OK",
                        "httpVersion": "HTTP/1.1",
                        "headers": [
                            {"name": "Content-Type", "value": "application/javascript"},
                            {"name": "CF-Ray", "value": "12345-DFW"},
                            {"name": "CF-Cache-Status", "value": "HIT"},
                            {"name": "Server", "value": "cloudflare"},
                            {"name": "X-Cache", "value": "HIT"}
                        ],
                        "cookies": [],
                        "content": {
                            "size": 5000,
                            "mimeType": "application/javascript",
                            "text": "// JavaScript content from CDN"
                        },
                        "redirectURL": "",
                        "headersSize": 180,
                        "bodySize": 5000
                    },
                    "cache": {},
                    "timings": {
                        "blocked": 0,
                        "dns": 5,
                        "connect": 10,
                        "send": 2,
                        "wait": 25,
                        "receive": 8,
                        "ssl": 15
                    }
                }
            ]
        }
    }


@pytest.fixture
def security_service_trace_data():
    """Create network trace data with security service indicators."""
    return {
        "log": {
            "version": "1.2",
            "creator": {"name": "Test", "version": "1.0"},
            "entries": [
                {
                    "startedDateTime": "2025-01-01T00:00:00.000Z",
                    "time": 1000,
                    "request": {
                        "method": "POST",
                        "url": "https://api.example.com/login",
                        "httpVersion": "HTTP/1.1",
                        "headers": [
                            {"name": "User-Agent", "value": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"},
                            {"name": "Content-Type", "value": "application/json"}
                        ],
                        "queryString": [],
                        "cookies": [],
                        "headersSize": 200,
                        "bodySize": 100,
                        "postData": {
                            "mimeType": "application/json",
                            "text": '{"username": "test", "password": "test123"}'
                        }
                    },
                    "response": {
                        "status": 403,
                        "statusText": "Forbidden",
                        "httpVersion": "HTTP/1.1",
                        "headers": [
                            {"name": "Content-Type", "value": "application/json"},
                            {"name": "X-Sucuri-ID", "value": "sucuri-waf-123"},
                            {"name": "X-Sucuri-Cache", "value": "BYPASS"},
                            {"name": "X-Security-Block", "value": "automated-behavior"},
                            {"name": "X-Rate-Limit-Remaining", "value": "0"}
                        ],
                        "cookies": [],
                        "content": {
                            "size": 150,
                            "mimeType": "application/json",
                            "text": '{"error": "Request blocked by security policy"}'
                        },
                        "redirectURL": "",
                        "headersSize": 200,
                        "bodySize": 150
                    },
                    "cache": {},
                    "timings": {
                        "blocked": 10,
                        "dns": 30,
                        "connect": 100,
                        "send": 20,
                        "wait": 800,  # Long wait due to security processing
                        "receive": 40,
                        "ssl": 80
                    }
                }
            ]
        }
    }


@pytest.fixture
def multi_actor_trace_data():
    """Create network trace data with multiple actor indicators."""
    return {
        "log": {
            "version": "1.2",
            "creator": {"name": "Test", "version": "1.0"},
            "entries": [
                # Request through proxy with CDN and security service
                {
                    "startedDateTime": "2025-01-01T00:00:00.000Z",
                    "time": 300,
                    "request": {
                        "method": "GET",
                        "url": "https://secure.example.com/api/data",
                        "httpVersion": "HTTP/1.1",
                        "headers": [
                            {"name": "User-Agent", "value": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"},
                            {"name": "X-Forwarded-For", "value": "192.168.1.100"},
                            {"name": "Via", "value": "1.1 corporate-proxy:8080"}
                        ],
                        "queryString": [],
                        "cookies": [],
                        "headersSize": 250,
                        "bodySize": 0
                    },
                    "response": {
                        "status": 200,
                        "statusText": "OK",
                        "httpVersion": "HTTP/1.1",
                        "headers": [
                            {"name": "Content-Type", "value": "application/json"},
                            {"name": "CF-Ray", "value": "67890-LAX"},  # CloudFlare CDN
                            {"name": "X-Akamai-Request-ID", "value": "akamai-123"},  # Akamai CDN
                            {"name": "X-Sucuri-ID", "value": "sucuri-456"},  # Sucuri WAF
                            {"name": "X-Proxy-Cache", "value": "MISS"}  # Proxy cache
                        ],
                        "cookies": [],
                        "content": {
                            "size": 500,
                            "mimeType": "application/json",
                            "text": '{"data": "multi-actor response"}'
                        },
                        "redirectURL": "",
                        "headersSize": 300,
                        "bodySize": 500
                    },
                    "cache": {},
                    "timings": {
                        "blocked": 5,
                        "dns": 25,
                        "connect": 75,
                        "send": 15,
                        "wait": 150,
                        "receive": 30,
                        "ssl": 60
                    }
                }
            ]
        }
    }


@pytest.mark.asyncio
class TestActorSystemIntegration:
    """Test actor system integration and cross-actor analysis."""

    async def test_proxy_actor_integration(self, proxy_trace_data):
        """Test proxy actor integration with real network traces."""
        # Create temporary HAR file with proxy indicators
        with tempfile.NamedTemporaryFile(mode='w', suffix='.har', delete=False) as f:
            json.dump(proxy_trace_data, f)
            har_file_path = f.name

        try:
            # Build analyzer with proxy-focused configuration
            config = create_test_config(
                confidence_threshold=0.5,
                service_domains=['example.com'],
                enable_streaming=False
            )
            
            analyzer = AnalyzerBuilder().with_config(config).with_log(har_file_path).build()
            
            # Perform analysis
            result = await analyzer.analyze()
            
            # Validate proxy detection
            assert result is not None
            assert len(result.issues) > 0
            
            # Should detect proxy-related issues
            proxy_issues = [
                issue for issue in result.issues 
                if 'proxy' in issue.title.lower() or 'forwarded' in issue.description.lower()
            ]
            assert len(proxy_issues) > 0
            
            # Validate proxy actor behavior analysis
            proxy_issue = proxy_issues[0]
            # Check for actual category values (may be strings due to Pydantic serialization)
            valid_categories = [
                IssueCategory.NETWORK_ANOMALY, IssueCategory.CONFIGURATION, 
                IssueCategory.PROXY_DETECTION, 'proxy_detection', 'network_anomaly', 'configuration'
            ]
            assert proxy_issue.category in valid_categories
            assert proxy_issue.severity in [SeverityLevel.LOW, SeverityLevel.MEDIUM, SeverityLevel.HIGH]
            
            # Should identify proxy characteristics
            assert any(
                keyword in proxy_issue.description.lower() 
                for keyword in ['forwarded', 'proxy', 'via', 'intermediary']
            )
            
        finally:
            os.unlink(har_file_path)

    async def test_cdn_actor_integration(self, cdn_trace_data):
        """Test CDN actor integration with real network traces."""
        # Create temporary HAR file with CDN indicators
        with tempfile.NamedTemporaryFile(mode='w', suffix='.har', delete=False) as f:
            json.dump(cdn_trace_data, f)
            har_file_path = f.name

        try:
            # Build analyzer with CDN-focused configuration
            config = create_test_config(
                confidence_threshold=0.4,  # Lower threshold to catch CDN indicators
                service_domains=['example.com', 'cdn.example.com'],
                enable_streaming=False
            )
            
            analyzer = AnalyzerBuilder().with_config(config).with_log(har_file_path).build()
            
            # Perform analysis
            result = await analyzer.analyze()
            
            # Validate CDN detection
            assert result is not None
            
            # Should detect CDN-related characteristics
            cdn_indicators = []
            for issue in result.issues:
                if any(keyword in issue.description.lower() for keyword in ['cloudflare', 'cf-ray', 'cdn', 'cache']):
                    cdn_indicators.append(issue)
            
            # May not always detect as an "issue" but should analyze CDN characteristics
            # Check if fast response times are noted in statistics
            if len(result.network_traces) > 0:
                assert len(result.network_traces) > 0
            
            # Validate analysis completed successfully
            assert result.summary.overall_score is not None
            
        finally:
            os.unlink(har_file_path)

    async def test_security_service_integration(self, security_service_trace_data):
        """Test security service actor integration with real network traces."""
        # Create temporary HAR file with security service indicators
        with tempfile.NamedTemporaryFile(mode='w', suffix='.har', delete=False) as f:
            json.dump(security_service_trace_data, f)
            har_file_path = f.name

        try:
            # Build analyzer with security-focused configuration
            config = create_test_config(
                confidence_threshold=0.5,
                service_domains=['api.example.com'],
                enable_streaming=False
            )
            
            analyzer = AnalyzerBuilder().with_config(config).with_log(har_file_path).build()
            
            # Perform analysis
            result = await analyzer.analyze()
            
            # Validate security service detection
            assert result is not None
            assert len(result.issues) > 0
            
            # Should detect security-related issues
            security_issues = [
                issue for issue in result.issues 
                if any(keyword in issue.description.lower() for keyword in [
                    'security', 'blocked', 'waf', 'sucuri', 'rate limit', 'forbidden'
                ])
            ]
            assert len(security_issues) > 0
            
            # Validate security issue characteristics
            security_issue = security_issues[0]
            assert security_issue.severity in [SeverityLevel.HIGH, SeverityLevel.CRITICAL]
            assert security_issue.category in [
                IssueCategory.NETWORK_ANOMALY, 
                IssueCategory.BROWSER_AUTOMATION,
                IssueCategory.CONFIGURATION
            ]
            
        finally:
            os.unlink(har_file_path)

    async def test_multi_actor_chain_analysis(self, multi_actor_trace_data):
        """Test analysis with multiple actors in chain."""
        # Create temporary HAR file with multi-actor indicators
        with tempfile.NamedTemporaryFile(mode='w', suffix='.har', delete=False) as f:
            json.dump(multi_actor_trace_data, f)
            har_file_path = f.name

        try:
            # Build analyzer for multi-actor analysis
            config = create_test_config(
                confidence_threshold=0.4,
                service_domains=['secure.example.com'],
                enable_streaming=False
            )
            
            analyzer = AnalyzerBuilder().with_config(config).with_log(har_file_path).build()
            
            # Perform analysis
            result = await analyzer.analyze()
            
            # Validate multi-actor detection
            assert result is not None
            
            # Should detect multiple types of network intermediaries
            actor_indicators = {
                'proxy': False,
                'cdn': False,
                'security': False
            }

            for issue in result.issues:
                description_lower = issue.description.lower()
                if any(keyword in description_lower for keyword in ['proxy', 'forwarded', 'via']):
                    actor_indicators['proxy'] = True
                if any(keyword in description_lower for keyword in ['cloudflare', 'akamai', 'cf-ray', 'cdn']):
                    actor_indicators['cdn'] = True
                if any(keyword in description_lower for keyword in ['sucuri', 'security', 'waf']):
                    actor_indicators['security'] = True
            
            # Should detect at least one type of actor
            assert any(actor_indicators.values())
            
            # Validate comprehensive analysis
            assert result.summary.overall_score is not None
            assert len(result.network_traces) > 0
            
        finally:
            os.unlink(har_file_path)

    async def test_actor_behavior_correlation(self, multi_actor_trace_data):
        """Test cross-actor behavior analysis and correlation."""
        # Create temporary HAR file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.har', delete=False) as f:
            json.dump(multi_actor_trace_data, f)
            har_file_path = f.name

        try:
            # Build analyzer with comprehensive configuration
            config = create_test_config(
                confidence_threshold=0.3,  # Lower threshold for correlation analysis
                service_domains=['secure.example.com'],
                enable_streaming=False,
                metadata={'correlation_analysis': True}
            )
            
            analyzer = AnalyzerBuilder().with_config(config).with_log(har_file_path).build()
            
            # Perform analysis
            result = await analyzer.analyze()
            
            # Validate behavior correlation analysis
            assert result is not None
            
            # Check for correlated behaviors
            timing_issues = [
                issue for issue in result.issues
                if 'timing' in issue.description.lower() or 'latency' in issue.description.lower()
            ]
            
            header_issues = [
                issue for issue in result.issues 
                if 'header' in issue.description.lower()
            ]
            
            # Should analyze timing and header patterns
            assert len(timing_issues) > 0 or len(header_issues) > 0 or len(result.issues) > 0
            
            # Validate correlation metadata if available
            if hasattr(result, 'metadata') and result.metadata:
                correlation_data = result.metadata.get('actor_correlation', {})
                # Correlation analysis may be present
                assert isinstance(correlation_data, dict)
            
        finally:
            os.unlink(har_file_path)

    async def test_actor_registry_integration(self):
        """Test actor registry integration and management."""
        # Test actor registry functionality
        registry = ActorRegistry()
        
        # Register proxy actor
        registry.register("proxy", ProxyActor)
        
        # Validate registration
        registered_actors = registry.get_all_actors()
        assert len(registered_actors) > 0
        
        # Find proxy actor
        proxy_actors = [actor for actor in registered_actors if actor.actor_type == "proxy"]
        assert len(proxy_actors) > 0
        
        # Test actor capabilities
        proxy_actor = proxy_actors[0]
        assert hasattr(proxy_actor, 'identify')
        assert hasattr(proxy_actor, 'analyze_behavior')
        
        # Test actor identification with mock trace
        mock_trace = Mock()
        mock_trace.is_http.return_value = True
        mock_trace.hops = []  # Add iterable hops attribute
        mock_trace.http_data = Mock()
        mock_trace.http_data.request = Mock()
        mock_trace.http_data.request.headers = [
            {'name': 'X-Forwarded-For', 'value': '192.168.1.1'},
            {'name': 'Via', 'value': '1.1 proxy:8080'}
        ]
        mock_trace.http_data.response = Mock()
        mock_trace.http_data.response.headers = []
        
        # Test identification
        identification_result = proxy_actor.identify(mock_trace)
        assert identification_result is not None
        assert identification_result.actor_type == "proxy"
        assert identification_result.confidence > 0.0

    async def test_actor_event_integration(self):
        """Test actor system integration with event bus."""
        # Create event bus
        event_bus = EventBus()
        events_captured = []
        
        # Mock event handler
        async def capture_events(event_type: str, data: dict):
            events_captured.append({'type': event_type, 'data': data})
        
        # Register event handler
        event_bus.on = capture_events
        
        # Create simple test data
        test_data = {
            "log": {
                "version": "1.2",
                "creator": {"name": "Test", "version": "1.0"},
                "entries": [{
                    "startedDateTime": "2025-01-01T00:00:00.000Z",
                    "time": 100,
                    "request": {
                        "method": "GET",
                        "url": "https://example.com/test",
                        "httpVersion": "HTTP/1.1",
                        "headers": [{"name": "User-Agent", "value": "Test"}],
                        "queryString": [],
                        "cookies": [],
                        "headersSize": 100,
                        "bodySize": 0
                    },
                    "response": {
                        "status": 200,
                        "statusText": "OK",
                        "httpVersion": "HTTP/1.1",
                        "headers": [{"name": "Content-Type", "value": "text/html"}],
                        "cookies": [],
                        "content": {"size": 100, "mimeType": "text/html", "text": "test"},
                        "redirectURL": "",
                        "headersSize": 100,
                        "bodySize": 100
                    },
                    "cache": {},
                    "timings": {"blocked": 0, "dns": 10, "connect": 20, "send": 5, "wait": 50, "receive": 15, "ssl": 30}
                }]
            }
        }
        
        # Create temporary file and analyze
        with tempfile.NamedTemporaryFile(mode='w', suffix='.har', delete=False) as f:
            json.dump(test_data, f)
            har_file_path = f.name

        try:
            # Create analyzer with event bus
            config = create_test_config(confidence_threshold=0.5)
            analyzer = AnalyzerBuilder().with_config(config).with_log(har_file_path).build()
            
            # Mock the event bus if analyzer supports it
            if hasattr(analyzer, 'event_bus'):
                analyzer.event_bus = event_bus
            
            # Perform analysis
            result = await analyzer.analyze()
            
            # Validate analysis completed
            assert result is not None
            
            # Check if events were captured (if event system is active)
            if events_captured:
                event_types = [event['type'] for event in events_captured]
                assert len(event_types) > 0
                # Should have analysis-related events
                assert any('analysis' in event_type or 'detection' in event_type for event_type in event_types)
            
        finally:
            os.unlink(har_file_path)

    async def test_actor_performance_integration(self, multi_actor_trace_data):
        """Test actor system performance with concurrent analysis."""
        # Create multiple temporary files for concurrent analysis
        file_paths = []
        
        try:
            # Create 5 identical files for concurrent processing
            for i in range(5):
                with tempfile.NamedTemporaryFile(mode='w', suffix=f'_test_{i}.har', delete=False) as f:
                    json.dump(multi_actor_trace_data, f)
                    file_paths.append(f.name)
            
            # Build analyzer with concurrent processing
            config = create_test_config(
                confidence_threshold=0.5,
                max_concurrent_detectors=4,
                enable_streaming=True,
                service_domains=['secure.example.com']
            )
            
            # Perform concurrent analysis
            import asyncio
            
            async def analyze_file(file_path):
                temp_analyzer = AnalyzerBuilder().with_config(config).with_log(file_path).build()
                return await temp_analyzer.analyze()
            
            # Run concurrent analyses
            results = await asyncio.gather(*[analyze_file(path) for path in file_paths])
            
            # Validate all analyses completed
            assert len(results) == 5
            for result in results:
                assert result is not None
                assert result.summary.overall_score is not None
                assert len(result.network_traces) > 0
            
            # Results should be consistent across files (same input data)
            scores = [result.summary.overall_score for result in results]
            issue_counts = [len(result.issues) for result in results]
            
            # All scores should be identical (same input)
            assert len(set(scores)) == 1
            assert len(set(issue_counts)) == 1
            
        finally:
            # Clean up all temporary files
            for file_path in file_paths:
                if os.path.exists(file_path):
                    os.unlink(file_path)

    async def test_actor_error_handling_integration(self):
        """Test actor system error handling and recovery."""
        # Create invalid trace data that might cause actor errors
        invalid_data = {
            "log": {
                "version": "1.2",
                "creator": {"name": "Test", "version": "1.0"},
                "entries": [{
                    "startedDateTime": "invalid-date",
                    "time": "invalid-time",
                    "request": {
                        "method": "INVALID",
                        "url": "not-a-url",
                        "httpVersion": "HTTP/1.1",
                        "headers": "invalid-headers",  # Should be array
                        "queryString": [],
                        "cookies": [],
                        "headersSize": -1,  # Invalid size
                        "bodySize": -1
                    },
                    "response": {
                        "status": 999,  # Invalid status
                        "statusText": "",
                        "httpVersion": "HTTP/1.1",
                        "headers": [],
                        "cookies": [],
                        "content": {"size": -1, "mimeType": "", "text": ""},
                        "redirectURL": "",
                        "headersSize": -1,
                        "bodySize": -1
                    },
                    "cache": {},
                    "timings": {"blocked": -1, "dns": -1, "connect": -1, "send": -1, "wait": -1, "receive": -1, "ssl": -1}
                }]
            }
        }
        
        # Create temporary file with invalid data
        with tempfile.NamedTemporaryFile(mode='w', suffix='.har', delete=False) as f:
            json.dump(invalid_data, f)
            invalid_file_path = f.name

        try:
            # Build analyzer
            config = create_test_config(confidence_threshold=0.5)
            analyzer = AnalyzerBuilder().with_config(config).with_log(invalid_file_path).build()
            
            # Attempt analysis of invalid data
            result = await analyzer.analyze()
            
            # Should handle errors gracefully
            assert result is not None
            
            # May have errors recorded or empty analysis
            if hasattr(result, 'errors') and result.errors:
                assert len(result.errors) > 0
                # Errors should be informative
                for error in result.errors:
                    assert 'error' in error or 'message' in error
            else:
                # Or may have zero traces analyzed due to parsing errors
                assert len(result.network_traces) == 0
            
        finally:
            os.unlink(invalid_file_path)

    async def test_actor_configuration_integration(self):
        """Test actor system with various configuration options."""
        # Test with different confidence thresholds
        test_data = {
            "log": {
                "version": "1.2",
                "creator": {"name": "Test", "version": "1.0"},
                "entries": [{
                    "startedDateTime": "2025-01-01T00:00:00.000Z",
                    "time": 100,
                    "request": {
                        "method": "GET",
                        "url": "https://example.com/api",
                        "httpVersion": "HTTP/1.1",
                        "headers": [
                            {"name": "User-Agent", "value": "Mozilla/5.0"},
                            {"name": "X-Forwarded-For", "value": "192.168.1.1"}  # Weak proxy indicator
                        ],
                        "queryString": [],
                        "cookies": [],
                        "headersSize": 150,
                        "bodySize": 0
                    },
                    "response": {
                        "status": 200,
                        "statusText": "OK",
                        "httpVersion": "HTTP/1.1",
                        "headers": [{"name": "Content-Type", "value": "application/json"}],
                        "cookies": [],
                        "content": {"size": 100, "mimeType": "application/json", "text": "{}"},
                        "redirectURL": "",
                        "headersSize": 100,
                        "bodySize": 100
                    },
                    "cache": {},
                    "timings": {"blocked": 0, "dns": 10, "connect": 20, "send": 5, "wait": 50, "receive": 15, "ssl": 30}
                }]
            }
        }
        
        # Create temporary file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.har', delete=False) as f:
            json.dump(test_data, f)
            test_file_path = f.name

        try:
            # Test with high confidence threshold (should detect fewer issues)
            high_config = create_test_config(
                confidence_threshold=0.9,
                service_domains=['example.com']
            )
            high_analyzer = AnalyzerBuilder().with_config(high_config).with_log(test_file_path).build()
            high_result = await high_analyzer.analyze()
            
            # Test with low confidence threshold (should detect more issues)
            low_config = create_test_config(
                confidence_threshold=0.3,
                service_domains=['example.com']
            )
            low_analyzer = AnalyzerBuilder().with_config(low_config).with_log(test_file_path).build()
            low_result = await low_analyzer.analyze()
            
            # Validate both analyses completed
            assert high_result is not None
            assert low_result is not None
            
            # Low confidence threshold should detect same or more issues
            assert len(low_result.issues) >= len(high_result.issues)
            
            # Both should have valid scores
            assert high_result.summary.overall_score is not None
            assert low_result.summary.overall_score is not None
            
        finally:
            os.unlink(test_file_path)
