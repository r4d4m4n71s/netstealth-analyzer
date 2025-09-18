"""
Unit tests for Mitmproxy parser.

Tests the MitmproxyParser class with comprehensive coverage including
async operations, streaming, error handling, and edge cases.
"""

import asyncio
import pytest
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, List
from unittest.mock import AsyncMock, Mock, patch

from src.netstealth_analyzer.parsers.mitmproxy import MitmproxyParser
from src.netstealth_analyzer.parsers.base import ParseResult
from src.netstealth_analyzer.models.enums import LogFormat
from src.netstealth_analyzer.models.network import NetworkTrace
from src.netstealth_analyzer.core.events import EventBus


class TestMitmproxyParser:
    """Test MitmproxyParser class."""
    
    @pytest.fixture
    def mitmproxy_parser(self):
        """Create Mitmproxy parser instance."""
        return MitmproxyParser()
    
    @pytest.fixture
    def mitmproxy_parser_with_event_bus(self, event_bus):
        """Create Mitmproxy parser with event bus."""
        return MitmproxyParser(event_bus=event_bus, service_domains=["example.com", "test.com"])
    
    @pytest.fixture
    def sample_mitmproxy_log(self):
        """Create sample Mitmproxy log data for testing."""
        return """[12:30:45.123] [client-123] client connect
[12:30:45.124] [client-123] server connect example.com (203.0.113.1)
[12:30:45.125] Request: GET https://example.com/api/test
[12:30:45.200] Response: 200 OK
[12:30:46.123] [client-456] client connect
[12:30:46.124] [client-456] server connect test.com (203.0.113.2)
[12:30:46.125] Request: POST https://test.com/oauth/token
[12:30:46.300] Response: 401 Unauthorized
"""
    
    @pytest.fixture
    def malformed_mitmproxy_log(self):
        """Create malformed Mitmproxy log for error testing."""
        return """[12:30:45.123] Invalid log line without proper format
[12:30:45.124] Request: INVALID_METHOD
[12:30:45.125] Response: INVALID_STATUS
"""
    
    def test_mitmproxy_parser_properties(self, mitmproxy_parser):
        """Test Mitmproxy parser basic properties."""
        assert mitmproxy_parser.supported_format == LogFormat.MITMPROXY
        assert '.mitm' in mitmproxy_parser.file_extensions
        assert '.log' in mitmproxy_parser.file_extensions
        assert '.txt' in mitmproxy_parser.file_extensions
    
    def test_mitmproxy_parser_with_service_domains(self):
        """Test Mitmproxy parser with service domains."""
        service_domains = ["example.com", "api.test.com"]
        parser = MitmproxyParser(service_domains=service_domains)
        assert parser.service_domains == service_domains
    
    @pytest.mark.asyncio
    async def test_parse_valid_mitmproxy_file(self, mitmproxy_parser, sample_mitmproxy_log, temp_directory):
        """Test parsing valid Mitmproxy log file."""
        # Create temporary Mitmproxy log file
        mitm_file = temp_directory / "test.mitm"
        mitm_file.write_text(sample_mitmproxy_log)
        
        # Parse the file
        result = await mitmproxy_parser.parse(mitm_file)
        
        # Verify result
        assert isinstance(result, ParseResult)
        assert result.format == LogFormat.MITMPROXY
        assert result.source_file == str(mitm_file)
        assert len(result.network_traces) == 2
        
        # Verify metadata
        assert result.metadata['line_count'] == 8
        assert 'parser_version' in result.metadata
        
        # Verify first trace
        trace1 = result.network_traces[0]
        assert trace1.trace_id.startswith("mitm_")
        assert trace1.metadata['domain'] == 'example.com'
        assert trace1.metadata['is_secure'] is True
        
        # Verify HTTP data in metadata
        assert 'http_request' in trace1.metadata
        assert 'http_response' in trace1.metadata
        assert trace1.metadata['http_request']['method'] == 'GET'
        assert trace1.metadata['http_response']['status_code'] == 200
        
        # Verify second trace (OAuth)
        trace2 = result.network_traces[1]
        assert trace2.metadata['domain'] == 'test.com'
        assert trace2.metadata['is_oauth'] is True
        assert trace2.metadata['http_request']['method'] == 'POST'
        assert trace2.metadata['http_response']['status_code'] == 401
        
        # Verify statistics
        stats = result.statistics
        assert stats['total_requests'] == 2
        assert stats['successful_responses'] == 1
        assert stats['client_errors'] == 1
        assert stats['secure_requests'] == 2
        assert stats['unique_domains'] == 2
    
    @pytest.mark.asyncio
    async def test_parse_nonexistent_file(self, mitmproxy_parser):
        """Test parsing nonexistent file."""
        with pytest.raises(FileNotFoundError):
            await mitmproxy_parser.parse("nonexistent.mitm")
    
    @pytest.mark.asyncio
    async def test_parse_empty_file(self, mitmproxy_parser, temp_directory):
        """Test parsing empty Mitmproxy file."""
        mitm_file = temp_directory / "empty.mitm"
        mitm_file.write_text("")
        
        result = await mitmproxy_parser.parse(mitm_file)
        
        assert len(result.network_traces) == 0
        assert result.statistics['total_requests'] == 0
    
    @pytest.mark.asyncio
    async def test_parse_malformed_entries(self, mitmproxy_parser, malformed_mitmproxy_log, temp_directory):
        """Test parsing Mitmproxy file with malformed entries."""
        mitm_file = temp_directory / "malformed.mitm"
        mitm_file.write_text(malformed_mitmproxy_log)
        
        result = await mitmproxy_parser.parse(mitm_file)
        
        # Should handle malformed entries gracefully without creating traces
        # Malformed entries don't match patterns so no traces are created
        assert len(result.network_traces) == 0
        assert result.statistics['total_requests'] == 0
        # Parser handles malformed entries gracefully without raising errors
        assert len(result.errors) == 0
    
    @pytest.mark.asyncio
    async def test_stream_parse(self, mitmproxy_parser, sample_mitmproxy_log, temp_directory):
        """Test streaming parse functionality."""
        mitm_file = temp_directory / "stream_test.mitm"
        mitm_file.write_text(sample_mitmproxy_log)
        
        traces = []
        async for trace in mitmproxy_parser.stream_parse(mitm_file):
            traces.append(trace)
        
        assert len(traces) == 2
        assert all(isinstance(trace, NetworkTrace) for trace in traces)
        assert traces[0].metadata['http_request']['method'] == "GET"
        assert traces[1].metadata['http_request']['method'] == "POST"
    
    @pytest.mark.asyncio
    async def test_stream_parse_with_errors(self, mitmproxy_parser, malformed_mitmproxy_log, temp_directory):
        """Test streaming parse with malformed entries."""
        mitm_file = temp_directory / "stream_malformed.mitm"
        mitm_file.write_text(malformed_mitmproxy_log)
        
        traces = []
        async for trace in mitmproxy_parser.stream_parse(mitm_file):
            traces.append(trace)
        
        # Should skip malformed entries and continue
        assert len(traces) == 0  # All entries are malformed
    
    @pytest.mark.asyncio
    async def test_parse_large_mitmproxy_file(self, mitmproxy_parser, temp_directory):
        """Test parsing large Mitmproxy file with many entries."""
        # Create large log with many request/response pairs
        log_lines = []
        for i in range(100):
            log_lines.extend([
                f"[12:30:{i:02d}.123] [client-{i}] client connect",
                f"[12:30:{i:02d}.124] [client-{i}] server connect example.com (203.0.113.{i % 255})",
                f"[12:30:{i:02d}.125] Request: GET https://example.com/api/test/{i}",
                f"[12:30:{i:02d}.200] Response: 200 OK"
            ])
        
        large_log = "\n".join(log_lines)
        mitm_file = temp_directory / "large.mitm"
        mitm_file.write_text(large_log)
        
        result = await mitmproxy_parser.parse(mitm_file)
        
        assert len(result.network_traces) == 100
        assert result.statistics['total_requests'] == 100
        assert result.statistics['successful_responses'] == 100
    
    @pytest.mark.asyncio
    async def test_parse_with_proxy_headers(self, mitmproxy_parser, temp_directory):
        """Test parsing Mitmproxy with proxy-revealing patterns."""
        proxy_log = """[12:30:45.123] [client-123] client connect
[12:30:45.124] [client-123] server connect example.com (203.0.113.1)
[12:30:45.125] Request: GET https://example.com/test X-Forwarded-For: 192.168.1.1
[12:30:45.200] Response: 200 OK Via: 1.1 proxy.example.com
"""
        
        mitm_file = temp_directory / "proxy_test.mitm"
        mitm_file.write_text(proxy_log)
        
        result = await mitmproxy_parser.parse(mitm_file)
        
        assert len(result.network_traces) == 1
        trace = result.network_traces[0]
        
        # Verify proxy detection
        assert trace.metadata['has_proxy_headers'] is True
        assert result.statistics['proxy_indicators'] == 1
        assert result.statistics['proxy_detection_risk'] == 100.0
    
    @pytest.mark.asyncio
    async def test_parse_ip_detection_services(self, mitmproxy_parser, temp_directory):
        """Test parsing Mitmproxy with IP detection service requests."""
        ip_log = """[12:30:45.123] [client-123] client connect
[12:30:45.124] [client-123] server connect ipinfo.io (203.0.113.1)
[12:30:45.125] Request: GET https://ipinfo.io/json
[12:30:45.200] Response: 200 OK
"""
        
        mitm_file = temp_directory / "ip_services.mitm"
        mitm_file.write_text(ip_log)
        
        result = await mitmproxy_parser.parse(mitm_file)
        
        assert len(result.network_traces) == 1
        assert result.statistics['ip_detection_requests'] == 1
        
        # Verify IP detection service detection
        trace = result.network_traces[0]
        assert trace.metadata['is_ip_detection'] is True
    
    @pytest.mark.asyncio
    async def test_parse_oauth_requests(self, mitmproxy_parser, temp_directory):
        """Test parsing Mitmproxy with OAuth-related requests."""
        oauth_log = """[12:30:45.123] [client-123] client connect
[12:30:45.124] [client-123] server connect accounts.google.com (203.0.113.1)
[12:30:45.125] Request: POST https://accounts.google.com/oauth/token
[12:30:45.200] Response: 200 OK
"""
        
        mitm_file = temp_directory / "oauth_test.mitm"
        mitm_file.write_text(oauth_log)
        
        result = await mitmproxy_parser.parse(mitm_file)
        
        assert len(result.network_traces) == 1
        trace = result.network_traces[0]
        
        assert trace.metadata['is_oauth'] is True
        assert result.statistics['oauth_requests'] == 1
    
    @pytest.mark.asyncio
    async def test_validate_format_valid_mitmproxy(self, mitmproxy_parser, sample_mitmproxy_log, temp_directory):
        """Test format validation with valid Mitmproxy file."""
        mitm_file = temp_directory / "valid.mitm"
        mitm_file.write_text(sample_mitmproxy_log)
        
        is_valid = await mitmproxy_parser._validate_format(mitm_file)
        assert is_valid is True
    
    @pytest.mark.asyncio
    async def test_validate_format_invalid_file(self, mitmproxy_parser, temp_directory):
        """Test format validation with invalid file."""
        # Create non-Mitmproxy file
        invalid_file = temp_directory / "invalid.txt"
        invalid_file.write_text("This is not a Mitmproxy log file\nJust some random text\nNothing mitmproxy-related here")
        
        is_valid = await mitmproxy_parser._validate_format(invalid_file)
        assert is_valid is False
    
    @pytest.mark.asyncio
    async def test_validate_format_nonexistent_file(self, mitmproxy_parser):
        """Test format validation with nonexistent file."""
        is_valid = await mitmproxy_parser._validate_format(Path("nonexistent.mitm"))
        assert is_valid is False
    
    def test_parse_timestamp_valid(self, mitmproxy_parser):
        """Test parsing valid timestamp."""
        timestamp_str = "12:30:45.123"
        dt = mitmproxy_parser._parse_timestamp(timestamp_str)
        
        assert dt is not None
        assert dt.hour == 12
        assert dt.minute == 30
        assert dt.second == 45
        assert dt.microsecond == 123000
    
    def test_parse_timestamp_invalid(self, mitmproxy_parser):
        """Test parsing invalid timestamp."""
        dt = mitmproxy_parser._parse_timestamp("invalid-timestamp")
        assert dt is None
        
        dt = mitmproxy_parser._parse_timestamp(None)
        assert dt is None
    
    def test_statistics_initialization(self, mitmproxy_parser):
        """Test statistics initialization."""
        stats = mitmproxy_parser._init_statistics()
        
        assert stats['total_requests'] == 0
        assert stats['successful_responses'] == 0
        assert stats['proxy_indicators'] == 0
        assert stats['tls_events'] == 0
        assert stats['proxy_errors'] == 0
        assert isinstance(stats['unique_domains'], set)
    
    def test_update_context_from_line(self, mitmproxy_parser):
        """Test context updating from log lines."""
        context = {}
        
        # Test client connect
        mitmproxy_parser._update_context_from_line(
            "[12:30:45.123] [client-123] client connect", 
            1, None, context
        )
        assert context['current_client'] == 'client-123'
        
        # Test server connect
        mitmproxy_parser._update_context_from_line(
            "[12:30:45.124] [client-123] server connect example.com (203.0.113.1)", 
            2, None, context
        )
        assert context['current_server'] == 'example.com'
        assert context['current_server_ip'] == '203.0.113.1'
    
    @pytest.mark.asyncio
    async def test_parse_request_without_response(self, mitmproxy_parser, temp_directory):
        """Test parsing request without corresponding response."""
        incomplete_log = """[12:30:45.123] [client-123] client connect
[12:30:45.124] [client-123] server connect example.com (203.0.113.1)
[12:30:45.125] Request: GET https://example.com/api/test
"""
        
        mitm_file = temp_directory / "incomplete.mitm"
        mitm_file.write_text(incomplete_log)
        
        result = await mitmproxy_parser.parse(mitm_file)
        
        # Should not create trace without response
        assert len(result.network_traces) == 0
        assert result.statistics['total_requests'] == 0
    
    @pytest.mark.asyncio
    async def test_parse_response_without_request(self, mitmproxy_parser, temp_directory):
        """Test parsing response without corresponding request."""
        orphan_log = """[12:30:45.123] [client-123] client connect
[12:30:45.124] [client-123] server connect example.com (203.0.113.1)
[12:30:45.200] Response: 200 OK
"""
        
        mitm_file = temp_directory / "orphan.mitm"
        mitm_file.write_text(orphan_log)
        
        result = await mitmproxy_parser.parse(mitm_file)
        
        # Should not create trace without request
        assert len(result.network_traces) == 0
        assert result.statistics['total_requests'] == 0
