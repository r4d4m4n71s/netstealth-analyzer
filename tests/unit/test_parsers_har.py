"""
Unit tests for HAR parser.

Tests the HarParser class with comprehensive coverage including
async operations, streaming, error handling, and edge cases.
"""

import asyncio
import json
import pytest
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any
from unittest.mock import AsyncMock, Mock, patch

from src.netstealth_analyzer.parsers.har import HarParser
from src.netstealth_analyzer.parsers.base import ParseResult
from src.netstealth_analyzer.models.enums import LogFormat
from src.netstealth_analyzer.models.network import NetworkTrace, HttpRequest, HttpResponse, TimingInfo
from src.netstealth_analyzer.core.events import EventBus


class TestHarParser:
    """Test HarParser class."""
    
    @pytest.fixture
    def har_parser(self):
        """Create HAR parser instance."""
        return HarParser()
    
    @pytest.fixture
    def har_parser_with_event_bus(self, event_bus):
        """Create HAR parser with event bus."""
        return HarParser(event_bus=event_bus, service_domains=["example.com", "test.com"])
    
    @pytest.fixture
    def sample_har_data(self):
        """Create sample HAR data for testing."""
        return {
            "log": {
                "version": "1.2",
                "creator": {
                    "name": "Test Creator",
                    "version": "1.0.0"
                },
                "browser": {
                    "name": "Test Browser",
                    "version": "1.0.0"
                },
                "pages": [
                    {
                        "startedDateTime": "2023-01-01T00:00:00.000Z",
                        "id": "page_1",
                        "title": "Test Page"
                    }
                ],
                "entries": [
                    {
                        "startedDateTime": "2023-01-01T00:00:00.000Z",
                        "request": {
                            "method": "GET",
                            "url": "https://example.com/api/test",
                            "headers": [
                                {"name": "User-Agent", "value": "Mozilla/5.0"},
                                {"name": "X-Forwarded-For", "value": "192.168.1.1"}
                            ],
                            "postData": {
                                "text": "test=data"
                            }
                        },
                        "response": {
                            "status": 200,
                            "statusText": "OK",
                            "headers": [
                                {"name": "Content-Type", "value": "application/json"},
                                {"name": "Server", "value": "nginx/1.18.0"}
                            ],
                            "content": {
                                "text": '{"status": "success"}'
                            },
                            "bodySize": 20
                        },
                        "timings": {
                            "dns": 10,
                            "connect": 20,
                            "ssl": 30,
                            "send": 5,
                            "wait": 100,
                            "receive": 15,
                            "blocked": 2
                        }
                    },
                    {
                        "startedDateTime": "2023-01-01T00:00:01.000Z",
                        "request": {
                            "method": "POST",
                            "url": "https://test.com/oauth/token",
                            "headers": [
                                {"name": "Content-Type", "value": "application/x-www-form-urlencoded"}
                            ],
                            "postData": {
                                "params": [
                                    {"name": "grant_type", "value": "client_credentials"},
                                    {"name": "client_id", "value": "test_client"}
                                ]
                            }
                        },
                        "response": {
                            "status": 401,
                            "statusText": "Unauthorized",
                            "headers": [
                                {"name": "Content-Type", "value": "application/json"}
                            ],
                            "content": {
                                "text": '{"error": "invalid_client"}'
                            },
                            "bodySize": 30
                        },
                        "timings": {
                            "dns": 5,
                            "connect": 15,
                            "ssl": 25,
                            "send": 3,
                            "wait": 200,
                            "receive": 10,
                            "blocked": 1
                        }
                    }
                ]
            }
        }
    
    @pytest.fixture
    def malformed_har_data(self):
        """Create malformed HAR data for error testing."""
        return {
            "log": {
                "version": "1.2",
                "entries": [
                    {
                        # Missing required fields
                        "request": {
                            "method": "GET"
                            # Missing URL
                        },
                        "response": {
                            # Missing status
                            "statusText": "OK"
                        }
                    }
                ]
            }
        }
    
    def test_har_parser_properties(self, har_parser):
        """Test HAR parser basic properties."""
        assert har_parser.supported_format == LogFormat.HAR
        assert '.har' in har_parser.file_extensions
        assert '.json' in har_parser.file_extensions
    
    def test_har_parser_with_service_domains(self):
        """Test HAR parser with service domains."""
        service_domains = ["example.com", "api.test.com"]
        parser = HarParser(service_domains=service_domains)
        assert parser.service_domains == service_domains
    
    @pytest.mark.asyncio
    async def test_parse_valid_har_file(self, har_parser, sample_har_data, temp_directory):
        """Test parsing valid HAR file."""
        # Create temporary HAR file
        har_file = temp_directory / "test.har"
        har_file.write_text(json.dumps(sample_har_data))
        
        # Parse the file
        result = await har_parser.parse(har_file)
        
        # Verify result
        assert isinstance(result, ParseResult)
        assert result.format == LogFormat.HAR
        assert result.source_file == str(har_file)
        assert len(result.network_traces) == 2
        assert len(result.errors) == 0
        
        # Verify metadata
        assert result.metadata['har_version'] == '1.2'
        assert result.metadata['entry_count'] == 2
        assert 'creator' in result.metadata
        assert 'browser' in result.metadata
        
        # Verify first trace
        trace1 = result.network_traces[0]
        assert trace1.trace_id == "har_0"
        assert trace1.metadata['source_format'] == LogFormat.HAR.value
        assert trace1.metadata['http_request']['method'] == "GET"
        assert trace1.metadata['http_request']['url'] == "https://example.com/api/test"
        assert trace1.metadata['http_response']['status_code'] == 200
        assert trace1.metadata['http_response']['status_text'] == "OK"
        
        # Verify timing info
        assert trace1.metadata['http_timing']['dns_lookup'] == 10
        assert trace1.metadata['http_timing']['tcp_connect'] == 20
        assert trace1.metadata['http_timing']['ssl_handshake'] == 30
        
        # Verify metadata flags
        assert trace1.metadata['domain'] == 'example.com'
        assert trace1.metadata['is_secure'] is True
        assert trace1.metadata['has_proxy_headers'] is True  # X-Forwarded-For header
        
        # Verify second trace (OAuth)
        trace2 = result.network_traces[1]
        assert trace2.metadata['http_request']['method'] == "POST"
        assert trace2.metadata['http_request']['url'] == "https://test.com/oauth/token"
        assert trace2.metadata['http_response']['status_code'] == 401
        assert trace2.metadata['is_oauth'] is True
        
        # Verify statistics
        stats = result.statistics
        assert stats['total_requests'] == 2
        assert stats['successful_responses'] == 1
        assert stats['client_errors'] == 1
        assert stats['secure_requests'] == 2
        assert stats['proxy_indicators'] == 1
        assert stats['unique_domains'] == 2
    
    @pytest.mark.asyncio
    async def test_parse_nonexistent_file(self, har_parser):
        """Test parsing nonexistent file."""
        with pytest.raises(FileNotFoundError):
            await har_parser.parse("nonexistent.har")
    
    @pytest.mark.asyncio
    async def test_parse_invalid_json(self, har_parser, temp_directory):
        """Test parsing invalid JSON file."""
        # Create file with invalid JSON
        har_file = temp_directory / "invalid.har"
        har_file.write_text("{ invalid json }")
        
        with pytest.raises(ValueError, match="Invalid JSON"):
            await har_parser.parse(har_file)
    
    @pytest.mark.asyncio
    async def test_parse_missing_log_section(self, har_parser, temp_directory):
        """Test parsing HAR file without log section."""
        # Create HAR file without log section
        invalid_har = {"version": "1.2"}
        har_file = temp_directory / "no_log.har"
        har_file.write_text(json.dumps(invalid_har))
        
        with pytest.raises(ValueError, match="missing 'log' section"):
            await har_parser.parse(har_file)
    
    @pytest.mark.asyncio
    async def test_parse_empty_entries(self, har_parser, temp_directory):
        """Test parsing HAR file with empty entries."""
        empty_har = {
            "log": {
                "version": "1.2",
                "entries": []
            }
        }
        har_file = temp_directory / "empty.har"
        har_file.write_text(json.dumps(empty_har))
        
        result = await har_parser.parse(har_file)
        
        assert len(result.network_traces) == 0
        assert result.statistics['total_requests'] == 0
    
    @pytest.mark.asyncio
    async def test_parse_malformed_entries(self, har_parser, malformed_har_data, temp_directory):
        """Test parsing HAR file with malformed entries."""
        har_file = temp_directory / "malformed.har"
        har_file.write_text(json.dumps(malformed_har_data))
        
        result = await har_parser.parse(har_file)
        
        # Should handle malformed entries gracefully without creating traces
        # Malformed entries don't match patterns so no traces are created
        assert len(result.network_traces) == 0
        assert result.statistics['total_requests'] == 0
        # Parser handles malformed entries gracefully without raising errors
        assert len(result.errors) == 0
    
    @pytest.mark.asyncio
    async def test_stream_parse(self, har_parser, sample_har_data, temp_directory):
        """Test streaming parse functionality."""
        har_file = temp_directory / "stream_test.har"
        har_file.write_text(json.dumps(sample_har_data))
        
        traces = []
        async for trace in har_parser.stream_parse(har_file):
            traces.append(trace)
        
        assert len(traces) == 2
        assert all(isinstance(trace, NetworkTrace) for trace in traces)
        assert traces[0].metadata['http_request']['method'] == "GET"
        assert traces[1].metadata['http_request']['method'] == "POST"
    
    @pytest.mark.asyncio
    async def test_stream_parse_with_errors(self, har_parser, malformed_har_data, temp_directory):
        """Test streaming parse with malformed entries."""
        har_file = temp_directory / "stream_malformed.har"
        har_file.write_text(json.dumps(malformed_har_data))
        
        traces = []
        async for trace in har_parser.stream_parse(har_file):
            traces.append(trace)
        
        # Should skip malformed entries and continue
        assert len(traces) == 0  # All entries are malformed
    
    @pytest.mark.asyncio
    async def test_parse_large_har_file(self, har_parser, temp_directory):
        """Test parsing large HAR file with many entries."""
        # Create HAR with many entries
        entries = []
        for i in range(500):
            entry = {
                "startedDateTime": f"2023-01-01T00:00:{i:02d}.000Z",
                "request": {
                    "method": "GET",
                    "url": f"https://example.com/api/test/{i}",
                    "headers": [
                        {"name": "User-Agent", "value": "Mozilla/5.0"}
                    ]
                },
                "response": {
                    "status": 200,
                    "statusText": "OK",
                    "headers": [
                        {"name": "Content-Type", "value": "application/json"}
                    ],
                    "content": {
                        "text": f'{{"id": {i}}}'
                    }
                },
                "timings": {
                    "dns": 10,
                    "connect": 20,
                    "send": 5,
                    "wait": 50 + i,  # Variable wait time
                    "receive": 10
                }
            }
            entries.append(entry)
        
        large_har = {
            "log": {
                "version": "1.2",
                "entries": entries
            }
        }
        
        har_file = temp_directory / "large.har"
        har_file.write_text(json.dumps(large_har))
        
        result = await har_parser.parse(har_file)
        
        assert len(result.network_traces) == 500
        assert result.statistics['total_requests'] == 500
        assert result.statistics['successful_responses'] == 500
        
        # Verify timing statistics
        assert result.statistics['average_response_time'] > 0
        assert result.statistics['max_response_time'] > result.statistics['min_response_time']
    
    @pytest.mark.asyncio
    async def test_parse_with_tls_info(self, har_parser, temp_directory):
        """Test parsing HAR with TLS information."""
        har_with_tls = {
            "log": {
                "version": "1.2",
                "entries": [
                    {
                        "startedDateTime": "2023-01-01T00:00:00.000Z",
                        "request": {
                            "method": "GET",
                            "url": "https://secure.example.com/api",
                            "headers": []
                        },
                        "response": {
                            "status": 200,
                            "statusText": "OK",
                            "headers": [
                                {"name": "Strict-Transport-Security", "value": "max-age=31536000"}
                            ],
                            "content": {"text": "{}"}
                        },
                        "timings": {
                            "ssl": 150,  # Long SSL handshake
                            "connect": 50,
                            "send": 5,
                            "wait": 100,
                            "receive": 10
                        },
                        "_securityState": "secure"
                    }
                ]
            }
        }
        
        har_file = temp_directory / "tls_test.har"
        har_file.write_text(json.dumps(har_with_tls))
        
        result = await har_parser.parse(har_file)
        
        assert len(result.network_traces) == 1
        trace = result.network_traces[0]
        
        # Verify TLS timing
        assert trace.metadata['http_timing']['ssl_handshake'] == 150
        assert trace.metadata['is_secure'] is True
        
        # Verify SSL statistics
        assert result.statistics['average_ssl_time'] == 150
        assert result.statistics['max_ssl_time'] == 150
    
    @pytest.mark.asyncio
    async def test_parse_with_proxy_headers(self, har_parser, temp_directory):
        """Test parsing HAR with various proxy headers."""
        har_with_proxy = {
            "log": {
                "version": "1.2",
                "entries": [
                    {
                        "startedDateTime": "2023-01-01T00:00:00.000Z",
                        "request": {
                            "method": "GET",
                            "url": "https://example.com/test",
                            "headers": [
                                {"name": "X-Forwarded-For", "value": "203.0.113.1"},
                                {"name": "Via", "value": "1.1 proxy.example.com"},
                                {"name": "X-Real-IP", "value": "203.0.113.1"}
                            ]
                        },
                        "response": {
                            "status": 200,
                            "statusText": "OK",
                            "headers": [
                                {"name": "X-Proxy-Cache", "value": "HIT"}
                            ],
                            "content": {"text": "{}"}
                        },
                        "timings": {
                            "send": 5,
                            "wait": 100,
                            "receive": 10
                        }
                    }
                ]
            }
        }
        
        har_file = temp_directory / "proxy_test.har"
        har_file.write_text(json.dumps(har_with_proxy))
        
        result = await har_parser.parse(har_file)
        
        assert len(result.network_traces) == 1
        trace = result.network_traces[0]
        
        # Verify proxy detection
        assert trace.metadata['has_proxy_headers'] is True
        assert result.statistics['proxy_indicators'] == 1
        assert result.statistics['proxy_detection_risk'] == 100.0
    
    @pytest.mark.asyncio
    async def test_parse_ip_detection_services(self, har_parser, temp_directory):
        """Test parsing HAR with IP detection service requests."""
        har_with_ip_services = {
            "log": {
                "version": "1.2",
                "entries": [
                    {
                        "startedDateTime": "2023-01-01T00:00:00.000Z",
                        "request": {
                            "method": "GET",
                            "url": "https://ipinfo.io/json",
                            "headers": []
                        },
                        "response": {
                            "status": 200,
                            "statusText": "OK",
                            "headers": [],
                            "content": {
                                "text": '{"ip": "203.0.113.1", "country": "US"}'
                            }
                        },
                        "timings": {"wait": 100, "receive": 10}
                    },
                    {
                        "startedDateTime": "2023-01-01T00:00:01.000Z",
                        "request": {
                            "method": "GET",
                            "url": "https://api.ipify.org",
                            "headers": []
                        },
                        "response": {
                            "status": 200,
                            "statusText": "OK",
                            "headers": [],
                            "content": {"text": "203.0.113.1"}
                        },
                        "timings": {"wait": 80, "receive": 5}
                    }
                ]
            }
        }
        
        har_file = temp_directory / "ip_services.har"
        har_file.write_text(json.dumps(har_with_ip_services))
        
        result = await har_parser.parse(har_file)
        
        assert len(result.network_traces) == 2
        assert result.statistics['ip_detection_requests'] == 2
        
        # Verify IP detection service detection
        for trace in result.network_traces:
            assert trace.metadata['is_ip_detection'] is True
    
    @pytest.mark.asyncio
    async def test_parse_oauth_requests(self, har_parser, temp_directory):
        """Test parsing HAR with OAuth-related requests."""
        har_with_oauth = {
            "log": {
                "version": "1.2",
                "entries": [
                    {
                        "startedDateTime": "2023-01-01T00:00:00.000Z",
                        "request": {
                            "method": "POST",
                            "url": "https://accounts.google.com/oauth/token",
                            "headers": [
                                {"name": "Content-Type", "value": "application/x-www-form-urlencoded"}
                            ],
                            "postData": {
                                "text": "grant_type=authorization_code&code=abc123"
                            }
                        },
                        "response": {
                            "status": 200,
                            "statusText": "OK",
                            "headers": [],
                            "content": {
                                "text": '{"access_token": "token123", "token_type": "Bearer"}'
                            }
                        },
                        "timings": {"wait": 200, "receive": 15}
                    }
                ]
            }
        }
        
        har_file = temp_directory / "oauth_test.har"
        har_file.write_text(json.dumps(har_with_oauth))
        
        result = await har_parser.parse(har_file)
        
        assert len(result.network_traces) == 1
        trace = result.network_traces[0]
        
        assert trace.metadata['is_oauth'] is True
        assert result.statistics['oauth_requests'] == 1
    
    @pytest.mark.asyncio
    async def test_parse_with_event_bus(self, har_parser_with_event_bus, sample_har_data, temp_directory):
        """Test parsing with event bus notifications."""
        har_file = temp_directory / "event_test.har"
        har_file.write_text(json.dumps(sample_har_data))
        
        # Mock event bus to capture events
        events_captured = []
        original_emit = har_parser_with_event_bus.event_bus.emit
        
        def mock_emit(event_type, data):
            events_captured.append((event_type, data))
            return original_emit(event_type, data)
        
        har_parser_with_event_bus.event_bus.emit = mock_emit
        
        result = await har_parser_with_event_bus.parse(har_file)
        
        # Verify events were emitted
        event_types = [event[0] for event in events_captured]
        assert "har_parse_started" in event_types
        assert "har_parse_completed" in event_types
        
        # Verify result
        assert len(result.network_traces) == 2
    
    @pytest.mark.asyncio
    async def test_validate_format_valid_har(self, har_parser, sample_har_data, temp_directory):
        """Test format validation with valid HAR file."""
        har_file = temp_directory / "valid.har"
        har_file.write_text(json.dumps(sample_har_data))
        
        is_valid = await har_parser._validate_format(har_file)
        assert is_valid is True
    
    @pytest.mark.asyncio
    async def test_validate_format_invalid_file(self, har_parser, temp_directory):
        """Test format validation with invalid file."""
        # Create non-HAR file
        invalid_file = temp_directory / "invalid.txt"
        invalid_file.write_text("This is not a HAR file")
        
        is_valid = await har_parser._validate_format(invalid_file)
        assert is_valid is False
    
    @pytest.mark.asyncio
    async def test_validate_format_nonexistent_file(self, har_parser):
        """Test format validation with nonexistent file."""
        is_valid = await har_parser._validate_format(Path("nonexistent.har"))
        assert is_valid is False
    
    def test_extract_request_body_text(self, har_parser):
        """Test extracting request body from text."""
        post_data = {"text": "username=test&password=secret"}
        body = har_parser._extract_request_body(post_data)
        assert body == "username=test&password=secret"
    
    def test_extract_request_body_params(self, har_parser):
        """Test extracting request body from params."""
        post_data = {
            "params": [
                {"name": "username", "value": "test"},
                {"name": "password", "value": "secret"}
            ]
        }
        body = har_parser._extract_request_body(post_data)
        assert body == "username=test&password=secret"
    
    def test_extract_request_body_empty(self, har_parser):
        """Test extracting request body from empty data."""
        body = har_parser._extract_request_body({})
        assert body is None
        
        body = har_parser._extract_request_body(None)
        assert body is None
    
    def test_extract_response_body(self, har_parser):
        """Test extracting response body."""
        content = {"text": '{"status": "success"}'}
        body = har_parser._extract_response_body(content)
        assert body == '{"status": "success"}'
        
        # Test empty content
        body = har_parser._extract_response_body({})
        assert body is None
    
    def test_parse_timestamp_valid(self, har_parser):
        """Test parsing valid timestamp."""
        timestamp_str = "2023-01-01T12:30:45.123Z"
        dt = har_parser._parse_timestamp(timestamp_str)
        
        assert dt is not None
        assert dt.year == 2023
        assert dt.month == 1
        assert dt.day == 1
        assert dt.hour == 12
        assert dt.minute == 30
        assert dt.second == 45
    
    def test_parse_timestamp_invalid(self, har_parser):
        """Test parsing invalid timestamp."""
        dt = har_parser._parse_timestamp("invalid-timestamp")
        assert dt is None
        
        dt = har_parser._parse_timestamp(None)
        assert dt is None
    
    def test_statistics_initialization(self, har_parser):
        """Test statistics initialization."""
        stats = har_parser._init_statistics()
        
        assert stats['total_requests'] == 0
        assert stats['successful_responses'] == 0
        assert stats['proxy_indicators'] == 0
        assert isinstance(stats['unique_domains'], set)
        assert isinstance(stats['response_times'], list)
    
    def test_statistics_finalization(self, har_parser):
        """Test statistics finalization."""
        stats = har_parser._init_statistics()
        stats['total_requests'] = 10
        stats['successful_responses'] = 8
        stats['proxy_indicators'] = 2
        stats['unique_domains'].add('example.com')
        stats['unique_domains'].add('test.com')
        stats['response_times'] = [100, 200, 150]
        stats['ssl_times'] = [50, 75]
        
        har_parser._finalize_statistics(stats, [])
        
        # Verify calculations
        assert stats['unique_domains'] == 2
        assert stats['success_rate'] == 80.0
        assert stats['proxy_detection_risk'] == 20.0
        assert stats['average_response_time'] == 150.0
        assert stats['max_response_time'] == 200
        assert stats['min_response_time'] == 100
        assert stats['average_ssl_time'] == 62.5
        assert stats['max_ssl_time'] == 75
        
        # Verify cleanup
        assert 'response_times' not in stats
        assert 'ssl_times' not in stats
    
    @pytest.mark.asyncio
    async def test_parse_with_progress_events(self, har_parser_with_event_bus, temp_directory):
        """Test parsing with progress events for large files."""
        # Create HAR with enough entries to trigger progress events
        entries = []
        for i in range(150):  # More than 100 to trigger progress event
            entry = {
                "startedDateTime": f"2023-01-01T00:00:{i:02d}.000Z",
                "request": {
                    "method": "GET",
                    "url": f"https://example.com/api/{i}",
                    "headers": []
                },
                "response": {
                    "status": 200,
                    "statusText": "OK",
                    "headers": [],
                    "content": {"text": "{}"}
                },
                "timings": {"wait": 100, "receive": 10}
            }
            entries.append(entry)
        
        large_har = {
            "log": {
                "version": "1.2",
                "entries": entries
            }
        }
        
        har_file = temp_directory / "progress_test.har"
        har_file.write_text(json.dumps(large_har))
        
        # Capture events
        events_captured = []
        original_emit = har_parser_with_event_bus.event_bus.emit
        
        def mock_emit(event_type, data):
            events_captured.append((event_type, data))
            return original_emit(event_type, data)
        
        har_parser_with_event_bus.event_bus.emit = mock_emit
        
        result = await har_parser_with_event_bus.parse(har_file)
        
        # Verify progress events were emitted
        progress_events = [e for e in events_captured if e[0] == "har_entries_processed"]
        assert len(progress_events) >= 1  # Should have at least one progress event
        
        # Verify final result
        assert len(result.network_traces) == 150
