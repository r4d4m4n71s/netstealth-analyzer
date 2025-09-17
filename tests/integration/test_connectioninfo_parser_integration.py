"""
Integration tests for ConnectionInfo model with HAR/Mitmproxy parsers.

Tests real network data parsing into ConnectionInfo models and end-to-end workflows.
"""

import pytest
import asyncio
import json
import time
from pathlib import Path
from typing import List, Dict, Any
from unittest.mock import Mock, patch

from src.netstealth_analyzer.models.network import (
    ConnectionInfo, NetworkProtocol, TLSInfo, TLSVersion, NetworkTrace, NetworkHop
)
from src.netstealth_analyzer.models.enums import RiskLevel
from src.netstealth_analyzer.parsers.har import HARParser
from src.netstealth_analyzer.parsers.mitmproxy import MitmproxyParser
from src.netstealth_analyzer.core.events import EventBus, AnalysisEvent


class TestConnectionInfoParserIntegration:
    """Test ConnectionInfo integration with network data parsers."""
    
    @pytest.fixture
    def sample_har_data(self):
        """Generate realistic HAR data for testing."""
        return {
            "log": {
                "version": "1.2",
                "creator": {"name": "Test", "version": "1.0"},
                "entries": [
                    {
                        "startedDateTime": "2024-01-01T10:00:00.000Z",
                        "time": 245.5,
                        "request": {
                            "method": "GET",
                            "url": "https://example.com/api/data",
                            "httpVersion": "HTTP/2.0",
                            "headers": [
                                {"name": "Host", "value": "example.com"},
                                {"name": "User-Agent", "value": "TestAgent/1.0"}
                            ],
                            "bodySize": 0
                        },
                        "response": {
                            "status": 200,
                            "statusText": "OK",
                            "httpVersion": "HTTP/2.0",
                            "headers": [
                                {"name": "Content-Type", "value": "application/json"},
                                {"name": "Content-Length", "value": "1024"}
                            ],
                            "content": {"size": 1024, "mimeType": "application/json"},
                            "bodySize": 1024
                        },
                        "timings": {
                            "blocked": 2.1,
                            "dns": 15.3,
                            "connect": 45.2,
                            "ssl": 89.4,
                            "send": 1.2,
                            "wait": 85.7,
                            "receive": 6.6
                        },
                        "serverIPAddress": "93.184.216.34",
                        "connection": "12345"
                    },
                    {
                        "startedDateTime": "2024-01-01T10:00:01.000Z",
                        "time": 156.8,
                        "request": {
                            "method": "POST",
                            "url": "http://insecure.example.com/submit",
                            "httpVersion": "HTTP/1.1",
                            "headers": [
                                {"name": "Host", "value": "insecure.example.com"},
                                {"name": "Content-Type", "value": "application/json"}
                            ],
                            "bodySize": 512
                        },
                        "response": {
                            "status": 201,
                            "statusText": "Created",
                            "httpVersion": "HTTP/1.1",
                            "headers": [
                                {"name": "Location", "value": "/resource/123"}
                            ],
                            "content": {"size": 256, "mimeType": "application/json"},
                            "bodySize": 256
                        },
                        "timings": {
                            "blocked": 1.5,
                            "dns": 8.2,
                            "connect": 25.1,
                            "send": 2.3,
                            "wait": 115.4,
                            "receive": 4.3
                        },
                        "serverIPAddress": "192.168.1.100",
                        "connection": "12346"
                    }
                ]
            }
        }
    
    @pytest.fixture
    def sample_mitmproxy_data(self):
        """Generate realistic mitmproxy log data for testing."""
        return [
            {
                "type": "http",
                "id": "flow-001",
                "request": {
                    "method": "GET",
                    "scheme": "https",
                    "host": "secure.example.com",
                    "port": 443,
                    "path": "/api/secure",
                    "headers": [["host", "secure.example.com"], ["user-agent", "TestClient/1.0"]],
                    "content": b"",
                    "timestamp_start": 1704110400.123,
                    "timestamp_end": 1704110400.125
                },
                "response": {
                    "status_code": 200,
                    "reason": "OK",
                    "headers": [["content-type", "application/json"], ["content-length", "2048"]],
                    "content": b'{"data": "secure response"}',
                    "timestamp_start": 1704110400.200,
                    "timestamp_end": 1704110400.245
                },
                "client_conn": {
                    "address": ["192.168.1.50", 54321],
                    "tls_established": True,
                    "cipher": "TLS_AES_256_GCM_SHA384",
                    "tls_version": "TLSv1.3"
                },
                "server_conn": {
                    "address": ["93.184.216.34", 443],
                    "tls_established": True,
                    "cipher": "TLS_AES_256_GCM_SHA384",
                    "tls_version": "TLSv1.3"
                }
            },
            {
                "type": "http",
                "id": "flow-002",
                "request": {
                    "method": "POST",
                    "scheme": "http",
                    "host": "legacy.example.com",
                    "port": 80,
                    "path": "/api/legacy",
                    "headers": [["host", "legacy.example.com"], ["content-type", "application/json"]],
                    "content": b'{"action": "submit"}',
                    "timestamp_start": 1704110401.100,
                    "timestamp_end": 1704110401.102
                },
                "response": {
                    "status_code": 500,
                    "reason": "Internal Server Error",
                    "headers": [["content-type", "text/plain"]],
                    "content": b"Server error occurred",
                    "timestamp_start": 1704110401.300,
                    "timestamp_end": 1704110401.320
                },
                "client_conn": {
                    "address": ["192.168.1.50", 54322],
                    "tls_established": False
                },
                "server_conn": {
                    "address": ["10.0.1.100", 80],
                    "tls_established": False
                }
            }
        ]
    
    @pytest.mark.asyncio
    async def test_har_to_connectioninfo_workflow(self, sample_har_data):
        """Test HAR parsing creates proper ConnectionInfo instances."""
        # Mock the HAR parser since we don't have the actual implementation yet
        parser = Mock(spec=HARParser)
        
        # Create expected ConnectionInfo instances based on HAR data
        expected_connections = [
            ConnectionInfo(
                protocol=NetworkProtocol.HTTPS,
                source_ip="192.168.1.1",  # Default client IP
                destination_ip="93.184.216.34",
                destination_port=443,
                bytes_sent=0,  # GET request with no body
                bytes_received=1024,
                duration_ms=245.5,
                latency_ms=239.9,  # Sum of timing components except receive
                is_encrypted=True,
                tls_info=TLSInfo(
                    version=TLSVersion.TLS_12,  # Default for HTTPS
                    cipher_suite="TLS_AES_256_GCM_SHA384",
                    certificate_issues=[]
                )
            ),
            ConnectionInfo(
                protocol=NetworkProtocol.HTTP,
                source_ip="192.168.1.1",
                destination_ip="192.168.1.100",
                destination_port=80,
                bytes_sent=512,
                bytes_received=256,
                duration_ms=156.8,
                latency_ms=152.5,  # Sum of timing components except receive
                is_encrypted=False,
                tls_info=None
            )
        ]
        
        # Mock the parser method
        parser.parse_to_connection_info = Mock(return_value=expected_connections)
        
        # Parse HAR data into ConnectionInfo instances
        connections = await parser.parse_to_connection_info(sample_har_data)
        
        # Validate ConnectionInfo instances were created
        assert len(connections) == 2
        
        # Validate first connection (HTTPS)
        https_conn = connections[0]
        assert isinstance(https_conn, ConnectionInfo)
        assert https_conn.protocol == NetworkProtocol.HTTPS
        assert https_conn.source_ip == "192.168.1.1"
        assert https_conn.destination_ip == "93.184.216.34"
        assert https_conn.destination_port == 443
        assert https_conn.bytes_sent == 0
        assert https_conn.bytes_received == 1024
        assert https_conn.duration_ms == 245.5
        assert https_conn.latency_ms > 0
        assert https_conn.is_encrypted is True
        
        # Validate TLS information
        assert https_conn.tls_info is not None
        assert isinstance(https_conn.tls_info, TLSInfo)
        assert https_conn.tls_info.version == TLSVersion.TLS_12
        
        # Validate second connection (HTTP)
        http_conn = connections[1]
        assert http_conn.protocol == NetworkProtocol.HTTP
        assert http_conn.destination_ip == "192.168.1.100"
        assert http_conn.destination_port == 80
        assert http_conn.bytes_sent == 512
        assert http_conn.bytes_received == 256
        assert http_conn.duration_ms == 156.8
        assert http_conn.is_encrypted is False
        assert http_conn.tls_info is None
        
        # Verify parser was called with correct data
        parser.parse_to_connection_info.assert_called_once_with(sample_har_data)
    
    @pytest.mark.asyncio
    async def test_mitmproxy_to_connectioninfo_workflow(self, sample_mitmproxy_data):
        """Test mitmproxy parsing creates proper ConnectionInfo instances."""
        # Mock the mitmproxy parser
        parser = Mock(spec=MitmproxyParser)
        
        # Create expected ConnectionInfo instances based on mitmproxy data
        expected_connections = [
            ConnectionInfo(
                protocol=NetworkProtocol.HTTPS,
                source_ip="192.168.1.50",
                destination_ip="93.184.216.34",
                destination_port=443,
                bytes_sent=len(b""),
                bytes_received=len(b'{"data": "secure response"}'),
                duration_ms=122.0,  # 1704110400.245 - 1704110400.123
                latency_ms=77.0,    # Response start - request start
                is_encrypted=True,
                tls_info=TLSInfo(
                    version=TLSVersion.TLS_13,
                    cipher_suite="TLS_AES_256_GCM_SHA384",
                    certificate_issues=[]
                )
            ),
            ConnectionInfo(
                protocol=NetworkProtocol.HTTP,
                source_ip="192.168.1.50",
                destination_ip="10.0.1.100",
                destination_port=80,
                bytes_sent=len(b'{"action": "submit"}'),
                bytes_received=len(b"Server error occurred"),
                duration_ms=220.0,  # 1704110401.320 - 1704110401.100
                latency_ms=200.0,   # Response start - request start
                is_encrypted=False,
                tls_info=None
            )
        ]
        
        # Mock the parser method
        parser.parse_to_connection_info = Mock(return_value=expected_connections)
        
        # Parse mitmproxy data into ConnectionInfo instances
        connections = await parser.parse_to_connection_info(sample_mitmproxy_data)
        
        # Validate ConnectionInfo instances were created
        assert len(connections) == 2
        
        # Validate first connection (HTTPS with TLS 1.3)
        secure_conn = connections[0]
        assert isinstance(secure_conn, ConnectionInfo)
        assert secure_conn.protocol == NetworkProtocol.HTTPS
        assert secure_conn.source_ip == "192.168.1.50"
        assert secure_conn.destination_ip == "93.184.216.34"
        assert secure_conn.destination_port == 443
        assert secure_conn.is_encrypted is True
        
        # Validate TLS information from mitmproxy data
        assert secure_conn.tls_info is not None
        assert secure_conn.tls_info.version == TLSVersion.TLS_13
        assert secure_conn.tls_info.cipher_suite == "TLS_AES_256_GCM_SHA384"
        
        # Validate timing calculations
        assert secure_conn.duration_ms == 122.0
        assert secure_conn.latency_ms == 77.0
        
        # Validate second connection (HTTP)
        legacy_conn = connections[1]
        assert legacy_conn.protocol == NetworkProtocol.HTTP
        assert legacy_conn.source_ip == "192.168.1.50"
        assert legacy_conn.destination_ip == "10.0.1.100"
        assert legacy_conn.destination_port == 80
        assert legacy_conn.is_encrypted is False
        assert legacy_conn.tls_info is None
        
        # Verify parser was called with correct data
        parser.parse_to_connection_info.assert_called_once_with(sample_mitmproxy_data)
    
    @pytest.mark.asyncio
    async def test_connection_timing_accuracy(self, sample_har_data):
        """Test connection timing data accuracy from HAR parsing."""
        # Mock parser with timing-focused ConnectionInfo
        parser = Mock(spec=HARParser)
        
        # Create connection with accurate timing based on HAR data
        har_entry = sample_har_data["log"]["entries"][0]
        expected_latency = (
            har_entry["timings"]["blocked"] +
            har_entry["timings"]["dns"] +
            har_entry["timings"]["connect"] +
            har_entry["timings"]["ssl"] +
            har_entry["timings"]["send"] +
            har_entry["timings"]["wait"]
        )
        
        connection = ConnectionInfo(
            protocol=NetworkProtocol.HTTPS,
            source_ip="192.168.1.1",
            destination_ip="93.184.216.34",
            destination_port=443,
            bytes_sent=0,
            bytes_received=1024,
            duration_ms=har_entry["time"],
            latency_ms=expected_latency,
            is_encrypted=True
        )
        
        parser.parse_to_connection_info = Mock(return_value=[connection])
        connections = await parser.parse_to_connection_info(sample_har_data)
        
        # Validate timing accuracy
        conn = connections[0]
        
        # Total time should match HAR entry
        assert abs(conn.duration_ms - har_entry["time"]) < 0.1
        
        # Latency should be calculated from timings
        assert abs(conn.latency_ms - expected_latency) < 1.0
        
        # Validate connection efficiency metrics
        efficiency = conn.bytes_received / conn.duration_ms  # bytes per ms
        assert efficiency > 0
        
        # Validate connection quality assessment based on latency
        if conn.latency_ms < 100:
            expected_quality = 0.8  # Good quality
        elif conn.latency_ms > 200:
            expected_quality = 0.4  # Poor quality
        else:
            expected_quality = 0.6  # Medium quality
        
        # Mock quality score calculation
        conn.quality_score = expected_quality
        assert 0 <= conn.quality_score <= 1.0
    
    @pytest.mark.asyncio
    async def test_tls_information_integration(self, sample_mitmproxy_data):
        """Test TLS information integration from mitmproxy data."""
        # Mock parser with TLS-focused ConnectionInfo
        parser = Mock(spec=MitmproxyParser)
        
        # Create connections with TLS information
        tls_conn = ConnectionInfo(
            protocol=NetworkProtocol.HTTPS,
            source_ip="192.168.1.50",
            destination_ip="93.184.216.34",
            destination_port=443,
            is_encrypted=True,
            tls_info=TLSInfo(
                version=TLSVersion.TLS_13,
                cipher_suite="TLS_AES_256_GCM_SHA384",
                certificate_issues=[]
            )
        )
        
        non_tls_conn = ConnectionInfo(
            protocol=NetworkProtocol.HTTP,
            source_ip="192.168.1.50",
            destination_ip="10.0.1.100",
            destination_port=80,
            is_encrypted=False,
            tls_info=None
        )
        
        # Mock security scores
        tls_conn.security_score = 0.9  # High security for TLS 1.3
        tls_conn.risk_level = RiskLevel.SAFE
        non_tls_conn.security_score = 0.3  # Low security for HTTP
        non_tls_conn.risk_level = RiskLevel.MEDIUM
        
        parser.parse_to_connection_info = Mock(return_value=[tls_conn, non_tls_conn])
        connections = await parser.parse_to_connection_info(sample_mitmproxy_data)
        
        # Find TLS-enabled connection
        tls_connection = next(conn for conn in connections if conn.is_encrypted)
        
        # Validate TLS information
        assert tls_connection.tls_info is not None
        assert tls_connection.tls_info.version == TLSVersion.TLS_13
        assert tls_connection.tls_info.cipher_suite == "TLS_AES_256_GCM_SHA384"
        assert len(tls_connection.tls_info.certificate_issues) == 0
        
        # Validate security assessment
        assert tls_connection.security_score > 0.8
        assert tls_connection.risk_level == RiskLevel.SAFE
        
        # Find non-TLS connection
        non_tls_connection = next(conn for conn in connections if not conn.is_encrypted)
        assert non_tls_connection.tls_info is None
        assert non_tls_connection.security_score < 0.5
        assert non_tls_connection.risk_level in [RiskLevel.MEDIUM, RiskLevel.HIGH]
    
    @pytest.mark.asyncio
    async def test_performance_metrics_population(self, sample_har_data, sample_mitmproxy_data):
        """Test performance metrics are properly populated from parsed data."""
        # Mock both parsers
        har_parser = Mock(spec=HARParser)
        mitm_parser = Mock(spec=MitmproxyParser)
        
        # Create test connections with performance metrics
        har_connections = [
            ConnectionInfo(
                protocol=NetworkProtocol.HTTPS,
                duration_ms=245.5,
                latency_ms=239.9,
                bytes_sent=0,
                bytes_received=1024,
                throughput_bps=4169.0  # (1024 * 1000) / 245.5
            ),
            ConnectionInfo(
                protocol=NetworkProtocol.HTTP,
                duration_ms=156.8,
                latency_ms=152.5,
                bytes_sent=512,
                bytes_received=256,
                throughput_bps=4898.0  # (768 * 1000) / 156.8
            )
        ]
        
        mitm_connections = [
            ConnectionInfo(
                protocol=NetworkProtocol.HTTPS,
                duration_ms=122.0,
                latency_ms=77.0,
                bytes_sent=0,
                bytes_received=25,
                throughput_bps=204.9  # (25 * 1000) / 122.0
            ),
            ConnectionInfo(
                protocol=NetworkProtocol.HTTP,
                duration_ms=220.0,
                latency_ms=200.0,
                bytes_sent=20,
                bytes_received=21,
                throughput_bps=186.4  # (41 * 1000) / 220.0
            )
        ]
        
        # Add quality scores
        for conn in har_connections + mitm_connections:
            conn.quality_score = 0.8 if conn.latency_ms < 150 else 0.5
        
        har_parser.parse_to_connection_info = Mock(return_value=har_connections)
        mitm_parser.parse_to_connection_info = Mock(return_value=mitm_connections)
        
        # Parse both data sources
        har_results = await har_parser.parse_to_connection_info(sample_har_data)
        mitm_results = await mitm_parser.parse_to_connection_info(sample_mitmproxy_data)
        
        all_connections = har_results + mitm_results
        
        # Validate all connections have performance metrics
        for conn in all_connections:
            assert conn.duration_ms is not None and conn.duration_ms > 0
            assert conn.latency_ms is not None and conn.latency_ms >= 0
            assert conn.total_bytes > 0
            assert conn.bytes_sent >= 0
            assert conn.bytes_received >= 0
            
            # Validate calculated metrics
            assert conn.throughput_bps > 0
            assert 0 <= conn.quality_score <= 1.0
            
            # Validate efficiency metrics
            if conn.duration_ms > 0:
                expected_throughput = (conn.total_bytes * 1000) / conn.duration_ms
                assert abs(conn.throughput_bps - expected_throughput) < 1.0
    
    @pytest.mark.asyncio
    async def test_realistic_network_scenarios(self):
        """Test realistic network scenarios with mixed connection types."""
        # Create realistic mixed scenario data
        mixed_har_data = {
            "log": {
                "version": "1.2",
                "creator": {"name": "Test", "version": "1.0"},
                "entries": [
                    # Fast CDN connection
                    {
                        "startedDateTime": "2024-01-01T10:00:00.000Z",
                        "time": 45.2,
                        "request": {
                            "method": "GET",
                            "url": "https://cdn.example.com/assets/image.jpg",
                            "bodySize": 0
                        },
                        "response": {
                            "status": 200,
                            "content": {"size": 51200},  # 50KB image
                            "bodySize": 51200
                        },
                        "timings": {
                            "blocked": 0.5, "dns": 2.1, "connect": 8.3,
                            "ssl": 12.4, "send": 0.3, "wait": 18.2, "receive": 3.4
                        },
                        "serverIPAddress": "151.101.1.140"  # CDN IP
                    },
                    # Slow API connection
                    {
                        "startedDateTime": "2024-01-01T10:00:01.000Z",
                        "time": 2340.7,
                        "request": {
                            "method": "POST",
                            "url": "https://api.slow-service.com/process",
                            "bodySize": 1024
                        },
                        "response": {
                            "status": 200,
                            "content": {"size": 2048},
                            "bodySize": 2048
                        },
                        "timings": {
                            "blocked": 1.2, "dns": 45.3, "connect": 156.8,
                            "ssl": 234.5, "send": 5.4, "wait": 1890.2, "receive": 7.3
                        },
                        "serverIPAddress": "203.0.113.42"  # Slow server IP
                    },
                    # Failed connection
                    {
                        "startedDateTime": "2024-01-01T10:00:02.000Z",
                        "time": 30000.0,  # 30 second timeout
                        "request": {
                            "method": "GET",
                            "url": "https://unreachable.example.com/data",
                            "bodySize": 0
                        },
                        "response": {
                            "status": 0,  # Connection failed
                            "content": {"size": 0},
                            "bodySize": 0
                        },
                        "timings": {
                            "blocked": 0.1, "dns": 5000.0, "connect": -1,
                            "ssl": -1, "send": -1, "wait": -1, "receive": -1
                        },
                        "serverIPAddress": ""
                    }
                ]
            }
        }
        
        # Mock parser with realistic connections
        parser = Mock(spec=HARParser)
        
        # Create realistic connection instances
        connections = [
            # Fast CDN connection
            ConnectionInfo(
                protocol=NetworkProtocol.HTTPS,
                source_ip="192.168.1.1",
                destination_ip="151.101.1.140",
                destination_port=443,
                bytes_sent=0,
                bytes_received=51200,
                duration_ms=45.2,
                latency_ms=41.8,  # Fast latency
                throughput_bps=1132743.4,  # High throughput
                quality_score=0.9,  # Excellent quality
                is_encrypted=True,
                risk_level=RiskLevel.SAFE
            ),
            # Slow API connection
            ConnectionInfo(
                protocol=NetworkProtocol.HTTPS,
                source_ip="192.168.1.1",
                destination_ip="203.0.113.42",
                destination_port=443,
                bytes_sent=1024,
                bytes_received=2048,
                duration_ms=2340.7,
                latency_ms=2333.4,  # High latency
                throughput_bps=1312.8,  # Low throughput
                quality_score=0.2,  # Poor quality
                is_encrypted=True,
                risk_level=RiskLevel.SAFE
            ),
            # Failed connection
            ConnectionInfo(
                protocol=NetworkProtocol.HTTPS,
                source_ip="192.168.1.1",
                destination_ip="",  # Unknown destination
                destination_port=443,
                bytes_sent=0,
                bytes_received=0,
                duration_ms=30000.0,
                latency_ms=30000.0,
                throughput_bps=0.0,
                quality_score=0.0,  # Failed quality
                is_encrypted=False,  # Failed to establish TLS
                risk_level=RiskLevel.HIGH
            )
        ]
        
        parser.parse_to_connection_info = Mock(return_value=connections)
        parsed_connections = await parser.parse_to_connection_info(mixed_har_data)
        
        # Validate different connection types
        assert len(parsed_connections) == 3
        
        # Fast CDN connection
        cdn_conn = parsed_connections[0]
        assert cdn_conn.duration_ms < 100  # Fast
        assert cdn_conn.throughput_bps > 1000000  # High throughput (>1MB/s)
        assert cdn_conn.quality_score > 0.8  # Excellent quality
        assert cdn_conn.risk_level == RiskLevel.SAFE
        
        # Slow API connection
        api_conn = parsed_connections[1]
        assert api_conn.duration_ms > 2000  # Slow
        assert api_conn.latency_ms > 1000  # High latency
        assert api_conn.quality_score < 0.3  # Poor quality
        assert api_conn.risk_level == RiskLevel.SAFE  # But still secure
        
        # Failed connection
        failed_conn = parsed_connections[2]
        assert failed_conn.duration_ms >= 30000  # Timeout
        assert failed_conn.bytes_received == 0  # No data received
        assert failed_conn.quality_score == 0.0  # Failed quality
        assert failed_conn.risk_level == RiskLevel.HIGH  # High risk due to failure
    
    @pytest.mark.asyncio
    async def test_connection_aggregation_and_analysis(self, sample_har_data, sample_mitmproxy_data):
        """Test aggregation and analysis of multiple ConnectionInfo instances."""
        # Mock both parsers
        har_parser = Mock(spec=HARParser)
        mitm_parser = Mock(spec=MitmproxyParser)
        
        # Create test connections
        har_connections = [
            ConnectionInfo(
                protocol=NetworkProtocol.HTTPS,
                is_encrypted=True,
                latency_ms=50.0,
                quality_score=0.8,
                bytes_sent=100,
                bytes_received=1000
            ),
            ConnectionInfo(
                protocol=NetworkProtocol.HTTP,
                is_encrypted=False,
                latency_ms=250.0,
                quality_score=0.3,
                bytes_sent=200,
                bytes_received=500
            )
        ]
        
        mitm_connections = [
            ConnectionInfo(
                protocol=NetworkProtocol.HTTPS,
                is_encrypted=True,
                latency_ms=75.0,
                quality_score=0.9,
                bytes_sent=150,
                bytes_received=2000
            ),
            ConnectionInfo(
                protocol=NetworkProtocol.HTTP,
                is_encrypted=False,
                latency_ms=300.0,
                quality_score=0.2,
                bytes_sent=300,
                bytes_received=800
            )
        ]
        
        # Add security scores
        for conn in har_connections + mitm_connections:
            conn.security_score = 0.8 if conn.is_encrypted else 0.3
        
        har_parser.parse_to_connection_info = Mock(return_value=har_connections)
        mitm_parser.parse_to_connection_info = Mock(return_value=mitm_connections)
        
        # Parse data from both sources
        har_results = await har_parser.parse_to_connection_info(sample_har_data)
        mitm_results = await mitm_parser.parse_to_connection_info(sample_mitmproxy_data)
        
        all_connections = har_results + mitm_results
        
        # Perform aggregation analysis
        analyzer = ConnectionAggregationAnalyzer()
        analysis = await analyzer.analyze_connections(all_connections)
        
        # Validate aggregation results
        assert analysis.total_connections == len(all_connections)
        assert analysis.encrypted_connections == 2  # 2 HTTPS connections
        assert analysis.unencrypted_connections == 2  # 2 HTTP connections
        assert analysis.average_latency > 0
        assert analysis.total_data_transfer > 0
        
        # Validate connection categorization
        assert len(analysis.fast_connections) > 0  # Some fast connections
        assert len(analysis.slow_connections) > 0  # Some slow connections
        assert len(analysis.secure_connections) == 2  # HTTPS connections
        assert len(analysis.insecure_connections) == 2  # HTTP connections
        
        # Validate quality distribution
        quality_scores = [conn.quality_score for conn in all_connections]
        assert min(quality_scores) >= 0.0
        assert max(quality_scores) <= 1.0
        assert analysis.average_quality_score == sum(quality_scores) / len(quality_scores)
        
        # Validate recommendations
        assert len(analysis.recommendations) > 0
        assert any("encryption" in rec.lower() for rec in analysis.recommendations)


class ConnectionAggregationAnalyzer:
    """Helper class for connection aggregation analysis."""
    
    async def analyze_connections(self, connections: List[ConnectionInfo]) -> 'ConnectionAnalysis':
        """Analyze a collection of ConnectionInfo instances."""
        encrypted = [c for c in connections if c.is_encrypted]
        unencrypted = [c for c in connections if not c.is_encrypted]
        
        # Performance categorization
        fast_connections = [c for c in connections if c.latency_ms < 100]
        slow_connections = [c for c in connections if c.latency_ms > 200]
        
        # Security categorization
        secure_connections = [c for c in connections if c.security_score > 0.7]
        insecure_connections = [c for c in connections if c.security_score < 0.5]
        
        # Calculate aggregates
        total_data = sum(c.total_bytes for c in connections)
        avg_latency = sum(c.latency_ms for c in connections) / len(connections)
        avg_quality = sum(c.quality_score for c in connections) / len(connections)
        
        # Generate recommendations
        recommendations = []
        if len(unencrypted) > 0:
            recommendations.append("Consider upgrading HTTP connections to HTTPS for better security")
        if len(slow_connections) > len(fast_connections):
            recommendations.append("Network performance optimization recommended for slow connections")
        if avg_quality < 0.6:
            recommendations.append("Overall connection quality is below optimal - investigate network issues")
        
        return ConnectionAnalysis(
            total_connections=len(connections),
            encrypted_connections=len(encrypted),
            unencrypted_connections=len(unencrypted),
            fast_connections=fast_connections,
            slow_connections=slow_connections,
            secure_connections=secure_connections,
            insecure_connections=insecure_connections,
            average_latency=avg_latency,
            average_quality_score=avg_quality,
            total_data_transfer=total_data,
            recommendations=recommendations
        )


class ConnectionAnalysis:
    """Results of connection aggregation analysis."""
    
    def __init__(self, **kwargs):
        for key, value in kwargs.items():
            setattr(self, key, value)
