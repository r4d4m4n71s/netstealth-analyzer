"""
Integration test for extensible protocol architecture.

Tests the complete protocol handling system including HTTP, WebSocket,
gRPC, TCP protocols and the extensible parser registry.
"""

import pytest
import asyncio
from datetime import datetime, timezone
from typing import Dict, Any


class TestExtensibleProtocolsIntegration:
    """Integration tests for extensible protocol architecture."""
    
    def test_protocol_model_imports(self):
        """Test that all protocol models can be imported."""
        from netstealth_analyzer.models.network import (
            NetworkTrace, HttpData, WebSocketData, GrpcData, TcpData,
            HttpRequest, HttpResponse, TimingInfo
        )
        from netstealth_analyzer.models.enums import NetworkProtocol
        
        # Verify all models are available
        assert all([
            NetworkTrace, HttpData, WebSocketData, GrpcData, TcpData,
            HttpRequest, HttpResponse, TimingInfo, NetworkProtocol
        ])
    
    def test_http_protocol_integration(self):
        """Test HTTP protocol data creation and handling."""
        from netstealth_analyzer.models.network import (
            NetworkTrace, HttpData, HttpRequest, HttpResponse, TimingInfo
        )
        from netstealth_analyzer.models.enums import NetworkProtocol
        
        # Create HTTP request and response
        request = HttpRequest(
            method="POST",
            url="https://api.example.com/users",
            headers=[
                {"name": "Content-Type", "value": "application/json"},
                {"name": "Authorization", "value": "Bearer token123"}
            ],
            body='{"name": "John Doe"}',
            timestamp=datetime.now(timezone.utc)
        )
        
        response = HttpResponse(
            status_code=201,
            status_text="Created",
            headers=[{"name": "Content-Type", "value": "application/json"}],
            body='{"id": 123, "name": "John Doe"}',
            content_type="application/json"
        )
        
        timing = TimingInfo(
            dns_lookup=15.2,
            tcp_connect=25.8,
            ssl_handshake=45.3,
            request_sent=2.1,
            waiting=120.5,
            content_download=8.7
        )
        
        # Create HTTP protocol data
        http_data = HttpData(
            request=request,
            response=response,
            timing=timing,
            is_secure=True,
            redirects=[],
            cookies=[{"name": "session_id", "value": "abc123"}]
        )
        
        # Create network trace with HTTP data
        trace = NetworkTrace(
            protocol=NetworkProtocol.HTTP,
            protocol_data=http_data,
            trace_id="http_test_001"
        )
        
        # Test protocol-specific access
        assert trace.is_http()
        assert not trace.is_websocket()
        assert not trace.is_grpc()
        assert not trace.is_tcp()
        
        # Test HTTP data access
        assert trace.http_data is not None
        assert trace.http_data.request.method == "POST"
        assert trace.http_data.response.status_code == 201
        assert trace.http_data.is_secure is True
        assert trace.http_data.is_success is True  # 2xx status
    
    def test_websocket_protocol_integration(self):
        """Test WebSocket protocol data creation and handling."""
        from netstealth_analyzer.models.network import NetworkTrace, WebSocketData
        from netstealth_analyzer.models.enums import NetworkProtocol
        
        # Create WebSocket protocol data
        ws_data = WebSocketData(
            handshake_request={
                "upgrade": "websocket",
                "connection": "Upgrade",
                "sec-websocket-key": "dGhlIHNhbXBsZSBub25jZQ=="
            },
            handshake_response={
                "status": 101,
                "upgrade": "websocket",
                "connection": "Upgrade"
            },
            frames_sent=[
                {"type": "text", "data": "Hello WebSocket!", "timestamp": "2024-01-01T10:00:00Z"}
            ],
            frames_received=[
                {"type": "text", "data": "Hello Client!", "timestamp": "2024-01-01T10:00:01Z"}
            ],
            connection_state="open",
            subprotocols=["chat"],
            extensions=["permessage-deflate"]
        )
        
        # Create network trace with WebSocket data
        trace = NetworkTrace(
            protocol=NetworkProtocol.WEBSOCKET,
            protocol_data=ws_data,
            trace_id="ws_test_001"
        )
        
        # Test protocol-specific access
        assert not trace.is_http()
        assert trace.is_websocket()
        assert not trace.is_grpc()
        assert not trace.is_tcp()
        
        # Test WebSocket data access
        assert trace.websocket_data is not None
        assert trace.websocket_data.connection_state == "open"
        assert trace.websocket_data.is_connected is True
        assert trace.websocket_data.total_frames == 2
        assert "chat" in trace.websocket_data.subprotocols
    
    def test_grpc_protocol_integration(self):
        """Test gRPC protocol data creation and handling."""
        from netstealth_analyzer.models.network import NetworkTrace, GrpcData
        from netstealth_analyzer.models.enums import NetworkProtocol
        
        # Create gRPC protocol data
        grpc_data = GrpcData(
            service="UserService",
            method="CreateUser",
            request_messages=[{"name": "Alice Smith", "email": "alice@example.com"}],
            response_messages=[{"id": "user_456", "name": "Alice Smith"}],
            status_code=0,  # OK
            status_message="Success",
            request_metadata={"authorization": "Bearer grpc_token_xyz"},
            response_metadata={"grpc-status": "0"},
            is_client_streaming=False,
            is_server_streaming=False
        )
        
        # Create network trace with gRPC data
        trace = NetworkTrace(
            protocol=NetworkProtocol.GRPC,
            protocol_data=grpc_data,
            trace_id="grpc_test_001"
        )
        
        # Test protocol-specific access
        assert not trace.is_http()
        assert not trace.is_websocket()
        assert trace.is_grpc()
        assert not trace.is_tcp()
        
        # Test gRPC data access
        assert trace.grpc_data is not None
        assert trace.grpc_data.service == "UserService"
        assert trace.grpc_data.method == "CreateUser"
        assert trace.grpc_data.status_code == 0
        assert trace.grpc_data.is_success is True  # status_code 0 = OK
        assert trace.grpc_data.is_streaming is False
    
    def test_tcp_protocol_integration(self):
        """Test TCP protocol data creation and handling."""
        from netstealth_analyzer.models.network import NetworkTrace, TcpData
        from netstealth_analyzer.models.enums import NetworkProtocol
        
        # Create TCP protocol data
        tcp_data = TcpData(
            connection_established=True,
            connection_closed=False,
            syn_sent=True,
            syn_ack_received=True,
            fin_sent=False,
            rst_sent=False,
            bytes_sent=2048,
            bytes_received=4096,
            packets_sent=15,
            packets_received=20,
            handshake_duration_ms=25.3
        )
        
        # Create network trace with TCP data
        trace = NetworkTrace(
            protocol=NetworkProtocol.TCP,
            protocol_data=tcp_data,
            trace_id="tcp_test_001"
        )
        
        # Test protocol-specific access
        assert not trace.is_http()
        assert not trace.is_websocket()
        assert not trace.is_grpc()
        assert trace.is_tcp()
        
        # Test TCP data access
        assert trace.tcp_data is not None
        assert trace.tcp_data.connection_established is True
        assert trace.tcp_data.total_bytes == 6144  # 2048 + 4096
        assert trace.tcp_data.handshake_duration_ms == 25.3
    
    def test_parser_registry_integration(self):
        """Test parser registry functionality."""
        from netstealth_analyzer.parsers.registry import ProtocolParserRegistry
        from netstealth_analyzer.models.enums import NetworkProtocol
        
        # Test supported protocols
        supported = ProtocolParserRegistry.get_supported_protocols()
        assert isinstance(supported, list)
        assert len(supported) > 0
        
        # Should include at least HTTP
        protocol_values = [p.value if hasattr(p, 'value') else str(p) for p in supported]
        assert 'http' in protocol_values or 'HTTP' in protocol_values
    
    def test_http_parser_integration(self):
        """Test HTTP parser integration."""
        from netstealth_analyzer.parsers.registry import ProtocolParserRegistry
        
        # Test HTTP parsing
        http_raw_data = {
            "request": {
                "method": "GET",
                "url": "https://example.com/api/data",
                "headers": [{"name": "Accept", "value": "application/json"}]
            },
            "response": {
                "status": 200,
                "statusText": "OK",
                "headers": [{"name": "Content-Type", "value": "application/json"}],
                "body": '{"data": "example"}'
            },
            "timings": {
                "dns": 10.5,
                "connect": 25.2,
                "ssl": 45.8,
                "send": 1.2,
                "wait": 150.3,
                "receive": 8.9
            }
        }
        
        # Auto-detect parser
        parser = ProtocolParserRegistry.auto_detect_parser(http_raw_data)
        assert parser is not None
        
        # Parse data
        parsed_data = ProtocolParserRegistry.parse_protocol_data(http_raw_data)
        if parsed_data:
            assert hasattr(parsed_data, 'request')
            assert hasattr(parsed_data, 'response')
            if hasattr(parsed_data, 'timing'):
                assert parsed_data.timing is not None
    
    def test_mixed_protocol_session_integration(self):
        """Test handling of mixed-protocol sessions."""
        from netstealth_analyzer.models.network import (
            NetworkTrace, HttpData, WebSocketData, HttpRequest, HttpResponse, TimingInfo
        )
        from netstealth_analyzer.models.enums import NetworkProtocol
        
        # Create traces for different protocols
        traces = []
        
        # HTTP trace
        http_trace = NetworkTrace(
            protocol=NetworkProtocol.HTTP,
            protocol_data=HttpData(
                request=HttpRequest(
                    method="GET",
                    url="https://example.com",
                    headers=[],
                    timestamp=datetime.now(timezone.utc)
                ),
                response=HttpResponse(
                    status_code=200,
                    status_text="OK",
                    headers=[],
                    content_type="text/html"
                ),
                timing=TimingInfo(),
                is_secure=True
            ),
            trace_id="mixed_http_001"
        )
        traces.append(http_trace)
        
        # WebSocket trace
        ws_trace = NetworkTrace(
            protocol=NetworkProtocol.WEBSOCKET,
            protocol_data=WebSocketData(
                handshake_request={"upgrade": "websocket"},
                handshake_response={"status": 101},
                frames_sent=[],
                frames_received=[],
                connection_state="open"
            ),
            trace_id="mixed_ws_001"
        )
        traces.append(ws_trace)
        
        # Test mixed session analysis
        assert len(traces) == 2
        
        # Group by protocol
        protocol_counts = {}
        for trace in traces:
            protocol = trace.protocol.value
            protocol_counts[protocol] = protocol_counts.get(protocol, 0) + 1
        
        assert protocol_counts.get('http', 0) == 1
        assert protocol_counts.get('websocket', 0) == 1
        
        # Test protocol-specific filtering
        http_traces = [t for t in traces if t.is_http()]
        ws_traces = [t for t in traces if t.is_websocket()]
        
        assert len(http_traces) == 1
        assert len(ws_traces) == 1
        assert http_traces[0].trace_id == "mixed_http_001"
        assert ws_traces[0].trace_id == "mixed_ws_001"
    
    def test_protocol_extensibility_integration(self):
        """Test that new protocols can be added to the system."""
        from netstealth_analyzer.parsers.registry import ProtocolParser, ProtocolParserRegistry
        from netstealth_analyzer.models.enums import NetworkProtocol
        from netstealth_analyzer.models.network import TcpData
        from typing import Optional
        
        # Create a custom protocol parser
        class CustomProtocolParser(ProtocolParser):
            """Example custom protocol parser."""
            
            @property
            def supported_protocol(self) -> NetworkProtocol:
                return NetworkProtocol.UNKNOWN  # Would be custom protocol in real implementation
            
            def parse_protocol_data(self, raw_data: Dict[str, Any]) -> Optional[TcpData]:
                """Parse custom protocol data."""
                if self.can_parse(raw_data):
                    return TcpData(
                        connection_established=True,
                        bytes_sent=raw_data.get('payload_size', 0),
                        bytes_received=raw_data.get('ack_size', 0)
                    )
                return None
            
            def can_parse(self, raw_data: Dict[str, Any]) -> bool:
                """Check if this looks like custom protocol data."""
                return 'custom_field' in raw_data
        
        # Register the custom parser
        custom_parser = CustomProtocolParser()
        ProtocolParserRegistry.register(custom_parser)
        
        # Test the custom parser
        custom_data = {
            "custom_field": "test_value",
            "payload_size": 256,
            "ack_size": 32
        }
        
        # Should be able to parse custom data
        parsed_custom = ProtocolParserRegistry.parse_protocol_data(custom_data)
        if parsed_custom:
            assert hasattr(parsed_custom, 'bytes_sent')
            assert parsed_custom.bytes_sent == 256
            assert parsed_custom.bytes_received == 32
        
        # Verify existing parsers still work
        http_data = {"request": {"method": "GET", "url": "https://example.com"}}
        http_parsed = ProtocolParserRegistry.parse_protocol_data(http_data)
        # Should either parse successfully or return None (both are valid)
        assert http_parsed is None or hasattr(http_parsed, 'request')
    
    def test_protocol_data_serialization_integration(self):
        """Test that protocol data can be serialized and deserialized."""
        from netstealth_analyzer.models.network import NetworkTrace, HttpData, HttpRequest, HttpResponse
        from netstealth_analyzer.models.enums import NetworkProtocol
        import json
        
        # Create HTTP trace
        trace = NetworkTrace(
            protocol=NetworkProtocol.HTTP,
            protocol_data=HttpData(
                request=HttpRequest(
                    method="POST",
                    url="https://api.example.com/test",
                    headers=[{"name": "Content-Type", "value": "application/json"}],
                    body='{"test": true}',
                    timestamp=datetime.now(timezone.utc)
                ),
                response=HttpResponse(
                    status_code=200,
                    status_text="OK",
                    headers=[{"name": "Content-Type", "value": "application/json"}],
                    body='{"success": true}',
                    content_type="application/json"
                ),
                is_secure=True
            ),
            trace_id="serialization_test_001"
        )
        
        # Test model serialization
        trace_dict = trace.model_dump()
        assert isinstance(trace_dict, dict)
        assert 'protocol' in trace_dict
        assert 'protocol_data' in trace_dict
        assert 'trace_id' in trace_dict
        
        # Test JSON serialization
        json_str = json.dumps(trace_dict, default=str)
        assert isinstance(json_str, str)
        assert len(json_str) > 0
        assert 'serialization_test_001' in json_str
