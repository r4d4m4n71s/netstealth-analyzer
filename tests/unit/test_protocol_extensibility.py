"""
Unit tests for extensible protocol architecture.

Tests the new protocol data structures, parser registry,
and protocol-aware functionality.
"""

import pytest
from datetime import datetime, timezone
from typing import Dict, Any, Optional

from src.netstealth_analyzer.models.network import (
    NetworkTrace, HttpData, WebSocketData, GrpcData, TcpData,
    HttpRequest, HttpResponse, TimingInfo
)
from src.netstealth_analyzer.models.enums import NetworkProtocol
from src.netstealth_analyzer.parsers.registry import (
    ProtocolParserRegistry, HttpProtocolParser, WebSocketProtocolParser,
    GrpcProtocolParser, TcpProtocolParser, ProtocolParser
)


class TestProtocolDataStructures:
    """Test protocol-specific data structures."""
    
    def test_http_data_creation(self):
        """Test HttpData creation and computed properties."""
        request = HttpRequest(
            method="GET",
            url="https://example.com/api",
            headers=[{"name": "User-Agent", "value": "Test"}],
            timestamp=datetime.now(timezone.utc)
        )
        
        response = HttpResponse(
            status_code=200,
            status_text="OK",
            headers=[{"name": "Content-Type", "value": "application/json"}],
            body='{"success": true}'
        )
        
        timing = TimingInfo(
            dns_lookup=10.0,
            tcp_connect=20.0,
            ssl_handshake=30.0,
            request_sent=5.0,
            waiting=100.0,
            content_download=15.0
        )
        
        http_data = HttpData(
            request=request,
            response=response,
            timing=timing,
            is_secure=True
        )
        
        assert http_data.protocol_type == "http"
        assert http_data.has_request_data is True
        assert http_data.has_response_data is True
        assert http_data.is_success is True
        assert http_data.is_secure is True
    
    def test_websocket_data_creation(self):
        """Test WebSocketData creation and computed properties."""
        ws_data = WebSocketData(
            handshake_request={"upgrade": "websocket"},
            handshake_response={"status": 101},
            frames_sent=[{"type": "text", "data": "hello"}],
            frames_received=[{"type": "text", "data": "world"}],
            connection_state="open",
            subprotocols=["chat"],
            extensions=["permessage-deflate"]
        )
        
        assert ws_data.protocol_type == "websocket"
        assert ws_data.total_frames == 2
        assert ws_data.is_connected is True
    
    def test_grpc_data_creation(self):
        """Test GrpcData creation and computed properties."""
        grpc_data = GrpcData(
            service="UserService",
            method="GetUser",
            request_messages=[{"user_id": "123"}],
            response_messages=[{"name": "John", "email": "john@example.com"}],
            status_code=0,
            status_message="OK",
            is_server_streaming=True
        )
        
        assert grpc_data.protocol_type == "grpc"
        assert grpc_data.is_streaming is True
        assert grpc_data.is_success is True
    
    def test_tcp_data_creation(self):
        """Test TcpData creation and computed properties."""
        tcp_data = TcpData(
            connection_established=True,
            syn_sent=True,
            syn_ack_received=True,
            bytes_sent=1024,
            bytes_received=2048,
            packets_sent=10,
            packets_received=15,
            handshake_duration_ms=50.0
        )
        
        assert tcp_data.protocol_type == "tcp"
        assert tcp_data.total_bytes == 3072


class TestNetworkTraceProtocolAwareness:
    """Test NetworkTrace protocol-aware functionality."""
    
    def test_http_trace_creation(self):
        """Test creating NetworkTrace with HTTP data."""
        request = HttpRequest(method="POST", url="https://api.example.com/users")
        response = HttpResponse(status_code=201, status_text="Created")
        http_data = HttpData(request=request, response=response, is_secure=True)
        
        trace = NetworkTrace(
            protocol=NetworkProtocol.HTTP,
            protocol_data=http_data
        )
        
        assert trace.is_http() is True
        assert trace.is_websocket() is False
        assert trace.is_grpc() is False
        assert trace.is_tcp() is False
        
        assert trace.http_data is not None
        assert trace.http_data.is_secure is True
        assert trace.websocket_data is None
        assert trace.supports_protocol(NetworkProtocol.HTTP) is True
    
    def test_websocket_trace_creation(self):
        """Test creating NetworkTrace with WebSocket data."""
        ws_data = WebSocketData(
            connection_state="open",
            frames_sent=[{"type": "ping"}],
            frames_received=[{"type": "pong"}]
        )
        
        trace = NetworkTrace(
            protocol=NetworkProtocol.WEBSOCKET,
            protocol_data=ws_data
        )
        
        assert trace.is_websocket() is True
        assert trace.is_http() is False
        assert trace.websocket_data is not None
        assert trace.websocket_data.total_frames == 2
        assert trace.supports_protocol(NetworkProtocol.WEBSOCKET) is True
    
    def test_grpc_trace_creation(self):
        """Test creating NetworkTrace with gRPC data."""
        grpc_data = GrpcData(
            service="OrderService",
            method="CreateOrder",
            status_code=0,
            is_client_streaming=True
        )
        
        trace = NetworkTrace(
            protocol=NetworkProtocol.GRPC,
            protocol_data=grpc_data
        )
        
        assert trace.is_grpc() is True
        assert trace.grpc_data is not None
        assert trace.grpc_data.is_streaming is True
        assert trace.supports_protocol(NetworkProtocol.GRPC) is True
    
    def test_tcp_trace_creation(self):
        """Test creating NetworkTrace with TCP data."""
        tcp_data = TcpData(
            connection_established=True,
            bytes_sent=512,
            bytes_received=1024
        )
        
        trace = NetworkTrace(
            protocol=NetworkProtocol.TCP,
            protocol_data=tcp_data
        )
        
        assert trace.is_tcp() is True
        assert trace.tcp_data is not None
        assert trace.tcp_data.total_bytes == 1536
        assert trace.supports_protocol(NetworkProtocol.TCP) is True


class TestProtocolParsers:
    """Test individual protocol parsers."""
    
    def test_http_protocol_parser(self):
        """Test HTTP protocol parser."""
        parser = HttpProtocolParser()
        
        assert parser.supported_protocol == NetworkProtocol.HTTP
        
        # Test can_parse
        http_data = {
            "request": {"method": "GET", "url": "https://example.com"},
            "response": {"status": 200, "statusText": "OK"}
        }
        assert parser.can_parse(http_data) is True
        
        non_http_data = {"service": "UserService", "method": "GetUser"}
        assert parser.can_parse(non_http_data) is False
        
        # Test parse_protocol_data
        result = parser.parse_protocol_data(http_data)
        assert result is not None
        assert isinstance(result, HttpData)
        assert result.request.method == "GET"
        assert result.response.status_code == 200
    
    def test_websocket_protocol_parser(self):
        """Test WebSocket protocol parser."""
        parser = WebSocketProtocolParser()
        
        assert parser.supported_protocol == NetworkProtocol.WEBSOCKET
        
        # Test can_parse
        ws_data = {
            "handshake_request": {"upgrade": "websocket"},
            "frames_sent": [{"type": "text", "data": "hello"}]
        }
        assert parser.can_parse(ws_data) is True
        
        # Test parse_protocol_data
        result = parser.parse_protocol_data(ws_data)
        assert result is not None
        assert isinstance(result, WebSocketData)
        assert len(result.frames_sent) == 1
    
    def test_grpc_protocol_parser(self):
        """Test gRPC protocol parser."""
        parser = GrpcProtocolParser()
        
        assert parser.supported_protocol == NetworkProtocol.GRPC
        
        # Test can_parse
        grpc_data = {
            "service": "UserService",
            "method": "GetUser",
            "status_code": 0
        }
        assert parser.can_parse(grpc_data) is True
        
        # Test parse_protocol_data
        result = parser.parse_protocol_data(grpc_data)
        assert result is not None
        assert isinstance(result, GrpcData)
        assert result.service == "UserService"
        assert result.method == "GetUser"
    
    def test_tcp_protocol_parser(self):
        """Test TCP protocol parser."""
        parser = TcpProtocolParser()
        
        assert parser.supported_protocol == NetworkProtocol.TCP
        
        # Test can_parse
        tcp_data = {
            "connection_established": True,
            "bytes_sent": 1024,
            "syn_sent": True
        }
        assert parser.can_parse(tcp_data) is True
        
        # Test parse_protocol_data
        result = parser.parse_protocol_data(tcp_data)
        assert result is not None
        assert isinstance(result, TcpData)
        assert result.connection_established is True
        assert result.bytes_sent == 1024


class TestProtocolParserRegistry:
    """Test protocol parser registry functionality."""
    
    def test_registry_initialization(self):
        """Test that registry is initialized with default parsers."""
        supported_protocols = ProtocolParserRegistry.get_supported_protocols()
        
        assert NetworkProtocol.HTTP in supported_protocols
        assert NetworkProtocol.WEBSOCKET in supported_protocols
        assert NetworkProtocol.GRPC in supported_protocols
        assert NetworkProtocol.TCP in supported_protocols
    
    def test_get_parser(self):
        """Test getting specific parsers from registry."""
        http_parser = ProtocolParserRegistry.get_parser(NetworkProtocol.HTTP)
        assert http_parser is not None
        assert isinstance(http_parser, HttpProtocolParser)
        
        ws_parser = ProtocolParserRegistry.get_parser(NetworkProtocol.WEBSOCKET)
        assert ws_parser is not None
        assert isinstance(ws_parser, WebSocketProtocolParser)
        
        # Test non-existent protocol
        unknown_parser = ProtocolParserRegistry.get_parser(NetworkProtocol.UNKNOWN)
        assert unknown_parser is None
    
    def test_auto_detect_parser(self):
        """Test auto-detection of appropriate parser."""
        # HTTP data
        http_data = {"request": {"method": "GET", "url": "https://example.com"}}
        parser = ProtocolParserRegistry.auto_detect_parser(http_data)
        assert parser is not None
        assert isinstance(parser, HttpProtocolParser)
        
        # WebSocket data
        ws_data = {"handshake_request": {"upgrade": "websocket"}}
        parser = ProtocolParserRegistry.auto_detect_parser(ws_data)
        assert parser is not None
        assert isinstance(parser, WebSocketProtocolParser)
        
        # gRPC data
        grpc_data = {"service": "UserService", "method": "GetUser"}
        parser = ProtocolParserRegistry.auto_detect_parser(grpc_data)
        assert parser is not None
        assert isinstance(parser, GrpcProtocolParser)
        
        # TCP data
        tcp_data = {"syn_sent": True, "bytes_sent": 1024}
        parser = ProtocolParserRegistry.auto_detect_parser(tcp_data)
        assert parser is not None
        assert isinstance(parser, TcpProtocolParser)
        
        # Unknown data
        unknown_data = {"unknown_field": "value"}
        parser = ProtocolParserRegistry.auto_detect_parser(unknown_data)
        assert parser is None
    
    def test_parse_protocol_data(self):
        """Test parsing protocol data through registry."""
        # Test with specific protocol
        http_data = {
            "request": {"method": "POST", "url": "https://api.example.com"},
            "response": {"status": 201, "statusText": "Created"}
        }
        
        result = ProtocolParserRegistry.parse_protocol_data(
            http_data, 
            protocol=NetworkProtocol.HTTP
        )
        assert result is not None
        assert isinstance(result, HttpData)
        assert result.request.method == "POST"
        
        # Test with auto-detection
        result = ProtocolParserRegistry.parse_protocol_data(http_data)
        assert result is not None
        assert isinstance(result, HttpData)
    
    def test_custom_parser_registration(self):
        """Test registering a custom protocol parser."""
        
        class CustomProtocolParser(ProtocolParser):
            @property
            def supported_protocol(self) -> NetworkProtocol:
                return NetworkProtocol.UNKNOWN
            
            def parse_protocol_data(self, raw_data: Dict[str, Any]) -> Optional[TcpData]:
                # Simple custom parser that creates TCP data
                return TcpData(connection_established=True)
            
            def can_parse(self, raw_data: Dict[str, Any]) -> bool:
                return "custom_field" in raw_data
        
        # Register custom parser
        custom_parser = CustomProtocolParser()
        ProtocolParserRegistry.register(custom_parser)
        
        # Test that it's registered
        registered_parser = ProtocolParserRegistry.get_parser(NetworkProtocol.UNKNOWN)
        assert registered_parser is not None
        assert isinstance(registered_parser, CustomProtocolParser)
        
        # Test auto-detection
        custom_data = {"custom_field": "value"}
        detected_parser = ProtocolParserRegistry.auto_detect_parser(custom_data)
        assert detected_parser is not None
        assert isinstance(detected_parser, CustomProtocolParser)
        
        # Test parsing
        result = ProtocolParserRegistry.parse_protocol_data(custom_data)
        assert result is not None
        assert isinstance(result, TcpData)
        assert result.connection_established is True


class TestExtensibilityScenarios:
    """Test real-world extensibility scenarios."""
    
    def test_mixed_protocol_traces(self):
        """Test handling multiple protocol types in same session."""
        traces = []
        
        # HTTP trace
        http_data = HttpData(
            request=HttpRequest(method="GET", url="https://example.com"),
            response=HttpResponse(status_code=200),
            is_secure=True
        )
        http_trace = NetworkTrace(
            protocol=NetworkProtocol.HTTP,
            protocol_data=http_data
        )
        traces.append(http_trace)
        
        # WebSocket trace
        ws_data = WebSocketData(
            connection_state="open",
            frames_sent=[{"type": "text"}]
        )
        ws_trace = NetworkTrace(
            protocol=NetworkProtocol.WEBSOCKET,
            protocol_data=ws_data
        )
        traces.append(ws_trace)
        
        # gRPC trace
        grpc_data = GrpcData(
            service="UserService",
            method="GetUser",
            status_code=0
        )
        grpc_trace = NetworkTrace(
            protocol=NetworkProtocol.GRPC,
            protocol_data=grpc_data
        )
        traces.append(grpc_trace)
        
        # Verify each trace maintains its protocol identity
        assert traces[0].is_http() is True
        assert traces[0].http_data.is_secure is True
        
        assert traces[1].is_websocket() is True
        assert traces[1].websocket_data.total_frames == 1
        
        assert traces[2].is_grpc() is True
        assert traces[2].grpc_data.is_success is True
        
        # Verify type guards work correctly
        http_traces = [t for t in traces if t.is_http()]
        ws_traces = [t for t in traces if t.is_websocket()]
        grpc_traces = [t for t in traces if t.is_grpc()]
        
        assert len(http_traces) == 1
        assert len(ws_traces) == 1
        assert len(grpc_traces) == 1
    
    def test_protocol_specific_analysis(self):
        """Test protocol-specific analysis patterns."""
        # Create HTTP trace with specific characteristics
        http_data = HttpData(
            request=HttpRequest(
                method="POST",
                url="https://api.example.com/sensitive",
                headers=[{"name": "Authorization", "value": "Bearer token123"}]
            ),
            response=HttpResponse(status_code=403, status_text="Forbidden"),
            is_secure=True
        )
        
        trace = NetworkTrace(
            protocol=NetworkProtocol.HTTP,
            protocol_data=http_data
        )
        
        # Protocol-specific analysis
        if trace.is_http():
            http_data = trace.http_data
            
            # Check for sensitive endpoints
            is_sensitive = "sensitive" in http_data.request.url
            assert is_sensitive is True
            
            # Check for authentication
            has_auth = any(
                h.get("name", "").lower() == "authorization" 
                for h in http_data.request.headers
            )
            assert has_auth is True
            
            # Check response status
            is_forbidden = http_data.response.status_code == 403
            assert is_forbidden is True
    
    def test_future_protocol_extensibility(self):
        """Test that new protocols can be added without breaking existing code."""
        
        # Simulate adding a new protocol (e.g., MQTT)
        class MqttData(TcpData):  # Extend existing protocol data
            protocol_type: str = "mqtt"
            topic: str = ""
            qos_level: int = 0
            retained: bool = False
            
            def __init__(self, **data):
                super().__init__(**data)
                self.topic = data.get('topic', '')
                self.qos_level = data.get('qos_level', 0)
                self.retained = data.get('retained', False)
        
        class MqttProtocolParser(ProtocolParser):
            @property
            def supported_protocol(self) -> NetworkProtocol:
                return NetworkProtocol.UNKNOWN  # Would be NetworkProtocol.MQTT in real implementation
            
            def parse_protocol_data(self, raw_data: Dict[str, Any]) -> Optional[MqttData]:
                if self.can_parse(raw_data):
                    return MqttData(
                        topic=raw_data.get('topic', ''),
                        qos_level=raw_data.get('qos_level', 0),
                        retained=raw_data.get('retained', False),
                        connection_established=True
                    )
                return None
            
            def can_parse(self, raw_data: Dict[str, Any]) -> bool:
                return 'topic' in raw_data and 'qos_level' in raw_data
        
        # Register new parser
        mqtt_parser = MqttProtocolParser()
        ProtocolParserRegistry.register(mqtt_parser)
        
        # Test that it works
        mqtt_data = {
            "topic": "sensors/temperature",
            "qos_level": 1,
            "retained": True
        }
        
        result = ProtocolParserRegistry.parse_protocol_data(mqtt_data)
        assert result is not None
        assert isinstance(result, MqttData)
        assert result.topic == "sensors/temperature"
        assert result.qos_level == 1
        assert result.retained is True
        
        # Verify existing protocols still work
        http_data = {"request": {"method": "GET", "url": "https://example.com"}}
        http_result = ProtocolParserRegistry.parse_protocol_data(http_data)
        assert http_result is not None
        assert isinstance(http_result, HttpData)


if __name__ == "__main__":
    pytest.main([__file__])
