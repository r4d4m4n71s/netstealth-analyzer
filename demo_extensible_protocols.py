#!/usr/bin/env python3
"""
Demonstration of the Extensible Protocol Architecture

This script showcases the new extensible protocol support in NetStealth Analyzer,
demonstrating how different protocols can be handled uniformly while maintaining
protocol-specific functionality.
"""

import asyncio
from datetime import datetime, timezone
from typing import Dict, Any

from src.netstealth_analyzer.models.network import (
    NetworkTrace, HttpData, WebSocketData, GrpcData, TcpData,
    HttpRequest, HttpResponse, TimingInfo
)
from src.netstealth_analyzer.models.enums import NetworkProtocol
from src.netstealth_analyzer.parsers.registry import ProtocolParserRegistry


def create_sample_http_trace() -> NetworkTrace:
    """Create a sample HTTP trace with protocol-specific data."""
    print("🌐 Creating HTTP trace...")
    
    # Create HTTP request and response
    request = HttpRequest(
        method="POST",
        url="https://api.example.com/users",
        headers=[
            {"name": "Content-Type", "value": "application/json"},
            {"name": "Authorization", "value": "Bearer token123"},
            {"name": "User-Agent", "value": "NetStealth/2.0"}
        ],
        body='{"name": "John Doe", "email": "john@example.com"}',
        timestamp=datetime.now(timezone.utc)
    )
    
    response = HttpResponse(
        status_code=201,
        status_text="Created",
        headers=[
            {"name": "Content-Type", "value": "application/json"},
            {"name": "Location", "value": "/users/123"}
        ],
        body='{"id": 123, "name": "John Doe", "email": "john@example.com"}',
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
        trace_id="http_demo_001"
    )
    
    print(f"   ✓ HTTP trace created: {request.method} {request.url}")
    print(f"   ✓ Response: {response.status_code} {response.status_text}")
    print(f"   ✓ Total time: {timing.total_time:.1f}ms")
    
    return trace


def create_sample_websocket_trace() -> NetworkTrace:
    """Create a sample WebSocket trace with protocol-specific data."""
    print("\n🔌 Creating WebSocket trace...")
    
    # Create WebSocket protocol data
    ws_data = WebSocketData(
        handshake_request={
            "upgrade": "websocket",
            "connection": "Upgrade",
            "sec-websocket-key": "dGhlIHNhbXBsZSBub25jZQ==",
            "sec-websocket-version": "13"
        },
        handshake_response={
            "status": 101,
            "upgrade": "websocket",
            "connection": "Upgrade",
            "sec-websocket-accept": "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        },
        frames_sent=[
            {"type": "text", "data": "Hello WebSocket!", "timestamp": "2024-01-01T10:00:00Z"},
            {"type": "ping", "data": "", "timestamp": "2024-01-01T10:00:30Z"}
        ],
        frames_received=[
            {"type": "text", "data": "Hello Client!", "timestamp": "2024-01-01T10:00:01Z"},
            {"type": "pong", "data": "", "timestamp": "2024-01-01T10:00:31Z"}
        ],
        connection_state="open",
        subprotocols=["chat", "superchat"],
        extensions=["permessage-deflate"]
    )
    
    # Create network trace with WebSocket data
    trace = NetworkTrace(
        protocol=NetworkProtocol.WEBSOCKET,
        protocol_data=ws_data,
        trace_id="ws_demo_001"
    )
    
    print(f"   ✓ WebSocket trace created")
    print(f"   ✓ Connection state: {ws_data.connection_state}")
    print(f"   ✓ Total frames: {ws_data.total_frames}")
    print(f"   ✓ Subprotocols: {', '.join(ws_data.subprotocols)}")
    
    return trace


def create_sample_grpc_trace() -> NetworkTrace:
    """Create a sample gRPC trace with protocol-specific data."""
    print("\n🚀 Creating gRPC trace...")
    
    # Create gRPC protocol data
    grpc_data = GrpcData(
        service="UserService",
        method="CreateUser",
        request_messages=[
            {"name": "Alice Smith", "email": "alice@example.com", "age": 30}
        ],
        response_messages=[
            {"id": "user_456", "name": "Alice Smith", "created_at": "2024-01-01T10:00:00Z"}
        ],
        status_code=0,  # OK
        status_message="Success",
        request_metadata={
            "authorization": "Bearer grpc_token_xyz",
            "content-type": "application/grpc+proto"
        },
        response_metadata={
            "content-type": "application/grpc+proto",
            "grpc-status": "0"
        },
        is_client_streaming=False,
        is_server_streaming=False
    )
    
    # Create network trace with gRPC data
    trace = NetworkTrace(
        protocol=NetworkProtocol.GRPC,
        protocol_data=grpc_data,
        trace_id="grpc_demo_001"
    )
    
    print(f"   ✓ gRPC trace created: {grpc_data.service}/{grpc_data.method}")
    print(f"   ✓ Status: {grpc_data.status_code} ({grpc_data.status_message})")
    print(f"   ✓ Streaming: {grpc_data.is_streaming}")
    print(f"   ✓ Messages: {len(grpc_data.request_messages)} req, {len(grpc_data.response_messages)} resp")
    
    return trace


def create_sample_tcp_trace() -> NetworkTrace:
    """Create a sample TCP trace with protocol-specific data."""
    print("\n🔗 Creating TCP trace...")
    
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
        trace_id="tcp_demo_001"
    )
    
    print(f"   ✓ TCP trace created")
    print(f"   ✓ Connection: {'Established' if tcp_data.connection_established else 'Not established'}")
    print(f"   ✓ Data transferred: {tcp_data.total_bytes} bytes")
    print(f"   ✓ Handshake time: {tcp_data.handshake_duration_ms}ms")
    
    return trace


def demonstrate_protocol_awareness(traces: list[NetworkTrace]) -> None:
    """Demonstrate protocol-aware functionality."""
    print("\n🧠 Demonstrating Protocol Awareness...")
    
    for trace in traces:
        print(f"\n--- Analyzing trace: {trace.trace_id} ---")
        print(f"Protocol: {trace.protocol.value}")
        
        # Use protocol-specific type guards
        if trace.is_http():
            http_data = trace.http_data
            print(f"HTTP Analysis:")
            print(f"  • Method: {http_data.request.method if http_data.request else 'N/A'}")
            print(f"  • Status: {http_data.response.status_code if http_data.response else 'N/A'}")
            print(f"  • Secure: {http_data.is_secure}")
            print(f"  • Success: {http_data.is_success}")
            
        elif trace.is_websocket():
            ws_data = trace.websocket_data
            print(f"WebSocket Analysis:")
            print(f"  • State: {ws_data.connection_state}")
            print(f"  • Frames: {ws_data.total_frames}")
            print(f"  • Connected: {ws_data.is_connected}")
            print(f"  • Protocols: {', '.join(ws_data.subprotocols) if ws_data.subprotocols else 'None'}")
            
        elif trace.is_grpc():
            grpc_data = trace.grpc_data
            print(f"gRPC Analysis:")
            print(f"  • Service: {grpc_data.service}")
            print(f"  • Method: {grpc_data.method}")
            print(f"  • Status: {grpc_data.status_code} ({grpc_data.status_message})")
            print(f"  • Streaming: {grpc_data.is_streaming}")
            print(f"  • Success: {grpc_data.is_success}")
            
        elif trace.is_tcp():
            tcp_data = trace.tcp_data
            print(f"TCP Analysis:")
            print(f"  • Connection: {'Established' if tcp_data.connection_established else 'Not established'}")
            print(f"  • Total bytes: {tcp_data.total_bytes}")
            print(f"  • Packets: {tcp_data.packets_sent + tcp_data.packets_received}")
            print(f"  • Handshake: {tcp_data.handshake_duration_ms}ms")


def demonstrate_parser_registry() -> None:
    """Demonstrate the parser registry functionality."""
    print("\n🔧 Demonstrating Parser Registry...")
    
    # Show supported protocols
    supported = ProtocolParserRegistry.get_supported_protocols()
    print(f"Supported protocols: {[p.value for p in supported]}")
    
    # Test HTTP parsing
    print("\n--- Testing HTTP Parser ---")
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
    print(f"Auto-detected parser: {parser.__class__.__name__}")
    
    # Parse data
    parsed_data = ProtocolParserRegistry.parse_protocol_data(http_raw_data)
    if parsed_data:
        print(f"Parsed as: {parsed_data.__class__.__name__}")
        print(f"Request method: {parsed_data.request.method}")
        print(f"Response status: {parsed_data.response.status_code}")
        print(f"Total time: {parsed_data.timing.total_time:.1f}ms")
    
    # Test WebSocket parsing
    print("\n--- Testing WebSocket Parser ---")
    ws_raw_data = {
        "handshake_request": {"upgrade": "websocket"},
        "frames_sent": [{"type": "text", "data": "hello"}],
        "connection_state": "open"
    }
    
    ws_parsed = ProtocolParserRegistry.parse_protocol_data(ws_raw_data)
    if ws_parsed:
        print(f"Parsed as: {ws_parsed.__class__.__name__}")
        print(f"Connection state: {ws_parsed.connection_state}")
        print(f"Frames sent: {len(ws_parsed.frames_sent)}")


def demonstrate_extensibility() -> None:
    """Demonstrate how new protocols can be added."""
    print("\n🔌 Demonstrating Extensibility...")
    
    # Create a custom protocol parser for demonstration
    from src.netstealth_analyzer.parsers.registry import ProtocolParser
    from src.netstealth_analyzer.models.enums import NetworkProtocol
    from typing import Optional
    
    class MqttProtocolParser(ProtocolParser):
        """Example custom protocol parser for MQTT."""
        
        @property
        def supported_protocol(self) -> NetworkProtocol:
            return NetworkProtocol.UNKNOWN  # Would be NetworkProtocol.MQTT in real implementation
        
        def parse_protocol_data(self, raw_data: Dict[str, Any]) -> Optional[TcpData]:
            """Parse MQTT data (simplified example)."""
            if self.can_parse(raw_data):
                return TcpData(
                    connection_established=True,
                    bytes_sent=raw_data.get('payload_size', 0),
                    bytes_received=raw_data.get('ack_size', 0)
                )
            return None
        
        def can_parse(self, raw_data: Dict[str, Any]) -> bool:
            """Check if this looks like MQTT data."""
            return 'mqtt_topic' in raw_data and 'qos_level' in raw_data
    
    # Register the custom parser
    mqtt_parser = MqttProtocolParser()
    ProtocolParserRegistry.register(mqtt_parser)
    
    print("✓ Registered custom MQTT parser")
    
    # Test the custom parser
    mqtt_data = {
        "mqtt_topic": "sensors/temperature",
        "qos_level": 1,
        "payload_size": 256,
        "ack_size": 32
    }
    
    parsed_mqtt = ProtocolParserRegistry.parse_protocol_data(mqtt_data)
    if parsed_mqtt:
        print(f"✓ Successfully parsed custom MQTT data")
        print(f"  • Protocol type: {parsed_mqtt.protocol_type}")
        print(f"  • Bytes sent: {parsed_mqtt.bytes_sent}")
        print(f"  • Bytes received: {parsed_mqtt.bytes_received}")
    
    # Show that existing protocols still work
    http_data = {"request": {"method": "GET", "url": "https://example.com"}}
    http_parsed = ProtocolParserRegistry.parse_protocol_data(http_data)
    print(f"✓ Existing HTTP parser still works: {http_parsed.__class__.__name__}")


def demonstrate_mixed_session() -> None:
    """Demonstrate analyzing a mixed-protocol session."""
    print("\n🌐 Demonstrating Mixed-Protocol Session Analysis...")
    
    # Create traces for different protocols
    traces = [
        create_sample_http_trace(),
        create_sample_websocket_trace(),
        create_sample_grpc_trace(),
        create_sample_tcp_trace()
    ]
    
    print(f"\n📊 Session Summary:")
    print(f"Total traces: {len(traces)}")
    
    # Group by protocol
    protocol_counts = {}
    for trace in traces:
        protocol = trace.protocol.value
        protocol_counts[protocol] = protocol_counts.get(protocol, 0) + 1
    
    for protocol, count in protocol_counts.items():
        print(f"  • {protocol.upper()}: {count} trace(s)")
    
    # Analyze each protocol type
    http_traces = [t for t in traces if t.is_http()]
    ws_traces = [t for t in traces if t.is_websocket()]
    grpc_traces = [t for t in traces if t.is_grpc()]
    tcp_traces = [t for t in traces if t.is_tcp()]
    
    print(f"\n🔍 Protocol-Specific Analysis:")
    
    if http_traces:
        successful_http = sum(1 for t in http_traces if t.http_data and t.http_data.is_success)
        print(f"  • HTTP: {successful_http}/{len(http_traces)} successful requests")
    
    if ws_traces:
        connected_ws = sum(1 for t in ws_traces if t.websocket_data and t.websocket_data.is_connected)
        print(f"  • WebSocket: {connected_ws}/{len(ws_traces)} active connections")
    
    if grpc_traces:
        successful_grpc = sum(1 for t in grpc_traces if t.grpc_data and t.grpc_data.is_success)
        print(f"  • gRPC: {successful_grpc}/{len(grpc_traces)} successful calls")
    
    if tcp_traces:
        established_tcp = sum(1 for t in tcp_traces if t.tcp_data and t.tcp_data.connection_established)
        print(f"  • TCP: {established_tcp}/{len(tcp_traces)} established connections")


def main():
    """Main demonstration function."""
    print("🚀 NetStealth Analyzer - Extensible Protocol Architecture Demo")
    print("=" * 70)
    
    # Create sample traces for different protocols
    traces = [
        create_sample_http_trace(),
        create_sample_websocket_trace(),
        create_sample_grpc_trace(),
        create_sample_tcp_trace()
    ]
    
    # Demonstrate protocol-aware functionality
    demonstrate_protocol_awareness(traces)
    
    # Demonstrate parser registry
    demonstrate_parser_registry()
    
    # Demonstrate extensibility
    demonstrate_extensibility()
    
    # Demonstrate mixed-protocol session analysis
    demonstrate_mixed_session()
    
    print("\n" + "=" * 70)
    print("✅ Extensible Protocol Architecture Demo Complete!")
    print("\nKey Features Demonstrated:")
    print("  • Protocol-specific data containers (HttpData, WebSocketData, etc.)")
    print("  • Type-safe protocol access with type guards")
    print("  • Extensible parser registry pattern")
    print("  • Auto-detection of protocol types")
    print("  • Mixed-protocol session analysis")
    print("  • Easy addition of new protocols")
    print("\nThe architecture is now ready for:")
    print("  • Adding new protocols (MQTT, CoAP, etc.)")
    print("  • Protocol-specific detectors")
    print("  • Advanced cross-protocol analysis")
    print("  • Custom protocol extensions")


if __name__ == "__main__":
    main()
