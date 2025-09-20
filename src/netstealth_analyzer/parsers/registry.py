"""
Parser registry for extensible protocol support.

This module provides a registry pattern for protocol parsers,
allowing new protocols to be added without modifying core code.
"""

from typing import Dict, Type, Optional, List, Any
from abc import ABC, abstractmethod

from ..models.enums import NetworkProtocol
from ..models.network import ProtocolData, ProtocolDataUnion
from .base import BaseLogParser


class ProtocolParser(ABC):
    """
    Abstract base class for protocol-specific parsers.
    
    Each protocol parser is responsible for extracting protocol-specific
    data from raw network traces and converting it to structured data.
    """
    
    @property
    @abstractmethod
    def supported_protocol(self) -> NetworkProtocol:
        """Get the protocol this parser supports."""
        pass
    
    @abstractmethod
    def parse_protocol_data(self, raw_data: Dict[str, Any]) -> Optional[ProtocolData]:
        """
        Parse raw data into protocol-specific data structure.
        
        Args:
            raw_data: Raw protocol data from log files
            
        Returns:
            Protocol-specific data object or None if parsing fails
        """
        pass
    
    @abstractmethod
    def can_parse(self, raw_data: Dict[str, Any]) -> bool:
        """
        Check if this parser can handle the given raw data.
        
        Args:
            raw_data: Raw data to check
            
        Returns:
            True if parser can handle this data
        """
        pass


class HttpProtocolParser(ProtocolParser):
    """Parser for HTTP protocol data."""
    
    @property
    def supported_protocol(self) -> NetworkProtocol:
        """Get the protocol this parser supports."""
        return NetworkProtocol.HTTP
    
    def parse_protocol_data(self, raw_data: Dict[str, Any]) -> Optional['HttpData']:
        """Parse HTTP data from raw trace data."""
        from ..models.network import HttpData, HttpRequest, HttpResponse, TimingInfo
        
        try:
            # Extract HTTP request data
            request = None
            if 'request' in raw_data:
                request_data = raw_data['request']
                request = HttpRequest(
                    method=request_data.get('method', 'GET'),
                    url=request_data.get('url', ''),
                    headers=request_data.get('headers', []),
                    body=request_data.get('body'),
                    body_size=request_data.get('bodySize', 0),
                    timestamp=request_data.get('timestamp')
                )
            
            # Extract HTTP response data
            response = None
            if 'response' in raw_data:
                response_data = raw_data['response']
                response = HttpResponse(
                    status_code=response_data.get('status', 0),
                    status_text=response_data.get('statusText', ''),
                    headers=response_data.get('headers', []),
                    body=response_data.get('body'),
                    body_size=response_data.get('bodySize', 0),
                    content_type=response_data.get('content', {}).get('mimeType')
                )
            
            # Extract timing data
            timing = None
            if 'timings' in raw_data:
                timing_data = raw_data['timings']
                timing = TimingInfo(
                    dns_lookup=timing_data.get('dns', -1),
                    tcp_connect=timing_data.get('connect', -1),
                    ssl_handshake=timing_data.get('ssl', -1),
                    request_sent=timing_data.get('send', -1),
                    waiting=timing_data.get('wait', -1),
                    content_download=timing_data.get('receive', -1),
                    blocked=timing_data.get('blocked', -1)
                )
            
            # Create HTTP data container
            return HttpData(
                request=request,
                response=response,
                timing=timing,
                is_secure=raw_data.get('url', '').startswith('https://'),
                redirects=raw_data.get('redirects', []),
                cookies=raw_data.get('cookies', [])
            )
            
        except Exception:
            return None
    
    def can_parse(self, raw_data: Dict[str, Any]) -> bool:
        """Check if this is HTTP data."""
        # Check for HTTP-specific fields
        has_http_request = 'request' in raw_data and 'method' in raw_data.get('request', {})
        has_http_response = 'response' in raw_data and 'status' in raw_data.get('response', {})
        has_http_url = 'url' in raw_data and raw_data['url'].startswith(('http://', 'https://'))
        
        return has_http_request or has_http_response or has_http_url


class WebSocketProtocolParser(ProtocolParser):
    """Parser for WebSocket protocol data."""
    
    @property
    def supported_protocol(self) -> NetworkProtocol:
        """Get the protocol this parser supports."""
        return NetworkProtocol.WEBSOCKET
    
    def parse_protocol_data(self, raw_data: Dict[str, Any]) -> Optional['WebSocketData']:
        """Parse WebSocket data from raw trace data."""
        from ..models.network import WebSocketData
        
        try:
            return WebSocketData(
                handshake_request=raw_data.get('handshake_request'),
                handshake_response=raw_data.get('handshake_response'),
                frames_sent=raw_data.get('frames_sent', []),
                frames_received=raw_data.get('frames_received', []),
                connection_state=raw_data.get('connection_state', 'unknown'),
                close_code=raw_data.get('close_code'),
                close_reason=raw_data.get('close_reason'),
                subprotocols=raw_data.get('subprotocols', []),
                extensions=raw_data.get('extensions', [])
            )
        except Exception:
            return None
    
    def can_parse(self, raw_data: Dict[str, Any]) -> bool:
        """Check if this is WebSocket data."""
        # Check for WebSocket-specific fields
        has_ws_handshake = 'handshake_request' in raw_data or 'handshake_response' in raw_data
        has_ws_frames = 'frames_sent' in raw_data or 'frames_received' in raw_data
        has_ws_url = 'url' in raw_data and raw_data['url'].startswith(('ws://', 'wss://'))
        
        return has_ws_handshake or has_ws_frames or has_ws_url


class GrpcProtocolParser(ProtocolParser):
    """Parser for gRPC protocol data."""
    
    @property
    def supported_protocol(self) -> NetworkProtocol:
        """Get the protocol this parser supports."""
        return NetworkProtocol.GRPC
    
    def parse_protocol_data(self, raw_data: Dict[str, Any]) -> Optional['GrpcData']:
        """Parse gRPC data from raw trace data."""
        from ..models.network import GrpcData
        
        try:
            return GrpcData(
                service=raw_data.get('service', ''),
                method=raw_data.get('method', ''),
                request_messages=raw_data.get('request_messages', []),
                response_messages=raw_data.get('response_messages', []),
                status_code=raw_data.get('status_code'),
                status_message=raw_data.get('status_message'),
                request_metadata=raw_data.get('request_metadata', {}),
                response_metadata=raw_data.get('response_metadata', {}),
                is_client_streaming=raw_data.get('is_client_streaming', False),
                is_server_streaming=raw_data.get('is_server_streaming', False)
            )
        except Exception:
            return None
    
    def can_parse(self, raw_data: Dict[str, Any]) -> bool:
        """Check if this is gRPC data."""
        # Check for gRPC-specific fields
        has_grpc_service = 'service' in raw_data and 'method' in raw_data
        has_grpc_messages = 'request_messages' in raw_data or 'response_messages' in raw_data
        has_grpc_status = 'status_code' in raw_data and isinstance(raw_data['status_code'], int)
        
        return has_grpc_service or has_grpc_messages or has_grpc_status


class TcpProtocolParser(ProtocolParser):
    """Parser for TCP protocol data."""
    
    @property
    def supported_protocol(self) -> NetworkProtocol:
        """Get the protocol this parser supports."""
        return NetworkProtocol.TCP
    
    def parse_protocol_data(self, raw_data: Dict[str, Any]) -> Optional['TcpData']:
        """Parse TCP data from raw trace data."""
        from ..models.network import TcpData
        
        try:
            return TcpData(
                connection_established=raw_data.get('connection_established', False),
                connection_closed=raw_data.get('connection_closed', False),
                syn_sent=raw_data.get('syn_sent', False),
                syn_ack_received=raw_data.get('syn_ack_received', False),
                fin_sent=raw_data.get('fin_sent', False),
                rst_sent=raw_data.get('rst_sent', False),
                bytes_sent=raw_data.get('bytes_sent', 0),
                bytes_received=raw_data.get('bytes_received', 0),
                packets_sent=raw_data.get('packets_sent', 0),
                packets_received=raw_data.get('packets_received', 0),
                handshake_duration_ms=raw_data.get('handshake_duration_ms')
            )
        except Exception:
            return None
    
    def can_parse(self, raw_data: Dict[str, Any]) -> bool:
        """Check if this is TCP data."""
        # Check for TCP-specific fields
        has_tcp_flags = any(key in raw_data for key in ['syn_sent', 'syn_ack_received', 'fin_sent'])
        has_tcp_data = any(key in raw_data for key in ['bytes_sent', 'bytes_received', 'packets_sent'])
        has_tcp_connection = 'connection_established' in raw_data or 'connection_closed' in raw_data
        
        return has_tcp_flags or has_tcp_data or has_tcp_connection


class ProtocolParserRegistry:
    """
    Registry for protocol parsers.
    
    Provides a centralized way to register and retrieve protocol parsers,
    enabling extensible protocol support without modifying core code.
    """
    
    _parsers: Dict[NetworkProtocol, ProtocolParser] = {}
    _auto_detect_parsers: List[ProtocolParser] = []
    
    @classmethod
    def register(cls, parser: ProtocolParser) -> None:
        """
        Register a protocol parser.
        
        Args:
            parser: Protocol parser instance to register
        """
        protocol = parser.supported_protocol
        cls._parsers[protocol] = parser
        
        # Add to auto-detect list if not already present
        if parser not in cls._auto_detect_parsers:
            cls._auto_detect_parsers.append(parser)
    
    @classmethod
    def get_parser(cls, protocol: NetworkProtocol) -> Optional[ProtocolParser]:
        """
        Get parser for specific protocol.
        
        Args:
            protocol: Network protocol to get parser for
            
        Returns:
            Protocol parser or None if not found
        """
        return cls._parsers.get(protocol)
    
    @classmethod
    def auto_detect_parser(cls, raw_data: Dict[str, Any]) -> Optional[ProtocolParser]:
        """
        Auto-detect the appropriate parser for raw data.
        
        Args:
            raw_data: Raw data to analyze
            
        Returns:
            Best matching parser or None if no match found
        """
        for parser in cls._auto_detect_parsers:
            if parser.can_parse(raw_data):
                return parser
        return None
    
    @classmethod
    def parse_protocol_data(
        cls, 
        raw_data: Dict[str, Any], 
        protocol: Optional[NetworkProtocol] = None
    ) -> Optional[ProtocolDataUnion]:
        """
        Parse raw data into protocol-specific data structure.
        
        Args:
            raw_data: Raw data to parse
            protocol: Specific protocol to use, or None for auto-detection
            
        Returns:
            Protocol-specific data object or None if parsing fails
        """
        # Use specific parser if protocol is provided
        if protocol:
            parser = cls.get_parser(protocol)
            if parser:
                return parser.parse_protocol_data(raw_data)
        
        # Auto-detect parser
        parser = cls.auto_detect_parser(raw_data)
        if parser:
            return parser.parse_protocol_data(raw_data)
        
        return None
    
    @classmethod
    def get_supported_protocols(cls) -> List[NetworkProtocol]:
        """Get list of supported protocols."""
        return list(cls._parsers.keys())
    
    @classmethod
    def clear_registry(cls) -> None:
        """Clear all registered parsers (mainly for testing)."""
        cls._parsers.clear()
        cls._auto_detect_parsers.clear()


# Register default parsers
def _register_default_parsers():
    """Register default protocol parsers."""
    ProtocolParserRegistry.register(HttpProtocolParser())
    ProtocolParserRegistry.register(WebSocketProtocolParser())
    ProtocolParserRegistry.register(GrpcProtocolParser())
    ProtocolParserRegistry.register(TcpProtocolParser())


# Auto-register default parsers when module is imported
_register_default_parsers()


__all__ = [
    'ProtocolParser',
    'HttpProtocolParser',
    'WebSocketProtocolParser', 
    'GrpcProtocolParser',
    'TcpProtocolParser',
    'ProtocolParserRegistry'
]
