"""
Network and connection models for NetStealth Analyzer.

This module defines models for network traces, TLS information, proxy details,
and geographic data with enhanced analysis capabilities.

Author: NetStealth Analyzer Team
Version: 2.0.0
Python: 3.13+
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Union, Literal
from ipaddress import IPv4Address, IPv6Address, AddressValueError
from uuid import UUID, uuid4

from pydantic import BaseModel, Field, field_validator, computed_field, Discriminator, ConfigDict

from .enums import (
    RiskLevel, NetworkProtocol, TLSVersion, ProxyType, 
    GeographicRegion, DetectionConfidence
)
from ..compatibility import override


# ============================================================================
# EXTENSIBLE PROTOCOL DATA ARCHITECTURE
# ============================================================================

class ProtocolData(BaseModel):
    """
    Base class for protocol-specific data.
    
    This provides the foundation for extensible protocol support,
    allowing new protocols to be added without modifying core code.
    """
    protocol_type: str = Field(..., description="Protocol type identifier")
    
    model_config = ConfigDict(extra="forbid")


class HttpData(ProtocolData):
    """HTTP protocol-specific data container."""
    
    protocol_type: Literal["http"] = "http"
    
    # HTTP request/response data
    request: Optional['HttpRequest'] = Field(None, description="HTTP request information")
    response: Optional['HttpResponse'] = Field(None, description="HTTP response information")
    timing: Optional['TimingInfo'] = Field(None, description="HTTP timing information")
    
    # HTTP-specific metadata
    is_secure: bool = Field(False, description="Whether connection uses HTTPS")
    redirects: List[str] = Field(default_factory=list, description="Redirect chain URLs")
    cookies: List[Dict[str, str]] = Field(default_factory=list, description="HTTP cookies")
    
    @computed_field
    @property
    def has_request_data(self) -> bool:
        """Check if HTTP request data is available."""
        return self.request is not None
    
    @computed_field
    @property
    def has_response_data(self) -> bool:
        """Check if HTTP response data is available."""
        return self.response is not None
    
    @computed_field
    @property
    def is_success(self) -> bool:
        """Check if HTTP response indicates success."""
        return self.response.is_success if self.response else False


class WebSocketData(ProtocolData):
    """WebSocket protocol-specific data container."""
    
    protocol_type: Literal["websocket"] = "websocket"
    
    # WebSocket handshake
    handshake_request: Optional[Dict[str, Any]] = Field(None, description="WebSocket handshake request")
    handshake_response: Optional[Dict[str, Any]] = Field(None, description="WebSocket handshake response")
    
    # WebSocket frames
    frames_sent: List[Dict[str, Any]] = Field(default_factory=list, description="Frames sent by client")
    frames_received: List[Dict[str, Any]] = Field(default_factory=list, description="Frames received from server")
    
    # Connection state
    connection_state: str = Field("unknown", description="WebSocket connection state")
    close_code: Optional[int] = Field(None, description="WebSocket close code")
    close_reason: Optional[str] = Field(None, description="WebSocket close reason")
    
    # WebSocket-specific metadata
    subprotocols: List[str] = Field(default_factory=list, description="Negotiated subprotocols")
    extensions: List[str] = Field(default_factory=list, description="WebSocket extensions")
    
    @computed_field
    @property
    def total_frames(self) -> int:
        """Get total number of frames exchanged."""
        return len(self.frames_sent) + len(self.frames_received)
    
    @computed_field
    @property
    def is_connected(self) -> bool:
        """Check if WebSocket connection is active."""
        return self.connection_state.lower() in ["open", "connected"]


class GrpcData(ProtocolData):
    """gRPC protocol-specific data container."""
    
    protocol_type: Literal["grpc"] = "grpc"
    
    # gRPC service information
    service: str = Field(..., description="gRPC service name")
    method: str = Field(..., description="gRPC method name")
    
    # gRPC messages
    request_messages: List[Dict[str, Any]] = Field(default_factory=list, description="Request messages")
    response_messages: List[Dict[str, Any]] = Field(default_factory=list, description="Response messages")
    
    # gRPC status
    status_code: Optional[int] = Field(None, description="gRPC status code")
    status_message: Optional[str] = Field(None, description="gRPC status message")
    
    # gRPC metadata
    request_metadata: Dict[str, str] = Field(default_factory=dict, description="Request metadata")
    response_metadata: Dict[str, str] = Field(default_factory=dict, description="Response metadata")
    
    # Streaming information
    is_client_streaming: bool = Field(False, description="Whether client streams messages")
    is_server_streaming: bool = Field(False, description="Whether server streams messages")
    
    @computed_field
    @property
    def is_streaming(self) -> bool:
        """Check if this is a streaming RPC."""
        return self.is_client_streaming or self.is_server_streaming
    
    @computed_field
    @property
    def is_success(self) -> bool:
        """Check if gRPC call was successful."""
        return self.status_code == 0 if self.status_code is not None else False


class TcpData(ProtocolData):
    """TCP protocol-specific data container."""
    
    protocol_type: Literal["tcp"] = "tcp"
    
    # TCP connection information
    connection_established: bool = Field(False, description="Whether TCP connection was established")
    connection_closed: bool = Field(False, description="Whether TCP connection was closed")
    
    # TCP flags and state
    syn_sent: bool = Field(False, description="SYN packet sent")
    syn_ack_received: bool = Field(False, description="SYN-ACK packet received")
    fin_sent: bool = Field(False, description="FIN packet sent")
    rst_sent: bool = Field(False, description="RST packet sent")
    
    # Data transfer
    bytes_sent: int = Field(0, ge=0, description="Bytes sent")
    bytes_received: int = Field(0, ge=0, description="Bytes received")
    packets_sent: int = Field(0, ge=0, description="Packets sent")
    packets_received: int = Field(0, ge=0, description="Packets received")
    
    # TCP-specific timing
    handshake_duration_ms: Optional[float] = Field(None, ge=0, description="TCP handshake duration")
    
    @computed_field
    @property
    def total_bytes(self) -> int:
        """Get total bytes transferred."""
        return self.bytes_sent + self.bytes_received


# Discriminated union for all protocol data types
def get_protocol_discriminator(v: Any) -> str:
    """Discriminator function for protocol data union."""
    if isinstance(v, dict):
        return v.get('protocol_type', 'unknown')
    return getattr(v, 'protocol_type', 'unknown')


ProtocolDataUnion = Union[
    HttpData,
    WebSocketData, 
    GrpcData,
    TcpData
]


class TLSInfo(BaseModel):
    """
    Comprehensive TLS connection information.
    
    Enhanced version with detailed cipher suite analysis and security assessment.
    """
    
    # Protocol information
    version: Optional[TLSVersion] = Field(None, description="TLS version used")
    cipher_suite: Optional[str] = Field(None, description="Cipher suite identifier")
    cipher_name: Optional[str] = Field(None, description="Human-readable cipher name")
    key_exchange: Optional[str] = Field(None, description="Key exchange algorithm")
    authentication: Optional[str] = Field(None, description="Authentication method")
    encryption: Optional[str] = Field(None, description="Encryption algorithm")
    mac: Optional[str] = Field(None, description="MAC algorithm")
    
    # Certificate information
    certificate_chain_length: int = Field(0, ge=0, description="Number of certificates in chain")
    certificate_issues: List[str] = Field(default_factory=list, description="Certificate problems")
    certificate_subject: Optional[str] = Field(None, description="Certificate subject")
    certificate_issuer: Optional[str] = Field(None, description="Certificate issuer")
    certificate_valid_from: Optional[datetime] = Field(None, description="Certificate valid from")
    certificate_valid_to: Optional[datetime] = Field(None, description="Certificate valid to")
    certificate_fingerprint: Optional[str] = Field(None, description="Certificate fingerprint")
    
    # Handshake information
    handshake_success: bool = Field(True, description="Whether handshake succeeded")
    handshake_duration_ms: Optional[float] = Field(None, ge=0, description="Handshake duration")
    server_name_indication: Optional[str] = Field(None, description="SNI value used")
    alpn_protocol: Optional[str] = Field(None, description="ALPN negotiated protocol")
    
    # Security assessment
    security_level: Optional[str] = Field(None, description="Overall security level")
    vulnerabilities: List[str] = Field(default_factory=list, description="Known vulnerabilities")
    recommendations: List[str] = Field(default_factory=list, description="Security recommendations")
    
    # Extensions and features
    extensions: List[str] = Field(default_factory=list, description="TLS extensions used")
    supported_groups: List[str] = Field(default_factory=list, description="Supported elliptic curves/groups")
    signature_algorithms: List[str] = Field(default_factory=list, description="Supported signature algorithms")
    
    @computed_field
    @property
    def is_secure(self) -> bool:
        """Assess if TLS configuration is secure."""
        if not self.version:
            return False
        
        # Check TLS version - handle both enum and string values
        version_is_secure = False
        if hasattr(self.version, 'is_secure'):
            # TLSVersion enum
            version_is_secure = self.version.is_secure
        else:
            # String value - check against known insecure versions
            version_str = str(self.version).lower()
            insecure_versions = ['ssl_2.0', 'ssl_3.0', 'tls_1.0', 'tls_1.1', 'sslv2', 'sslv3', 'tlsv1.0', 'tlsv1.1']
            version_is_secure = version_str not in insecure_versions
        
        if not version_is_secure:
            return False
        
        # Check for known vulnerabilities
        if self.vulnerabilities:
            return False
        
        # Check certificate issues
        critical_cert_issues = ['expired', 'invalid', 'self-signed', 'untrusted']
        if any(issue.lower() in ' '.join(self.certificate_issues).lower() 
               for issue in critical_cert_issues):
            return False
        
        return True
    
    @computed_field
    @property
    def risk_level(self) -> RiskLevel:
        """Calculate risk level based on TLS configuration."""
        if not self.handshake_success:
            return RiskLevel.HIGH
        
        if not self.is_secure:
            return RiskLevel.MEDIUM
        
        if self.vulnerabilities or self.certificate_issues:
            return RiskLevel.LOW
        
        return RiskLevel.SAFE
    
    def get_security_summary(self) -> Dict[str, Any]:
        """Get security assessment summary."""
        return {
            'is_secure': self.is_secure,
            'risk_level': self.risk_level.value,
            'version_secure': self.version.is_secure if self.version else False,
            'certificate_valid': len(self.certificate_issues) == 0,
            'vulnerabilities_count': len(self.vulnerabilities),
            'recommendations_count': len(self.recommendations)
        }


class ConnectionInfo(BaseModel):
    """Information about a network connection."""
    
    # Basic connection details
    protocol: NetworkProtocol = Field(..., description="Network protocol used")
    source_ip: str = Field(..., description="Source IP address")
    source_port: int = Field(..., ge=1, le=65535, description="Source port")
    destination_ip: str = Field(..., description="Destination IP address")
    destination_port: int = Field(..., ge=1, le=65535, description="Destination port")
    
    # Timing information
    connection_start: Optional[datetime] = Field(None, description="Connection start time")
    connection_end: Optional[datetime] = Field(None, description="Connection end time")
    duration_ms: Optional[float] = Field(None, ge=0, description="Connection duration")
    
    # Data transfer
    bytes_sent: int = Field(0, ge=0, description="Bytes sent")
    bytes_received: int = Field(0, ge=0, description="Bytes received")
    packets_sent: int = Field(0, ge=0, description="Packets sent")
    packets_received: int = Field(0, ge=0, description="Packets received")
    
    # Quality metrics
    latency_ms: Optional[float] = Field(None, ge=0, description="Connection latency")
    packet_loss_percent: float = Field(0.0, ge=0.0, le=100.0, description="Packet loss percentage")
    
    # Security information
    tls_info: Optional[TLSInfo] = Field(None, description="TLS connection details")
    
    @field_validator('source_ip', 'destination_ip')
    @classmethod
    def validate_ip_address(cls, v: str) -> str:
        try:
            # Try to parse as IPv4 or IPv6
            IPv4Address(v)
        except AddressValueError:
            try:
                IPv6Address(v)
            except AddressValueError:
                raise ValueError(f"Invalid IP address: {v}")
        return v
    
    @computed_field
    @property
    def is_encrypted(self) -> bool:
        """Check if connection uses encryption."""
        return self.protocol.is_encrypted or (self.tls_info is not None)
    
    @computed_field
    @property
    def total_bytes(self) -> int:
        """Get total bytes transferred."""
        return self.bytes_sent + self.bytes_received
    
    def get_connection_summary(self) -> str:
        """Get human-readable connection summary."""
        return f"{self.protocol.value}://{self.destination_ip}:{self.destination_port}"


class ProxyInfo(BaseModel):
    """Information about proxy server configuration and behavior."""
    
    # Basic proxy details
    proxy_type: ProxyType = Field(..., description="Type of proxy server")
    proxy_ip: str = Field(..., description="Proxy server IP address")
    proxy_port: int = Field(..., ge=1, le=65535, description="Proxy server port")
    proxy_hostname: Optional[str] = Field(None, description="Proxy server hostname")
    
    # Authentication
    requires_authentication: bool = Field(False, description="Whether proxy requires auth")
    authentication_method: Optional[str] = Field(None, description="Authentication method used")
    username: Optional[str] = Field(None, description="Username (if applicable)")
    
    # Capabilities
    supports_https: bool = Field(True, description="Whether proxy supports HTTPS")
    supports_websockets: bool = Field(False, description="Whether proxy supports WebSockets")
    supports_udp: bool = Field(False, description="Whether proxy supports UDP")
    
    # Performance metrics
    connection_time_ms: Optional[float] = Field(None, ge=0, description="Time to connect to proxy")
    response_time_ms: Optional[float] = Field(None, ge=0, description="Average response time")
    success_rate: float = Field(1.0, ge=0.0, le=1.0, description="Success rate (0.0-1.0)")
    
    # Detection indicators
    detected_by_target: bool = Field(False, description="Whether target detected proxy usage")
    detection_methods: List[str] = Field(default_factory=list, description="Methods used for detection")
    anonymity_level: str = Field("unknown", description="Anonymity level (transparent, anonymous, elite)")
    
    # Geographic information
    reported_country: Optional[str] = Field(None, description="Country reported by proxy")
    actual_country: Optional[str] = Field(None, description="Actual proxy location")
    geographic_consistency: bool = Field(True, description="Whether location is consistent")
    
    @field_validator('proxy_ip')
    @classmethod
    def validate_proxy_ip(cls, v: str) -> str:
        try:
            IPv4Address(v)
        except AddressValueError:
            try:
                IPv6Address(v)
            except AddressValueError:
                raise ValueError(f"Invalid proxy IP address: {v}")
        return v
    
    @field_validator('anonymity_level')
    @classmethod
    def validate_anonymity_level(cls, v: str) -> str:
        allowed_levels = ['transparent', 'anonymous', 'elite', 'unknown']
        if v not in allowed_levels:
            raise ValueError(f"Anonymity level must be one of: {allowed_levels}")
        return v
    
    @computed_field
    @property
    def risk_level(self) -> RiskLevel:
        """Calculate risk level based on proxy detection."""
        if self.detected_by_target:
            return RiskLevel.HIGH
        
        if not self.geographic_consistency:
            return RiskLevel.MEDIUM
        
        if self.anonymity_level == 'transparent':
            return RiskLevel.MEDIUM
        
        if self.success_rate < 0.9:
            return RiskLevel.LOW
        
        return RiskLevel.SAFE
    
    def get_detection_summary(self) -> Dict[str, Any]:
        """Get proxy detection summary."""
        return {
            'detected': self.detected_by_target,
            'detection_methods': self.detection_methods,
            'anonymity_level': self.anonymity_level,
            'risk_level': self.risk_level.value,
            'geographic_consistent': self.geographic_consistency
        }


class GeographicInfo(BaseModel):
    """Geographic location information."""
    
    # Location details
    country_code: Optional[str] = Field(None, description="ISO country code")
    country_name: Optional[str] = Field(None, description="Country name")
    region: Optional[GeographicRegion] = Field(None, description="Geographic region")
    city: Optional[str] = Field(None, description="City name")
    
    # Coordinates
    latitude: Optional[float] = Field(None, ge=-90.0, le=90.0, description="Latitude")
    longitude: Optional[float] = Field(None, ge=-180.0, le=180.0, description="Longitude")
    accuracy_km: Optional[float] = Field(None, ge=0, description="Location accuracy in kilometers")
    
    # Network information
    asn: Optional[int] = Field(None, description="Autonomous System Number")
    isp: Optional[str] = Field(None, description="Internet Service Provider")
    organization: Optional[str] = Field(None, description="Organization")
    
    # Timezone and locale
    timezone: Optional[str] = Field(None, description="Timezone identifier")
    locale: Optional[str] = Field(None, description="Locale/language code")
    
    # Detection metadata
    detection_method: Optional[str] = Field(None, description="How location was determined")
    confidence: float = Field(0.0, ge=0.0, le=1.0, description="Confidence in location data")
    
    @field_validator('country_code')
    @classmethod
    def validate_country_code(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and (len(v) != 2 or not v.isupper()):
            raise ValueError("Country code must be 2 uppercase letters")
        return v
    
    @computed_field
    @property
    def confidence_level(self) -> DetectionConfidence:
        """Get confidence level enum."""
        return DetectionConfidence.from_score(self.confidence)
    
    def distance_to(self, other: 'GeographicInfo') -> Optional[float]:
        """Calculate distance to another location in kilometers."""
        if (self.latitude is None or self.longitude is None or 
            other.latitude is None or other.longitude is None):
            return None
        
        # Haversine formula for great circle distance
        import math
        
        lat1, lon1 = math.radians(self.latitude), math.radians(self.longitude)
        lat2, lon2 = math.radians(other.latitude), math.radians(other.longitude)
        
        dlat = lat2 - lat1
        dlon = lon2 - lon1
        
        a = (math.sin(dlat/2)**2 + 
             math.cos(lat1) * math.cos(lat2) * math.sin(dlon/2)**2)
        c = 2 * math.asin(math.sqrt(a))
        
        # Earth's radius in kilometers
        r = 6371
        
        return c * r


class NetworkHop(BaseModel):
    """
    Represents a single hop in the network trace.
    
    Enhanced version with better actor classification and risk assessment.
    """
    
    # Basic hop information
    hop_number: int = Field(..., ge=1, description="Hop sequence number")
    hop_id: str = Field(default_factory=lambda: str(uuid4()), description="Unique hop identifier")
    
    # Actor information
    actor: str = Field(..., description="Network actor type")
    actor_name: str = Field(..., description="Descriptive name of the actor")
    actor_category: str = Field("unknown", description="Actor category (client, proxy, server, etc.)")
    
    # Network details
    incoming_ip: str = Field(..., description="IP address receiving traffic")
    outgoing_ip: str = Field(..., description="IP address sending traffic")
    connection_info: Optional[ConnectionInfo] = Field(None, description="Connection details")
    
    # Geographic information
    geographic_info: Optional[GeographicInfo] = Field(None, description="Geographic location")
    
    # Proxy information (if applicable)
    proxy_info: Optional[ProxyInfo] = Field(None, description="Proxy server details")
    
    # Detection and analysis
    detection_vectors: List[str] = Field(default_factory=list, description="Potential detection methods")
    risk_level: RiskLevel = Field(RiskLevel.SAFE, description="Risk assessment")
    anomalies: List[str] = Field(default_factory=list, description="Detected anomalies")
    
    # Timing information
    timestamp: Optional[datetime] = Field(None, description="When this hop occurred")
    response_time_ms: Optional[float] = Field(None, ge=0, description="Response time")
    
    # Metadata
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional metadata")
    
    @field_validator('incoming_ip', 'outgoing_ip')
    @classmethod
    def validate_ip_addresses(cls, v: str) -> str:
        try:
            IPv4Address(v)
        except AddressValueError:
            try:
                IPv6Address(v)
            except AddressValueError:
                raise ValueError(f"Invalid IP address: {v}")
        return v
    
    @field_validator('actor_category')
    @classmethod
    def validate_actor_category(cls, v: str) -> str:
        allowed_categories = [
            'client', 'proxy', 'server', 'load_balancer', 'cdn', 
            'firewall', 'router', 'gateway', 'unknown'
        ]
        if v not in allowed_categories:
            raise ValueError(f"Actor category must be one of: {allowed_categories}")
        return v
    
    @computed_field
    @property
    def is_proxy_hop(self) -> bool:
        """Check if this hop represents a proxy server."""
        return self.proxy_info is not None or 'proxy' in self.actor.lower()
    
    @computed_field
    @property
    def overall_risk_score(self) -> float:
        """Calculate overall risk score for this hop."""
        base_risk = self.risk_level.numeric_value / 4.0  # Normalize to 0-1
        
        # Add risk from proxy detection
        if self.proxy_info and self.proxy_info.detected_by_target:
            base_risk += 0.3
        
        # Add risk from anomalies
        anomaly_risk = min(0.2, len(self.anomalies) * 0.05)
        base_risk += anomaly_risk
        
        # Add risk from detection vectors
        detection_risk = min(0.2, len(self.detection_vectors) * 0.03)
        base_risk += detection_risk
        
        return min(1.0, base_risk)
    
    def get_security_summary(self) -> Dict[str, Any]:
        """Get security assessment summary for this hop."""
        return {
            'risk_level': self.risk_level.value,
            'risk_score': self.overall_risk_score,
            'is_proxy': self.is_proxy_hop,
            'detection_vectors_count': len(self.detection_vectors),
            'anomalies_count': len(self.anomalies),
            'proxy_detected': self.proxy_info.detected_by_target if self.proxy_info else False
        }


class NetworkTrace(BaseModel):
    """
    Complete network trace containing all hops and analysis.
    
    Enhanced version with better aggregation and risk assessment.
    Now supports extensible protocol-specific data.
    """
    
    # Basic trace information
    trace_id: str = Field(default_factory=lambda: str(uuid4()), description="Unique trace identifier")
    session_id: Optional[str] = Field(None, description="Associated session identifier")
    
    # Protocol information
    protocol: NetworkProtocol = Field(NetworkProtocol.HTTP, description="Network protocol used")
    protocol_data: Optional[ProtocolDataUnion] = Field(None, description="Protocol-specific data")
    
    # Hops and routing
    hops: List[NetworkHop] = Field(default_factory=list, description="Network hops in order")
    total_hops: int = Field(0, ge=0, description="Total number of hops")
    
    # Timing information
    trace_start: Optional[datetime] = Field(None, description="Trace start time")
    trace_end: Optional[datetime] = Field(None, description="Trace end time")
    total_duration_ms: Optional[float] = Field(None, ge=0, description="Total trace duration")
    
    # Analysis results
    proxy_chain_detected: bool = Field(False, description="Whether proxy chain was detected")
    geographic_consistency: bool = Field(True, description="Whether geography is consistent")
    overall_risk_level: RiskLevel = Field(RiskLevel.SAFE, description="Overall risk assessment")
    
    # Summary statistics
    unique_countries: List[str] = Field(default_factory=list, description="Unique countries in trace")
    proxy_hops_count: int = Field(0, ge=0, description="Number of proxy hops")
    anomalous_hops_count: int = Field(0, ge=0, description="Number of anomalous hops")
    
    # Metadata
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional trace metadata")
    
    def add_hop(self, hop: NetworkHop) -> None:
        """Add a hop to the trace."""
        self.hops.append(hop)
        self.total_hops = len(self.hops)
        self._update_statistics()
    
    def _update_statistics(self) -> None:
        """Update trace statistics based on current hops."""
        # Count proxy hops
        self.proxy_hops_count = sum(1 for hop in self.hops if hop.is_proxy_hop)
        
        # Count anomalous hops
        self.anomalous_hops_count = sum(1 for hop in self.hops if hop.anomalies)
        
        # Update unique countries
        countries = set()
        for hop in self.hops:
            if hop.geographic_info and hop.geographic_info.country_code:
                countries.add(hop.geographic_info.country_code)
        self.unique_countries = list(countries)
        
        # Update overall risk level
        if self.hops:
            max_risk = max(hop.risk_level for hop in self.hops)
            self.overall_risk_level = max_risk
        
        # Check proxy chain detection
        self.proxy_chain_detected = self.proxy_hops_count > 0
    
    @computed_field
    @property
    def average_risk_score(self) -> float:
        """Calculate average risk score across all hops."""
        if not self.hops:
            return 0.0
        return sum(hop.overall_risk_score for hop in self.hops) / len(self.hops)
    
    def get_hops_by_risk(self, min_risk: RiskLevel) -> List[NetworkHop]:
        """Get hops with risk level at or above minimum."""
        return [hop for hop in self.hops if hop.risk_level.numeric_value >= min_risk.numeric_value]
    
    def get_proxy_hops(self) -> List[NetworkHop]:
        """Get all hops that are proxy servers."""
        return [hop for hop in self.hops if hop.is_proxy_hop]
    
    def get_trace_summary(self) -> Dict[str, Any]:
        """Get comprehensive trace summary."""
        return {
            'total_hops': self.total_hops,
            'proxy_hops': self.proxy_hops_count,
            'anomalous_hops': self.anomalous_hops_count,
            'unique_countries': len(self.unique_countries),
            'countries': self.unique_countries,
            'overall_risk': self.overall_risk_level.value,
            'average_risk_score': self.average_risk_score,
            'proxy_chain_detected': self.proxy_chain_detected,
            'geographic_consistency': self.geographic_consistency,
            'duration_ms': self.total_duration_ms
        }
    
    def to_table_data(self) -> List[List[str]]:
        """Convert trace to table format for display."""
        headers = [
            "Hop", "Actor", "Incoming IP", "Outgoing IP", 
            "Actor Name", "Risk Level", "Detection Vectors", "Country"
        ]
        
        rows = [headers]
        for hop in self.hops:
            country = ""
            if hop.geographic_info and hop.geographic_info.country_code:
                country = hop.geographic_info.country_code
            
            detection_info = ", ".join(hop.detection_vectors[:2])
            if len(hop.detection_vectors) > 2:
                detection_info += "..."
            
            row = [
                str(hop.hop_number),
                hop.actor,
                hop.incoming_ip,
                hop.outgoing_ip,
                hop.actor_name,
                hop.risk_level.value,
                detection_info or "None",
                country
            ]
            rows.append(row)
        
        return rows
    
    # ============================================================================
    # PROTOCOL-AWARE ACCESS METHODS
    # ============================================================================
    
    @property
    def http_data(self) -> Optional[HttpData]:
        """Get HTTP data if this is an HTTP trace."""
        if isinstance(self.protocol_data, HttpData):
            return self.protocol_data
        return None
    
    @property
    def websocket_data(self) -> Optional[WebSocketData]:
        """Get WebSocket data if this is a WebSocket trace."""
        if isinstance(self.protocol_data, WebSocketData):
            return self.protocol_data
        return None
    
    @property
    def grpc_data(self) -> Optional[GrpcData]:
        """Get gRPC data if this is a gRPC trace."""
        if isinstance(self.protocol_data, GrpcData):
            return self.protocol_data
        return None
    
    @property
    def tcp_data(self) -> Optional[TcpData]:
        """Get TCP data if this is a TCP trace."""
        if isinstance(self.protocol_data, TcpData):
            return self.protocol_data
        return None
    
    # Protocol type guards
    def is_http(self) -> bool:
        """Type guard for HTTP traces."""
        return isinstance(self.protocol_data, HttpData)
    
    def is_websocket(self) -> bool:
        """Type guard for WebSocket traces."""
        return isinstance(self.protocol_data, WebSocketData)
    
    def is_grpc(self) -> bool:
        """Type guard for gRPC traces."""
        return isinstance(self.protocol_data, GrpcData)
    
    def is_tcp(self) -> bool:
        """Type guard for TCP traces."""
        return isinstance(self.protocol_data, TcpData)
    
    def supports_protocol(self, protocol: NetworkProtocol) -> bool:
        """Check if trace supports the specified protocol."""
        return self.protocol == protocol


class HttpRequest(BaseModel):
    """HTTP request information for parsing HAR files."""
    
    method: str = Field(..., description="HTTP method (GET, POST, etc.)")
    url: str = Field(..., description="Request URL")
    headers: List[Dict[str, str]] = Field(default_factory=list, description="Request headers")
    body: Optional[str] = Field(None, description="Request body")
    body_size: int = Field(0, ge=0, description="Request body size in bytes")
    timestamp: Optional[datetime] = Field(None, description="Request timestamp")
    
    @field_validator('method')
    @classmethod
    def validate_method(cls, v: str) -> str:
        """Validate HTTP method."""
        allowed_methods = ['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 'PATCH', 'TRACE']
        if v.upper() not in allowed_methods:
            raise ValueError(f"Invalid HTTP method: {v}")
        return v.upper()


class HttpResponse(BaseModel):
    """HTTP response information for parsing HAR files."""
    
    status_code: int = Field(..., ge=100, le=599, description="HTTP status code")
    status_text: str = Field("", description="HTTP status text")
    headers: List[Dict[str, str]] = Field(default_factory=list, description="Response headers")
    body: Optional[str] = Field(None, description="Response body")
    body_size: int = Field(0, ge=0, description="Response body size in bytes")
    content_type: Optional[str] = Field(None, description="Content type")
    
    @computed_field
    @property
    def is_success(self) -> bool:
        """Check if response indicates success."""
        return 200 <= self.status_code < 300
    
    @computed_field
    @property
    def is_redirect(self) -> bool:
        """Check if response is a redirect."""
        return 300 <= self.status_code < 400
    
    @computed_field
    @property
    def is_client_error(self) -> bool:
        """Check if response is a client error."""
        return 400 <= self.status_code < 500
    
    @computed_field
    @property
    def is_server_error(self) -> bool:
        """Check if response is a server error."""
        return 500 <= self.status_code < 600


class TimingInfo(BaseModel):
    """HTTP request/response timing information from HAR files."""
    
    dns_lookup: float = Field(-1, description="DNS lookup time in ms")
    tcp_connect: float = Field(-1, description="TCP connection time in ms")
    ssl_handshake: float = Field(-1, description="SSL handshake time in ms")
    request_sent: float = Field(-1, description="Time to send request in ms")
    waiting: float = Field(-1, description="Waiting time (TTFB) in ms")
    content_download: float = Field(-1, description="Content download time in ms")
    blocked: float = Field(-1, description="Blocked time in ms")
    
    @computed_field
    @property
    def total_time(self) -> float:
        """Calculate total request time."""
        times = [
            self.dns_lookup, self.tcp_connect, self.ssl_handshake,
            self.request_sent, self.waiting, self.content_download
        ]
        # Only sum positive values (HAR format uses -1 for unavailable timing)
        valid_times = [t for t in times if t > 0]
        return sum(valid_times) if valid_times else 0
    
    @computed_field
    @property
    def has_ssl(self) -> bool:
        """Check if this request used SSL/TLS."""
        return self.ssl_handshake > 0


class HttpTrace(NetworkTrace):
    """
    Network trace with HTTP request/response data.
    
    Extends NetworkTrace to include HTTP-specific information parsed from HAR files.
    """
    
    # HTTP data fields
    request: Optional[HttpRequest] = Field(None, description="HTTP request information")
    response: Optional[HttpResponse] = Field(None, description="HTTP response information")
    timing: Optional[TimingInfo] = Field(None, description="HTTP timing information")
    
    def __init__(self, **data):
        """Initialize HttpTrace, extracting HTTP data from metadata if needed."""
        # If HTTP data is provided in metadata, extract it to fields
        metadata = data.get('metadata', {})
        
        # Extract HTTP request from metadata
        if not data.get('request') and 'http_request' in metadata:
            http_request_data = metadata['http_request']
            try:
                data['request'] = HttpRequest(**http_request_data)
            except Exception:
                pass
        
        # Extract HTTP response from metadata
        if not data.get('response') and 'http_response' in metadata:
            http_response_data = metadata['http_response']
            try:
                data['response'] = HttpResponse(**http_response_data)
            except Exception:
                pass
        
        # Extract timing from metadata
        if not data.get('timing') and 'http_timing' in metadata:
            http_timing_data = metadata['http_timing']
            try:
                data['timing'] = TimingInfo(**http_timing_data)
            except Exception:
                pass
        
        super().__init__(**data)
    
    @computed_field
    @property
    def has_http_data(self) -> bool:
        """Check if trace has HTTP request/response data."""
        return self.request is not None or self.response is not None
    
    @computed_field
    @property
    def is_http_success(self) -> bool:
        """Check if HTTP response indicates success."""
        return self.response.is_success if self.response else False
    
    @computed_field
    @property
    def http_status_code(self) -> int:
        """Get HTTP status code."""
        return self.response.status_code if self.response else 0
    
    @computed_field
    @property
    def response_time_ms(self) -> Optional[float]:
        """Get response time in milliseconds."""
        return self.timing.total_time if self.timing else None
    
    @computed_field
    @property
    def timestamp(self) -> Optional[datetime]:
        """Get request timestamp."""
        return self.request.timestamp if self.request else None
    
    def get_http_summary(self) -> Dict[str, Any]:
        """Get HTTP-specific trace summary."""
        summary = self.get_trace_summary()
        summary.update({
            'has_http_data': self.has_http_data,
            'request_method': self.request.method if self.request else None,
            'request_url': self.request.url if self.request else None,
            'response_status': self.response.status_code if self.response else None,
            'response_success': self.is_http_success,
            'total_time_ms': self.timing.total_time if self.timing else None,
        })
        return summary


# Rebuild models to resolve forward references
HttpData.model_rebuild()
WebSocketData.model_rebuild()
GrpcData.model_rebuild()
TcpData.model_rebuild()
NetworkTrace.model_rebuild()
HttpTrace.model_rebuild()

# Export all models
__all__ = [
    'TLSInfo',
    'ConnectionInfo',
    'ProxyInfo',
    'GeographicInfo',
    'NetworkHop',
    'NetworkTrace',
    'HttpTrace',
    'HttpRequest',
    'HttpResponse',
    'TimingInfo',
    'ProtocolData',
    'HttpData',
    'WebSocketData',
    'GrpcData',
    'TcpData',
    'ProtocolDataUnion',
]
