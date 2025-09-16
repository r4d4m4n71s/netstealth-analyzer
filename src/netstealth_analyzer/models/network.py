"""
Network and connection models for NetStealth Analyzer.

This module defines models for network traces, TLS information, proxy details,
and geographic data with enhanced analysis capabilities.

Author: NetStealth Analyzer Team
Version: 2.0.0
Python: 3.11+
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Union
from ipaddress import IPv4Address, IPv6Address, AddressValueError
from uuid import UUID, uuid4

from pydantic import BaseModel, Field, field_validator, computed_field

from .enums import (
    RiskLevel, NetworkProtocol, TLSVersion, ProxyType, 
    GeographicRegion, DetectionConfidence
)
from ..compatibility import override


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
        
        # Check TLS version
        if not self.version.is_secure:
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


class HttpRequest(BaseModel):
    """HTTP request information."""
    
    # Request details
    method: str = Field(..., description="HTTP method (GET, POST, etc.)")
    url: str = Field(..., description="Request URL")
    headers: Dict[str, str] = Field(default_factory=dict, description="Request headers")
    body: Optional[str] = Field(None, description="Request body")
    
    # Timing
    timestamp: Optional[datetime] = Field(None, description="Request timestamp")
    duration_ms: Optional[float] = Field(None, ge=0, description="Request duration")
    
    # Response information
    status_code: Optional[int] = Field(None, ge=100, le=599, description="HTTP status code")
    response_headers: Dict[str, str] = Field(default_factory=dict, description="Response headers")
    response_body: Optional[str] = Field(None, description="Response body")
    response_size: int = Field(0, ge=0, description="Response size in bytes")
    
    @computed_field
    @property
    def is_successful(self) -> bool:
        """Check if request was successful (2xx status)."""
        return self.status_code is not None and 200 <= self.status_code < 300


class HttpResponse(BaseModel):
    """HTTP response information."""
    
    # Response details
    status_code: int = Field(..., ge=100, le=599, description="HTTP status code")
    status_text: str = Field("", description="HTTP status text")
    headers: Dict[str, str] = Field(default_factory=dict, description="Response headers")
    body: Optional[str] = Field(None, description="Response body")
    
    # Timing
    timestamp: Optional[datetime] = Field(None, description="Response timestamp")
    duration_ms: Optional[float] = Field(None, ge=0, description="Response time")
    
    # Size information
    content_length: int = Field(0, ge=0, description="Content length in bytes")
    headers_size: int = Field(0, ge=0, description="Headers size in bytes")
    
    @computed_field
    @property
    def is_successful(self) -> bool:
        """Check if response indicates success (2xx status)."""
        return 200 <= self.status_code < 300
    
    @computed_field
    @property
    def is_redirect(self) -> bool:
        """Check if response is a redirect (3xx status)."""
        return 300 <= self.status_code < 400
    
    @computed_field
    @property
    def is_client_error(self) -> bool:
        """Check if response indicates client error (4xx status)."""
        return 400 <= self.status_code < 500
    
    @computed_field
    @property
    def is_server_error(self) -> bool:
        """Check if response indicates server error (5xx status)."""
        return 500 <= self.status_code < 600


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
    def validate_ip_address(cls, v):
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
    
    @validator('proxy_ip')
    def validate_proxy_ip(cls, v):
        try:
            IPv4Address(v)
        except AddressValueError:
            try:
                IPv6Address(v)
            except AddressValueError:
                raise ValueError(f"Invalid proxy IP address: {v}")
        return v
    
    @validator('anonymity_level')
    def validate_anonymity_level(cls, v):
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
    
    @validator('country_code')
    def validate_country_code(cls, v):
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
    
    @validator('incoming_ip', 'outgoing_ip')
    def validate_ip_addresses(cls, v):
        try:
            IPv4Address(v)
        except AddressValueError:
            try:
                IPv6Address(v)
            except AddressValueError:
                raise ValueError(f"Invalid IP address: {v}")
        return v
    
    @validator('actor_category')
    def validate_actor_category(cls, v):
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
    """
    
    # Basic trace information
    trace_id: str = Field(default_factory=lambda: str(uuid4()), description="Unique trace identifier")
    session_id: Optional[str] = Field(None, description="Associated session identifier")
    
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


# Export all models
__all__ = [
    'TLSInfo',
    'HttpRequest',
    'HttpResponse',
    'ConnectionInfo',
    'ProxyInfo',
    'GeographicInfo',
    'NetworkHop',
    'NetworkTrace',
]
