"""
Enumerations for NetStealth Analyzer data models.

This module defines all enums used throughout the analyzer for consistent
categorization and classification of data.

Author: NetStealth Analyzer Team
Version: 2.0.0
Python: 3.11+
"""

from enum import Enum, IntEnum, auto
from typing import Dict, List, Optional


class SeverityLevel(str, Enum):
    """Severity levels for issues and detections."""
    
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    
    @property
    def numeric_value(self) -> int:
        """Get numeric value for sorting and comparison."""
        return {
            self.CRITICAL: 5,
            self.HIGH: 4,
            self.MEDIUM: 3,
            self.LOW: 2,
            self.INFO: 1
        }[self]
    
    @property
    def color_code(self) -> str:
        """Get color code for UI display."""
        return {
            self.CRITICAL: "#FF0000",  # Red
            self.HIGH: "#FF6600",      # Orange
            self.MEDIUM: "#FFCC00",    # Yellow
            self.LOW: "#00CC00",       # Green
            self.INFO: "#0066CC"       # Blue
        }[self]
    
    def __lt__(self, other) -> bool:
        """Enable sorting by severity."""
        if isinstance(other, SeverityLevel):
            return self.numeric_value < other.numeric_value
        return NotImplemented


class RiskLevel(str, Enum):
    """Risk levels for network components and operations."""
    
    SAFE = "safe"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    
    @property
    def numeric_value(self) -> int:
        """Get numeric value for risk assessment."""
        return {
            self.SAFE: 0,
            self.LOW: 1,
            self.MEDIUM: 2,
            self.HIGH: 3,
            self.CRITICAL: 4
        }[self]
    
    def __lt__(self, other) -> bool:
        """Enable sorting by risk level."""
        if isinstance(other, RiskLevel):
            return self.numeric_value < other.numeric_value
        return NotImplemented


class IssueCategory(str, Enum):
    """Categories for detected security and privacy issues."""
    
    # Core detection categories
    TLS_FINGERPRINT = "tls_fingerprint"
    PROXY_DETECTION = "proxy_detection"
    BROWSER_CONFIG = "browser_config"
    NETWORK_ANOMALY = "network_anomaly"
    
    # Extended categories
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    SESSION_MANAGEMENT = "session_management"
    DATA_LEAKAGE = "data_leakage"
    PRIVACY_VIOLATION = "privacy_violation"
    PERFORMANCE = "performance"
    CONFIGURATION = "configuration"
    COMPLIANCE = "compliance"
    
    # Geographic and location-based
    GEOGRAPHIC_LEAK = "geographic_leak"
    IP_EXPOSURE = "ip_exposure"
    DNS_LEAK = "dns_leak"
    
    # Browser and client-side
    JAVASCRIPT_FINGERPRINT = "javascript_fingerprint"
    WEBRTC_LEAK = "webrtc_leak"
    CANVAS_FINGERPRINT = "canvas_fingerprint"
    FONT_FINGERPRINT = "font_fingerprint"
    
    @property
    def display_name(self) -> str:
        """Get human-readable display name."""
        return {
            self.TLS_FINGERPRINT: "TLS Fingerprinting",
            self.PROXY_DETECTION: "Proxy Detection",
            self.BROWSER_CONFIG: "Browser Configuration",
            self.NETWORK_ANOMALY: "Network Anomaly",
            self.AUTHENTICATION: "Authentication Issue",
            self.AUTHORIZATION: "Authorization Problem",
            self.SESSION_MANAGEMENT: "Session Management",
            self.DATA_LEAKAGE: "Data Leakage",
            self.PRIVACY_VIOLATION: "Privacy Violation",
            self.PERFORMANCE: "Performance Issue",
            self.CONFIGURATION: "Configuration Problem",
            self.COMPLIANCE: "Compliance Violation",
            self.GEOGRAPHIC_LEAK: "Geographic Information Leak",
            self.IP_EXPOSURE: "IP Address Exposure",
            self.DNS_LEAK: "DNS Leak",
            self.JAVASCRIPT_FINGERPRINT: "JavaScript Fingerprinting",
            self.WEBRTC_LEAK: "WebRTC Leak",
            self.CANVAS_FINGERPRINT: "Canvas Fingerprinting",
            self.FONT_FINGERPRINT: "Font Fingerprinting",
        }.get(self, self.value.replace('_', ' ').title())
    
    @property
    def description(self) -> str:
        """Get detailed description of the category."""
        return {
            self.TLS_FINGERPRINT: "Detection of unique TLS characteristics that could identify the client",
            self.PROXY_DETECTION: "Evidence that proxy usage has been detected by the target service",
            self.BROWSER_CONFIG: "Browser configuration issues that may compromise anonymity",
            self.NETWORK_ANOMALY: "Unusual network behavior that could indicate detection",
            self.AUTHENTICATION: "Problems with authentication mechanisms or credentials",
            self.AUTHORIZATION: "Issues with access control and permissions",
            self.SESSION_MANAGEMENT: "Session handling problems that could affect security",
            self.DATA_LEAKAGE: "Unintended exposure of sensitive information",
            self.PRIVACY_VIOLATION: "Violations of privacy expectations or regulations",
            self.PERFORMANCE: "Performance issues that could affect user experience",
            self.CONFIGURATION: "Misconfiguration that could compromise security or functionality",
            self.COMPLIANCE: "Violations of regulatory or policy requirements",
            self.GEOGRAPHIC_LEAK: "Exposure of real geographic location despite masking attempts",
            self.IP_EXPOSURE: "Exposure of real IP address through various techniques",
            self.DNS_LEAK: "DNS queries revealing real location or identity",
            self.JAVASCRIPT_FINGERPRINT: "JavaScript-based fingerprinting techniques detected",
            self.WEBRTC_LEAK: "WebRTC exposing real IP addresses",
            self.CANVAS_FINGERPRINT: "Canvas-based fingerprinting detected",
            self.FONT_FINGERPRINT: "Font-based fingerprinting techniques identified",
        }.get(self, f"Issues related to {self.display_name.lower()}")


class LogFormat(str, Enum):
    """Supported log file formats for analysis."""
    
    # Network proxy logs
    MITMPROXY = "mitmproxy"
    BURP_SUITE = "burp_suite"
    CHARLES_PROXY = "charles_proxy"
    
    # Browser logs
    HAR = "har"
    BROWSER_CONSOLE = "browser_console"
    CHROME_DEBUG = "chrome_debug"
    FIREFOX_DEBUG = "firefox_debug"
    
    # Custom formats
    POC_EXECUTION = "poc_execution"
    NETSTEALTH_NATIVE = "netstealth_native"
    
    # Generic formats
    JSON_LINES = "json_lines"
    CSV = "csv"
    PLAIN_TEXT = "plain_text"
    
    @property
    def file_extensions(self) -> List[str]:
        """Get typical file extensions for this format."""
        return {
            self.MITMPROXY: ['.mitm', '.flow'],
            self.BURP_SUITE: ['.xml', '.json'],
            self.CHARLES_PROXY: ['.chlsj', '.xml'],
            self.HAR: ['.har'],
            self.BROWSER_CONSOLE: ['.log', '.txt'],
            self.CHROME_DEBUG: ['.json', '.log'],
            self.FIREFOX_DEBUG: ['.json', '.log'],
            self.POC_EXECUTION: ['.poc', '.json'],
            self.NETSTEALTH_NATIVE: ['.nsl', '.json'],
            self.JSON_LINES: ['.jsonl', '.ndjson'],
            self.CSV: ['.csv'],
            self.PLAIN_TEXT: ['.txt', '.log'],
        }.get(self, ['.log'])
    
    @property
    def supports_streaming(self) -> bool:
        """Check if format supports streaming/incremental parsing."""
        return self in {
            self.JSON_LINES,
            self.PLAIN_TEXT,
            self.BROWSER_CONSOLE,
            self.NETSTEALTH_NATIVE
        }


class AnalysisStatus(str, Enum):
    """Overall status of analysis execution."""
    
    SUCCESS = "success"
    PARTIAL_SUCCESS = "partial_success"
    FAILED = "failed"
    CANCELLED = "cancelled"
    TIMEOUT = "timeout"
    
    @property
    def is_successful(self) -> bool:
        """Check if status indicates successful completion."""
        return self in {self.SUCCESS, self.PARTIAL_SUCCESS}
    
    @property
    def is_terminal(self) -> bool:
        """Check if status is terminal (no further processing)."""
        return self in {self.SUCCESS, self.FAILED, self.CANCELLED, self.TIMEOUT}


class DetectionConfidence(str, Enum):
    """Confidence levels for detections and classifications."""
    
    VERY_HIGH = "very_high"    # 90-100%
    HIGH = "high"              # 75-89%
    MEDIUM = "medium"          # 50-74%
    LOW = "low"                # 25-49%
    VERY_LOW = "very_low"      # 0-24%
    
    @property
    def numeric_range(self) -> tuple[float, float]:
        """Get numeric confidence range."""
        return {
            self.VERY_HIGH: (0.90, 1.00),
            self.HIGH: (0.75, 0.89),
            self.MEDIUM: (0.50, 0.74),
            self.LOW: (0.25, 0.49),
            self.VERY_LOW: (0.00, 0.24),
        }[self]
    
    @classmethod
    def from_score(cls, score: float) -> 'DetectionConfidence':
        """Convert numeric score to confidence level."""
        if score >= 0.90:
            return cls.VERY_HIGH
        elif score >= 0.75:
            return cls.HIGH
        elif score >= 0.50:
            return cls.MEDIUM
        elif score >= 0.25:
            return cls.LOW
        else:
            return cls.VERY_LOW


class NetworkProtocol(str, Enum):
    """Network protocols used in connections."""
    
    HTTP = "http"
    HTTPS = "https"
    HTTP2 = "http2"
    HTTP3 = "http3"
    WEBSOCKET = "websocket"
    WEBSOCKET_SECURE = "websocket_secure"
    TCP = "tcp"
    UDP = "udp"
    QUIC = "quic"
    
    @property
    def is_encrypted(self) -> bool:
        """Check if protocol uses encryption."""
        return self in {
            self.HTTPS,
            self.HTTP2,  # Usually over TLS
            self.HTTP3,  # Always over QUIC/TLS
            self.WEBSOCKET_SECURE,
            self.QUIC
        }
    
    @property
    def default_port(self) -> int:
        """Get default port for protocol."""
        return {
            self.HTTP: 80,
            self.HTTPS: 443,
            self.HTTP2: 443,
            self.HTTP3: 443,
            self.WEBSOCKET: 80,
            self.WEBSOCKET_SECURE: 443,
            self.QUIC: 443,
        }.get(self, 0)


class TLSVersion(str, Enum):
    """TLS/SSL protocol versions."""
    
    SSL_30 = "ssl_3.0"
    TLS_10 = "tls_1.0"
    TLS_11 = "tls_1.1"
    TLS_12 = "tls_1.2"
    TLS_13 = "tls_1.3"
    
    @property
    def is_secure(self) -> bool:
        """Check if TLS version is considered secure."""
        return self in {self.TLS_12, self.TLS_13}
    
    @property
    def numeric_version(self) -> float:
        """Get numeric version for comparison."""
        return {
            self.SSL_30: 3.0,
            self.TLS_10: 1.0,
            self.TLS_11: 1.1,
            self.TLS_12: 1.2,
            self.TLS_13: 1.3,
        }[self]
    
    def __lt__(self, other) -> bool:
        """Enable version comparison."""
        if isinstance(other, TLSVersion):
            return self.numeric_version < other.numeric_version
        return NotImplemented


class ProxyType(str, Enum):
    """Types of proxy servers and configurations."""
    
    HTTP = "http"
    HTTPS = "https"
    SOCKS4 = "socks4"
    SOCKS5 = "socks5"
    TRANSPARENT = "transparent"
    REVERSE = "reverse"
    FORWARD = "forward"
    
    @property
    def supports_authentication(self) -> bool:
        """Check if proxy type supports authentication."""
        return self in {self.HTTP, self.HTTPS, self.SOCKS5}
    
    @property
    def supports_udp(self) -> bool:
        """Check if proxy type supports UDP traffic."""
        return self == self.SOCKS5


class GeographicRegion(str, Enum):
    """Geographic regions for location-based analysis."""
    
    NORTH_AMERICA = "north_america"
    SOUTH_AMERICA = "south_america"
    EUROPE = "europe"
    ASIA_PACIFIC = "asia_pacific"
    MIDDLE_EAST = "middle_east"
    AFRICA = "africa"
    OCEANIA = "oceania"
    
    @property
    def countries(self) -> List[str]:
        """Get common country codes for this region."""
        return {
            self.NORTH_AMERICA: ["US", "CA", "MX"],
            self.SOUTH_AMERICA: ["BR", "AR", "CL", "CO", "PE"],
            self.EUROPE: ["GB", "DE", "FR", "IT", "ES", "NL", "SE", "NO"],
            self.ASIA_PACIFIC: ["JP", "CN", "KR", "IN", "AU", "SG", "HK"],
            self.MIDDLE_EAST: ["AE", "SA", "IL", "TR", "IR"],
            self.AFRICA: ["ZA", "EG", "NG", "KE", "MA"],
            self.OCEANIA: ["AU", "NZ", "FJ"],
        }.get(self, [])


# Export all enums
__all__ = [
    'SeverityLevel',
    'RiskLevel', 
    'IssueCategory',
    'LogFormat',
    'AnalysisStatus',
    'DetectionConfidence',
    'NetworkProtocol',
    'TLSVersion',
    'ProxyType',
    'GeographicRegion',
]
