"""
Data models for Stealth Analyzer.

This module defines the core data structures used throughout the analyzer
for configuration, results, and reporting.
"""

from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from pydantic import BaseModel, Field, field_validator


class SeverityLevel(str, Enum):
    """Severity levels for issues and detections."""
    
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class RiskLevel(str, Enum):
    """Risk levels for network hops and components."""
    
    SAFE = "SAFE"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class IssueCategory(str, Enum):
    """Categories for detected issues."""
    
    TLS_FINGERPRINT = "tls_fingerprint"
    PROXY_DETECTION = "proxy_detection"
    BROWSER_CONFIG = "browser_config"
    NETWORK_ANOMALY = "network_anomaly"
    AUTHENTICATION = "authentication"
    PERFORMANCE = "performance"


class LogFormat(str, Enum):
    """Supported log formats."""
    
    MITMPROXY = "mitmproxy"
    POC_EXECUTION = "poc_execution"
    HAR = "har"
    BROWSER_CONSOLE = "browser_console"
    CHROME_DEBUG = "chrome_debug"


class DetectionRule(BaseModel):
    """Configuration for detection rules."""
    
    id: str = Field(..., description="Unique rule identifier")
    category: IssueCategory = Field(..., description="Issue category")
    pattern: str = Field(..., description="Regex pattern or string to match")
    severity: SeverityLevel = Field(..., description="Issue severity")
    description: str = Field(..., description="Human-readable description")
    recommendation: Optional[str] = Field(None, description="Fix recommendation")
    code_fix: Optional[str] = Field(None, description="Code snippet to fix issue")
    enabled: bool = Field(True, description="Whether rule is enabled")


class TLSInfo(BaseModel):
    """TLS connection information."""
    
    version: Optional[str] = Field(None, description="TLS version (e.g., 'TLS 1.3')")
    cipher_suite: Optional[str] = Field(None, description="Cipher suite used")
    certificate_issues: List[str] = Field(default_factory=list, description="Certificate problems")
    handshake_success: bool = Field(True, description="Whether handshake succeeded")


class NetworkHop(BaseModel):
    """Represents a single hop in the network trace."""
    
    hop_number: int = Field(..., description="Hop sequence number")
    actor: str = Field(..., description="Network actor type (Client, Proxy, etc.)")
    incoming_ip: str = Field(..., description="IP address receiving traffic")
    outgoing_ip: str = Field(..., description="IP address sending traffic")
    actor_name: str = Field(..., description="Descriptive name of the actor")
    tls_info: Optional[TLSInfo] = Field(None, description="TLS connection details")
    detection_vectors: List[str] = Field(default_factory=list, description="Potential detection methods")
    risk_level: RiskLevel = Field(RiskLevel.SAFE, description="Risk assessment")
    timestamp: Optional[datetime] = Field(None, description="When this hop occurred")
    response_time_ms: Optional[float] = Field(None, description="Response time in milliseconds")


class CriticalIssue(BaseModel):
    """Represents a critical issue found during analysis."""
    
    id: str = Field(..., description="Unique issue identifier")
    category: IssueCategory = Field(..., description="Issue category")
    severity: SeverityLevel = Field(..., description="Issue severity")
    title: str = Field(..., description="Short issue title")
    description: str = Field(..., description="Detailed description")
    location: Optional[str] = Field(None, description="Where the issue was found")
    timestamp: Optional[datetime] = Field(None, description="When issue occurred")
    log_line: Optional[int] = Field(None, description="Line number in log file")
    recommendation: Optional[str] = Field(None, description="How to fix the issue")
    code_fix: Optional[str] = Field(None, description="Code snippet to fix issue")
    impact_score: int = Field(..., ge=0, le=100, description="Impact score (0-100)")
    raw_data: Dict[str, Any] = Field(default_factory=dict, description="Raw log data")


class AnalysisSummary(BaseModel):
    """High-level summary of analysis results."""
    
    status: str = Field(..., description="Overall status (SUCCESS, PARTIAL_SUCCESS, FAILED)")
    overall_score: int = Field(..., ge=0, le=100, description="Overall success score (0-100)")
    critical_issues_count: int = Field(0, description="Number of critical issues")
    high_issues_count: int = Field(0, description="Number of high severity issues")
    medium_issues_count: int = Field(0, description="Number of medium severity issues")
    total_issues_count: int = Field(0, description="Total number of issues")
    
    proxy_chain_functional: bool = Field(False, description="Is proxy chain working")
    oauth_success: bool = Field(False, description="Did OAuth succeed")
    antibot_bypass_success: bool = Field(False, description="Was anti-bot protection bypassed")
    geographic_masking_active: bool = Field(False, description="Is geographic masking working")
    
    analysis_duration_ms: float = Field(0, description="Time taken for analysis")
    timestamp: datetime = Field(default_factory=datetime.now, description="Analysis timestamp")


class PerformanceMetrics(BaseModel):
    """Performance-related metrics."""
    
    total_requests: int = Field(0, description="Total number of requests")
    successful_requests: int = Field(0, description="Number of successful requests")
    failed_requests: int = Field(0, description="Number of failed requests")
    average_response_time_ms: float = Field(0, description="Average response time")
    max_response_time_ms: float = Field(0, description="Maximum response time")
    min_response_time_ms: float = Field(0, description="Minimum response time")
    success_rate_percent: float = Field(0, description="Success rate percentage")


class TargetGeography(BaseModel):
    """Target geography configuration for analysis."""
    
    country_code: str = Field("US", description="ISO country code (e.g., 'US', 'UK', 'DE')")
    country_name: str = Field("United States", description="Human-readable country name")
    ip_ranges: List[str] = Field(default_factory=list, description="Expected IP ranges (CIDR notation)")
    timezone: str = Field("America/New_York", description="Expected timezone")
    language: str = Field("en-US", description="Expected language code")
    
    @field_validator('country_code')
    @classmethod
    def validate_country_code(cls, v: str) -> str:
        """Validate country code format."""
        if len(v) != 2 or not v.isupper():
            raise ValueError("Country code must be 2 uppercase letters (ISO 3166-1 alpha-2)")
        return v


class AnalysisConfig(BaseModel):
    """Configuration for analysis operations."""
    
    # Core features (always enabled)
    core_features: List[str] = Field(
        default_factory=lambda: [
            "tls_fingerprint_detection",
            "proxy_header_analysis", 
            "network_trace_mapping",
            "critical_error_detection"
        ],
        description="Core analysis features"
    )
    
    # Service and geography configuration
    service_domains: List[str] = Field(
        default_factory=lambda: [
            "example.com",
            "api.example.com",
            "login.example.com",
            "oauth.example.com"
        ],
        description="Target service domains to monitor"
    )
    target_geography: TargetGeography = Field(
        default_factory=TargetGeography,
        description="Expected geographic location configuration"
    )
    
    # Optional features
    fingerprint_comparison: bool = Field(False, description="Enable fingerprint comparison")
    session_timeline: bool = Field(False, description="Generate session timeline")
    diff_analysis: bool = Field(False, description="Enable session diff analysis")
    auto_remediation: bool = Field(True, description="Generate auto-fix suggestions")
    extended_browser_analysis: bool = Field(False, description="Deep browser config analysis")
    
    # Detection rules
    detection_rules: List[DetectionRule] = Field(default_factory=list, description="Custom detection rules")
    
    # Output configuration
    output_format: str = Field("json", description="Output format (json, yaml, text)")
    include_raw_data: bool = Field(False, description="Include raw log data in output")
    max_issues_per_category: int = Field(10, description="Maximum issues to report per category")
    
    # Performance settings
    max_log_size_mb: int = Field(100, description="Maximum log file size to process")
    timeout_seconds: int = Field(300, description="Analysis timeout in seconds")
    parallel_processing: bool = Field(True, description="Enable parallel processing")

    @field_validator('output_format')
    @classmethod
    def validate_output_format(cls, v: str) -> str:
        """Validate output format."""
        allowed_formats = ['json', 'yaml', 'text', 'html']
        if v not in allowed_formats:
            raise ValueError(f"Output format must be one of: {allowed_formats}")
        return v


class LogSource(BaseModel):
    """Represents a log source for analysis."""
    
    path: Path = Field(..., description="Path to log file")
    format: LogFormat = Field(..., description="Log format type")
    encoding: str = Field("utf-8", description="File encoding")
    priority: int = Field(1, description="Processing priority (1=highest)")
    enabled: bool = Field(True, description="Whether to process this source")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional metadata")


class AnalysisResult(BaseModel):
    """Complete analysis results."""
    
    # Summary information
    summary: AnalysisSummary = Field(..., description="High-level summary")
    
    # Detailed findings
    critical_issues: List[CriticalIssue] = Field(default_factory=list, description="Critical issues found")
    network_trace: List[NetworkHop] = Field(default_factory=list, description="Complete network trace")
    performance_metrics: PerformanceMetrics = Field(default_factory=PerformanceMetrics, description="Performance data")
    
    # Analysis metadata
    config_used: AnalysisConfig = Field(..., description="Configuration used for analysis")
    log_sources: List[LogSource] = Field(default_factory=list, description="Log sources analyzed")
    analysis_version: str = Field("0.1.0", description="Analyzer version used")
    
    # Optional features (if enabled)
    session_timeline: Optional[List[Dict[str, Any]]] = Field(None, description="Timeline of events")
    fingerprint_comparison: Optional[Dict[str, Any]] = Field(None, description="Fingerprint analysis")
    remediation_suggestions: List[Dict[str, str]] = Field(default_factory=list, description="Auto-fix suggestions")
    
    # Raw data (if requested)
    raw_log_data: Dict[str, Any] = Field(default_factory=dict, description="Raw log excerpts")

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return self.model_dump(exclude_none=True)

    def get_issues_by_category(self, category: IssueCategory) -> List[CriticalIssue]:
        """Get all issues for a specific category."""
        return [issue for issue in self.critical_issues if issue.category == category]

    def get_issues_by_severity(self, severity: SeverityLevel) -> List[CriticalIssue]:
        """Get all issues with a specific severity level."""
        return [issue for issue in self.critical_issues if issue.severity == severity]

    def get_network_trace_table(self) -> List[List[str]]:
        """Get network trace formatted as table rows."""
        headers = [
            "Hop", "Actor", "Incoming IP", "Outgoing IP", 
            "Actor Name", "TLS Info", "Detection Vectors", "Risk Level"
        ]
        
        rows = [headers]
        for hop in self.network_trace:
            tls_info = ""
            if hop.tls_info:
                tls_info = f"{hop.tls_info.version or 'Unknown'}"
                if hop.tls_info.cipher_suite:
                    tls_info += f" ({hop.tls_info.cipher_suite[:20]}...)"
            
            detection_info = ", ".join(hop.detection_vectors[:2])  # Show first 2
            if len(hop.detection_vectors) > 2:
                detection_info += "..."
            
            row = [
                str(hop.hop_number),
                hop.actor,
                hop.incoming_ip,
                hop.outgoing_ip,
                hop.actor_name,
                tls_info,
                detection_info or "None",
                hop.risk_level.value
            ]
            rows.append(row)
        
        return rows

    def get_critical_issues_summary(self) -> Dict[str, int]:
        """Get summary of critical issues by category."""
        summary = {}
        for issue in self.critical_issues:
            category = issue.category.value
            summary[category] = summary.get(category, 0) + 1
        return summary
